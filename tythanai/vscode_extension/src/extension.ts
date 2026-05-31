/**
 * Ghost Security — VS Code Extension
 * Inline vulnerability detection via Ghost Security API (LSP-style).
 *
 * Архитектура:
 *   GhostClient     — HTTP клиент к Ghost API
 *   GhostDiagnostics— конвертирует findings → vscode.Diagnostic
 *   GhostScanner    — триггеры (onSave, onType, command)
 *   FindingsProvider— TreeView для панели findings
 *   CodeLensProvider— inline hints на строках с находками
 *   QuickFixProvider— code actions (explain + AI fix)
 */
import * as vscode from "vscode";

// ── Типы ─────────────────────────────────────────────────────────────────────

interface GhostFinding {
  rule_id:     string;
  type:        string;
  severity:    "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  message:     string;
  description: string;
  file:        string;
  line:        number;
  column?:     number;
  cwe?:        string;
  owasp?:      string;
  confidence?: number;
  priority?:   string;
  recommendation?: string;
  evidence?:   string;
}

interface GhostScanResult {
  findings:      GhostFinding[];
  severity_counts: Record<string, number>;
  risk_score?:   number;
  risk_level?:   string;
  scan_id?:      string;
}

// ── Config ────────────────────────────────────────────────────────────────────

function cfg<T>(key: string, def: T): T {
  return vscode.workspace.getConfiguration("ghost").get<T>(key, def);
}

// ── HTTP Client ───────────────────────────────────────────────────────────────

class GhostClient {
  private baseUrl: string;

  constructor() {
    this.baseUrl = cfg("serverUrl", "http://localhost:8000");
  }

  async isAlive(): Promise<boolean> {
    try {
      const resp = await fetch(`${this.baseUrl}/health`, { signal: AbortSignal.timeout(3000) });
      return resp.ok;
    } catch {
      return false;
    }
  }

  async scanFile(filePath: string, content: string, language: string): Promise<GhostScanResult> {
    const resp = await fetch(`${this.baseUrl}/api/scan/inline`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path: filePath, content, language }),
      signal: AbortSignal.timeout(30_000),
    });
    if (!resp.ok) throw new Error(`Ghost API error: ${resp.status}`);
    return resp.json() as Promise<GhostScanResult>;
  }

  async scanPath(path: string, mode: string = "all"): Promise<GhostScanResult> {
    const resp = await fetch(`${this.baseUrl}/api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path, mode }),
      signal: AbortSignal.timeout(120_000),
    });
    if (!resp.ok) throw new Error(`Ghost API error: ${resp.status}`);
    return resp.json() as Promise<GhostScanResult>;
  }

  async explainFinding(finding: GhostFinding): Promise<string> {
    const resp = await fetch(`${this.baseUrl}/api/v2/ollama/explain`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ finding }),
      signal: AbortSignal.timeout(60_000),
    });
    if (!resp.ok) return "Explanation unavailable (Ollama not running).";
    const data = await resp.json() as { explanation: string };
    return data.explanation;
  }

  async generateFix(finding: GhostFinding, codeContext: string): Promise<string> {
    const resp = await fetch(`${this.baseUrl}/api/v2/ollama/remediate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ finding, code_context: codeContext }),
      signal: AbortSignal.timeout(90_000),
    });
    if (!resp.ok) return "Fix generation unavailable (Ollama not running).";
    const data = await resp.json() as { remediation: string };
    return data.remediation;
  }

  async getScanHistory(target: string): Promise<unknown[]> {
    const resp = await fetch(
      `${this.baseUrl}/api/history?target=${encodeURIComponent(target)}`,
      { signal: AbortSignal.timeout(5_000) }
    );
    if (!resp.ok) return [];
    const data = await resp.json() as { scans: unknown[] };
    return data.scans || [];
  }
}

// ── Diagnostics ───────────────────────────────────────────────────────────────

const _SEV_MAP: Record<string, vscode.DiagnosticSeverity> = {
  CRITICAL: vscode.DiagnosticSeverity.Error,
  HIGH:     vscode.DiagnosticSeverity.Error,
  MEDIUM:   vscode.DiagnosticSeverity.Warning,
  LOW:      vscode.DiagnosticSeverity.Information,
  INFO:     vscode.DiagnosticSeverity.Hint,
};

function findingToDiagnostic(f: GhostFinding): vscode.Diagnostic {
  const line  = Math.max(0, (f.line || 1) - 1);
  const col   = Math.max(0, (f.column || 1) - 1);
  const range = new vscode.Range(line, col, line, col + 120);

  const sev  = _SEV_MAP[f.severity] ?? vscode.DiagnosticSeverity.Warning;
  const msg  = `[Ghost:${f.severity}] ${f.message}`;
  const diag = new vscode.Diagnostic(range, msg, sev);

  diag.source = "Ghost Security";
  diag.code   = {
    value:  f.rule_id || f.type || "GHOST",
    target: f.cwe
      ? vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${f.cwe.replace("CWE-","")}.html`)
      : vscode.Uri.parse("https://owasp.org"),
  };
  (diag as any).__ghost = f;  // сохраняем оригинал для quick-fix
  return diag;
}

// ── Scanner ───────────────────────────────────────────────────────────────────

const _MIN_SEV: Record<string, number> = { INFO:0, LOW:1, MEDIUM:2, HIGH:3, CRITICAL:4 };

class GhostScanner {
  private diagnostics:   vscode.DiagnosticCollection;
  private client:        GhostClient;
  private debounceTimer: NodeJS.Timeout | undefined;
  private statusBar:     vscode.StatusBarItem;
  private _findings:     Map<string, GhostFinding[]> = new Map();

  constructor(ctx: vscode.ExtensionContext) {
    this.diagnostics = vscode.languages.createDiagnosticCollection("ghost");
    this.client      = new GhostClient();
    this.statusBar   = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    this.statusBar.command = "ghost.showFindingsPanel";
    ctx.subscriptions.push(this.diagnostics, this.statusBar);
    this.statusBar.show();
    this._setStatus("idle");
  }

  findings(): Map<string, GhostFinding[]> { return this._findings; }

  async scanDocument(doc: vscode.TextDocument, silent = false): Promise<void> {
    const supported = ["python","javascript","typescript","javascriptreact","typescriptreact","solidity"];
    if (!supported.includes(doc.languageId)) return;

    const alive = await this.client.isAlive();
    if (!alive) {
      if (!silent) {
        vscode.window.showWarningMessage("Ghost Security: server not running at " + cfg("serverUrl","http://localhost:8000"));
      }
      this._setStatus("offline");
      return;
    }

    this._setStatus("scanning");

    try {
      const result = await this.client.scanFile(
        doc.uri.fsPath, doc.getText(), doc.languageId
      );

      const minSevIdx  = _MIN_SEV[cfg("minSeverity","MEDIUM")] ?? 2;
      const filtered   = result.findings.filter(
        f => (_MIN_SEV[f.severity] ?? 0) >= minSevIdx
      );

      this._findings.set(doc.uri.toString(), filtered);
      const diags = filtered.map(findingToDiagnostic);
      this.diagnostics.set(doc.uri, diags);
      this._updateStatus(result);

    } catch (err: any) {
      this._setStatus("error");
      if (!silent) vscode.window.showErrorMessage(`Ghost scan failed: ${err.message}`);
    }
  }

  async scanWorkspace(): Promise<void> {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) return;

    this._setStatus("scanning workspace…");
    try {
      const result = await this.client.scanPath(folder.uri.fsPath);
      vscode.window.showInformationMessage(
        `Ghost Security: ${result.findings.length} findings (${result.risk_level ?? "?"} risk)`
      );
      this._updateStatus(result);
    } catch (err: any) {
      this._setStatus("error");
      vscode.window.showErrorMessage(`Ghost workspace scan failed: ${err.message}`);
    }
  }

  scheduleDebounce(doc: vscode.TextDocument): void {
    clearTimeout(this.debounceTimer);
    this.debounceTimer = setTimeout(() => this.scanDocument(doc, true), 1500);
  }

  clear(): void {
    this.diagnostics.clear();
    this._findings.clear();
    this._setStatus("idle");
  }

  private _setStatus(msg: string): void {
    this.statusBar.text = `$(shield) Ghost: ${msg}`;
  }

  private _updateStatus(result: GhostScanResult): void {
    const c = result.severity_counts;
    const crits = c?.CRITICAL ?? 0;
    const highs = c?.HIGH     ?? 0;
    const icon  = crits > 0 ? "$(error)" : highs > 0 ? "$(warning)" : "$(pass)";
    this.statusBar.text = `${icon} Ghost: ${result.findings.length} issue(s)`;
  }

  getClient(): GhostClient { return this.client; }
}

// ── Code Lens Provider ────────────────────────────────────────────────────────

class GhostCodeLensProvider implements vscode.CodeLensProvider {
  constructor(private scanner: GhostScanner) {}

  provideCodeLenses(document: vscode.TextDocument): vscode.CodeLens[] {
    if (!cfg("showInlineHints", true)) return [];
    const findings = this.scanner.findings().get(document.uri.toString()) ?? [];
    return findings.map(f => {
      const line  = Math.max(0, (f.line || 1) - 1);
      const range = new vscode.Range(line, 0, line, 0);
      const icon  = { CRITICAL:"🔴", HIGH:"🟠", MEDIUM:"🟡", LOW:"🟢" }[f.severity] ?? "⚪";
      return new vscode.CodeLens(range, {
        title:     `${icon} ${f.severity}: ${f.message.slice(0, 60)}`,
        command:   "ghost.explainFinding",
        arguments: [f],
      });
    });
  }
}

// ── Quick Fix Provider ────────────────────────────────────────────────────────

class GhostQuickFixProvider implements vscode.CodeActionProvider {
  constructor(private scanner: GhostScanner) {}

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
  ): vscode.CodeAction[] {
    const findings = this.scanner.findings().get(document.uri.toString()) ?? [];
    const lineFindings = findings.filter(
      f => Math.abs((f.line || 1) - 1 - range.start.line) < 2
    );
    if (!lineFindings.length) return [];

    const actions: vscode.CodeAction[] = [];
    for (const f of lineFindings) {
      // Explain
      const explain = new vscode.CodeAction(
        `Ghost: Explain "${f.message.slice(0, 40)}"`,
        vscode.CodeActionKind.QuickFix,
      );
      explain.command = { command: "ghost.explainFinding", title: "Explain", arguments: [f] };
      actions.push(explain);

      // AI Fix
      if (cfg("autoFix", true)) {
        const fix = new vscode.CodeAction(
          `Ghost: AI Fix for ${f.severity} — ${f.rule_id || f.type}`,
          vscode.CodeActionKind.QuickFix,
        );
        fix.command = {
          command: "ghost.generateFix",
          title: "Generate Fix",
          arguments: [f, document.getText()],
        };
        fix.isPreferred = f.severity === "CRITICAL";
        actions.push(fix);
      }
    }
    return actions;
  }
}

// ── Findings Tree View ────────────────────────────────────────────────────────

class FindingItem extends vscode.TreeItem {
  constructor(
    public readonly finding: GhostFinding,
    public readonly resourceUri: vscode.Uri,
  ) {
    super(
      `[${finding.severity}] ${finding.message.slice(0, 60)}`,
      vscode.TreeItemCollapsibleState.None,
    );
    this.tooltip     = `${finding.message}\n\nCWE: ${finding.cwe || "N/A"}\nFile: ${finding.file}:${finding.line}`;
    this.description = `${finding.file}:${finding.line}`;
    this.iconPath    = new vscode.ThemeIcon(
      { CRITICAL:"error", HIGH:"warning", MEDIUM:"info" }[finding.severity] ?? "circle-outline"
    );
    this.command = {
      command: "vscode.open",
      title:   "Open File",
      arguments: [resourceUri, { selection: new vscode.Range(Math.max(0,(finding.line||1)-1), 0, Math.max(0,(finding.line||1)-1), 0) }],
    };
  }
}

class FindingsProvider implements vscode.TreeDataProvider<FindingItem> {
  private _onDidChange = new vscode.EventEmitter<FindingItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChange.event;
  private _items: FindingItem[] = [];

  refresh(scanner: GhostScanner): void {
    this._items = [];
    for (const [uriStr, findings] of scanner.findings()) {
      const uri = vscode.Uri.parse(uriStr);
      for (const f of findings) {
        this._items.push(new FindingItem(f, uri));
      }
    }
    this._items.sort((a,b) =>
      (_MIN_SEV[b.finding.severity]??0) - (_MIN_SEV[a.finding.severity]??0)
    );
    this._onDidChange.fire(undefined);
  }

  getTreeItem(el: FindingItem)  { return el; }
  getChildren(): FindingItem[]  { return this._items; }
}

// ── Extension Entry Point ─────────────────────────────────────────────────────

export function activate(ctx: vscode.ExtensionContext) {
  const scanner         = new GhostScanner(ctx);
  const findingsProvider = new FindingsProvider();

  // Register tree view
  vscode.window.registerTreeDataProvider("ghost.findingsView", findingsProvider);

  // Code lens + quick fix
  ctx.subscriptions.push(
    vscode.languages.registerCodeLensProvider(
      ["python","javascript","typescript","javascriptreact","typescriptreact","solidity"],
      new GhostCodeLensProvider(scanner),
    ),
    vscode.languages.registerCodeActionsProvider(
      ["python","javascript","typescript","javascriptreact","typescriptreact","solidity"],
      new GhostQuickFixProvider(scanner),
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] },
    ),
  );

  // Commands
  ctx.subscriptions.push(
    vscode.commands.registerCommand("ghost.scanFile", async () => {
      const doc = vscode.window.activeTextEditor?.document;
      if (doc) { await scanner.scanDocument(doc); findingsProvider.refresh(scanner); }
    }),

    vscode.commands.registerCommand("ghost.scanWorkspace", async () => {
      await scanner.scanWorkspace(); findingsProvider.refresh(scanner);
    }),

    vscode.commands.registerCommand("ghost.showFindingsPanel", () => {
      findingsProvider.refresh(scanner);
      vscode.commands.executeCommand("ghost.findingsView.focus");
    }),

    vscode.commands.registerCommand("ghost.clearDiagnostics", () => {
      scanner.clear(); findingsProvider.refresh(scanner);
    }),

    vscode.commands.registerCommand("ghost.explainFinding", async (finding: GhostFinding) => {
      const panel = vscode.window.createWebviewPanel(
        "ghost.explain", `Ghost: ${finding.severity} — ${finding.rule_id || finding.type}`,
        vscode.ViewColumn.Beside, { enableScripts: false },
      );
      panel.webview.html = `<body style="font-family:sans-serif;padding:16px">
        <h2>🔴 ${finding.severity} — ${finding.message}</h2>
        <p><b>File:</b> ${finding.file}:${finding.line}</p>
        <p><b>CWE:</b> ${finding.cwe||"N/A"} | <b>OWASP:</b> ${finding.owasp||"N/A"}</p>
        <p>⏳ Loading AI explanation...</p></body>`;
      const explanation = await scanner.getClient().explainFinding(finding);
      panel.webview.html = `<body style="font-family:sans-serif;padding:16px;max-width:720px">
        <h2>🔴 ${finding.severity} — ${finding.message}</h2>
        <p><b>File:</b> <code>${finding.file}:${finding.line}</code></p>
        <p><b>Rule:</b> ${finding.rule_id||finding.type} | <b>CWE:</b> ${finding.cwe||"N/A"} | <b>OWASP:</b> ${finding.owasp||"N/A"}</p>
        <hr>
        <h3>Explanation</h3>
        <pre style="white-space:pre-wrap;background:#f5f5f5;padding:12px;border-radius:6px">${explanation}</pre>
        ${finding.recommendation ? `<h3>Recommended Fix</h3><p>${finding.recommendation}</p>` : ""}
        </body>`;
    }),

    vscode.commands.registerCommand("ghost.generateFix", async (finding: GhostFinding, codeCtx: string) => {
      const panel = vscode.window.createWebviewPanel(
        "ghost.fix", `Ghost Fix: ${finding.rule_id || finding.type}`,
        vscode.ViewColumn.Beside, { enableScripts: false },
      );
      panel.webview.html = `<body style="font-family:sans-serif;padding:16px"><p>⏳ Generating fix with AI...</p></body>`;
      const fix = await scanner.getClient().generateFix(finding, codeCtx || "");
      panel.webview.html = `<body style="font-family:sans-serif;padding:16px;max-width:720px">
        <h2>💡 AI Fix: ${finding.message}</h2>
        <pre style="white-space:pre-wrap;background:#f0fff0;padding:12px;border-radius:6px">${fix}</pre>
        </body>`;
    }),
  );

  // Auto-scan triggers
  ctx.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(doc => {
      if (cfg("scanOnSave", true)) scanner.scanDocument(doc, true).then(() => findingsProvider.refresh(scanner));
    }),
    vscode.workspace.onDidChangeTextDocument(e => {
      if (cfg("scanOnType", false)) scanner.scheduleDebounce(e.document);
    }),
    vscode.window.onDidChangeActiveTextEditor(editor => {
      if (editor) scanner.scanDocument(editor.document, true).then(() => findingsProvider.refresh(scanner));
    }),
  );

  // Initial scan of open editors
  const activeDoc = vscode.window.activeTextEditor?.document;
  if (activeDoc) scanner.scanDocument(activeDoc, true);

  vscode.window.showInformationMessage("👻 Ghost Security activated — scanning for vulnerabilities");
}

export function deactivate() {}
