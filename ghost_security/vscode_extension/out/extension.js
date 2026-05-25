"use strict";
/**
 * Ghost Security VS Code Extension
 * Real-time SAST scanning with 3000+ rules.
 */
const vscode = require("vscode");
const cp = require("child_process");
const path = require("path");
const fs = require("fs");
const os = require("os");

// ── Constants ─────────────────────────────────────────────────────────────────
const EXT_ID = "ghost-security";
const STATUS_OK = "$(shield) Ghost";
const STATUS_SCANNING = "$(sync~spin) Ghost Scanning...";
const STATUS_ISSUES = (n) => `$(shield) Ghost: ${n} issue${n===1?"":"s"}`;
const SEVERITY_ORDER = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1 };
const SEVERITY_VSCODE = {
    CRITICAL: vscode.DiagnosticSeverity.Error,
    HIGH:     vscode.DiagnosticSeverity.Error,
    MEDIUM:   vscode.DiagnosticSeverity.Warning,
    LOW:      vscode.DiagnosticSeverity.Information,
    INFO:     vscode.DiagnosticSeverity.Hint,
};

// ── State ─────────────────────────────────────────────────────────────────────
let diagnosticCollection;
let statusBarItem;
let outputChannel;
let findingsTreeProvider;
let scanInProgress = false;
const findingsCache = new Map(); // uri.toString() -> findings[]

// ── Activation ────────────────────────────────────────────────────────────────
function activate(context) {
    outputChannel = vscode.window.createOutputChannel("Ghost Security");
    diagnosticCollection = vscode.languages.createDiagnosticCollection(EXT_ID);
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
    statusBarItem.command = "ghost.showFindings";
    statusBarItem.tooltip = "Click to view Ghost Security findings";
    statusBarItem.text = STATUS_OK;
    statusBarItem.show();

    findingsTreeProvider = new FindingsTreeProvider();
    vscode.window.registerTreeDataProvider("ghostSecurityFindings", findingsTreeProvider);

    // Register commands
    const cmds = [
        ["ghost.scanFile",       () => scanActiveFile()],
        ["ghost.scanWorkspace",  () => scanWorkspace()],
        ["ghost.showFindings",   () => showFindingsPanel(context)],
        ["ghost.clearFindings",  () => clearFindings()],
        ["ghost.openSettings",   () => vscode.commands.executeCommand("workbench.action.openSettings", "ghostSecurity")],
        ["ghost.showRuleInfo",   () => showRuleInfo()],
        ["ghost.runQuickFix",    () => applyQuickFix()],
        ["ghost.exportSarif",    () => exportReport("sarif")],
        ["ghost.exportJson",     () => exportReport("json")],
        ["ghost.updateRules",    () => updateRules()],
    ];
    cmds.forEach(([id, fn]) => context.subscriptions.push(vscode.commands.registerCommand(id, fn)));

    // Auto-scan triggers
    const cfg = getConfig();
    if (cfg.scanOnSave) {
        context.subscriptions.push(
            vscode.workspace.onDidSaveTextDocument(doc => {
                if (isSupportedFile(doc.uri)) scanDocument(doc.uri);
            })
        );
    }
    if (cfg.scanOnOpen) {
        context.subscriptions.push(
            vscode.window.onDidChangeActiveTextEditor(editor => {
                if (editor && isSupportedFile(editor.document.uri)) {
                    scanDocument(editor.document.uri);
                }
            })
        );
    }

    // Scan current open file on startup
    if (vscode.window.activeTextEditor) {
        const uri = vscode.window.activeTextEditor.document.uri;
        if (isSupportedFile(uri)) scanDocument(uri);
    }

    outputChannel.appendLine("[Ghost Security] Extension activated.");
    outputChannel.appendLine("[Ghost Security] Using 3000+ security rules across 15+ languages.");
    context.subscriptions.push(diagnosticCollection, statusBarItem, outputChannel);
}

function deactivate() {
    diagnosticCollection && diagnosticCollection.clear();
}

// ── Configuration ─────────────────────────────────────────────────────────────
function getConfig() {
    const cfg = vscode.workspace.getConfiguration("ghostSecurity");
    return {
        cliPath:             cfg.get("cliPath", "ghost"),
        scanOnSave:          cfg.get("scanOnSave", true),
        scanOnOpen:          cfg.get("scanOnOpen", true),
        minSeverity:         cfg.get("minSeverity", "MEDIUM"),
        rulesDir:            cfg.get("rulesDir", ""),
        enabledLanguages:    cfg.get("enabledLanguages", []),
        showInlineHints:     cfg.get("showInlineHints", true),
        maxFindingsPerFile:  cfg.get("maxFindingsPerFile", 100),
        suppressedRules:     cfg.get("suppressedRules", []),
        auditMode:           cfg.get("auditMode", false),
    };
}

// ── Language support ──────────────────────────────────────────────────────────
const SUPPORTED_EXTENSIONS = new Set([
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
    ".php", ".rb", ".rs", ".sol", ".tf", ".yaml", ".yml",
    ".cs", ".kt", ".swift", ".dockerfile", ".Dockerfile"
]);

function isSupportedFile(uri) {
    const ext = path.extname(uri.fsPath).toLowerCase();
    return SUPPORTED_EXTENSIONS.has(ext) || path.basename(uri.fsPath).startsWith("Dockerfile");
}

function getLangFromUri(uri) {
    const ext = path.extname(uri.fsPath).toLowerCase();
    const map = {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".jsx": "javascript", ".tsx": "typescript", ".java": "java",
        ".go": "go", ".php": "php", ".rb": "ruby", ".rs": "rust",
        ".sol": "solidity", ".tf": "terraform", ".cs": "csharp",
        ".kt": "kotlin", ".swift": "swift",
    };
    return map[ext] || "unknown";
}

// ── Scanning ──────────────────────────────────────────────────────────────────
async function scanActiveFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) { vscode.window.showWarningMessage("No active file to scan."); return; }
    await scanDocument(editor.document.uri);
}

async function scanDocument(uri) {
    if (scanInProgress) return;
    const cfg = getConfig();
    const filePath = uri.fsPath;
    if (!fs.existsSync(filePath)) return;

    scanInProgress = true;
    statusBarItem.text = STATUS_SCANNING;

    try {
        const findings = await runGhostScan(filePath, cfg);
        const filtered = findings.filter(f => {
            if (cfg.suppressedRules.includes(f.rule_id)) return false;
            return (SEVERITY_ORDER[f.severity] || 0) >= (SEVERITY_ORDER[cfg.minSeverity] || 0);
        }).slice(0, cfg.maxFindingsPerFile);

        findingsCache.set(uri.toString(), filtered);
        updateDiagnostics(uri, filtered);
        updateStatusBar();
        findingsTreeProvider.refresh();
    } catch (err) {
        outputChannel.appendLine(`[ERROR] Scan failed for ${filePath}: ${err.message}`);
    } finally {
        scanInProgress = false;
        if (statusBarItem.text === STATUS_SCANNING) statusBarItem.text = STATUS_OK;
    }
}

async function scanWorkspace() {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders || folders.length === 0) {
        vscode.window.showWarningMessage("No workspace folder open.");
        return;
    }
    const cfg = getConfig();
    const rootPath = folders[0].uri.fsPath;

    await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "Ghost Security: Scanning workspace...",
        cancellable: true,
    }, async (progress, token) => {
        const files = await findSupportedFiles(rootPath);
        let done = 0;
        for (const file of files) {
            if (token.isCancellationRequested) break;
            progress.report({ increment: (100 / files.length), message: path.basename(file) });
            await scanDocument(vscode.Uri.file(file));
            done++;
        }
        const totalIssues = Array.from(findingsCache.values()).reduce((sum, f) => sum + f.length, 0);
        vscode.window.showInformationMessage(
            `Ghost Security: Scanned ${done} files. Found ${totalIssues} issues.`
        );
    });
}

async function findSupportedFiles(rootPath) {
    return new Promise((resolve) => {
        const found = [];
        const walk = (dir) => {
            try {
                const entries = fs.readdirSync(dir, { withFileTypes: true });
                for (const e of entries) {
                    if (e.name.startsWith(".") || e.name === "node_modules" || e.name === "__pycache__") continue;
                    const full = path.join(dir, e.name);
                    if (e.isDirectory()) walk(full);
                    else if (SUPPORTED_EXTENSIONS.has(path.extname(e.name).toLowerCase())) found.push(full);
                }
            } catch {}
        };
        walk(rootPath);
        resolve(found);
    });
}

// ── Ghost CLI integration ──────────────────────────────────────────────────────
async function runGhostScan(filePath, cfg) {
    return new Promise((resolve) => {
        const args = ["scan", filePath, "--output", "json", "--quiet"];
        if (cfg.minSeverity) args.push("--min-severity", cfg.minSeverity);
        if (cfg.rulesDir) args.push("--rules-dir", cfg.rulesDir);
        if (cfg.auditMode) args.push("--thorough");

        const cliPath = resolveCLI(cfg.cliPath);
        if (!cliPath) {
            outputChannel.appendLine("[WARN] Ghost Security CLI not found. Using built-in regex scanner.");
            resolve(runBuiltinScan(filePath));
            return;
        }

        let stdout = "", stderr = "";
        const proc = cp.spawn(cliPath, args, { timeout: 30000 });
        proc.stdout.on("data", d => stdout += d);
        proc.stderr.on("data", d => stderr += d);
        proc.on("error", () => resolve(runBuiltinScan(filePath)));
        proc.on("close", () => {
            try {
                const parsed = JSON.parse(stdout);
                resolve(Array.isArray(parsed) ? parsed : (parsed.findings || []));
            } catch {
                resolve(runBuiltinScan(filePath));
            }
        });
    });
}

function resolveCLI(cliPath) {
    if (cliPath !== "ghost") {
        return fs.existsSync(cliPath) ? cliPath : null;
    }
    const candidates = [
        "ghost", "/usr/local/bin/ghost", "/usr/bin/ghost",
        path.join(os.homedir(), ".local/bin/ghost"),
        path.join(os.homedir(), ".ghost/bin/ghost"),
    ];
    for (const c of candidates) {
        try { cp.execSync(`"${c}" --version`, { timeout: 3000 }); return c; } catch {}
    }
    return null;
}

// ── Built-in scanner (fallback when CLI unavailable) ─────────────────────────
const BUILTIN_RULES = [
    {id:"GHOST-INLINE-001", name:"Hardcoded Secret", sev:"CRITICAL", pat:/(?:password|secret|api_key|token)\s*=\s*["'][^"']{8,}["']/gi},
    {id:"GHOST-INLINE-002", name:"SQL Injection Risk", sev:"HIGH",     pat:/execute\s*\([^)]*\+[^)]*\)/gi},
    {id:"GHOST-INLINE-003", name:"eval() Usage",      sev:"HIGH",     pat:/\beval\s*\([^)]+\)/gi},
    {id:"GHOST-INLINE-004", name:"MD5/SHA1 Usage",    sev:"MEDIUM",   pat:/\b(?:md5|sha1)\s*\(/gi},
    {id:"GHOST-INLINE-005", name:"Shell=True",        sev:"HIGH",     pat:/shell\s*=\s*True/g},
    {id:"GHOST-INLINE-006", name:"SSL Verify Bypass", sev:"CRITICAL", pat:/verify\s*=\s*False/g},
    {id:"GHOST-INLINE-007", name:"innerHTML XSS",     sev:"HIGH",     pat:/\.innerHTML\s*=[^=]/g},
    {id:"GHOST-INLINE-008", name:"dangerouslySetInnerHTML",sev:"HIGH",pat:/dangerouslySetInnerHTML/g},
    {id:"GHOST-INLINE-009", name:"Pickle Loads",      sev:"CRITICAL", pat:/pickle\.loads?\s*\(/g},
    {id:"GHOST-INLINE-010", name:"Hardcoded Private Key",sev:"CRITICAL",pat:/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g},
    {id:"GHOST-INLINE-011", name:"AWS Access Key",    sev:"CRITICAL", pat:/AKIA[0-9A-Z]{16}/g},
    {id:"GHOST-INLINE-012", name:"Path Traversal",    sev:"HIGH",     pat:/open\s*\([^)]*\.{2}\//g},
    {id:"GHOST-INLINE-013", name:"Command Injection", sev:"CRITICAL", pat:/subprocess\.run\s*\([^)]*shell\s*=\s*True/g},
    {id:"GHOST-INLINE-014", name:"Weak Random",       sev:"HIGH",     pat:/Math\.random\s*\(\s*\)/g},
    {id:"GHOST-INLINE-015", name:"JWT No Verify",     sev:"CRITICAL", pat:/jwt\.decode\s*\([^)]*algorithms\s*=\s*None/g},
    {id:"GHOST-INLINE-016", name:"Debugging Enabled", sev:"HIGH",     pat:/app\.run\s*\([^)]*debug\s*=\s*True/g},
    {id:"GHOST-INLINE-017", name:"Unencrypted HTTP",  sev:"MEDIUM",   pat:/http:\/\/(?!localhost|127\.0\.0\.1)/g},
    {id:"GHOST-INLINE-018", name:"TODO/FIXME Security",sev:"INFO",    pat:/(?:TODO|FIXME|HACK|XXX)\s*:?\s*(?:security|auth|crypto|secret)/gi},
    {id:"GHOST-INLINE-019", name:"Potential SSRF",    sev:"HIGH",     pat:/requests\.get\s*\([^)]*(?:url|URL)\s*=/g},
    {id:"GHOST-INLINE-020", name:"Unvalidated Redirect",sev:"HIGH",  pat:/redirect\s*\([^)]*request\.\w+/g},
];

function runBuiltinScan(filePath) {
    const findings = [];
    let content;
    try { content = fs.readFileSync(filePath, "utf8"); } catch { return findings; }
    const lines = content.split("\n");

    for (const rule of BUILTIN_RULES) {
        rule.pat.lastIndex = 0;
        let match;
        while ((match = rule.pat.exec(content)) !== null) {
            const lineIdx = content.substring(0, match.index).split("\n").length - 1;
            findings.push({
                rule_id: rule.id,
                name: rule.name,
                severity: rule.sev,
                message: `${rule.name} detected`,
                file: filePath,
                line: lineIdx + 1,
                column: match.index - content.lastIndexOf("\n", match.index - 1) - 1,
                snippet: (lines[lineIdx] || "").trim().substring(0, 120),
            });
        }
    }
    return findings;
}

// ── Diagnostics ────────────────────────────────────────────────────────────────
function updateDiagnostics(uri, findings) {
    const diagnostics = findings.map(f => {
        const line = Math.max(0, (f.line || 1) - 1);
        const col  = Math.max(0, f.column || 0);
        const range = new vscode.Range(line, col, line, col + (f.snippet || "").length || 80);
        const diag = new vscode.Diagnostic(
            range,
            `[${f.severity}] ${f.name || f.rule_id}: ${f.message || "Security issue detected"}`,
            SEVERITY_VSCODE[f.severity] || vscode.DiagnosticSeverity.Warning
        );
        diag.source = "Ghost Security";
        diag.code = { value: f.rule_id, target: vscode.Uri.parse(`https://ghost.security/rules/${f.rule_id}`) };
        if (f.fix) diag.relatedInformation = [new vscode.DiagnosticRelatedInformation(new vscode.Location(uri, range), `Fix: ${f.fix}`)];
        return diag;
    });
    diagnosticCollection.set(uri, diagnostics);
}

function updateStatusBar() {
    const total = Array.from(findingsCache.values()).reduce((s, f) => s + f.length, 0);
    statusBarItem.text = total > 0 ? STATUS_ISSUES(total) : STATUS_OK;
    statusBarItem.backgroundColor = total > 0 ? new vscode.ThemeColor("statusBarItem.warningBackground") : undefined;
}

function clearFindings() {
    findingsCache.clear();
    diagnosticCollection.clear();
    statusBarItem.text = STATUS_OK;
    statusBarItem.backgroundColor = undefined;
    findingsTreeProvider.refresh();
    vscode.window.showInformationMessage("Ghost Security: Findings cleared.");
}

// ── Findings Panel (Webview) ──────────────────────────────────────────────────
function showFindingsPanel(context) {
    const panel = vscode.window.createWebviewPanel(
        "ghostFindings", "Ghost Security — Findings",
        vscode.ViewColumn.Beside,
        { enableScripts: true, retainContextWhenHidden: true }
    );

    const allFindings = [];
    for (const [uriStr, findings] of findingsCache) {
        const file = vscode.Uri.parse(uriStr).fsPath;
        findings.forEach(f => allFindings.push({ ...f, file: path.basename(file), fullPath: file }));
    }
    allFindings.sort((a, b) => (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0));

    const stats = {};
    allFindings.forEach(f => stats[f.severity] = (stats[f.severity] || 0) + 1);

    panel.webview.html = generateFindingsHTML(allFindings, stats);
    panel.webview.onDidReceiveMessage(msg => {
        if (msg.command === "gotoLine") {
            const uri = vscode.Uri.file(msg.file);
            vscode.window.showTextDocument(uri, { selection: new vscode.Range(msg.line - 1, 0, msg.line - 1, 0) });
        } else if (msg.command === "copyFix") {
            vscode.env.clipboard.writeText(msg.fix);
            vscode.window.showInformationMessage("Fix copied to clipboard.");
        }
    });
}

function generateFindingsHTML(findings, stats) {
    const sevColor = { CRITICAL: "#dc2626", HIGH: "#ea580c", MEDIUM: "#d97706", LOW: "#2563eb", INFO: "#6b7280" };
    const rows = findings.map(f => `
        <tr class="finding-row" data-sev="${f.severity}" onclick="goto('${f.fullPath}',${f.line||1})">
            <td><span class="badge" style="background:${sevColor[f.severity]||'#888'}">${f.severity}</span></td>
            <td class="rule-id">${f.rule_id||""}</td>
            <td>${escHtml(f.name||f.message||"")}</td>
            <td class="file-cell">${escHtml(f.file||"")}:${f.line||1}</td>
            <td class="fix-cell">${f.fix ? `<button onclick="copyFix(event,'${escHtml(f.fix)}')">Copy Fix</button>` : ""}</td>
        </tr>`).join("");

    const statHtml = Object.entries(stats).map(([sev, n]) =>
        `<span class="stat-badge" style="background:${sevColor[sev]||'#888'}">${sev}: ${n}</span>`
    ).join(" ");

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>Ghost Security Findings</title>
<style>
  :root { --bg: #1e1e1e; --surface: #252526; --border: #3e3e42; --text: #cccccc; --accent: #0078d4; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 13px; padding: 16px; }
  h1 { font-size: 18px; color: #fff; margin-bottom: 8px; display: flex; align-items: center; gap: 8px; }
  .shield { font-size: 22px; }
  .stats { margin-bottom: 16px; display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
  .stat-badge { padding: 3px 10px; border-radius: 12px; color: #fff; font-size: 12px; font-weight: 600; }
  .controls { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
  input[type=text], select { background: var(--surface); color: var(--text); border: 1px solid var(--border); border-radius: 4px; padding: 5px 10px; font-size: 12px; }
  input[type=text] { flex: 1; min-width: 200px; }
  table { width: 100%; border-collapse: collapse; }
  th { background: var(--surface); padding: 8px 10px; text-align: left; font-size: 11px; text-transform: uppercase; color: #888; border-bottom: 1px solid var(--border); position: sticky; top: 0; }
  td { padding: 7px 10px; border-bottom: 1px solid #2d2d30; vertical-align: top; }
  .finding-row:hover { background: #2a2a2c; cursor: pointer; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; color: #fff; font-size: 11px; font-weight: 700; }
  .rule-id { font-family: monospace; font-size: 11px; color: #569cd6; }
  .file-cell { font-family: monospace; font-size: 11px; color: #9cdcfe; }
  .fix-cell button { background: var(--accent); color: #fff; border: none; border-radius: 3px; padding: 2px 8px; font-size: 11px; cursor: pointer; }
  .fix-cell button:hover { background: #106ebe; }
  #total { color: #888; font-size: 12px; }
  .empty { text-align: center; padding: 40px; color: #555; }
  .filter-row { display: flex; gap: 8px; align-items: center; }
</style>
</head>
<body>
<h1><span class="shield">🔒</span> Ghost Security Findings <span id="total">(${findings.length} total)</span></h1>
<div class="stats">${statHtml || "<span style='color:#555'>No issues found</span>"}</div>
<div class="controls">
  <div class="filter-row">
    <input type="text" id="search" placeholder="Search findings..." oninput="filterRows()"/>
    <select id="sevFilter" onchange="filterRows()">
      <option value="">All Severities</option>
      <option value="CRITICAL">CRITICAL</option>
      <option value="HIGH">HIGH</option>
      <option value="MEDIUM">MEDIUM</option>
      <option value="LOW">LOW</option>
      <option value="INFO">INFO</option>
    </select>
  </div>
</div>
${findings.length === 0 ? '<div class="empty">✅ No security issues found!</div>' : `
<table>
  <thead><tr><th>Severity</th><th>Rule</th><th>Description</th><th>Location</th><th>Fix</th></tr></thead>
  <tbody id="tbody">${rows}</tbody>
</table>`}
<script>
const vscode = acquireVsCodeApi();
function goto(file, line) { vscode.postMessage({command:'gotoLine', file, line}); }
function copyFix(e, fix) { e.stopPropagation(); vscode.postMessage({command:'copyFix', fix}); }
function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function filterRows() {
  const q = document.getElementById('search').value.toLowerCase();
  const sev = document.getElementById('sevFilter').value;
  document.querySelectorAll('#tbody .finding-row').forEach(row => {
    const text = row.textContent.toLowerCase();
    const rowSev = row.dataset.sev;
    row.style.display = ((!q || text.includes(q)) && (!sev || rowSev === sev)) ? '' : 'none';
  });
}
</script>
</body></html>`;
}

function escHtml(s) {
    return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

// ── Tree View ─────────────────────────────────────────────────────────────────
class FindingsTreeProvider {
    constructor() { this._onDidChangeTreeData = new vscode.EventEmitter(); this.onDidChangeTreeData = this._onDidChangeTreeData.event; }
    refresh() { this._onDidChangeTreeData.fire(); }
    getTreeItem(element) { return element; }
    getChildren(element) {
        if (!element) {
            const items = [];
            for (const [uriStr, findings] of findingsCache) {
                if (findings.length === 0) continue;
                const label = path.basename(vscode.Uri.parse(uriStr).fsPath);
                const item = new vscode.TreeItem(`${label} (${findings.length})`, vscode.TreeItemCollapsibleState.Collapsed);
                item.resourceUri = vscode.Uri.parse(uriStr);
                item.contextValue = "file";
                item._findings = findings;
                item._uriStr = uriStr;
                return [item];
            }
            return items;
        }
        if (element._findings) {
            return element._findings.map(f => {
                const item = new vscode.TreeItem(`[${f.severity}] ${f.name || f.rule_id}`);
                item.description = `Line ${f.line || "?"}`;
                item.tooltip = f.message || "";
                item.command = { command: "vscode.open", title: "Open", arguments: [vscode.Uri.parse(element._uriStr), { selection: new vscode.Range(Math.max(0,(f.line||1)-1), 0, Math.max(0,(f.line||1)-1), 0) }] };
                return item;
            });
        }
        return [];
    }
}

// ── Quick Fix ─────────────────────────────────────────────────────────────────
async function applyQuickFix() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;
    const line = editor.selection.active.line;
    const findings = findingsCache.get(editor.document.uri.toString()) || [];
    const f = findings.find(x => (x.line || 1) - 1 === line);
    if (!f || !f.fix) { vscode.window.showInformationMessage("No quick fix available for this line."); return; }
    vscode.window.showInformationMessage(`Fix: ${f.fix}`, "Copy").then(sel => {
        if (sel === "Copy") vscode.env.clipboard.writeText(f.fix);
    });
}

// ── Export ────────────────────────────────────────────────────────────────────
async function exportReport(format) {
    const allFindings = [];
    for (const [uriStr, findings] of findingsCache) allFindings.push(...findings);
    if (allFindings.length === 0) { vscode.window.showInformationMessage("No findings to export."); return; }

    const uri = await vscode.window.showSaveDialog({ defaultUri: vscode.Uri.file(`ghost_findings.${format}`), filters: { [format.toUpperCase()]: [format] } });
    if (!uri) return;

    let content;
    if (format === "sarif") {
        content = JSON.stringify({
            version: "2.1.0",
            $schema: "https://json.schemastore.org/sarif-2.1.0.json",
            runs: [{ tool: { driver: { name: "Ghost Security", version: "1.0.0", rules: [] } }, results: allFindings.map(f => ({ ruleId: f.rule_id || "GHOST-UNKNOWN", message: { text: f.message || f.name || "" }, locations: [{ physicalLocation: { artifactLocation: { uri: f.file || "" }, region: { startLine: f.line || 1 } } }], level: { CRITICAL: "error", HIGH: "error", MEDIUM: "warning", LOW: "note", INFO: "none" }[f.severity] || "warning" })) }]
        }, null, 2);
    } else {
        content = JSON.stringify({ generated: new Date().toISOString(), tool: "Ghost Security", total: allFindings.length, findings: allFindings }, null, 2);
    }
    fs.writeFileSync(uri.fsPath, content);
    vscode.window.showInformationMessage(`Ghost Security: Report exported to ${path.basename(uri.fsPath)}`);
}

// ── Rules Update ──────────────────────────────────────────────────────────────
async function updateRules() {
    const cfg = getConfig();
    const cliPath = resolveCLI(cfg.cliPath);
    if (!cliPath) { vscode.window.showWarningMessage("Ghost Security CLI not found. Cannot update rules."); return; }

    statusBarItem.text = "$(cloud-download~spin) Updating rules...";
    try {
        await new Promise((resolve, reject) => {
            const proc = cp.spawn(cliPath, ["rules", "update"], { timeout: 60000 });
            let out = "";
            proc.stdout.on("data", d => out += d);
            proc.on("close", code => code === 0 ? resolve(out) : reject(new Error(`Exit ${code}`)));
            proc.on("error", reject);
        });
        vscode.window.showInformationMessage("Ghost Security: Rules updated successfully.");
    } catch (err) {
        vscode.window.showErrorMessage(`Ghost Security: Rule update failed — ${err.message}`);
    } finally {
        updateStatusBar();
    }
}

// ── Rule Info ─────────────────────────────────────────────────────────────────
async function showRuleInfo() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;
    const line = editor.selection.active.line;
    const findings = findingsCache.get(editor.document.uri.toString()) || [];
    const f = findings.find(x => (x.line || 1) - 1 === line);
    if (!f) { vscode.window.showInformationMessage("No finding on this line."); return; }
    vscode.window.showInformationMessage(
        `${f.rule_id}: ${f.name}\nSeverity: ${f.severity}\n${f.message || ""}`,
        "Copy Fix", "Open Docs"
    ).then(sel => {
        if (sel === "Copy Fix" && f.fix) vscode.env.clipboard.writeText(f.fix);
        if (sel === "Open Docs") vscode.env.openExternal(vscode.Uri.parse(`https://ghost.security/rules/${f.rule_id}`));
    });
}

module.exports = { activate, deactivate };
