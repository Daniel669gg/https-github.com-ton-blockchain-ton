"use strict";
/**
 * Ghost Security VS Code Extension
 * Real-time security scanning for TON/Web3 and general code.
 * Feature 4: Shortest path to DAU — scans on save, inline diagnostics, findings panel.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const path = __importStar(require("path"));
const http = __importStar(require("http"));
const https = __importStar(require("https"));
// ── Severity helpers ──────────────────────────────────────────────────────────
const SEV_ORDER = {
    CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1,
};
const SEV_ICON = {
    CRITICAL: "$(error)",
    HIGH: "$(warning)",
    MEDIUM: "$(info)",
    LOW: "$(circle-outline)",
    INFO: "$(circle-slash)",
};
const SEV_DIAG = {
    CRITICAL: vscode.DiagnosticSeverity.Error,
    HIGH: vscode.DiagnosticSeverity.Error,
    MEDIUM: vscode.DiagnosticSeverity.Warning,
    LOW: vscode.DiagnosticSeverity.Information,
    INFO: vscode.DiagnosticSeverity.Hint,
};
// ── HTTP helper (no axios in node env) ───────────────────────────────────────
function httpPost(url, body, apiKey) {
    return new Promise((resolve, reject) => {
        const data = JSON.stringify(body);
        const parsed = new URL(url);
        const lib = parsed.protocol === "https:" ? https : http;
        const options = {
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
            path: parsed.pathname + parsed.search,
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Content-Length": Buffer.byteLength(data),
                ...(apiKey ? { "X-API-Key": apiKey } : {}),
            },
        };
        const req = lib.request(options, (res) => {
            let raw = "";
            res.on("data", (chunk) => (raw += chunk));
            res.on("end", () => {
                try {
                    resolve(JSON.parse(raw));
                }
                catch (e) {
                    resolve({ error: raw });
                }
            });
        });
        req.on("error", reject);
        req.setTimeout(30000, () => { req.destroy(); reject(new Error("timeout")); });
        req.write(data);
        req.end();
    });
}
function httpGet(url, apiKey) {
    return new Promise((resolve, reject) => {
        const parsed = new URL(url);
        const lib = parsed.protocol === "https:" ? https : http;
        const options = {
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
            path: parsed.pathname + parsed.search,
            method: "GET",
            headers: apiKey ? { "X-API-Key": apiKey } : {},
        };
        const req = lib.request(options, (res) => {
            let raw = "";
            res.on("data", (chunk) => (raw += chunk));
            res.on("end", () => {
                try {
                    resolve(JSON.parse(raw));
                }
                catch (e) {
                    resolve({ error: raw });
                }
            });
        });
        req.on("error", reject);
        req.setTimeout(15000, () => { req.destroy(); reject(new Error("timeout")); });
        req.end();
    });
}
// ── Findings Tree Provider ────────────────────────────────────────────────────
class FindingItem extends vscode.TreeItem {
    constructor(label, collapsibleState, finding, groupKey) {
        super(label, collapsibleState);
        this.label = label;
        this.collapsibleState = collapsibleState;
        this.finding = finding;
        this.groupKey = groupKey;
        if (finding) {
            const icon = SEV_ICON[finding.severity] || "$(circle-outline)";
            this.iconPath = new vscode.ThemeIcon(finding.severity === "CRITICAL" || finding.severity === "HIGH"
                ? "error"
                : finding.severity === "MEDIUM"
                    ? "warning"
                    : "info");
            this.description = `${finding.file}:${finding.line}`;
            this.tooltip = new vscode.MarkdownString(`**${finding.type}** [${finding.severity}]\n\n` +
                `${finding.description || finding.message}\n\n` +
                (finding.cwe ? `CWE: \`${finding.cwe}\`\n\n` : "") +
                (finding.recommendation ? `💡 ${finding.recommendation}` : ""));
            this.command = {
                command: "ghost.openFinding",
                title: "Open Finding",
                arguments: [finding],
            };
            if (finding.reachability === "unreachable") {
                this.description += " [filtered]";
            }
        }
    }
}
class GhostFindingsProvider {
    constructor() {
        this._onDidChange = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChange.event;
        this.findings = [];
        this.minSeverity = "MEDIUM";
    }
    setFindings(findings, minSev) {
        this.findings = findings;
        this.minSeverity = minSev;
        this._onDidChange.fire(undefined);
    }
    clear() {
        this.findings = [];
        this._onDidChange.fire(undefined);
    }
    getTreeItem(el) { return el; }
    getChildren(el) {
        const minOrder = SEV_ORDER[this.minSeverity] || 1;
        const filtered = this.findings.filter((f) => (SEV_ORDER[f.severity] || 0) >= minOrder);
        if (!el) {
            // Group by severity
            const groups = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
            return groups
                .map((sev) => {
                const count = filtered.filter((f) => f.severity === sev).length;
                if (count === 0)
                    return null;
                return new FindingItem(`${SEV_ICON[sev]} ${sev} (${count})`, vscode.TreeItemCollapsibleState.Expanded, undefined, sev);
            })
                .filter(Boolean);
        }
        if (el.groupKey) {
            return filtered
                .filter((f) => f.severity === el.groupKey)
                .map((f) => new FindingItem(f.type || "Finding", vscode.TreeItemCollapsibleState.None, f));
        }
        return [];
    }
}
// ── History Tree Provider ─────────────────────────────────────────────────────
class GhostHistoryProvider {
    constructor() {
        this._onDidChange = new vscode.EventEmitter();
        this.onDidChangeTreeData = this._onDidChange.event;
        this.items = [];
    }
    setHistory(items) {
        this.items = items;
        this._onDidChange.fire(undefined);
    }
    getTreeItem(el) { return el; }
    getChildren() {
        return this.items.map((h) => {
            const item = new vscode.TreeItem(`${h.riskLevel}: ${h.target}`, vscode.TreeItemCollapsibleState.None);
            item.description = new Date(h.timestamp * 1000).toLocaleString();
            item.tooltip = `${h.totalFindings} findings — risk ${h.riskScore}/100`;
            return item;
        });
    }
}
// ── Extension main ────────────────────────────────────────────────────────────
let diagnostics;
let statusBar;
let findingsProvider;
let historyProvider;
let scanTimeout;
function getConfig() {
    const cfg = vscode.workspace.getConfiguration("ghost");
    return {
        serverUrl: cfg.get("serverUrl", "http://localhost:8000"),
        apiKey: cfg.get("apiKey", ""),
        scanOnSave: cfg.get("scanOnSave", true),
        minSeverity: cfg.get("minSeverity", "MEDIUM"),
        enableTON: cfg.get("enableTON", true),
        enableReachability: cfg.get("enableReachability", true),
    };
}
async function scanFile(doc) {
    const cfg = getConfig();
    const code = doc.getText();
    if (!code.trim())
        return;
    const ext = path.extname(doc.fileName).toLowerCase();
    const langMap = {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".jsx": "javascript", ".tsx": "typescript",
        ".sol": "solidity", ".fc": "func", ".tact": "tact",
    };
    const lang = langMap[ext] || doc.languageId;
    statusBar.text = "$(loading~spin) Ghost: scanning…";
    statusBar.show();
    try {
        // Code scan
        const result = (await httpPost(`${cfg.serverUrl}/api/scan/code`, { code, language: lang, filename: path.basename(doc.fileName) }, cfg.apiKey));
        // TON-specific scan if applicable
        let tonFindings = [];
        if (cfg.enableTON && [".fc", ".tact", ".fif"].includes(ext)) {
            try {
                const tonResult = (await httpPost(`${cfg.serverUrl}/api/ton/analyze-snippet`, { code, lang: ext.slice(1) }, cfg.apiKey));
                tonFindings = tonResult.findings || [];
            }
            catch (_) { }
        }
        const all = [
            ...(result.findings || []),
            ...tonFindings,
        ];
        // Update diagnostics
        diagnostics.clear();
        const minOrder = SEV_ORDER[cfg.minSeverity] || 1;
        const visible = all.filter((f) => (SEV_ORDER[f.severity] || 0) >= minOrder);
        const diags = visible.map((f) => {
            const line = Math.max(0, (f.line || 1) - 1);
            const range = new vscode.Range(line, 0, line, 999);
            const msg = `[Ghost] ${f.type}: ${f.description || f.message}` +
                (f.cwe ? ` (${f.cwe})` : "");
            const d = new vscode.Diagnostic(range, msg, SEV_DIAG[f.severity]);
            d.source = "Ghost Security";
            d.code = f.cwe || f.type;
            return d;
        });
        diagnostics.set(doc.uri, diags);
        // Update tree
        findingsProvider.setFindings(all, cfg.minSeverity);
        const counts = result.severity_counts || {};
        const crit = counts["CRITICAL"] || 0;
        const high = counts["HIGH"] || 0;
        statusBar.text =
            all.length === 0
                ? "$(shield) Ghost: clean"
                : `$(warning) Ghost: ${all.length} issues` +
                    (crit > 0 ? ` · ${crit} CRITICAL` : high > 0 ? ` · ${high} HIGH` : "");
        statusBar.color =
            crit > 0 ? "red" : high > 0 ? "orange" : undefined;
    }
    catch (err) {
        statusBar.text = "$(x) Ghost: error (server down?)";
        console.error("[Ghost]", err);
    }
}
async function scanWorkspace() {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders) {
        vscode.window.showWarningMessage("Ghost: No workspace folder open");
        return;
    }
    const cfg = getConfig();
    const wsPath = folders[0].uri.fsPath;
    statusBar.text = "$(loading~spin) Ghost: workspace scan…";
    statusBar.show();
    try {
        const result = (await httpPost(`${cfg.serverUrl}/api/scan/all`, { path: wsPath, mode: "all" }, cfg.apiKey));
        const all = result.findings || [];
        findingsProvider.setFindings(all, cfg.minSeverity);
        const score = result.risk_score || 0;
        const level = result.risk_level || "LOW";
        vscode.window.showInformationMessage(`Ghost Workspace Scan: ${all.length} findings — Risk ${level} (${score}/100)`);
        statusBar.text = `$(shield) Ghost: ${all.length} workspace findings`;
        // Refresh history
        loadHistory(cfg);
    }
    catch (err) {
        vscode.window.showErrorMessage(`Ghost: Workspace scan failed — ${err}`);
        statusBar.text = "$(x) Ghost: scan failed";
    }
}
async function runTONSelfCheck() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage("Ghost: Open a TON contract file first");
        return;
    }
    const cfg = getConfig();
    const code = editor.document.getText();
    const fileName = path.basename(editor.document.fileName);
    statusBar.text = "$(loading~spin) Ghost: TON self-check…";
    try {
        // Scan the file first
        const scanResult = (await httpPost(`${cfg.serverUrl}/api/ton/analyze-snippet`, { code, lang: path.extname(fileName).slice(1) || "fc" }, cfg.apiKey));
        const findings = scanResult.findings || [];
        if (findings.length === 0) {
            vscode.window.showInformationMessage("Ghost TON Self-Check: No issues found — contract looks clean ✅");
            statusBar.text = "$(shield) Ghost: TON clean";
            return;
        }
        // Run self-check on best finding
        const best = findings.sort((a, b) => (SEV_ORDER[b.severity] || 0) - (SEV_ORDER[a.severity] || 0))[0];
        const checkResult = (await httpPost(`${cfg.serverUrl}/api/bounty/self-check`, { finding: best, context: `File: ${fileName}` }, cfg.apiKey));
        // Show result in new document
        const verdict = checkResult.verdict || "UNKNOWN";
        const score = checkResult.score || 0;
        const reportMd = checkResult.report_md ||
            `# TON Self-Check\nVerdict: ${verdict}\nScore: ${score}/100`;
        const doc = await vscode.workspace.openTextDocument({
            content: reportMd,
            language: "markdown",
        });
        await vscode.window.showTextDocument(doc, vscode.ViewColumn.Beside);
        if (verdict.startsWith("READY")) {
            vscode.window.showInformationMessage(`Ghost TON Self-Check: ${verdict} — Score ${score}/100`);
        }
        else {
            vscode.window.showWarningMessage(`Ghost TON Self-Check: ${verdict} — Score ${score}/100`);
        }
        statusBar.text = `$(checklist) Ghost: Self-check ${score}/100`;
    }
    catch (err) {
        vscode.window.showErrorMessage(`Ghost: TON self-check failed — ${err}`);
        statusBar.text = "$(x) Ghost: self-check error";
    }
}
async function loadHistory(cfg) {
    try {
        const result = (await httpGet(`${cfg.serverUrl}/api/history/scans?limit=20`, cfg.apiKey));
        historyProvider.setHistory(result.scans || []);
    }
    catch (_) { }
}
async function openFinding(finding) {
    if (!finding.file)
        return;
    try {
        const doc = await vscode.workspace.openTextDocument(finding.file);
        const editor = await vscode.window.showTextDocument(doc);
        const line = Math.max(0, (finding.line || 1) - 1);
        const range = new vscode.Range(line, 0, line, 999);
        editor.selection = new vscode.Selection(range.start, range.end);
        editor.revealRange(range, vscode.TextEditorRevealType.InCenter);
    }
    catch (_) { }
}
// ── Activation ────────────────────────────────────────────────────────────────
function activate(context) {
    console.log("[Ghost Security] Extension activated");
    // Diagnostics collection
    diagnostics = vscode.languages.createDiagnosticCollection("ghost-security");
    context.subscriptions.push(diagnostics);
    // Status bar
    statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 10);
    statusBar.text = "$(shield) Ghost Security";
    statusBar.command = "ghost.scanFile";
    statusBar.tooltip = "Click to scan current file";
    statusBar.show();
    context.subscriptions.push(statusBar);
    // Tree providers
    findingsProvider = new GhostFindingsProvider();
    historyProvider = new GhostHistoryProvider();
    vscode.window.registerTreeDataProvider("ghostFindings", findingsProvider);
    vscode.window.registerTreeDataProvider("ghostHistory", historyProvider);
    // Commands
    context.subscriptions.push(vscode.commands.registerCommand("ghost.scanFile", async () => {
        const editor = vscode.window.activeTextEditor;
        if (editor)
            await scanFile(editor.document);
    }), vscode.commands.registerCommand("ghost.scanWorkspace", scanWorkspace), vscode.commands.registerCommand("ghost.tonSelfCheck", runTONSelfCheck), vscode.commands.registerCommand("ghost.clearFindings", () => {
        findingsProvider.clear();
        diagnostics.clear();
        statusBar.text = "$(shield) Ghost Security";
        statusBar.color = undefined;
    }), vscode.commands.registerCommand("ghost.openSettings", () => {
        vscode.commands.executeCommand("workbench.action.openSettings", "ghost");
    }), vscode.commands.registerCommand("ghost.openFinding", openFinding));
    // Scan on save
    context.subscriptions.push(vscode.workspace.onDidSaveTextDocument(async (doc) => {
        if (!getConfig().scanOnSave)
            return;
        const ext = path.extname(doc.fileName).toLowerCase();
        const supported = [
            ".py", ".js", ".ts", ".jsx", ".tsx",
            ".fc", ".tact", ".sol",
        ];
        if (!supported.includes(ext))
            return;
        // Debounce: wait 500ms after save
        if (scanTimeout)
            clearTimeout(scanTimeout);
        scanTimeout = setTimeout(() => scanFile(doc), 500);
    }));
    // Load history on startup
    const cfg = getConfig();
    loadHistory(cfg);
    vscode.window.showInformationMessage("Ghost Security active — scanning on save 🔍");
}
function deactivate() {
    if (scanTimeout)
        clearTimeout(scanTimeout);
    console.log("[Ghost Security] Extension deactivated");
}
//# sourceMappingURL=extension.js.map