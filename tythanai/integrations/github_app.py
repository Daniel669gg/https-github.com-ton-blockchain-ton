"""
TythanAI Platform — GitHub App Integration
Работает как GitHub App (не Actions):
  • Webhook-приёмник для pull_request events
  • Скачивает изменённые файлы через GitHub API
  • Запускает Ghost сканирование
  • Постит review comments прямо в PR (inline на строки кода)
  • Постит summary comment + check run со статусом

Настройка:
  GITHUB_APP_ID         — App ID из настроек GitHub App
  GITHUB_PRIVATE_KEY    — PEM-ключ (путь к файлу или сам ключ)
  GITHUB_WEBHOOK_SECRET — webhook secret

Установка: создать GitHub App на github.com/settings/apps
  Permissions: pull_requests: write, checks: write, contents: read
  Events: pull_request
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import urllib.request
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ── JWT для GitHub App auth ───────────────────────────────────────────────────

def _b64url(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_jwt(app_id: str, private_key_pem: str) -> str:
    """RS256 JWT для аутентификации GitHub App (без зависимостей)."""
    import base64, json, struct
    now = int(time.time())
    header  = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps({"iat": now - 60, "exp": now + 600, "iss": app_id}).encode())
    message = f"{header}.{payload}".encode()

    # Подпись через subprocess openssl (стандартный инструмент)
    import subprocess, tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as kf:
        kf.write(private_key_pem)
        kf.flush()
        proc = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", kf.name],
            input=message, capture_output=True,
        )
        sig = _b64url(proc.stdout)
        os.unlink(kf.name)

    return f"{header}.{payload}.{sig}"


# ── GitHub API client ─────────────────────────────────────────────────────────

class GitHubClient:
    """Минимальный GitHub API v3 клиент."""

    BASE = "https://api.github.com"

    def __init__(self, token: str) -> None:
        self._token = token

    def _req(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        url  = self.BASE + path
        data = json.dumps(body).encode() if body else None
        req  = urllib.request.Request(
            url, data=data, method=method,
            headers={
                "Authorization":    f"Bearer {self._token}",
                "Accept":           "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "Content-Type":     "application/json",
                "User-Agent":       "GhostSecurity/2.2",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return json.loads(r.read()) if r.length != 0 else {}
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            raise RuntimeError(f"GitHub API {method} {path} → {e.code}: {body}")

    def get(self,    path: str)             -> dict: return self._req("GET",    path)
    def post(self,   path: str, body: dict) -> dict: return self._req("POST",   path, body)
    def patch(self,  path: str, body: dict) -> dict: return self._req("PATCH",  path, body)
    def delete(self, path: str)             -> dict: return self._req("DELETE", path)

    # ── Файлы PR ──────────────────────────────────────────────────────────────

    def pr_files(self, owner: str, repo: str, pr_number: int) -> List[dict]:
        return self.get(f"/repos/{owner}/{repo}/pulls/{pr_number}/files")

    def file_content(self, owner: str, repo: str, path: str, ref: str) -> str:
        import base64
        data = self.get(f"/repos/{owner}/{repo}/contents/{path}?ref={ref}")
        return base64.b64decode(data["content"]).decode("utf-8", errors="replace")

    # ── Check Run ─────────────────────────────────────────────────────────────

    def create_check(self, owner: str, repo: str, sha: str, name: str = "TythanAI") -> str:
        resp = self.post(f"/repos/{owner}/{repo}/check-runs", {
            "name":       name,
            "head_sha":   sha,
            "status":     "in_progress",
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })
        return str(resp.get("id", ""))

    def finish_check(
        self,
        owner: str, repo: str, check_id: str,
        conclusion: str,       # success | failure | neutral
        summary: str,
        annotations: List[dict],
    ) -> None:
        self.patch(f"/repos/{owner}/{repo}/check-runs/{check_id}", {
            "status":       "completed",
            "completed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "conclusion":   conclusion,
            "output": {
                "title":       "TythanAI Scan",
                "summary":     summary,
                "annotations": annotations[:50],  # GitHub limit
            },
        })

    # ── PR Comments ───────────────────────────────────────────────────────────

    def post_review(
        self,
        owner: str, repo: str, pr_number: int,
        commit_id: str,
        body: str,
        comments: List[dict],  # [{path, line, body}]
    ) -> None:
        self.post(f"/repos/{owner}/{repo}/pulls/{pr_number}/reviews", {
            "commit_id": commit_id,
            "body":      body,
            "event":     "COMMENT",
            "comments":  comments[:20],  # не перегружаем PR
        })

    def post_issue_comment(self, owner: str, repo: str, pr_number: int, body: str) -> None:
        self.post(f"/repos/{owner}/{repo}/issues/{pr_number}/comments", {"body": body})


# ── Installation token ────────────────────────────────────────────────────────

class GitHubApp:
    """Управляет установкой GitHub App и получением installation tokens."""

    def __init__(self) -> None:
        self.app_id      = os.getenv("GITHUB_APP_ID", "")
        key_env          = os.getenv("GITHUB_PRIVATE_KEY", "")
        key_path         = os.getenv("GITHUB_PRIVATE_KEY_PATH", "")
        if key_path and Path(key_path).exists():
            self.private_key = Path(key_path).read_text()
        else:
            self.private_key = key_env.replace("\\n", "\n")
        self._token_cache: Dict[str, Tuple[str, float]] = {}

    def is_configured(self) -> bool:
        return bool(self.app_id and self.private_key)

    def installation_token(self, installation_id: str) -> str:
        """Получает/кэширует installation access token (TTL 55 min)."""
        cached = self._token_cache.get(installation_id)
        if cached and time.time() < cached[1]:
            return cached[0]

        jwt     = _make_jwt(self.app_id, self.private_key)
        req     = urllib.request.Request(
            f"https://api.github.com/app/installations/{installation_id}/access_tokens",
            method="POST",
            headers={
                "Authorization": f"Bearer {jwt}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "GhostSecurity/2.2",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            data  = json.loads(r.read())
        token = data["token"]
        self._token_cache[installation_id] = (token, time.time() + 3300)
        return token

    def client_for(self, installation_id: str) -> GitHubClient:
        return GitHubClient(self.installation_token(installation_id))


# ── Webhook verifier ──────────────────────────────────────────────────────────

def verify_webhook(payload: bytes, signature: str, secret: str) -> bool:
    expected = "sha256=" + hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


# ── PR Scanner ────────────────────────────────────────────────────────────────

@dataclass
class PRScanResult:
    owner:        str
    repo:         str
    pr_number:    int
    sha:          str
    findings:     List[dict]      = field(default_factory=list)
    files_scanned: List[str]      = field(default_factory=list)
    severity_counts: Dict[str, int] = field(default_factory=dict)

    @property
    def has_critical(self) -> bool:
        return self.severity_counts.get("CRITICAL", 0) > 0

    @property
    def conclusion(self) -> str:
        if self.severity_counts.get("CRITICAL", 0) > 0:
            return "failure"
        if self.severity_counts.get("HIGH", 0) > 0:
            return "failure"
        return "success"


class PRScanner:
    """
    Сканирует изменённые файлы PR через GitHub API.
    Постит inline comments на конкретные строки.
    """

    # Расширения для сканирования
    _SCAN_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".sol", ".fc", ".func", ".tact"}

    def __init__(self, gh: GitHubClient) -> None:
        self._gh = gh

    async def scan_pr(
        self,
        owner: str, repo: str, pr_number: int,
        head_sha: str,
        max_files: int = 30,
    ) -> PRScanResult:
        import asyncio, tempfile, os
        result = PRScanResult(owner=owner, repo=repo, pr_number=pr_number, sha=head_sha)

        # Получаем список изменённых файлов
        try:
            files = self._gh.pr_files(owner, repo, pr_number)
        except Exception as e:
            result.findings = [{"error": str(e), "severity": "INFO"}]
            return result

        # Фильтруем по расширению и статусу (не удалённые)
        scannable = [
            f for f in files
            if f.get("status") != "removed"
            and Path(f.get("filename", "")).suffix in self._SCAN_EXTS
        ][:max_files]

        all_findings: List[dict] = []

        with tempfile.TemporaryDirectory() as tmpdir:
            for pr_file in scannable:
                filename  = pr_file["filename"]
                rel_path  = Path(filename)
                local     = Path(tmpdir) / rel_path.name
                result.files_scanned.append(filename)

                # Скачиваем содержимое
                try:
                    content = self._gh.file_content(owner, repo, filename, head_sha)
                    local.write_text(content, encoding="utf-8")
                except Exception:
                    continue

                # Сканируем
                file_findings = await asyncio.get_event_loop().run_in_executor(
                    None, self._scan_file, str(local), filename
                )
                all_findings.extend(file_findings)

        # Нормализация + enrichment
        from core.knowledge.message_normalizer import normalise_all
        from core.knowledge.cve_enricher import CVEEnricher
        from verifier.confidence_engine import ConfidenceEngine

        all_findings = normalise_all(all_findings)
        all_findings = CVEEnricher(online=False).enrich(all_findings)
        processed    = ConfidenceEngine(fp_threshold=0.35).process(all_findings)
        result.findings = processed["findings"]
        result.severity_counts = {
            k: v for k, v in processed["stats"].get("by_priority", {}).items()
        }
        # Пересчитываем по severity
        counts: Dict[str, int] = {}
        for f in result.findings:
            s = f.get("severity", "MEDIUM")
            counts[s] = counts.get(s, 0) + 1
        result.severity_counts = counts

        return result

    @staticmethod
    def _scan_file(local_path: str, original_path: str) -> List[dict]:
        findings = []
        ext = Path(local_path).suffix.lower()
        try:
            if ext == ".py":
                from scanners.owasp_scanner import OWASPScanner
                from scanners.secret_scanner.secret_detector import SecretDetector
                findings += OWASPScanner().scan_file(local_path)
                findings += SecretDetector().scan_file(local_path)
            elif ext in (".js", ".ts", ".jsx", ".tsx"):
                from scanners.js_scanner import JSScanner
                findings += JSScanner().scan_file(local_path)
            elif ext == ".sol":
                from scanners.solidity_scanner.solidity_analyzer import SolidityAnalyzer
                findings += SolidityAnalyzer().scan_file(local_path)
            elif ext in (".fc", ".func", ".tact"):
                from scanners.ton_scanner.ton_analyzer import TONAnalyzer
                findings += TONAnalyzer().scan_file(local_path)
        except Exception:
            pass

        # Исправляем file path на оригинальный
        for f in findings:
            f["file"] = original_path
        return findings


# ── Formatter для GitHub ──────────────────────────────────────────────────────

def findings_to_annotations(findings: List[dict]) -> List[dict]:
    """Конвертирует findings в GitHub Check Annotations."""
    _level_map = {"CRITICAL": "failure", "HIGH": "failure",
                  "MEDIUM": "warning", "LOW": "notice", "INFO": "notice"}
    annotations = []
    for f in findings:
        sev  = f.get("severity", "MEDIUM").upper()
        msg  = f.get("message") or f.get("description") or "Security finding"
        ann  = {
            "path":             f.get("file", ""),
            "start_line":       max(1, int(f.get("line", 1))),
            "end_line":         max(1, int(f.get("line", 1))),
            "annotation_level": _level_map.get(sev, "warning"),
            "title":            f.get("rule_id") or f.get("type") or "TythanAI",
            "message":          f"{msg}\n\nCWE: {f.get('cwe','N/A')} | OWASP: {f.get('owasp','N/A')}",
            "raw_details":      f"Confidence: {f.get('confidence', 'N/A')} | Priority: {f.get('priority','N/A')}",
        }
        annotations.append(ann)
    return annotations


def findings_to_review_comments(findings: List[dict]) -> List[dict]:
    """Конвертирует findings в inline PR review comments."""
    comments = []
    for f in findings:
        sev  = f.get("severity", "MEDIUM").upper()
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
        msg  = f.get("message") or "Security finding"
        body = (
            f"{icon} **{sev}** — {msg}\n\n"
            f"**Rule:** `{f.get('rule_id') or f.get('type') or 'N/A'}`  \n"
            f"**CWE:** {f.get('cwe', 'N/A')} | **OWASP:** {f.get('owasp', 'N/A')}  \n"
            f"**Confidence:** {f.get('confidence', 'N/A')}\n\n"
        )
        if f.get("recommendation"):
            body += f"> 💡 **Fix:** {f['recommendation']}\n"
        comments.append({
            "path": f.get("file", ""),
            "line": max(1, int(f.get("line", 1))),
            "body": body,
        })
    return comments


def pr_summary_comment(result: PRScanResult) -> str:
    """Генерирует Markdown-сводку для issue comment."""
    counts = result.severity_counts
    total  = sum(counts.values())
    icon   = "🔴" if counts.get("CRITICAL", 0) > 0 else "🟠" if counts.get("HIGH", 0) > 0 else "✅"

    lines = [
        f"## {icon} TythanAI — PR #{result.pr_number} Scan Results",
        "",
        f"Scanned **{len(result.files_scanned)}** file(s), found **{total}** issue(s).",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🔴 CRITICAL | {counts.get('CRITICAL', 0)} |",
        f"| 🟠 HIGH     | {counts.get('HIGH',     0)} |",
        f"| 🟡 MEDIUM   | {counts.get('MEDIUM',   0)} |",
        f"| 🟢 LOW      | {counts.get('LOW',      0)} |",
        "",
    ]

    if total == 0:
        lines.append("✅ **No security issues found in this PR.**")
    else:
        # Top-3 критичных
        top = sorted(
            result.findings,
            key=lambda f: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(f.get("severity","LOW"),4)
        )[:3]
        lines.append("### Top findings")
        for f in top:
            sev = f.get("severity", "?")
            msg = f.get("message") or "finding"
            loc = f"{f.get('file','')}: {f.get('line','')}"
            lines.append(f"- **[{sev}]** {msg} — `{loc}`")

    lines += [
        "",
        "_[TythanAI Platform](https://github.com/ghost-security/platform) — defensive AppSec scanning_",
    ]
    return "\n".join(lines)


# ── FastAPI webhook endpoint (монтируется в server.py) ─────────────────────────

APP = GitHubApp()


async def handle_webhook(payload: bytes, signature: str) -> dict:
    """
    Обработчик GitHub App webhook.
    Вызывается из FastAPI endpoint POST /github/webhook
    """
    secret = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    if secret and not verify_webhook(payload, signature, secret):
        return {"error": "invalid signature"}

    event = json.loads(payload)
    action = event.get("action")

    if action not in ("opened", "synchronize", "reopened"):
        return {"status": "ignored", "action": action}

    installation_id = str(event["installation"]["id"])
    pr              = event["pull_request"]
    repo_data       = event["repository"]
    owner           = repo_data["owner"]["login"]
    repo            = repo_data["name"]
    pr_number       = pr["number"]
    head_sha        = pr["head"]["sha"]

    if not APP.is_configured():
        return {"status": "skipped", "reason": "GitHub App not configured"}

    # Запускаем скан асинхронно
    import asyncio
    asyncio.create_task(
        _run_pr_scan(installation_id, owner, repo, pr_number, head_sha)
    )
    return {"status": "scan_started", "pr": pr_number}


async def _run_pr_scan(
    installation_id: str,
    owner: str, repo: str,
    pr_number: int, head_sha: str,
) -> None:
    """Полный цикл: скан → check run → review comments."""
    try:
        gh      = APP.client_for(installation_id)
        check_id = gh.create_check(owner, repo, head_sha)
        scanner  = PRScanner(gh)
        result   = await scanner.scan_pr(owner, repo, pr_number, head_sha)

        annotations = findings_to_annotations(result.findings)
        summary     = pr_summary_comment(result)

        gh.finish_check(
            owner, repo, check_id,
            conclusion  = result.conclusion,
            summary     = f"Found {len(result.findings)} issue(s) in {len(result.files_scanned)} file(s)",
            annotations = annotations,
        )

        # Inline review comments для P1/P2
        top_findings = [
            f for f in result.findings
            if f.get("priority", "P5") in ("P1_CRITICAL", "P2_HIGH")
        ]
        if top_findings:
            gh.post_review(
                owner, repo, pr_number, head_sha,
                body     = summary,
                comments = findings_to_review_comments(top_findings),
            )
        else:
            gh.post_issue_comment(owner, repo, pr_number, summary)

    except Exception as exc:
        import logging
        logging.getLogger("ghost.github_app").error("PR scan failed: %s", exc)
