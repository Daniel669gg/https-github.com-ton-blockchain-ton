"""Security Log Analyzer — parse and correlate security events from application logs."""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class LogEventType(str, Enum):
    AUTH_FAILURE = "auth_failure"
    AUTH_SUCCESS = "auth_success"
    INJECTION_ATTEMPT = "injection_attempt"
    PATH_TRAVERSAL = "path_traversal"
    RATE_LIMIT_HIT = "rate_limit"
    PRIVILEGE_ESCALATION = "priv_esc"
    DATA_EXFILTRATION = "data_exfil"
    C2_BEACON = "c2_beacon"
    SQL_ERROR = "sql_error"
    UNHANDLED_EXCEPTION = "exception"


class LogEvent(BaseModel):
    timestamp: str
    event_type: LogEventType
    source_ip: str = ""
    user: str = ""
    endpoint: str = ""
    payload: str = ""
    severity: str = "MEDIUM"
    raw_line: str = ""
    line_number: int = 0


class LogAnalysisReport(BaseModel):
    analyzed_lines: int
    events_found: int
    events_by_type: Dict[str, int]
    top_source_ips: List[Tuple[str, int]]    # (ip, count)
    top_endpoints: List[Tuple[str, int]]
    attack_patterns: List[Dict[str, Any]]
    timeline: List[LogEvent]                  # chronological
    risk_score: float
    recommendations: List[str]


# ---------------------------------------------------------------------------
# Log patterns
# ---------------------------------------------------------------------------

# Pre-compiled pattern sets per event type.
# Each entry is (description, compiled_pattern).
_RAW_PATTERNS: Dict[LogEventType, List[str]] = {
    LogEventType.AUTH_FAILURE: [
        r"(?i)(authentication\s+failed|invalid\s+password|login\s+failed|401\s+unauthorized)",
        r"(?i)(wrong\s+password|bad\s+credentials|access\s+denied|invalid\s+credentials)",
        r"(?i)(failed\s+login|login\s+attempt\s+failed|incorrect\s+password|auth\s+failure)",
        r'(?i)\b(401)\b.*(unauthorized|authentication)',
        r"(?i)(password\s+mismatch|credential\s+rejected|account\s+locked)",
    ],
    LogEventType.AUTH_SUCCESS: [
        r"(?i)(login\s+successful|authentication\s+successful|user\s+logged\s+in)",
        r"(?i)(session\s+created|access\s+granted|auth\s+success)",
        r'(?i)\b(200)\b.*(login|auth|signin)',
        r"(?i)(signed\s+in\s+successfully|welcome\s+back)",
    ],
    LogEventType.INJECTION_ATTEMPT: [
        r"(?i)(union\s+select|select\s+\*\s+from|drop\s+table|insert\s+into)",
        r"(?i)(<script\b|javascript:|onerror\s*=|onload\s*=|alert\s*\()",
        r"(?i)(\.\.\/|%2e%2e%2f|etc/passwd|/proc/self)",
        r"(?i)(exec\s*\(|system\s*\(|passthru\s*\(|shell_exec\s*\()",
        r"(?i)(xss|sql\s*injection|command\s*injection|code\s*injection)",
        r"(?i)(1\s*=\s*1|or\s+1=1|and\s+1=1|'\s+or\s+')",
    ],
    LogEventType.PATH_TRAVERSAL: [
        r"(?i)(\.\.\/\.\.\/|%2e%2e%2f%2e%2e%2f)",
        r"(?i)(\/etc\/passwd|\/etc\/shadow|\/etc\/hosts)",
        r"(?i)(\.\.%2f|\.\.%5c|%252e%252e)",
        r"(?i)(path\s+traversal|directory\s+traversal|file\s+inclusion)",
    ],
    LogEventType.RATE_LIMIT_HIT: [
        r"(?i)(rate\s+limit|too\s+many\s+requests|throttled|429)",
        r"(?i)(request\s+limit\s+exceeded|quota\s+exceeded|api\s+limit)",
        r'\b429\b',
    ],
    LogEventType.PRIVILEGE_ESCALATION: [
        r"(?i)(privilege\s+escalation|sudo\s+abuse|setuid|permission\s+denied.*root)",
        r"(?i)(unauthorized\s+admin|privilege\s+gain|escalated\s+privileges)",
        r"(?i)(sudo\s+command|run\s+as\s+root|su\s+root)",
        r"(?i)(403\s+forbidden.*admin|access\s+denied.*admin)",
    ],
    LogEventType.DATA_EXFILTRATION: [
        r"(?i)(exfil|data\s*leak|dump\s+database|bulk\s+export|mass\s+download)",
        r"Content-Length:\s*[1-9]\d{6,}",   # > 1 MB response
        r"(?i)(wget\s+http|curl\s+-o|download\s+file\s+from)",
        r"(?i)(sensitive\s+data\s+accessed|pii\s+export|gdpr\s+data\s+access)",
    ],
    LogEventType.C2_BEACON: [
        r"\b(4444|1337|9001|31337|6666|5555)\b",
        r"(?i)(beacon|cobalt.?strike|meterpreter|mimikatz|c2\s+server)",
        r"(?i)(reverse\s+shell|bind\s+shell|connect\s+back)",
        r"(?i)(empire|metasploit|sliver|havoc|brute.?ratel)",
    ],
    LogEventType.SQL_ERROR: [
        r"(?i)(sql\s+syntax\s+error|mysql_fetch|ORA-\d+|PG::)",
        r"(?i)(database\s+error|query\s+failed|sql\s+exception)",
        r"(?i)(unclosed\s+quotation|syntax\s+error.*sql|invalid\s+column\s+name)",
    ],
    LogEventType.UNHANDLED_EXCEPTION: [
        r"(?i)(traceback\s+\(most\s+recent|unhandled\s+exception|fatal\s+error)",
        r"(?i)(stack\s+overflow|null\s+pointer|segmentation\s+fault)",
        r"(?i)(internal\s+server\s+error|500\s+error|application\s+crash)",
        r"(?i)(exception\s+in\s+thread|java\s+lang\s+exception|NullPointerException)",
    ],
}

# Compiled pattern registry
LOG_PATTERNS: Dict[LogEventType, List[re.Pattern]] = {
    evt_type: [re.compile(p) for p in patterns]
    for evt_type, patterns in _RAW_PATTERNS.items()
}

# Severity mapping for event types
_EVENT_SEVERITY: Dict[LogEventType, str] = {
    LogEventType.AUTH_FAILURE: "MEDIUM",
    LogEventType.AUTH_SUCCESS: "INFO",
    LogEventType.INJECTION_ATTEMPT: "CRITICAL",
    LogEventType.PATH_TRAVERSAL: "HIGH",
    LogEventType.RATE_LIMIT_HIT: "LOW",
    LogEventType.PRIVILEGE_ESCALATION: "HIGH",
    LogEventType.DATA_EXFILTRATION: "CRITICAL",
    LogEventType.C2_BEACON: "CRITICAL",
    LogEventType.SQL_ERROR: "MEDIUM",
    LogEventType.UNHANDLED_EXCEPTION: "LOW",
}

# Risk weights for scoring
_RISK_WEIGHTS: Dict[LogEventType, float] = {
    LogEventType.C2_BEACON: 25.0,
    LogEventType.DATA_EXFILTRATION: 20.0,
    LogEventType.INJECTION_ATTEMPT: 18.0,
    LogEventType.PRIVILEGE_ESCALATION: 15.0,
    LogEventType.PATH_TRAVERSAL: 12.0,
    LogEventType.AUTH_FAILURE: 3.0,
    LogEventType.SQL_ERROR: 5.0,
    LogEventType.UNHANDLED_EXCEPTION: 2.0,
    LogEventType.RATE_LIMIT_HIT: 1.5,
    LogEventType.AUTH_SUCCESS: 0.0,
}


# ---------------------------------------------------------------------------
# Extraction regexes
# ---------------------------------------------------------------------------

# Apache/Nginx Combined Log Format
_APACHE_RE = re.compile(
    r'^(?P<ip>[\d\.]+)\s+'    # IP
    r'\S+\s+\S+\s+'           # ident auth
    r'\[(?P<ts>[^\]]+)\]\s+'  # timestamp
    r'"(?P<method>\w+)\s+'    # method
    r'(?P<path>\S+)'          # path
    r'[^"]*"\s+'              # rest of request
    r'(?P<status>\d{3})\s+'   # status code
    r'\d+'                    # response size
)

# Django / Flask / Python logging format
_DJANGO_RE = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[.,\d]*)\s+'
    r'(?P<level>\w+)\s+'
    r'(?P<msg>.*)$'
)

# Gunicorn / uvicorn access log
_UVICORN_RE = re.compile(
    r'^(?P<ip>[\d\.]+):?\d*\s+-\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)\s+HTTP'
    r'[^"]*"\s+(?P<status>\d{3})'
)

# Generic ISO timestamp
_TIMESTAMP_RE = re.compile(
    r'\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b'
)

# IP address
_IP_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')

# Common username patterns
_USER_RE = re.compile(
    r'(?i)(?:user[=: ]+|username[=: ]+|login[=: ]+|account[=: ]+)'
    r'["\']?([A-Za-z0-9@._\-]{2,64})["\']?'
)

# URL/endpoint
_ENDPOINT_RE = re.compile(r'"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/[^\s"]*)')


# ---------------------------------------------------------------------------
# LogAnalyzer
# ---------------------------------------------------------------------------

class LogAnalyzer:
    """Parse and correlate security events from application logs."""

    # ------------------------------------------------------------------ #
    #  Parsing helpers                                                     #
    # ------------------------------------------------------------------ #

    def _extract_fields(self, line: str) -> Tuple[str, str, str, str]:
        """Extract (timestamp, source_ip, user, endpoint) from a log line.

        Tries structured formats first, then falls back to regex extraction.
        Returns empty strings for fields not found.
        """
        timestamp = ""
        source_ip = ""
        user = ""
        endpoint = ""

        # ── Try JSON log ─────────────────────────────────────────────────
        stripped = line.strip()
        if stripped.startswith("{"):
            try:
                obj = json.loads(stripped)
                timestamp = str(
                    obj.get("timestamp", obj.get("time", obj.get("@timestamp", "")))
                )
                source_ip = str(obj.get("remote_addr", obj.get("ip", obj.get("client_ip", ""))))
                user = str(obj.get("user", obj.get("username", obj.get("account", ""))))
                endpoint = str(obj.get("path", obj.get("uri", obj.get("url", obj.get("endpoint", "")))))
                return timestamp, source_ip, user, endpoint
            except (json.JSONDecodeError, ValueError):
                pass

        # ── Try Apache/Nginx combined log ─────────────────────────────────
        m = _APACHE_RE.match(line)
        if m:
            return m.group("ts"), m.group("ip"), "", m.group("path")

        # ── Try uvicorn/gunicorn ──────────────────────────────────────────
        m = _UVICORN_RE.match(line)
        if m:
            ip_m = _IP_RE.search(line)
            ts_m = _TIMESTAMP_RE.search(line)
            return (
                ts_m.group(1) if ts_m else "",
                m.group("ip"),
                "",
                m.group("path"),
            )

        # ── Generic regex fallback ────────────────────────────────────────
        ts_m = _TIMESTAMP_RE.search(line)
        if ts_m:
            timestamp = ts_m.group(1)

        ip_m = _IP_RE.search(line)
        if ip_m:
            source_ip = ip_m.group(1)

        user_m = _USER_RE.search(line)
        if user_m:
            user = user_m.group(1)

        ep_m = _ENDPOINT_RE.search(line)
        if ep_m:
            endpoint = ep_m.group(1)

        return timestamp, source_ip, user, endpoint

    def _classify_line(self, line: str) -> Optional[LogEventType]:
        """Return the first matching LogEventType for a line, or None."""
        for evt_type, patterns in LOG_PATTERNS.items():
            for pat in patterns:
                if pat.search(line):
                    return evt_type
        return None

    def _extract_payload(self, line: str, event_type: LogEventType) -> str:
        """Extract a relevant payload snippet from the line."""
        if event_type == LogEventType.INJECTION_ATTEMPT:
            # Look for the suspicious part
            for pat in LOG_PATTERNS[LogEventType.INJECTION_ATTEMPT]:
                m = pat.search(line)
                if m:
                    start = max(0, m.start() - 20)
                    end = min(len(line), m.end() + 40)
                    return line[start:end].strip()
        if len(line) > 200:
            return line[:200] + "..."
        return line.strip()

    # ------------------------------------------------------------------ #
    #  Core analysis                                                       #
    # ------------------------------------------------------------------ #

    def _analyse_lines(self, lines: List[str]) -> LogAnalysisReport:
        events: List[LogEvent] = []
        total_lines = len(lines)

        for lineno, line in enumerate(lines, 1):
            if not line.strip():
                continue
            event_type = self._classify_line(line)
            if event_type is None:
                continue

            ts, ip, user, endpoint = self._extract_fields(line)
            payload = self._extract_payload(line, event_type)

            events.append(LogEvent(
                timestamp=ts,
                event_type=event_type,
                source_ip=ip,
                user=user,
                endpoint=endpoint,
                payload=payload,
                severity=_EVENT_SEVERITY[event_type],
                raw_line=line.rstrip(),
                line_number=lineno,
            ))

        # ── Aggregations ──────────────────────────────────────────────────
        type_counter: Counter = Counter(e.event_type.value for e in events)
        ip_counter: Counter = Counter(e.source_ip for e in events if e.source_ip)
        ep_counter: Counter = Counter(e.endpoint for e in events if e.endpoint)

        # ── Attack pattern detection ──────────────────────────────────────
        attack_patterns: List[Dict[str, Any]] = []

        # Brute force: >5 auth failures from same IP
        auth_failures_by_ip: Dict[str, int] = Counter(
            e.source_ip for e in events
            if e.event_type == LogEventType.AUTH_FAILURE and e.source_ip
        )
        for ip, count in auth_failures_by_ip.items():
            if count > 5:
                attack_patterns.append({
                    "pattern": "brute_force",
                    "description": f"Auth brute force from {ip}: {count} failures",
                    "source_ip": ip,
                    "event_count": count,
                    "severity": "HIGH",
                })

        # SQL injection scan: >3 injection attempts
        total_injections = type_counter.get(LogEventType.INJECTION_ATTEMPT.value, 0)
        if total_injections > 3:
            injection_ips = Counter(
                e.source_ip for e in events
                if e.event_type == LogEventType.INJECTION_ATTEMPT and e.source_ip
            )
            top_injector = injection_ips.most_common(1)
            attack_patterns.append({
                "pattern": "sql_injection_scan",
                "description": f"SQL/code injection scan detected: {total_injections} attempts",
                "top_source_ip": top_injector[0][0] if top_injector else "",
                "event_count": total_injections,
                "severity": "CRITICAL",
            })

        # Credential stuffing: >50 auth events across multiple users
        total_auth = (
            type_counter.get(LogEventType.AUTH_FAILURE.value, 0)
            + type_counter.get(LogEventType.AUTH_SUCCESS.value, 0)
        )
        unique_users = len(set(e.user for e in events if e.user))
        if total_auth > 50 and unique_users > 5:
            attack_patterns.append({
                "pattern": "credential_stuffing",
                "description": (
                    f"Credential stuffing: {total_auth} auth events "
                    f"across {unique_users} unique users"
                ),
                "auth_event_count": total_auth,
                "unique_users": unique_users,
                "severity": "CRITICAL",
            })

        # Path traversal campaign: >2 path traversal events
        total_traversal = type_counter.get(LogEventType.PATH_TRAVERSAL.value, 0)
        if total_traversal > 2:
            attack_patterns.append({
                "pattern": "path_traversal_campaign",
                "description": f"Path traversal campaign: {total_traversal} attempts",
                "event_count": total_traversal,
                "severity": "HIGH",
            })

        # C2 activity
        total_c2 = type_counter.get(LogEventType.C2_BEACON.value, 0)
        if total_c2 > 0:
            c2_ips = Counter(
                e.source_ip for e in events
                if e.event_type == LogEventType.C2_BEACON and e.source_ip
            )
            attack_patterns.append({
                "pattern": "c2_activity",
                "description": f"Potential C2 activity detected: {total_c2} indicators",
                "event_count": total_c2,
                "source_ips": [ip for ip, _ in c2_ips.most_common(3)],
                "severity": "CRITICAL",
            })

        # Data exfiltration
        total_exfil = type_counter.get(LogEventType.DATA_EXFILTRATION.value, 0)
        if total_exfil > 0:
            attack_patterns.append({
                "pattern": "data_exfiltration",
                "description": f"Potential data exfiltration: {total_exfil} indicators",
                "event_count": total_exfil,
                "severity": "CRITICAL",
            })

        # ── Risk score ────────────────────────────────────────────────────
        risk_score = self._compute_risk_score(type_counter, attack_patterns)

        # ── Recommendations ───────────────────────────────────────────────
        recommendations = self._generate_recommendations(type_counter, attack_patterns)

        return LogAnalysisReport(
            analyzed_lines=total_lines,
            events_found=len(events),
            events_by_type=dict(type_counter),
            top_source_ips=ip_counter.most_common(10),
            top_endpoints=ep_counter.most_common(10),
            attack_patterns=attack_patterns,
            timeline=events,
            risk_score=risk_score,
            recommendations=recommendations,
        )

    def _compute_risk_score(
        self,
        type_counter: Counter,
        attack_patterns: List[Dict[str, Any]],
    ) -> float:
        """Compute a 0-100 risk score from event counts and detected patterns."""
        score = 0.0

        for evt_type, weight in _RISK_WEIGHTS.items():
            count = type_counter.get(evt_type.value, 0)
            if count > 0:
                # Logarithmic scaling: each doubling adds ~half the base weight
                import math
                score += weight * (1 + math.log2(count) * 0.4)

        # Bonus for confirmed attack patterns
        pattern_bonuses = {
            "brute_force": 10.0,
            "sql_injection_scan": 15.0,
            "credential_stuffing": 20.0,
            "path_traversal_campaign": 10.0,
            "c2_activity": 30.0,
            "data_exfiltration": 25.0,
        }
        for pattern in attack_patterns:
            score += pattern_bonuses.get(pattern["pattern"], 5.0)

        return round(min(100.0, score), 2)

    def _generate_recommendations(
        self,
        type_counter: Counter,
        attack_patterns: List[Dict[str, Any]],
    ) -> List[str]:
        """Generate prioritised recommendations based on findings."""
        recs: List[str] = []
        pattern_names = {p["pattern"] for p in attack_patterns}

        if "c2_activity" in pattern_names:
            recs.append(
                "CRITICAL: Block all traffic to/from identified C2 IPs immediately. "
                "Isolate affected hosts and initiate incident response."
            )
        if "data_exfiltration" in pattern_names:
            recs.append(
                "CRITICAL: Investigate large outbound data transfers. "
                "Review DLP policies and audit access to sensitive data stores."
            )
        if "credential_stuffing" in pattern_names:
            recs.append(
                "HIGH: Enable multi-factor authentication on all accounts. "
                "Implement CAPTCHA and rate limiting on authentication endpoints."
            )
        if "brute_force" in pattern_names:
            recs.append(
                "HIGH: Implement account lockout after 5 failed attempts. "
                "Deploy IP-based rate limiting and geo-blocking for suspicious IPs."
            )
        if "sql_injection_scan" in pattern_names:
            recs.append(
                "HIGH: Enable WAF rules for SQL injection patterns. "
                "Audit all database queries for parameterised query usage."
            )
        if "path_traversal_campaign" in pattern_names:
            recs.append(
                "HIGH: Validate and canonicalize all file paths. "
                "Deploy WAF rules for path traversal patterns."
            )

        # Event-type based recommendations
        if type_counter.get(LogEventType.AUTH_FAILURE.value, 0) > 10:
            recs.append(
                "MEDIUM: Review authentication failure rates. "
                "Consider deploying a SIEM alert for sustained auth failures."
            )
        if type_counter.get(LogEventType.SQL_ERROR.value, 0) > 0:
            recs.append(
                "MEDIUM: SQL errors in logs may indicate injection attempts or application bugs. "
                "Ensure all SQL errors are caught and not exposed to users."
            )
        if type_counter.get(LogEventType.UNHANDLED_EXCEPTION.value, 0) > 5:
            recs.append(
                "LOW: Multiple unhandled exceptions detected. "
                "Review exception handling and ensure stack traces are not exposed to clients."
            )

        if not recs:
            recs.append("No immediate critical recommendations. Continue monitoring.")

        return recs

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def analyze_file(self, log_path: str) -> LogAnalysisReport:
        """Analyse a log file on disk."""
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError as exc:
            return LogAnalysisReport(
                analyzed_lines=0,
                events_found=0,
                events_by_type={},
                top_source_ips=[],
                top_endpoints=[],
                attack_patterns=[],
                timeline=[],
                risk_score=0.0,
                recommendations=[f"Error reading file: {exc}"],
            )
        return self._analyse_lines(lines)

    def analyze_string(self, log_content: str) -> LogAnalysisReport:
        """Analyse log content provided as a string."""
        if not log_content:
            return LogAnalysisReport(
                analyzed_lines=0,
                events_found=0,
                events_by_type={},
                top_source_ips=[],
                top_endpoints=[],
                attack_patterns=[],
                timeline=[],
                risk_score=0.0,
                recommendations=["No log content provided."],
            )
        lines = log_content.splitlines(keepends=True)
        return self._analyse_lines(lines)

    def generate_siem_queries(self, report: LogAnalysisReport) -> Dict[str, str]:
        """Generate targeted SIEM queries based on what was found in the report."""
        splunk_parts: List[str] = []
        elastic_parts: List[str] = []
        kql_parts: List[str] = []

        pattern_names = {p["pattern"] for p in report.attack_patterns}
        top_ips = [ip for ip, _ in report.top_source_ips[:5]]

        # ── Base query components ─────────────────────────────────────────

        if LogEventType.AUTH_FAILURE.value in report.events_by_type:
            splunk_parts.append(
                'index=auth (sourcetype=access_log OR sourcetype=app_log) '
                '| search "authentication failed" OR "login failed" OR "invalid password"'
            )
            elastic_parts.append(
                '{"query": {"bool": {"should": ['
                '{"match": {"message": "authentication failed"}}, '
                '{"match": {"message": "login failed"}}'
                ']}}}'
            )
            kql_parts.append(
                'SigninLogs | where ResultType != 0 | summarize count() by UserPrincipalName'
            )

        if LogEventType.INJECTION_ATTEMPT.value in report.events_by_type:
            splunk_parts.append(
                'index=web_logs | search (uri="*UNION*SELECT*" OR uri="*<script*" '
                'OR uri="*../.*" OR uri="*exec(*")'
            )
            elastic_parts.append(
                '{"query": {"regexp": {"request.uri": '
                '".*(?:union.select|<script|exec\\\\(|etc/passwd).*"}}}'
            )
            kql_parts.append(
                'DeviceNetworkEvents | where RemoteUrl matches regex '
                r'@".*(?:union.select|<script|exec\(|\.\./).*"'
            )

        if LogEventType.C2_BEACON.value in report.events_by_type:
            splunk_parts.append(
                'index=network sourcetype=firewall '
                '| search dest_port IN (4444, 1337, 9001, 31337, 6666)'
            )
            elastic_parts.append(
                '{"query": {"terms": {"destination.port": [4444, 1337, 9001, 31337, 6666]}}}'
            )
            kql_parts.append(
                'DeviceNetworkEvents | where RemotePort in (4444, 1337, 9001, 31337, 6666)'
            )

        if LogEventType.DATA_EXFILTRATION.value in report.events_by_type:
            splunk_parts.append(
                'index=network sourcetype=proxy | eval mb=bytes/1048576 '
                '| where mb > 10 | stats sum(mb) by src_ip'
            )

        # IP-specific hunting if suspicious IPs found
        if top_ips:
            ip_list_splunk = " OR ".join(f'src_ip="{ip}"' for ip in top_ips)
            splunk_parts.append(
                f'index=* | search ({ip_list_splunk}) '
                '| stats count by src_ip, action | sort -count'
            )
            ip_list_elastic = json.dumps(top_ips)
            elastic_parts.append(
                f'{{"query": {{"terms": {{"source.ip": {ip_list_elastic}}}}}}}'
            )
            kql_parts.append(
                f'DeviceNetworkEvents | where RemoteIP in ({", ".join(repr(ip) for ip in top_ips)})'
            )

        # Pattern-specific
        if "brute_force" in pattern_names:
            splunk_parts.append(
                'index=auth | stats count by src_ip | where count > 10 '
                '| sort -count | head 20'
            )
        if "credential_stuffing" in pattern_names:
            splunk_parts.append(
                'index=auth | stats dc(user) as unique_users, count by src_ip '
                '| where unique_users > 5 AND count > 50'
            )

        # Build final query strings
        splunk_query = "\n\n".join(splunk_parts) if splunk_parts else (
            "index=* | search * | head 100  /* No specific threats detected */"
        )
        elastic_query = "\n\n".join(elastic_parts) if elastic_parts else (
            '{"query": {"match_all": {}}, "size": 100}'
        )
        kql_query = "\n\n".join(kql_parts) if kql_parts else (
            "DeviceEvents | take 100  // No specific threats detected"
        )

        return {
            "splunk": splunk_query,
            "elastic": elastic_query,
            "kql": kql_query,
        }


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

def analyze_logs(log_content: str) -> LogAnalysisReport:
    """Analyse log content and return a security analysis report."""
    return LogAnalyzer().analyze_string(log_content)
