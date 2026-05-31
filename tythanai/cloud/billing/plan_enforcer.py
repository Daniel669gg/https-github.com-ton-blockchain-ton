"""
TythanAI Cloud — Plan Enforcer
Enforces per-plan quotas by consulting TenantManager and UsageTracker.
"""

from datetime import datetime, timezone
from typing import Tuple

# ── Plan limits ───────────────────────────────────────────────────────────────
PLANS: dict = {
    "free": {
        "scans_per_month": 100,
        "max_repos": 1,
        "api_calls_per_day": 500,
        "description": "Free tier",
    },
    "developer": {
        "scans_per_month": 1_000,
        "max_repos": 5,
        "api_calls_per_day": 5_000,
        "description": "Developer ($49/mo)",
    },
    "team": {
        "scans_per_month": 10_000,
        "max_repos": 50,
        "api_calls_per_day": 50_000,
        "description": "Team ($299/mo)",
    },
    "enterprise": {
        "scans_per_month": None,   # unlimited
        "max_repos": None,
        "api_calls_per_day": None,
        "description": "Enterprise — unlimited",
    },
}


class PlanEnforcer:
    """Gate scan and API access based on org plan and current usage."""

    def __init__(self, tenant_manager, usage_tracker) -> None:
        self._tenants = tenant_manager
        self._usage = usage_tracker

    # ── Private helpers ────────────────────────────────────────────────────────

    def _get_plan_limits(self, org_id: str) -> Tuple[dict, dict]:
        """Return (tenant_dict, plan_limits_dict). Raises ValueError if unknown org."""
        tenant = self._tenants.get_tenant(org_id)
        if tenant is None:
            raise ValueError(f"Unknown org_id: {org_id!r}")
        plan = tenant.get("plan", "free")
        limits = PLANS.get(plan, PLANS["free"])
        return tenant, limits

    def _current_month_usage(self, org_id: str) -> dict:
        now = datetime.now(timezone.utc)
        return self._usage.get_monthly_usage(org_id, now.year, now.month)

    # ── Public API ─────────────────────────────────────────────────────────────

    def check_scan_allowed(self, org_id: str) -> Tuple[bool, str]:
        """
        Check whether *org_id* may run another scan this month.
        Returns (allowed: bool, reason: str).
        """
        try:
            tenant, limits = self._get_plan_limits(org_id)
        except ValueError as exc:
            return False, str(exc)

        scan_limit = limits["scans_per_month"]
        if scan_limit is None:
            return True, "unlimited scans"

        current = self._current_month_usage(org_id)
        used = current.get("scans", 0)
        if used >= scan_limit:
            plan = tenant.get("plan", "free")
            return (
                False,
                f"Monthly scan quota exhausted ({used}/{scan_limit}) on plan '{plan}'. "
                "Upgrade to increase your limit.",
            )

        remaining = scan_limit - used
        return True, f"{remaining} scans remaining this month"

    def check_api_allowed(self, org_id: str, endpoint: str) -> Tuple[bool, str]:
        """
        Check whether *org_id* may make another API call today.
        Returns (allowed: bool, reason: str).
        """
        try:
            tenant, limits = self._get_plan_limits(org_id)
        except ValueError as exc:
            return False, str(exc)

        daily_limit = limits.get("api_calls_per_day")
        if daily_limit is None:
            return True, "unlimited API calls"

        # Query today's api_call events directly from usage_tracker
        import sqlite3, json
        from pathlib import Path

        db_path = getattr(self._usage, "_db_path", None)
        if db_path is None:
            # Fallback: allow
            return True, "quota check unavailable"

        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        conn = sqlite3.connect(str(db_path))
        try:
            count = conn.execute(
                """
                SELECT COUNT(*) FROM usage_events
                WHERE  org_id = ?
                  AND  event_type = 'api_call'
                  AND  substr(created_at, 1, 10) = ?
                """,
                (org_id, today),
            ).fetchone()[0]
        finally:
            conn.close()

        if count >= daily_limit:
            plan = tenant.get("plan", "free")
            return (
                False,
                f"Daily API call quota exhausted ({count}/{daily_limit}) on plan '{plan}'.",
            )

        return True, f"{daily_limit - count} API calls remaining today"

    def get_remaining_quota(self, org_id: str) -> dict:
        """
        Return a dict describing remaining quotas for the current period.
        """
        try:
            tenant, limits = self._get_plan_limits(org_id)
        except ValueError:
            return {}

        now = datetime.now(timezone.utc)
        monthly = self._current_month_usage(org_id)

        scan_limit = limits["scans_per_month"]
        scans_used = monthly.get("scans", 0)
        scans_remaining = (scan_limit - scans_used) if scan_limit is not None else None

        repo_limit = limits["max_repos"]

        return {
            "org_id": org_id,
            "plan": tenant.get("plan", "free"),
            "period": f"{now.year:04d}-{now.month:02d}",
            "scans": {
                "limit": scan_limit,
                "used": scans_used,
                "remaining": scans_remaining,
            },
            "repos": {
                "limit": repo_limit,
            },
            "api_calls": {
                "daily_limit": limits.get("api_calls_per_day"),
            },
        }
