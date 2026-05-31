"""
TythanAI — Rules CDN
Downloads and caches the latest security rules from the remote rules registry.

Usage:
    cdn = RulesCDN()
    info = cdn.check_updates()
    if info["has_update"]:
        result = cdn.download_rules()
        print(f"Downloaded {result['downloaded']} new rules (version {result['version']})")
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
from urllib.error import URLError
from urllib.request import urlopen, Request

__all__ = ["RulesCDNConfig", "RulesCDN"]

_MANIFEST_FILENAME = ".manifest.json"
_LAST_CHECK_FILENAME = ".last_check"


@dataclass
class RulesCDNConfig:
    base_url: str = "https://raw.githubusercontent.com/ghost-security/rules/main"
    local_dir: str = "~/.ghost/rules"
    cache_ttl: int = 86400  # 24 hours
    verify_checksums: bool = True


class RulesCDN:
    """Download and cache TythanAI rules from the CDN."""

    def __init__(self, config: Optional[RulesCDNConfig] = None) -> None:
        self.config = config or RulesCDNConfig()
        self._local_dir = Path(self.config.local_dir).expanduser()

    # ── Public API ────────────────────────────────────────────────────────────

    def check_updates(self) -> dict:
        """
        Check whether a newer version of the rules is available.

        Returns:
            {
                "has_update": bool,
                "current": "x.x.x" | None,
                "latest": "x.x.x" | None,
                "new_rules": [...],
            }
            On network failure:
            {
                "has_update": False,
                "error": "network unavailable",
            }
        """
        remote = self._fetch_manifest()
        if remote is None:
            return {"has_update": False, "error": "network unavailable"}

        local = self._load_local_manifest()
        remote_version = remote.get("version")
        local_version = local.get("version") if local else None

        # Build sets for diffing
        remote_names = {r["name"] for r in remote.get("rules", [])}
        local_names: set = set()
        if local:
            local_names = {r["name"] for r in local.get("rules", [])}

        new_rules = [r for r in remote.get("rules", []) if r["name"] not in local_names]

        # Also consider checksum changes on existing rules as "updates"
        if local:
            local_checksums = {r["name"]: r.get("checksum", "") for r in local.get("rules", [])}
            for r in remote.get("rules", []):
                if r["name"] in local_checksums and r.get("checksum") != local_checksums[r["name"]]:
                    if r not in new_rules:
                        new_rules.append(r)

        has_update = bool(
            remote_version != local_version
            or new_rules
        )

        # Record the time of this check
        self._save_last_check_time()

        return {
            "has_update": has_update,
            "current": local_version,
            "latest": remote_version,
            "new_rules": new_rules,
        }

    def download_rules(self, force: bool = False) -> dict:
        """
        Download changed / new rules from the CDN.

        Args:
            force: Re-download all rules even if checksums match.

        Returns:
            {"downloaded": N, "skipped": N, "errors": N, "version": "x.x.x" | None}
        """
        remote = self._fetch_manifest()
        if remote is None:
            return {"downloaded": 0, "skipped": 0, "errors": 0,
                    "version": self.get_version(), "error": "network unavailable"}

        self._local_dir.mkdir(parents=True, exist_ok=True)

        downloaded = 0
        skipped = 0
        errors = 0

        for rule_meta in remote.get("rules", []):
            name = rule_meta.get("name", "")
            remote_checksum = rule_meta.get("checksum", "")
            if not name:
                errors += 1
                continue

            local_path = self._local_dir / name

            # Skip if file exists and checksum matches (unless forced)
            if not force and local_path.exists() and self.config.verify_checksums:
                local_checksum = self._compute_sha256(str(local_path))
                if local_checksum == remote_checksum:
                    skipped += 1
                    continue

            # Download rule file
            rule_url = f"{self.config.base_url.rstrip('/')}/{name}"
            try:
                req = Request(rule_url, headers={"User-Agent": "ghost-security-cdn/1.0"})
                with urlopen(req, timeout=30) as resp:
                    content = resp.read()

                # Verify checksum of downloaded content if configured
                if self.config.verify_checksums and remote_checksum:
                    dl_checksum = "sha256:" + hashlib.sha256(content).hexdigest()
                    if dl_checksum != remote_checksum:
                        errors += 1
                        continue

                # Ensure parent directories exist (for namespaced rule names)
                local_path.parent.mkdir(parents=True, exist_ok=True)
                local_path.write_bytes(content)
                downloaded += 1

            except (URLError, OSError):
                errors += 1
                continue

        # Persist updated manifest
        try:
            manifest_path = self._local_dir / _MANIFEST_FILENAME
            manifest_path.write_text(json.dumps(remote, indent=2))
        except OSError:
            pass

        self._save_last_check_time()

        return {
            "downloaded": downloaded,
            "skipped": skipped,
            "errors": errors,
            "version": remote.get("version"),
        }

    def list_local_rules(self) -> List[dict]:
        """
        Return metadata for all locally installed rule files.

        Returns a list of dicts:
            [{"name": "...", "checksum": "sha256:...", "size": N}, ...]
        """
        if not self._local_dir.exists():
            return []

        manifest = self._load_local_manifest()
        manifest_checksums: dict = {}
        if manifest:
            manifest_checksums = {r["name"]: r for r in manifest.get("rules", [])}

        rules: List[dict] = []
        for p in sorted(self._local_dir.rglob("*.yml")) + sorted(self._local_dir.rglob("*.yaml")):
            rel_name = str(p.relative_to(self._local_dir))
            entry = {"name": rel_name, "size": p.stat().st_size}
            if rel_name in manifest_checksums:
                entry["checksum"] = manifest_checksums[rel_name].get("checksum", "")
                entry["updated_at"] = manifest_checksums[rel_name].get("updated_at", "")
            else:
                entry["checksum"] = self._compute_sha256(str(p))
            rules.append(entry)

        return rules

    def get_version(self) -> Optional[str]:
        """Return the version string from the local manifest, or None if absent."""
        manifest = self._load_local_manifest()
        if manifest is None:
            return None
        return manifest.get("version")

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _fetch_manifest(self) -> Optional[dict]:
        """
        GET {base_url}/manifest.json with a 10-second timeout.
        Returns parsed JSON dict or None on any error.
        """
        url = f"{self.config.base_url.rstrip('/')}/manifest.json"
        try:
            req = Request(url, headers={"User-Agent": "ghost-security-cdn/1.0"})
            with urlopen(req, timeout=10) as resp:
                raw = resp.read()
            return json.loads(raw)
        except (URLError, OSError, json.JSONDecodeError):
            return None

    def _compute_sha256(self, path: str) -> str:
        """Compute SHA-256 digest of file content, returned as 'sha256:<hex>'."""
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return "sha256:" + h.hexdigest()

    def _is_cache_fresh(self) -> bool:
        """
        Return True if the last CDN check happened within cache_ttl seconds.
        """
        check_file = self._local_dir / _LAST_CHECK_FILENAME
        if not check_file.exists():
            return False
        try:
            last_ts = float(check_file.read_text().strip())
            return (time.time() - last_ts) < self.config.cache_ttl
        except (ValueError, OSError):
            return False

    def _load_local_manifest(self) -> Optional[dict]:
        """Load the local manifest JSON, or return None if absent/corrupt."""
        manifest_path = self._local_dir / _MANIFEST_FILENAME
        if not manifest_path.exists():
            return None
        try:
            return json.loads(manifest_path.read_text())
        except (json.JSONDecodeError, OSError):
            return None

    def _save_last_check_time(self) -> None:
        """Persist the current Unix timestamp as the last-check marker."""
        try:
            self._local_dir.mkdir(parents=True, exist_ok=True)
            check_file = self._local_dir / _LAST_CHECK_FILENAME
            check_file.write_text(str(time.time()))
        except OSError:
            pass
