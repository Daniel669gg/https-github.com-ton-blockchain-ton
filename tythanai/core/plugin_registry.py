"""
TythanAI Platform — Plugin Registry
Зрелая plugin ecosystem: discovery, loading, versioning, validation.

Plugin types:
  scanner   — добавляет новый сканер (любой язык / фреймворк)
  enricher  — обогащает findings (CVE lookup, context, risk)
  reporter  — добавляет формат отчёта
  action    — action при нахождении (notify, ticket, block)

Plugin format (plugin.yaml):
  id:         ghost-plugin-mycompany-scanner
  name:       MyScanner
  version:    1.0.0
  type:       scanner
  entrypoint: my_scanner.MyScanner
  languages:  [go, rust]
  author:     Company <security@company.com>
  ghost_min:  9.0.0
  description: Scans Go and Rust codebases for company-specific patterns
"""
from __future__ import annotations

import importlib
import importlib.util
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set


_PLUGINS_DIR  = Path("./plugins")
_REGISTRY_DB  = Path("./data/plugin_registry.json")
_GHOST_VERSION = "10.0.0"

_VALID_TYPES = {"scanner", "enricher", "reporter", "action", "rule_provider"}


# ── Plugin model ──────────────────────────────────────────────────────────────

@dataclass
class PluginMeta:
    plugin_id:   str
    name:        str
    version:     str
    plugin_type: str
    entrypoint:  str
    languages:   List[str] = field(default_factory=list)
    author:      str = ""
    description: str = ""
    ghost_min:   str = "0.0.0"
    enabled:     bool = True
    source_path: str = ""
    loaded_at:   float = 0.0
    error:       str = ""

    def to_dict(self) -> dict:
        return {
            "id":          self.plugin_id,
            "name":        self.name,
            "version":     self.version,
            "type":        self.plugin_type,
            "entrypoint":  self.entrypoint,
            "languages":   self.languages,
            "author":      self.author,
            "description": self.description,
            "ghost_min":   self.ghost_min,
            "enabled":     self.enabled,
            "loaded":      self.loaded_at > 0,
            "error":       self.error,
        }


@dataclass
class LoadedPlugin:
    meta:     PluginMeta
    instance: Any   # the actual plugin class/object

    def scan_file(self, filepath: str) -> List[dict]:
        if hasattr(self.instance, "scan_file"):
            return self.instance.scan_file(filepath) or []
        return []

    def scan_directory(self, path: str) -> dict:
        if hasattr(self.instance, "scan_directory"):
            return self.instance.scan_directory(path) or {}
        return {"findings": []}

    def enrich(self, findings: List[dict]) -> List[dict]:
        if hasattr(self.instance, "enrich"):
            return self.instance.enrich(findings) or findings
        return findings

    def generate_report(self, findings: List[dict], **kwargs) -> str:
        if hasattr(self.instance, "generate_report"):
            return self.instance.generate_report(findings, **kwargs) or ""
        return ""


# ── Plugin Registry ───────────────────────────────────────────────────────────

class PluginRegistry:
    """
    Discovers, loads, validates and manages Ghost plugins.
    Hot-reload supported: plugins can be added/removed without restart.
    """

    def __init__(self, plugins_dir: Optional[str] = None) -> None:
        self._dir    = Path(plugins_dir or _PLUGINS_DIR)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._meta:   Dict[str, PluginMeta]   = {}
        self._loaded: Dict[str, LoadedPlugin] = {}
        self._scan_count = 0
        # Load persisted registry
        self._load_registry()
        # Auto-discover on startup
        self.discover()

    def discover(self) -> int:
        """Scan plugins directory and register any new plugins."""
        found = 0
        for plugin_dir in self._dir.iterdir():
            if not plugin_dir.is_dir():
                continue
            yaml_path = plugin_dir / "plugin.yaml"
            if not yaml_path.exists():
                yaml_path = plugin_dir / "plugin.yml"
            if yaml_path.exists():
                meta = self._parse_meta(yaml_path)
                if meta:
                    self._meta[meta.plugin_id] = meta
                    found += 1
        self._save_registry()
        return found

    def load(self, plugin_id: str) -> bool:
        """Load a registered plugin into memory."""
        meta = self._meta.get(plugin_id)
        if not meta or not meta.enabled:
            return False
        if plugin_id in self._loaded:
            return True

        try:
            instance = self._import_entrypoint(meta)
            meta.loaded_at = time.time()
            meta.error     = ""
            self._loaded[plugin_id] = LoadedPlugin(meta=meta, instance=instance)
            self._save_registry()
            return True
        except Exception as e:
            meta.error = str(e)[:200]
            self._save_registry()
            return False

    def load_all(self) -> dict:
        """Load all enabled plugins. Returns {ok: [ids], failed: [ids]}."""
        ok, failed = [], []
        for pid in self._meta:
            if self._meta[pid].enabled:
                (ok if self.load(pid) else failed).append(pid)
        return {"loaded": ok, "failed": failed}

    def unload(self, plugin_id: str) -> bool:
        if plugin_id in self._loaded:
            del self._loaded[plugin_id]
            return True
        return False

    def reload(self, plugin_id: str) -> bool:
        self.unload(plugin_id)
        self.discover()
        return self.load(plugin_id)

    # ── Plugin execution ───────────────────────────────────────────────────────

    def run_scanners(self, filepath: str) -> List[dict]:
        """Run all loaded scanner plugins on a file."""
        findings = []
        for plugin in self._loaded.values():
            if plugin.meta.plugin_type == "scanner":
                try:
                    findings += plugin.scan_file(filepath)
                except Exception as e:
                    findings.append({
                        "type": "PLUGIN_ERROR",
                        "severity": "INFO",
                        "message": f"Plugin {plugin.meta.plugin_id} error: {e}",
                        "source": "plugin_registry",
                    })
        return findings

    def run_enrichers(self, findings: List[dict]) -> List[dict]:
        """Run all enricher plugins on findings."""
        for plugin in self._loaded.values():
            if plugin.meta.plugin_type == "enricher":
                try:
                    findings = plugin.enrich(findings)
                except Exception:
                    pass
        return findings

    def run_reporters(self, findings: List[dict], fmt: str = "markdown") -> Dict[str, str]:
        """Run all reporter plugins."""
        reports = {}
        for plugin in self._loaded.values():
            if plugin.meta.plugin_type == "reporter":
                try:
                    report = plugin.generate_report(findings, format=fmt)
                    if report:
                        reports[plugin.meta.plugin_id] = report
                except Exception:
                    pass
        return reports

    # ── Management ─────────────────────────────────────────────────────────────

    def enable(self, plugin_id: str) -> bool:
        if plugin_id in self._meta:
            self._meta[plugin_id].enabled = True
            self._save_registry()
            return True
        return False

    def disable(self, plugin_id: str) -> bool:
        if plugin_id in self._meta:
            self._meta[plugin_id].enabled = False
            self.unload(plugin_id)
            self._save_registry()
            return True
        return False

    def validate(self, plugin_dir: str) -> dict:
        """Validate a plugin before installing."""
        path = Path(plugin_dir)
        errors = []
        yaml_path = path / "plugin.yaml"
        if not yaml_path.exists():
            yaml_path = path / "plugin.yml"

        if not yaml_path.exists():
            return {"valid": False, "errors": ["Missing plugin.yaml"]}

        meta = self._parse_meta(yaml_path)
        if not meta:
            return {"valid": False, "errors": ["Invalid plugin.yaml format"]}

        if meta.plugin_type not in _VALID_TYPES:
            errors.append(f"Invalid type '{meta.plugin_type}', must be one of {_VALID_TYPES}")

        if not meta.entrypoint:
            errors.append("entrypoint is required")

        # Try import
        if not errors:
            try:
                if (path / "main.py").exists():
                    sys.path.insert(0, str(path))
                    self._import_entrypoint(meta)
                    sys.path.pop(0)
            except Exception as e:
                errors.append(f"Import error: {e}")

        return {
            "valid":   len(errors) == 0,
            "errors":  errors,
            "plugin":  meta.to_dict() if meta else None,
        }

    def list_all(self) -> List[dict]:
        return [m.to_dict() for m in self._meta.values()]

    def stats(self) -> dict:
        return {
            "total":           len(self._meta),
            "loaded":          len(self._loaded),
            "enabled":         sum(1 for m in self._meta.values() if m.enabled),
            "by_type":         {t: sum(1 for m in self._meta.values() if m.plugin_type==t)
                                 for t in _VALID_TYPES},
            "languages":       sorted({l for m in self._meta.values() for l in m.languages}),
            "plugins_dir":     str(self._dir),
        }

    # ── Internal ───────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_meta(yaml_path: Path) -> Optional[PluginMeta]:
        try:
            import yaml
            with open(yaml_path) as f:
                d = yaml.safe_load(f)
            return PluginMeta(
                plugin_id   = str(d.get("id", "")),
                name        = str(d.get("name", "")),
                version     = str(d.get("version", "0.0.0")),
                plugin_type = str(d.get("type", "")),
                entrypoint  = str(d.get("entrypoint", "")),
                languages   = list(d.get("languages", [])),
                author      = str(d.get("author", "")),
                description = str(d.get("description", "")),
                ghost_min   = str(d.get("ghost_min", "0.0.0")),
                source_path = str(yaml_path.parent),
            )
        except Exception:
            return None

    @staticmethod
    def _import_entrypoint(meta: PluginMeta) -> Any:
        src = Path(meta.source_path)
        if str(src) not in sys.path:
            sys.path.insert(0, str(src))
        module_name, class_name = (meta.entrypoint.rsplit(".", 1)
                                   if "." in meta.entrypoint
                                   else (meta.entrypoint, None))
        mod = importlib.import_module(module_name)
        if class_name:
            cls = getattr(mod, class_name)
            return cls()
        return mod

    def _load_registry(self) -> None:
        if _REGISTRY_DB.exists():
            try:
                data = json.loads(_REGISTRY_DB.read_text())
                for d in data.get("plugins", []):
                    m = PluginMeta(**{k: v for k, v in d.items()
                                      if k in PluginMeta.__dataclass_fields__})
                    self._meta[m.plugin_id] = m
            except Exception:
                pass

    def _save_registry(self) -> None:
        try:
            _REGISTRY_DB.parent.mkdir(parents=True, exist_ok=True)
            _REGISTRY_DB.write_text(json.dumps({
                "version": _GHOST_VERSION,
                "saved_at": time.time(),
                "plugins": [m.to_dict() for m in self._meta.values()],
            }, indent=2))
        except Exception:
            pass


PLUGIN_REGISTRY = PluginRegistry()
