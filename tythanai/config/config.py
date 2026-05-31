"""
TythanAI Platform — Configuration
Real configuration, no placeholders.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent

# LLM Configuration
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
LLM_MODEL = os.environ.get("LLM_MODEL", "gpt-4o-mini")
LLM_FAST_MODEL = os.environ.get("LLM_FAST_MODEL", "gpt-4o-mini")

# Agent Loop
MAX_ITERATIONS = int(os.environ.get("MAX_ITERATIONS", "20"))
MAX_RETRIES = int(os.environ.get("MAX_RETRIES", "3"))
TOOL_TIMEOUT = int(os.environ.get("TOOL_TIMEOUT", "30"))

# Memory
CHROMA_PERSIST_DIR = str(BASE_DIR / "memory_store")
MEMORY_COLLECTION = "ghost_security_memory"

# Reports
REPORTS_DIR = str(BASE_DIR / "reports")

# GitHub
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

# Sandbox
SANDBOX_TIMEOUT = int(os.environ.get("SANDBOX_TIMEOUT", "15"))
SANDBOX_MAX_OUTPUT = int(os.environ.get("SANDBOX_MAX_OUTPUT", "10000"))

# Semgrep
SEMGREP_TIMEOUT = int(os.environ.get("SEMGREP_TIMEOUT", "60"))

# Severity levels
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

# Supported languages for AST analysis
SUPPORTED_LANGUAGES = ["python", "javascript", "c", "cpp"]

# API Server
API_HOST = os.environ.get("API_HOST", "0.0.0.0")
API_PORT = int(os.environ.get("API_PORT", "8000"))
