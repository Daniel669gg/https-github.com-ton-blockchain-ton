"""cli/tythanai_cli.py — canonical CLI entry point for TythanAI.

Implementation lives in cli/ghostsec_cli.py (kept for backward compatibility).
This module re-exports everything so both of these work identically:

    python -m cli.tythanai_cli scan .
    python -m cli.ghostsec_cli scan .
"""
from cli.ghostsec_cli import *  # noqa: F401, F403
from cli.ghostsec_cli import main

if __name__ == "__main__":
    main()
