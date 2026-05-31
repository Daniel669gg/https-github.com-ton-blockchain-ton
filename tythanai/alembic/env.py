"""Alembic environment configuration for TythanAI Platform."""
from __future__ import annotations

import logging
import os
import sys
from logging.config import fileConfig
from pathlib import Path

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path so backend.* imports work
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from alembic import context

# SQLAlchemy engine / metadata imports — gracefully handle missing package
try:
    from sqlalchemy import engine_from_config, pool
    _SQLALCHEMY_AVAILABLE = True
except ImportError:
    _SQLALCHEMY_AVAILABLE = False

# ---------------------------------------------------------------------------
# Alembic Config object
# ---------------------------------------------------------------------------

config = context.config

# Interpret the config file for Python logging, if present
if config.config_file_name is not None:
    try:
        fileConfig(config.config_file_name)
    except Exception:
        pass  # graceful skip in test contexts

logger = logging.getLogger("alembic.env")

# ---------------------------------------------------------------------------
# Optional: load SQLAlchemy metadata from models if defined
# ---------------------------------------------------------------------------
# If the project uses SQLAlchemy declarative models, import Base.metadata here.
# For now TythanAI uses raw sqlite3, so target_metadata stays None.
target_metadata = None


def _get_url() -> str:
    """Resolve the SQLAlchemy URL, allowing override via env var."""
    env_url = os.environ.get("GHOST_DB_URL")
    if env_url:
        return env_url
    # Allow override via alembic.ini key
    url = config.get_main_option("sqlalchemy.url", "sqlite:///data/tythanai.db")
    return url


# ---------------------------------------------------------------------------
# Run migrations offline
# ---------------------------------------------------------------------------

def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode.

    This configures the context with just a URL and not an Engine.
    Calls to context.execute() emit the given string to the script output.
    """
    url = _get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,   # needed for SQLite ALTER TABLE support
    )

    with context.begin_transaction():
        context.run_migrations()


# ---------------------------------------------------------------------------
# Run migrations online
# ---------------------------------------------------------------------------

def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode.

    Creates an Engine and associates a connection with the context.
    """
    if not _SQLALCHEMY_AVAILABLE:
        logger.warning("SQLAlchemy not available — cannot run online migrations")
        return

    # Override sqlalchemy.url from env if provided
    cfg_section = config.get_section(config.config_ini_section, {})
    cfg_section["sqlalchemy.url"] = _get_url()

    connectable = engine_from_config(
        cfg_section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,   # SQLite ALTER TABLE workaround
        )

        with context.begin_transaction():
            context.run_migrations()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
