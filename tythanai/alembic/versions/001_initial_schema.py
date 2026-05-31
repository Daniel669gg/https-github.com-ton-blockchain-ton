"""Initial schema for TythanAI Platform.

Revision ID: 001
Revises:
Create Date: 2025-01-01 00:00:00.000000 UTC

Creates tables:
- agent_runs
- findings
- scan_history
- generated_rules
- attack_chains
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

# ---------------------------------------------------------------------------
# Alembic revision identifiers
# ---------------------------------------------------------------------------

revision:     str        = "001"
down_revision: str | None = None
branch_labels: str | None = None
depends_on:    str | None = None


# ---------------------------------------------------------------------------
# Upgrade — create all tables
# ---------------------------------------------------------------------------

def upgrade() -> None:
    """Create the initial schema."""

    # -- agent_runs ----------------------------------------------------------
    op.create_table(
        "agent_runs",
        sa.Column("id",          sa.Integer(),  nullable=False, autoincrement=True),
        sa.Column("session_id",  sa.Text(),     nullable=False),
        sa.Column("timestamp",   sa.Text(),     nullable=False),
        sa.Column("step_number", sa.Integer(),  nullable=False),
        sa.Column("reasoning",   sa.Text(),     nullable=True),
        sa.Column("action",      sa.Text(),     nullable=True),
        sa.Column("observation", sa.Text(),     nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    # -- findings ------------------------------------------------------------
    op.create_table(
        "findings",
        sa.Column("id",          sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("scan_id",     sa.Text(),    nullable=False),
        sa.Column("rule_id",     sa.Text(),    nullable=False),
        sa.Column("file",        sa.Text(),    nullable=False),
        sa.Column("line",        sa.Integer(), nullable=True),
        sa.Column("severity",    sa.Text(),    nullable=True),
        sa.Column("confidence",  sa.Real(),    nullable=True),
        sa.Column("cwe_id",      sa.Text(),    nullable=True),
        sa.Column("description", sa.Text(),    nullable=True),
        sa.Column("created_at",  sa.Text(),    nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_findings_scan_id",  "findings", ["scan_id"])
    op.create_index("ix_findings_rule_id",  "findings", ["rule_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])

    # -- scan_history --------------------------------------------------------
    op.create_table(
        "scan_history",
        sa.Column("id",             sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("scan_id",        sa.Text(),    nullable=False),
        sa.Column("path",           sa.Text(),    nullable=False),
        sa.Column("started_at",     sa.Text(),    nullable=False),
        sa.Column("completed_at",   sa.Text(),    nullable=True),
        sa.Column("total_findings", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("critical_count", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("high_count",     sa.Integer(), nullable=True, server_default="0"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id"),
    )
    op.create_index("ix_scan_history_started_at", "scan_history", ["started_at"])

    # -- generated_rules -----------------------------------------------------
    op.create_table(
        "generated_rules",
        sa.Column("id",             sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("rule_id",        sa.Text(),    nullable=False),
        sa.Column("yaml_content",   sa.Text(),    nullable=False),
        sa.Column("created_at",     sa.Text(),    nullable=False),
        sa.Column("hit_count",      sa.Integer(), nullable=True, server_default="1"),
        sa.Column("status",         sa.Text(),    nullable=True, server_default="draft"),
        sa.Column("confidence_avg", sa.Real(),    nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("rule_id"),
    )

    # -- attack_chains -------------------------------------------------------
    op.create_table(
        "attack_chains",
        sa.Column("id",          sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("session_id",  sa.Text(),    nullable=False),
        sa.Column("chain_id",    sa.Text(),    nullable=False),
        sa.Column("finding_ids", sa.Text(),    nullable=True),
        sa.Column("severity",    sa.Text(),    nullable=True),
        sa.Column("narrative",   sa.Text(),    nullable=True),
        sa.Column("created_at",  sa.Text(),    nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_attack_chains_session_id", "attack_chains", ["session_id"])
    op.create_index("ix_attack_chains_chain_id",   "attack_chains", ["chain_id"])


# ---------------------------------------------------------------------------
# Downgrade — drop all tables
# ---------------------------------------------------------------------------

def downgrade() -> None:
    """Drop all tables created in upgrade()."""
    # Drop in reverse dependency order
    op.drop_index("ix_attack_chains_chain_id",    table_name="attack_chains")
    op.drop_index("ix_attack_chains_session_id",  table_name="attack_chains")
    op.drop_table("attack_chains")

    op.drop_table("generated_rules")

    op.drop_index("ix_scan_history_started_at", table_name="scan_history")
    op.drop_table("scan_history")

    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_rule_id",  table_name="findings")
    op.drop_index("ix_findings_scan_id",  table_name="findings")
    op.drop_table("findings")

    op.drop_table("agent_runs")
