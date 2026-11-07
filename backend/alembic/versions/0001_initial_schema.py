"""Initial schema (matches the tables previously created by create_all)

Revision ID: 0001
Revises:
Create Date: 2026-11-05
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "request_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("ip_address", sa.String(45)),
        sa.Column("method", sa.String(10)),
        sa.Column("url", sa.Text()),
        sa.Column("path", sa.Text()),
        sa.Column("query_string", sa.Text()),
        sa.Column("user_agent", sa.Text()),
        sa.Column("referer", sa.Text()),
        sa.Column("status_code", sa.Integer()),
        sa.Column("response_size", sa.Integer()),
        sa.Column("request_body", sa.Text()),
        sa.Column("headers", sa.JSON()),
        sa.Column("threat_score", sa.Float()),
        sa.Column("threat_level", sa.String(10)),
        sa.Column("is_malicious", sa.Boolean()),
        sa.Column("attack_types", sa.JSON()),
        sa.Column("rule_score", sa.Float()),
        sa.Column("isolation_forest_score", sa.Float()),
        sa.Column("random_forest_score", sa.Float()),
        sa.Column("autoencoder_score", sa.Float()),
        sa.Column("features", sa.JSON()),
    )
    op.create_index("ix_request_logs_timestamp", "request_logs", ["timestamp"])
    op.create_index("ix_request_logs_ip_address", "request_logs", ["ip_address"])
    op.create_index("ix_request_logs_threat_score", "request_logs", ["threat_score"])

    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("log_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("ip_address", sa.String(45)),
        sa.Column("threat_level", sa.String(10)),
        sa.Column("threat_score", sa.Float()),
        sa.Column("attack_types", sa.JSON()),
        sa.Column("message", sa.Text()),
        sa.Column("acknowledged", sa.Boolean()),
    )
    op.create_index("ix_alerts_timestamp", "alerts", ["timestamp"])

    op.create_table(
        "model_metadata",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("model_name", sa.String(100)),
        sa.Column("version", sa.String(20)),
        sa.Column("trained_at", sa.DateTime(timezone=True)),
        sa.Column("accuracy", sa.Float()),
        sa.Column("samples_used", sa.Integer()),
        sa.Column("is_active", sa.Boolean()),
        sa.Column("model_metadata", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("model_metadata")
    op.drop_index("ix_alerts_timestamp", table_name="alerts")
    op.drop_table("alerts")
    op.drop_index("ix_request_logs_threat_score", table_name="request_logs")
    op.drop_index("ix_request_logs_ip_address", table_name="request_logs")
    op.drop_index("ix_request_logs_timestamp", table_name="request_logs")
    op.drop_table("request_logs")
