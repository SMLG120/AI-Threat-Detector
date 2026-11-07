"""Verified labels, indexes, and alerts → request_logs foreign key

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-05
"""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("request_logs", sa.Column("verified_label", sa.Boolean(), nullable=True))
    op.add_column("request_logs", sa.Column("labeled_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_request_logs_verified_label", "request_logs", ["verified_label"])
    op.create_index("ix_request_logs_threat_level", "request_logs", ["threat_level"])
    op.create_index("ix_request_logs_is_malicious", "request_logs", ["is_malicious"])

    # Remove orphaned alerts so the foreign key can be created
    op.execute(
        "DELETE FROM alerts a WHERE NOT EXISTS "
        "(SELECT 1 FROM request_logs r WHERE r.id = a.log_id)"
    )
    op.create_foreign_key(
        "fk_alerts_log_id_request_logs",
        "alerts", "request_logs",
        ["log_id"], ["id"],
        ondelete="CASCADE",
    )
    op.create_index("ix_alerts_log_id", "alerts", ["log_id"])

    op.alter_column("model_metadata", "version", type_=sa.String(40))


def downgrade() -> None:
    op.alter_column("model_metadata", "version", type_=sa.String(20))
    op.drop_index("ix_alerts_log_id", table_name="alerts")
    op.drop_constraint("fk_alerts_log_id_request_logs", "alerts", type_="foreignkey")
    op.drop_index("ix_request_logs_is_malicious", table_name="request_logs")
    op.drop_index("ix_request_logs_threat_level", table_name="request_logs")
    op.drop_index("ix_request_logs_verified_label", table_name="request_logs")
    op.drop_column("request_logs", "labeled_at")
    op.drop_column("request_logs", "verified_label")
