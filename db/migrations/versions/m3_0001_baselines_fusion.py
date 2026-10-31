"""M3: versioned behavioural baselines, peer assignments, and the fusion columns on alerts.

Revision ID: m3_0001
Revises: None
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "m3_0001"
down_revision = None  # Initial Alembic migration
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "baselines",
        sa.Column(
            "entity_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("entities.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("version", sa.Integer(), primary_key=True),
        sa.Column("profile", postgresql.JSONB(), nullable=False),
        sa.Column("behaviour_vector", postgresql.ARRAY(sa.Float()), nullable=False),
        sa.Column("peer_cluster", sa.Integer(), nullable=False, server_default="-1"),
        # sufficient=false means "scored nothing", NOT "scored everything as
        # anomalous". Storing it explicitly keeps that distinction queryable.
        sa.Column("sufficient", sa.Boolean(), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_baselines_cluster", "baselines", ["peer_cluster"])

    op.create_table(
        "peer_models",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("version", sa.Integer(), nullable=False, unique=True),
        sa.Column("centroids", postgresql.JSONB(), nullable=False),
        sa.Column("spreads", postgresql.JSONB(), nullable=False),
        sa.Column("k", sa.Integer(), nullable=False),
        sa.Column("singletons", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )

    op.create_table(
        "fusion_config",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("version", sa.Integer(), nullable=False, unique=True),
        sa.Column("weights", postgresql.JSONB(), nullable=False),
        sa.Column("tier_thresholds", postgresql.JSONB(), nullable=False),
        sa.Column("fitted_pr_auc", sa.Float(), nullable=False),
        sa.Column("fitted_on", postgresql.JSONB(), nullable=False),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )

    # alerts exists from M2 with the rule layer; M3 adds the other two and the
    # fused score. layer_scores keeps every component so an analyst asking
    # "why did this fire" gets an answer instead of one opaque number.
    op.add_column("alerts", sa.Column("layer_scores", postgresql.JSONB(), nullable=True))
    op.add_column("alerts", sa.Column("fusion_version", sa.Integer(), nullable=True))
    op.add_column("alerts", sa.Column("baseline_version", sa.Integer(), nullable=True))
    op.add_column(
        "alerts",
        sa.Column(
            "criticality_tier",
            sa.String(16),
            nullable=False,
            server_default="standard",
        ),
    )
    op.create_index("ix_alerts_fused", "alerts", ["fused_score"])


def downgrade():
    op.drop_index("ix_alerts_fused", "alerts")
    for col in (
        "criticality_tier",
        "baseline_version",
        "fusion_version",
        "layer_scores",
    ):
        op.drop_column("alerts", col)
    op.drop_table("fusion_config")
    op.drop_table("peer_models")
    op.drop_table("baselines")
