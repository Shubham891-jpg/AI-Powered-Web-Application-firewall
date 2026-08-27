"""Initial schema for AI-WAF persistence (Phase 7)

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-08-28 05:25:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

json_type = sa.JSON().with_variant(JSONB, "postgresql")


def upgrade() -> None:
    # 1. users
    op.create_table(
        'users',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('username', sa.String(length=50), nullable=False, unique=True),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('email', sa.String(length=100), unique=True, nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('is_admin', sa.Boolean(), nullable=False, default=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_login', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_users_username', 'users', ['username'])

    # 2. applications
    op.create_table(
        'applications',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('name', sa.String(length=100), nullable=False, unique=True),
        sa.Column('upstream_url', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('detection_mode', sa.String(length=20), nullable=False, default='BLOCK'),
        sa.Column('rate_limit_requests', sa.Integer(), nullable=False, default=100),
        sa.Column('rate_limit_window_seconds', sa.Integer(), nullable=False, default=60),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_applications_name', 'applications', ['name'])

    # 3. security_events
    op.create_table(
        'security_events',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('request_id', sa.String(length=64), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('client_ip', sa.String(length=45), nullable=False),
        sa.Column('http_method', sa.String(length=10), nullable=False),
        sa.Column('path', sa.String(length=2048), nullable=False),
        sa.Column('query_params', json_type, nullable=True),
        sa.Column('headers', json_type, nullable=True),
        sa.Column('raw_payload', sa.Text(), nullable=True),
        sa.Column('normalized_payload', sa.Text(), nullable=True),
        sa.Column('attack_category', sa.String(length=50), nullable=False),
        sa.Column('risk_score', sa.Integer(), nullable=False),
        sa.Column('ml_confidence', sa.Float(), nullable=True),
        sa.Column('action', sa.String(length=20), nullable=False),
        sa.Column('matched_rules', json_type, nullable=True),
        sa.Column('primary_reason', sa.Text(), nullable=True),
        sa.Column('ml_prediction', json_type, nullable=True),
        sa.Column('contextual_penalties', json_type, nullable=True),
        sa.Column('explanation_json', json_type, nullable=True),
        sa.Column('model_version', sa.String(length=50), nullable=True),
        sa.Column('response_status', sa.Integer(), nullable=False, default=200),
        sa.Column('processing_latency_ms', sa.Float(), nullable=False, default=0.0),
        sa.Column('review_status', sa.String(length=20), nullable=False, default='UNREVIEWED'),
        sa.Column('reviewed_at', sa.DateTime(), nullable=True),
        sa.Column('review_notes', sa.Text(), nullable=True),
    )
    op.create_index('ix_security_events_request_id', 'security_events', ['request_id'])
    op.create_index('ix_security_events_timestamp', 'security_events', ['timestamp'])
    op.create_index('ix_security_events_client_ip', 'security_events', ['client_ip'])
    op.create_index('ix_security_events_path', 'security_events', ['path'])
    op.create_index('ix_security_events_attack_category', 'security_events', ['attack_category'])
    op.create_index('ix_security_events_risk_score', 'security_events', ['risk_score'])
    op.create_index('ix_security_events_action', 'security_events', ['action'])

    # 4. rules
    op.create_table(
        'rules',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('rule_id', sa.String(length=50), nullable=False, unique=True),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('category', sa.String(length=50), nullable=False),
        sa.Column('pattern', sa.Text(), nullable=False),
        sa.Column('score', sa.Integer(), nullable=False),
        sa.Column('is_regex', sa.Boolean(), nullable=False, default=True),
        sa.Column('enabled', sa.Boolean(), nullable=False, default=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_rules_rule_id', 'rules', ['rule_id'])
    op.create_index('ix_rules_category', 'rules', ['category'])

    # 5. model_versions
    op.create_table(
        'model_versions',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('model_name', sa.String(length=100), nullable=False),
        sa.Column('version', sa.String(length=50), nullable=False, unique=True),
        sa.Column('algorithm', sa.String(length=50), nullable=False),
        sa.Column('metrics', json_type, nullable=True),
        sa.Column('artifact_path', sa.String(length=255), nullable=False),
        sa.Column('vectorizer_path', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )

    # 6. rate_limit_events
    op.create_table(
        'rate_limit_events',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('client_ip', sa.String(length=45), nullable=False),
        sa.Column('request_count', sa.Integer(), nullable=False),
        sa.Column('window_seconds', sa.Integer(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('action_taken', sa.String(length=20), nullable=False, default='BLOCK'),
    )
    op.create_index('ix_rate_limit_events_client_ip', 'rate_limit_events', ['client_ip'])
    op.create_index('ix_rate_limit_events_timestamp', 'rate_limit_events', ['timestamp'])


def downgrade() -> None:
    op.drop_table('rate_limit_events')
    op.drop_table('model_versions')
    op.drop_table('rules')
    op.drop_table('security_events')
    op.drop_table('applications')
    op.drop_table('users')
