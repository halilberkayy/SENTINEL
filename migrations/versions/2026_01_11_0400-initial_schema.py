"""Initial database schema

Revision ID: initial_schema
Revises: 
Create Date: 2026-01-11 04:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create users table
    op.create_table(
        'users',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('username', sa.String(length=100), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=50), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('api_key', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_login', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('username'),
        sa.UniqueConstraint('email'),
        sa.UniqueConstraint('api_key')
    )
    op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)

    # Create scan_jobs table
    op.create_table(
        'scan_jobs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('target_url', sa.String(length=2048), nullable=False),
        sa.Column('status', sa.Enum('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED', name='scanstatus'), nullable=False),
        sa.Column('modules', sa.JSON(), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('total_vulnerabilities', sa.Integer(), nullable=False),
        sa.Column('duration_seconds', sa.Float(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scan_jobs_target_url'), 'scan_jobs', ['target_url'], unique=False)
    op.create_index(op.f('ix_scan_jobs_status'), 'scan_jobs', ['status'], unique=False)
    op.create_index(op.f('ix_scan_jobs_user_id'), 'scan_jobs', ['user_id'], unique=False)

    # Create vulnerabilities table
    op.create_table(
        'vulnerabilities',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('scan_job_id', sa.String(length=36), nullable=False),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('type', sa.String(length=100), nullable=False),
        sa.Column('severity', sa.Enum('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', name='severity'), nullable=False),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('cwe_id', sa.String(length=20), nullable=True),
        sa.Column('evidence', sa.JSON(), nullable=False),
        sa.Column('remediation', sa.Text(), nullable=True),
        sa.Column('references', sa.JSON(), nullable=False),
        sa.Column('module_name', sa.String(length=100), nullable=False),
        sa.Column('detected_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['scan_job_id'], ['scan_jobs.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_vulnerabilities_scan_job_id'), 'vulnerabilities', ['scan_job_id'], unique=False)
    op.create_index(op.f('ix_vulnerabilities_type'), 'vulnerabilities', ['type'], unique=False)
    op.create_index(op.f('ix_vulnerabilities_severity'), 'vulnerabilities', ['severity'], unique=False)

    # Create audit_logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=True),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('resource_type', sa.String(length=100), nullable=False),
        sa.Column('resource_id', sa.String(length=36), nullable=True),
        sa.Column('details', sa.JSON(), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.String(length=500), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_audit_logs_user_id'), 'audit_logs', ['user_id'], unique=False)
    op.create_index(op.f('ix_audit_logs_action'), 'audit_logs', ['action'], unique=False)
    op.create_index(op.f('ix_audit_logs_created_at'), 'audit_logs', ['created_at'], unique=False)

    # Create plugins table
    op.create_table(
        'plugins',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('version', sa.String(length=20), nullable=False),
        sa.Column('author', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('config', sa.JSON(), nullable=False),
        sa.Column('installed_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )
    op.create_index(op.f('ix_plugins_name'), 'plugins', ['name'], unique=True)


def downgrade() -> None:
    op.drop_index(op.f('ix_plugins_name'), table_name='plugins')
    op.drop_table('plugins')
    op.drop_index(op.f('ix_audit_logs_created_at'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_action'), table_name='audit_logs')
    op.drop_index(op.f('ix_audit_logs_user_id'), table_name='audit_logs')
    op.drop_table('audit_logs')
    op.drop_index(op.f('ix_vulnerabilities_severity'), table_name='vulnerabilities')
    op.drop_index(op.f('ix_vulnerabilities_type'), table_name='vulnerabilities')
    op.drop_index(op.f('ix_vulnerabilities_scan_job_id'), table_name='vulnerabilities')
    op.drop_table('vulnerabilities')
    op.drop_index(op.f('ix_scan_jobs_user_id'), table_name='scan_jobs')
    op.drop_index(op.f('ix_scan_jobs_status'), table_name='scan_jobs')
    op.drop_index(op.f('ix_scan_jobs_target_url'), table_name='scan_jobs')
    op.drop_table('scan_jobs')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_index(op.f('ix_users_username'), table_name='users')
    op.drop_table('users')
