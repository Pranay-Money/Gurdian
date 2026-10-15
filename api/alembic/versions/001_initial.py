"""
Initial migration - Create all tables
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB, TSVECTOR, ENUM

# revision identifiers, used by Alembic
revision = '001_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:

    # Define PostgreSQL enums; create them explicitly below.
    risk_level = ENUM(
        'Low', 'Medium', 'High', 'Critical',
        name='risklevel', create_type=False
    )
    action_type = ENUM(
        'allow', 'warn', 'block',
        name='actiontype', create_type=False
    )
    channel_type = ENUM(
        'email', 'sms', 'social', 'url',
        name='channeltype', create_type=False
    )
    verdict_type = ENUM(
        'false_positive', 'false_negative', 'correct',
        name='verdicttype', create_type=False
    )
    signal_category = ENUM(
        'linguistic', 'structural', 'reputation', 'behavioral',
        'metadata', 'impersonation', 'sensitive_request',
        name='signalcategory', create_type=False
    )
    intel_source = ENUM(
        'google_safe_browsing', 'virustotal', 'openphish',
        'phishtank', 'rdap', 'dns', 'tls',
        name='intelsource', create_type=False
    )
    intel_verdict = ENUM(
        'clean', 'malicious', 'suspicious', 'unknown',
        name='intelverdict', create_type=False
    )


    risk_level.create(op.get_bind(), checkfirst=True)
    action_type.create(op.get_bind(), checkfirst=True)
    channel_type.create(op.get_bind(), checkfirst=True)
    verdict_type.create(op.get_bind(), checkfirst=True)
    signal_category.create(op.get_bind(), checkfirst=True)
    intel_source.create(op.get_bind(), checkfirst=True)
    intel_verdict.create(op.get_bind(), checkfirst=True)

    # Devices table
    op.create_table(
        'devices',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('device_token', sa.String(255), unique=True, nullable=False),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('expires_at', sa.DateTime, nullable=False),
        sa.Column('last_seen_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('is_active', sa.Boolean, nullable=False, default=True),
        sa.Column('store_raw_text', sa.Boolean, nullable=False, default=False),
    )
    op.create_index('ix_devices_device_token', 'devices', ['device_token'], unique=True)

    # Cases table
    op.create_table(
        'cases',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('device_id', UUID(as_uuid=True), sa.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False),
        sa.Column('channel', channel_type, nullable=False),
        sa.Column('sender', sa.String(255), nullable=True),
        sa.Column('text', sa.Text, nullable=True),
        sa.Column('text_hash', sa.String(64), nullable=True),
        sa.Column('score', sa.Integer, nullable=False),
        sa.Column('level', risk_level, nullable=False),
        sa.Column('action', action_type, nullable=False),
        sa.Column('model_version', sa.String(50), nullable=False),
        sa.Column('latency_ms', sa.Integer, nullable=False),
        sa.Column('signals', JSONB, nullable=False, default=[]),
        sa.Column('urls', JSONB, nullable=False, default=[]),
        sa.Column('domains_text', sa.Text, nullable=True),
        sa.Column('signal_labels_text', sa.Text, nullable=True),
        sa.Column('tsv', TSVECTOR, nullable=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_cases_device_id', 'cases', ['device_id'])
    op.create_index('ix_cases_device_created', 'cases', ['device_id', 'created_at'])
    op.create_index('ix_cases_level_created', 'cases', ['level', 'created_at'])
    op.create_index('ix_cases_sender', 'cases', ['sender'])
    op.create_index('ix_cases_text_hash', 'cases', ['text_hash'])
    op.create_index('ix_cases_tsv', 'cases', ['tsv'], postgresql_using='gin')
    op.create_index('ix_cases_created_at', 'cases', ['created_at'])

    # Signals table
    op.create_table(
        'signals',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('case_id', UUID(as_uuid=True), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('key', sa.String(100), nullable=False),
        sa.Column('category', signal_category, nullable=False),
        sa.Column('label', sa.String(200), nullable=False),
        sa.Column('points', sa.Integer, nullable=False),
        sa.Column('reason', sa.Text, nullable=False),
        sa.Column('evidence', JSONB, nullable=False, default=[]),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_signals_case_id', 'signals', ['case_id'])
    op.create_index('ix_signals_case_category', 'signals', ['case_id', 'category'])
    op.create_index('ix_signals_label', 'signals', ['label'])

    # URLs table
    op.create_table(
        'urls',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('case_id', UUID(as_uuid=True), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('url', sa.Text, nullable=False),
        sa.Column('host', sa.String(255), nullable=False),
        sa.Column('registrable_domain', sa.String(255), nullable=False),
        sa.Column('tld', sa.String(50), nullable=False),
        sa.Column('scheme', sa.String(10), nullable=False),
        sa.Column('subdomains', JSONB, nullable=False, default=[]),
        sa.Column('length', sa.Integer, nullable=False),
        sa.Column('age_days', sa.Integer, nullable=True),
        sa.Column('redirects', JSONB, nullable=False, default=[]),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_urls_case_id', 'urls', ['case_id'])
    op.create_index('ix_urls_case_created', 'urls', ['case_id', 'created_at'])
    op.create_index('ix_urls_registrable_domain', 'urls', ['registrable_domain'])
    op.create_index('ix_urls_host', 'urls', ['host'])

    # URL Intel table
    op.create_table(
        'url_intel',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('url_id', UUID(as_uuid=True), sa.ForeignKey('urls.id', ondelete='CASCADE'), nullable=False),
        sa.Column('source', intel_source, nullable=False),
        sa.Column('verdict', intel_verdict, nullable=False),
        sa.Column('confidence', sa.Integer, nullable=False),
        sa.Column('details', JSONB, nullable=False, default={}),
        sa.Column('note', sa.String(255), nullable=True),
        sa.Column('cached', sa.Boolean, nullable=False, default=False),
        sa.Column('latency_ms', sa.Integer, nullable=False),
        sa.Column('checked_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('expires_at', sa.DateTime, nullable=False),
    )
    op.create_index('ix_url_intel_url_id', 'url_intel', ['url_id'])
    op.create_index('ix_url_intel_url_source', 'url_intel', ['url_id', 'source'], unique=True)
    op.create_index('ix_url_intel_source', 'url_intel', ['source'])
    op.create_index('ix_url_intel_verdict', 'url_intel', ['verdict'])
    op.create_index('ix_url_intel_expires', 'url_intel', ['expires_at'])

    # Feedback table
    op.create_table(
        'feedback',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('case_id', UUID(as_uuid=True), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False, unique=True),
        sa.Column('verdict', verdict_type, nullable=False),
        sa.Column('notes', sa.Text, nullable=True),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_feedback_case_id', 'feedback', ['case_id'], unique=True)

    # Reported URLs table
    op.create_table(
        'reported_urls',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('url', sa.Text, nullable=False),
        sa.Column('domain', sa.String(255), nullable=False),
        sa.Column('note', sa.Text, nullable=True),
        sa.Column('reporter_device_id', UUID(as_uuid=True), sa.ForeignKey('devices.id', ondelete='SET NULL'), nullable=True),
        sa.Column('status', sa.String(50), nullable=False, default='pending'),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('reviewed_at', sa.DateTime, nullable=True),
    )
    op.create_index('ix_reported_urls_url', 'reported_urls', ['url'])
    op.create_index('ix_reported_urls_domain', 'reported_urls', ['domain'])
    op.create_index('ix_reported_urls_created', 'reported_urls', ['created_at'])

    # Blocklist table
    op.create_table(
        'blocklist',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('domain', sa.String(255), unique=True, nullable=False),
        sa.Column('domain_hash', sa.String(16), unique=True, nullable=False),
        sa.Column('reason', sa.String(50), nullable=False),
        sa.Column('source', sa.String(50), nullable=False),
        sa.Column('expires_at', sa.DateTime, nullable=False),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_blocklist_domain', 'blocklist', ['domain'], unique=True)
    op.create_index('ix_blocklist_domain_hash', 'blocklist', ['domain_hash'], unique=True)
    op.create_index('ix_blocklist_expires', 'blocklist', ['expires_at'])
    op.create_index('ix_blocklist_source', 'blocklist', ['source'])

    # Stats Daily table
    op.create_table(
        'stats_daily',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('date', sa.DateTime, nullable=False, unique=True),
        sa.Column('total_cases', sa.Integer, nullable=False, default=0),
        sa.Column('by_level_low', sa.Integer, nullable=False, default=0),
        sa.Column('by_level_medium', sa.Integer, nullable=False, default=0),
        sa.Column('by_level_high', sa.Integer, nullable=False, default=0),
        sa.Column('by_level_critical', sa.Integer, nullable=False, default=0),
        sa.Column('by_channel_email', sa.Integer, nullable=False, default=0),
        sa.Column('by_channel_sms', sa.Integer, nullable=False, default=0),
        sa.Column('by_channel_social', sa.Integer, nullable=False, default=0),
        sa.Column('by_channel_url', sa.Integer, nullable=False, default=0),
        sa.Column('avg_score', sa.Integer, nullable=False, default=0),
        sa.Column('avg_latency_ms', sa.Integer, nullable=False, default=0),
        sa.Column('top_signals', JSONB, nullable=False, default=[]),
        sa.Column('top_domains', JSONB, nullable=False, default=[]),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_stats_daily_date', 'stats_daily', ['date'], unique=True)

    # API Usage table
    op.create_table(
        'api_usage',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('device_id', UUID(as_uuid=True), sa.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False),
        sa.Column('endpoint', sa.String(100), nullable=False),
        sa.Column('status_code', sa.Integer, nullable=False),
        sa.Column('latency_ms', sa.Integer, nullable=False),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_api_usage_device_id', 'api_usage', ['device_id'])
    op.create_index('ix_api_usage_device_created', 'api_usage', ['device_id', 'created_at'])

    # Rate Limit Buckets table
    op.create_table(
        'rate_limit_buckets',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('device_id', UUID(as_uuid=True), sa.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False),
        sa.Column('endpoint', sa.String(100), nullable=False),
        sa.Column('tokens', sa.Integer, nullable=False, default=0),
        sa.Column('last_refill', sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.func.now()),
    )
    op.create_index('ix_rate_limit_device_endpoint', 'rate_limit_buckets', ['device_id', 'endpoint'], unique=True)

    # Create tsvector update trigger function
    op.execute("""
        CREATE OR REPLACE FUNCTION update_case_tsv()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.tsv :=
                setweight(to_tsvector('english', COALESCE(NEW.text, '')), 'A') ||
                setweight(to_tsvector('english', COALESCE(NEW.sender, '')), 'B') ||
                setweight(to_tsvector('english', COALESCE(NEW.domains_text, '')), 'C') ||
                setweight(to_tsvector('english', COALESCE(NEW.signal_labels_text, '')), 'C');
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)

    op.execute("DROP TRIGGER IF EXISTS trigger_update_case_tsv ON cases")

    op.execute("""
        CREATE TRIGGER trigger_update_case_tsv
        BEFORE INSERT OR UPDATE ON cases
        FOR EACH ROW EXECUTE FUNCTION update_case_tsv()
    """)

    # Create updated_at trigger function
    op.execute("""
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = NOW();
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)

    # Apply updated_at triggers
    for table in ['cases', 'blocklist', 'stats_daily', 'rate_limit_buckets']:
        op.execute(
            f"DROP TRIGGER IF EXISTS trigger_update_{table}_updated_at ON {table}"
        )

        op.execute(f"""
            CREATE TRIGGER trigger_update_{table}_updated_at
            BEFORE UPDATE ON {table}
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column()
        """)


def downgrade() -> None:
    # Drop triggers
    for table in ['cases', 'blocklist', 'stats_daily', 'rate_limit_buckets']:
        op.execute(f"DROP TRIGGER IF EXISTS trigger_update_{table}_updated_at ON {table};")

    op.execute("DROP TRIGGER IF EXISTS trigger_update_case_tsv ON cases;")
    op.execute("DROP FUNCTION IF EXISTS update_case_tsv();")
    op.execute("DROP FUNCTION IF EXISTS update_updated_at_column();")

    # Drop tables in reverse order
    op.drop_table('rate_limit_buckets')
    op.drop_table('api_usage')
    op.drop_table('stats_daily')
    op.drop_table('blocklist')
    op.drop_table('reported_urls')
    op.drop_table('feedback')
    op.drop_table('url_intel')
    op.drop_table('urls')
    op.drop_table('signals')
    op.drop_table('cases')
    op.drop_table('devices')

    # Drop enums
    sa.Enum(name='intelverdict').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='intelsource').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='signalcategory').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='verdicttype').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='channeltype').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='actiontype').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='risklevel').drop(op.get_bind(), checkfirst=True)