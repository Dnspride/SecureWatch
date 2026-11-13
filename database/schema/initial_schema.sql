-- ==============================================================================
-- SecureWatch Cybersecurity Platform - Initial Database Schema
-- Unified IAM, RBAC, Endpoint Device Inventory, SIEM Events, Alerts & Audit
-- ==============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(64) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    department VARCHAR(128),
    hashed_password VARCHAR(512) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_superuser BOOLEAN NOT NULL DEFAULT FALSE,
    is_locked BOOLEAN NOT NULL DEFAULT FALSE,
    failed_login_attempts INT NOT NULL DEFAULT 0,
    lockout_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret VARCHAR(512)
);

CREATE INDEX IF NOT EXISTS ix_users_username ON users(username);
CREATE INDEX IF NOT EXISTS ix_users_email ON users(email);
CREATE INDEX IF NOT EXISTS ix_users_department ON users(department);

-- 2. Permissions Table
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    code VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(128) NOT NULL,
    description VARCHAR(512),
    category VARCHAR(64) NOT NULL
);

-- 3. Roles Table
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(64) UNIQUE NOT NULL,
    description VARCHAR(512),
    is_system_role BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4. Role-Permissions Junction
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

-- 5. User-Roles Junction
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- 6. Groups Table
CREATE TABLE IF NOT EXISTS groups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(128) UNIQUE NOT NULL,
    description VARCHAR(512),
    department VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 7. Group Members Junction
CREATE TABLE IF NOT EXISTS group_members (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_group_members UNIQUE (group_id, user_id)
);

-- 8. Group Roles Junction
CREATE TABLE IF NOT EXISTS group_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    CONSTRAINT uq_group_roles UNIQUE (group_id, role_id)
);

-- 9. Enrollment Tokens Table
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    token_hash VARCHAR(64) UNIQUE NOT NULL,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    is_used BOOLEAN NOT NULL DEFAULT FALSE,
    used_by_device_id UUID,
    requires_approval BOOLEAN NOT NULL DEFAULT FALSE
);

-- 10. Devices Table
CREATE TYPE device_status_enum AS ENUM (
    'online', 'offline', 'pending_approval', 'unhealthy', 'critical', 'revoked'
);

CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hostname VARCHAR(255) NOT NULL,
    os_name VARCHAR(64) NOT NULL,
    os_version VARCHAR(64) NOT NULL,
    os_arch VARCHAR(32) NOT NULL,
    device_owner_id UUID REFERENCES users(id) ON DELETE SET NULL,
    department VARCHAR(128),
    private_ip VARCHAR(45),
    public_ip VARCHAR(45),
    mac_address VARCHAR(17),
    agent_version VARCHAR(32),
    enrollment_date TIMESTAMPTZ,
    last_heartbeat TIMESTAMPTZ,
    status device_status_enum NOT NULL DEFAULT 'pending_approval',
    security_status VARCHAR(64) DEFAULT 'healthy',
    risk_score FLOAT NOT NULL DEFAULT 0.0,
    enrollment_token_id UUID REFERENCES enrollment_tokens(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS ix_devices_hostname ON devices(hostname);
CREATE INDEX IF NOT EXISTS ix_devices_status ON devices(status);

-- 11. Device Credentials Table
CREATE TABLE IF NOT EXISTS device_credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    credential_hash VARCHAR(64) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ
);

-- 12. Detection Rules Table
CREATE TABLE IF NOT EXISTS detection_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    event_source VARCHAR(64) NOT NULL,
    condition_config JSONB NOT NULL,
    severity VARCHAR(32) NOT NULL,
    mitre_tactic VARCHAR(64),
    mitre_technique VARCHAR(64),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_custom BOOLEAN NOT NULL DEFAULT FALSE,
    recommended_steps TEXT,
    suppress_duplicate_minutes INT DEFAULT 15,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 13. Security Events (Reference Table)
CREATE TABLE IF NOT EXISTS security_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id VARCHAR(256),
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    event_source VARCHAR(64) NOT NULL,
    event_category VARCHAR(64) NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    process_name VARCHAR(255),
    process_id INT,
    event_description TEXT,
    raw_event_ref VARCHAR(512),
    detection_rule_id UUID REFERENCES detection_rules(id) ON DELETE SET NULL,
    is_alert_generated BOOLEAN NOT NULL DEFAULT FALSE
);

-- 14. Alerts Table
CREATE TYPE alert_severity_enum AS ENUM ('critical', 'high', 'medium', 'low', 'informational');
CREATE TYPE alert_status_enum AS ENUM ('new', 'acknowledged', 'investigating', 'resolved', 'false_positive');

CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(512) NOT NULL,
    description TEXT,
    severity alert_severity_enum NOT NULL DEFAULT 'medium',
    status alert_status_enum NOT NULL DEFAULT 'new',
    detection_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    source_event_id UUID REFERENCES security_events(id) ON DELETE SET NULL,
    detection_rule_id UUID REFERENCES detection_rules(id) ON DELETE SET NULL,
    risk_score FLOAT NOT NULL DEFAULT 0.0,
    assigned_to UUID REFERENCES users(id) ON DELETE SET NULL,
    resolved_at TIMESTAMPTZ,
    resolution_notes TEXT
);

-- 15. Alert Notes Table
CREATE TABLE IF NOT EXISTS alert_notes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    author_id UUID REFERENCES users(id) ON DELETE SET NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 16. Audit Logs Table (Tamper-evident SHA-256 hash chain)
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_username VARCHAR(64),
    action VARCHAR(128) NOT NULL,
    resource_type VARCHAR(64) NOT NULL,
    resource_id VARCHAR(256),
    source_ip VARCHAR(45),
    result VARCHAR(32) NOT NULL DEFAULT 'success',
    old_value JSONB,
    new_value JSONB,
    hash VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS ix_audit_logs_action ON audit_logs(action);

-- 17. User Sessions Table
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash VARCHAR(64) NOT NULL,
    device_info VARCHAR(255),
    ip_address VARCHAR(45),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    last_activity TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 18. Login History Table
CREATE TABLE IF NOT EXISTS login_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address VARCHAR(45),
    user_agent VARCHAR(255),
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(128),
    mfa_used BOOLEAN NOT NULL DEFAULT FALSE
);
