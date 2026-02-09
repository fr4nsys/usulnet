-- ============================================================================
-- 001_foundation: Core user system, sessions, API keys, audit logging, roles
-- ============================================================================

-- Generic updated_at trigger function (reused across all tables)
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Users
-- ============================================================================
CREATE TABLE users (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username                VARCHAR(255) NOT NULL UNIQUE,
    email                   VARCHAR(255) UNIQUE,
    password_hash           VARCHAR(255) NOT NULL,
    role                    VARCHAR(50) NOT NULL DEFAULT 'viewer',
    role_id                 UUID,  -- FK added after roles table creation
    is_active               BOOLEAN NOT NULL DEFAULT true,
    is_ldap                 BOOLEAN NOT NULL DEFAULT false,
    ldap_dn                 VARCHAR(512),
    failed_login_attempts   INTEGER NOT NULL DEFAULT 0,
    locked_until            TIMESTAMPTZ,
    last_login_at           TIMESTAMPTZ,
    -- TOTP 2FA
    totp_secret             VARCHAR(512),
    totp_enabled            BOOLEAN NOT NULL DEFAULT false,
    totp_verified_at        TIMESTAMPTZ,
    -- Backup codes for TOTP recovery
    backup_codes            JSONB DEFAULT NULL,
    backup_codes_generated_at TIMESTAMPTZ DEFAULT NULL,
    -- Timestamps
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_is_active ON users(is_active);
CREATE INDEX idx_users_totp_enabled ON users(totp_enabled);
CREATE INDEX idx_users_backup_codes ON users USING GIN (backup_codes) WHERE backup_codes IS NOT NULL;

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

COMMENT ON COLUMN users.backup_codes IS 'JSONB array of backup code objects: [{hash: string, used: bool}]';

-- ============================================================================
-- Sessions (JWT refresh tokens)
-- ============================================================================
CREATE TABLE sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash  VARCHAR(255) NOT NULL UNIQUE,
    user_agent          VARCHAR(512),
    ip_address          INET,
    expires_at          TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sessions_refresh_token ON sessions(refresh_token_hash);

COMMENT ON TABLE sessions IS 'JWT refresh token sessions for authentication';

-- ============================================================================
-- API Keys
-- ============================================================================
CREATE TABLE api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    key_prefix      VARCHAR(8) NOT NULL,
    key_hash        VARCHAR(255) NOT NULL UNIQUE,
    last_used_at    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);

-- ============================================================================
-- Audit Log
-- ============================================================================
CREATE TABLE audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    action          VARCHAR(100) NOT NULL,
    resource_type   VARCHAR(100),
    resource_id     VARCHAR(255),
    details         JSONB DEFAULT '{}',
    ip_address      INET,
    user_agent      VARCHAR(512),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX idx_audit_log_action ON audit_log(action);
CREATE INDEX idx_audit_log_resource ON audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
CREATE INDEX idx_audit_log_user_created ON audit_log(user_id, created_at DESC);

-- ============================================================================
-- Roles (RBAC)
-- ============================================================================
CREATE TABLE roles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(100) NOT NULL UNIQUE,
    display_name    VARCHAR(255) NOT NULL,
    description     TEXT,
    permissions     TEXT[] NOT NULL DEFAULT '{}',
    is_system       BOOLEAN NOT NULL DEFAULT false,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    priority        INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_roles_name ON roles(name);
CREATE INDEX idx_roles_is_active ON roles(is_active);
CREATE INDEX idx_roles_is_system ON roles(is_system);

CREATE TRIGGER update_roles_updated_at
    BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Add FK from users.role_id -> roles.id
ALTER TABLE users ADD CONSTRAINT fk_users_role_id
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE SET NULL;
CREATE INDEX idx_users_role_id ON users(role_id);

-- Insert default system roles
INSERT INTO roles (name, display_name, description, permissions, is_system, priority) VALUES
(
    'admin', 'Administrator', 'Full access to all resources and operations',
    ARRAY[
        'container:view', 'container:create', 'container:start', 'container:stop',
        'container:restart', 'container:remove', 'container:exec', 'container:logs',
        'image:view', 'image:pull', 'image:remove', 'image:build',
        'volume:view', 'volume:create', 'volume:remove',
        'network:view', 'network:create', 'network:remove',
        'stack:view', 'stack:deploy', 'stack:update', 'stack:remove',
        'host:view', 'host:create', 'host:update', 'host:remove',
        'user:view', 'user:create', 'user:update', 'user:remove',
        'role:view', 'role:create', 'role:update', 'role:remove',
        'settings:view', 'settings:update',
        'backup:create', 'backup:restore', 'backup:view',
        'security:scan', 'security:view',
        'config:view', 'config:create', 'config:update', 'config:remove',
        'audit:view'
    ],
    true, 100
),
(
    'operator', 'Operator', 'Can manage containers, images, volumes, networks, and stacks',
    ARRAY[
        'container:view', 'container:create', 'container:start', 'container:stop',
        'container:restart', 'container:remove', 'container:exec', 'container:logs',
        'image:view', 'image:pull', 'image:remove',
        'volume:view', 'volume:create', 'volume:remove',
        'network:view', 'network:create', 'network:remove',
        'stack:view', 'stack:deploy', 'stack:update', 'stack:remove',
        'host:view',
        'backup:create', 'backup:view',
        'security:scan', 'security:view',
        'config:view', 'config:create', 'config:update', 'config:remove'
    ],
    true, 50
),
(
    'viewer', 'Viewer', 'Read-only access to all resources',
    ARRAY[
        'container:view', 'container:logs',
        'image:view', 'volume:view', 'network:view', 'stack:view',
        'host:view', 'backup:view', 'security:view', 'config:view'
    ],
    true, 10
);

-- Link existing users to their role
UPDATE users u SET role_id = r.id FROM roles r WHERE u.role = r.name;

-- ============================================================================
-- Password Reset Tokens
-- ============================================================================
CREATE TABLE password_reset_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      VARCHAR(255) NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ DEFAULT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address      INET,
    user_agent      VARCHAR(512)
);

CREATE INDEX idx_password_reset_token_hash ON password_reset_tokens(token_hash);
CREATE INDEX idx_password_reset_user_id ON password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_expires_at ON password_reset_tokens(expires_at);
