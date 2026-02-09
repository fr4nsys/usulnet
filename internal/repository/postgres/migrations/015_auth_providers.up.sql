-- ============================================================================
-- 015_auth_providers: OAuth/OIDC and LDAP authentication providers
-- ============================================================================

-- ============================================================================
-- OAuth Providers
-- ============================================================================
CREATE TABLE oauth_configs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(100) NOT NULL UNIQUE,
    provider        VARCHAR(50) NOT NULL,
    client_id       VARCHAR(255) NOT NULL,
    client_secret   TEXT NOT NULL,
    auth_url        TEXT,
    token_url       TEXT,
    user_info_url   TEXT,
    scopes          TEXT[] DEFAULT '{}',
    redirect_url    TEXT,
    default_role    VARCHAR(50) DEFAULT 'viewer',
    auto_provision  BOOLEAN DEFAULT true,
    admin_group     VARCHAR(255),
    operator_group  VARCHAR(255),
    user_id_claim   VARCHAR(100) DEFAULT 'sub',
    username_claim  VARCHAR(100) DEFAULT 'preferred_username',
    email_claim     VARCHAR(100) DEFAULT 'email',
    groups_claim    VARCHAR(100) DEFAULT 'groups',
    is_enabled      BOOLEAN DEFAULT false,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_oauth_configs_provider ON oauth_configs(provider);
CREATE INDEX idx_oauth_configs_enabled ON oauth_configs(is_enabled);

CREATE TRIGGER update_oauth_configs_updated_at
    BEFORE UPDATE ON oauth_configs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- LDAP Providers
-- ============================================================================
CREATE TABLE ldap_configs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(100) NOT NULL UNIQUE,
    host            VARCHAR(255) NOT NULL,
    port            INTEGER NOT NULL DEFAULT 389,
    use_tls         BOOLEAN DEFAULT false,
    start_tls       BOOLEAN DEFAULT false,
    skip_tls_verify BOOLEAN DEFAULT false,
    bind_dn         VARCHAR(500) NOT NULL,
    bind_password   TEXT NOT NULL,
    base_dn         VARCHAR(500) NOT NULL,
    user_filter     VARCHAR(500) NOT NULL DEFAULT '(&(objectClass=person)(uid=%s))',
    username_attr   VARCHAR(100) NOT NULL DEFAULT 'uid',
    email_attr      VARCHAR(100) NOT NULL DEFAULT 'mail',
    group_filter    VARCHAR(500),
    group_attr      VARCHAR(100) DEFAULT 'memberOf',
    admin_group     VARCHAR(255),
    operator_group  VARCHAR(255),
    default_role    VARCHAR(50) DEFAULT 'viewer',
    is_enabled      BOOLEAN DEFAULT false,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_ldap_configs_enabled ON ldap_configs(is_enabled);

CREATE TRIGGER update_ldap_configs_updated_at
    BEFORE UPDATE ON ldap_configs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
