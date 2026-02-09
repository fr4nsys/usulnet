-- ============================================================================
-- 013_teams: Teams, members, resource permissions (RBAC scoping)
-- ============================================================================

CREATE TABLE teams (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    description     TEXT,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER update_teams_updated_at
    BEFORE UPDATE ON teams
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- Team Members
-- ============================================================================
CREATE TABLE team_members (
    team_id         UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_in_team    TEXT NOT NULL DEFAULT 'member',
    added_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    added_by        UUID REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (team_id, user_id)
);

CREATE INDEX idx_team_members_user ON team_members(user_id);

-- ============================================================================
-- Resource Permissions
-- ============================================================================
CREATE TABLE resource_permissions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id         UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    resource_type   TEXT NOT NULL,
    resource_id     TEXT NOT NULL,
    access_level    TEXT NOT NULL DEFAULT 'view',
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    granted_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE(team_id, resource_type, resource_id)
);

CREATE INDEX idx_resource_permissions_team ON resource_permissions(team_id);
CREATE INDEX idx_resource_permissions_resource ON resource_permissions(resource_type, resource_id);
