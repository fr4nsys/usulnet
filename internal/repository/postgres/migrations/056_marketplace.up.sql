-- ============================================================================
-- 056_marketplace: curated app templates catalogue with installations + reviews
--
-- Renumbered from v26.2.7 migration 054. The unique constraint on
-- (app_id, user_id) in marketplace_reviews enforces one review per user
-- per app — the application-layer code relies on this rather than
-- racing read-modify-write.
-- ============================================================================

CREATE TABLE marketplace_apps (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug             VARCHAR(128) NOT NULL UNIQUE,
    name             VARCHAR(255) NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    long_description TEXT NOT NULL DEFAULT '',
    icon             VARCHAR(100) NOT NULL DEFAULT 'fa-cube',
    icon_color       VARCHAR(20) NOT NULL DEFAULT '#6c757d',
    icon_svg         TEXT NOT NULL DEFAULT '',                -- inline SVG from the embedded catalogue (data: URIs OK)
    category         VARCHAR(50) NOT NULL DEFAULT 'other',    -- networking, storage, development, monitoring, security, communication, productivity, database, other
    version          VARCHAR(50) NOT NULL DEFAULT '',
    manifest_version INTEGER NOT NULL DEFAULT 1,              -- bump on breaking manifest changes; hydration replaces older rows
    website          VARCHAR(512) NOT NULL DEFAULT '',
    source           VARCHAR(512) NOT NULL DEFAULT '',
    author           VARCHAR(255) NOT NULL DEFAULT '',
    license          VARCHAR(100) NOT NULL DEFAULT '',
    compose_template TEXT NOT NULL,                            -- Go template with {{KEY}} placeholders
    fields           JSONB NOT NULL DEFAULT '[]',              -- [{key, label, description, type, default, required, options, placeholder}]
    tags             TEXT[] NOT NULL DEFAULT '{}',
    min_memory_mb    INTEGER NOT NULL DEFAULT 0,
    min_cpu_cores    DOUBLE PRECISION NOT NULL DEFAULT 0,
    is_official      BOOLEAN NOT NULL DEFAULT false,           -- curated by usulnet team
    is_verified      BOOLEAN NOT NULL DEFAULT false,           -- community verified
    featured         BOOLEAN NOT NULL DEFAULT false,
    built_in         BOOLEAN NOT NULL DEFAULT false,           -- true for rows hydrated from the embedded catalogue; user-submitted rows are false
    install_count    INTEGER NOT NULL DEFAULT 0,
    avg_rating       DOUBLE PRECISION NOT NULL DEFAULT 0,
    rating_count     INTEGER NOT NULL DEFAULT 0,
    created_by       UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_marketplace_apps_category ON marketplace_apps(category);
CREATE INDEX idx_marketplace_apps_featured ON marketplace_apps(featured) WHERE featured = true;
CREATE INDEX idx_marketplace_apps_rating ON marketplace_apps(avg_rating DESC);
CREATE INDEX idx_marketplace_apps_built_in ON marketplace_apps(built_in);

CREATE TABLE marketplace_installations (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id        UUID NOT NULL REFERENCES marketplace_apps(id) ON DELETE CASCADE,
    host_id       UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    stack_id      UUID REFERENCES stacks(id) ON DELETE SET NULL,
    name          VARCHAR(255) NOT NULL,
    status        VARCHAR(20) NOT NULL DEFAULT 'installed',    -- installed, running, stopped, error, uninstalled
    version       VARCHAR(50) NOT NULL DEFAULT '',
    config_values JSONB NOT NULL DEFAULT '{}',                 -- user-provided field values
    notes         TEXT NOT NULL DEFAULT '',
    installed_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    installed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_marketplace_installations_app ON marketplace_installations(app_id);
CREATE INDEX idx_marketplace_installations_host ON marketplace_installations(host_id);
CREATE INDEX idx_marketplace_installations_stack ON marketplace_installations(stack_id);
CREATE INDEX idx_marketplace_installations_status ON marketplace_installations(status);

CREATE TABLE marketplace_reviews (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id     UUID NOT NULL REFERENCES marketplace_apps(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rating     INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
    title      VARCHAR(255) NOT NULL DEFAULT '',
    comment    TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT marketplace_reviews_user_app_unique UNIQUE (user_id, app_id)
);

CREATE INDEX idx_marketplace_reviews_app ON marketplace_reviews(app_id);
CREATE INDEX idx_marketplace_reviews_user ON marketplace_reviews(user_id);
CREATE INDEX idx_marketplace_reviews_rating ON marketplace_reviews(rating);
