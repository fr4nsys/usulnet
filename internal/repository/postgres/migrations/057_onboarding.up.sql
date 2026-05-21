-- ============================================================================
-- 057_onboarding: system_state key/value table + onboarding_completed flag
--
-- system_state is a single-row-per-key key/value store for instance-wide
-- flags whose lifecycle does not fit neatly into any domain table. The
-- first consumer is the onboarding wizard introduced in v26.5.2 session
-- 04b: when a fresh install boots, the bootstrap admin user is forced
-- through a password-change flow before any other page renders.
--
-- Future entries should follow the same shape (short snake_case key,
-- string value the application parses). Booleans are stored as
-- 'true' / 'false' so SQL-side defaults stay portable.
-- ============================================================================

CREATE TABLE system_state (
    key        VARCHAR(64) PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed the onboarding flag at FALSE. The wizard sets it to TRUE on
-- completion. Existing deployments upgrading to v26.5.2 inherit FALSE
-- too — operators get one onboarding pass on first login regardless of
-- when they originally installed. The bootstrap admin still has the
-- default password 'usulnet' if they never rotated it, so this is a
-- pure win for security; the wizard's first mandatory step is the
-- password change.
INSERT INTO system_state (key, value) VALUES ('onboarding_completed', 'false')
ON CONFLICT (key) DO NOTHING;
