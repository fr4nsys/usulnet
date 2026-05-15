-- 046_calendar: operations calendar of events, maintenance windows,
-- and scheduled jobs.
-- Part of the usulnet calendar module — ported from v26.2.7 044_calendar.
-- Renumbered to 046 to slot above v26.5.0's 044 (recon_module) and 045
-- (recon_retention).
--
-- Only manually-entered events live here. Backup runs, scheduled jobs,
-- crontab entries, and alert windows are surfaced read-only by the
-- aggregator at /api/v1/calendar/events; persisting them here would
-- duplicate state. The `source` column is therefore always 'manual'
-- in this table — it is kept explicit so the schema documents the
-- event-source contract and so future event-source plugins can
-- write their own rows if that ever becomes necessary.

CREATE TABLE calendar_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id     UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    source      VARCHAR(32) NOT NULL DEFAULT 'manual',
    kind        VARCHAR(32) NOT NULL,
    title       VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    location    VARCHAR(255) NOT NULL DEFAULT '',
    url         TEXT NOT NULL DEFAULT '',
    starts_at   TIMESTAMPTZ NOT NULL,
    ends_at     TIMESTAMPTZ NOT NULL,
    all_day     BOOLEAN NOT NULL DEFAULT false,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT calendar_events_kind_check CHECK (
        kind IN ('maintenance','backup','deploy','job','alert','note')
    ),
    CONSTRAINT calendar_events_range_check CHECK (ends_at >= starts_at)
);

-- Range index drives the /events?from=...&to=... query: events overlap
-- the window when starts_at < to AND ends_at > from. A composite index
-- on (starts_at, ends_at) lets PostgreSQL use one ordered scan for both
-- bounds; per-host filtering adds host_id last so multi-host installs
-- still index-scan first then filter.
CREATE INDEX idx_calendar_events_range ON calendar_events (starts_at, ends_at);
CREATE INDEX idx_calendar_events_host  ON calendar_events (host_id);
CREATE INDEX idx_calendar_events_kind  ON calendar_events (kind);

CREATE TRIGGER calendar_events_updated_at
    BEFORE UPDATE ON calendar_events
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
