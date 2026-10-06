-- Saved, schedulable scan configurations. A config groups one or more target
-- domains, a schedule, and which stages to run; the scheduler fans each run
-- out to one scan per domain.
CREATE TABLE IF NOT EXISTS scan_configs (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT        NOT NULL,
    domains      TEXT[]      NOT NULL DEFAULT '{}',
    frequency    TEXT        NOT NULL DEFAULT 'manual'
                 CHECK (frequency IN ('manual', 'daily', 'weekly', 'monthly')),
    time_of_day  TEXT        NOT NULL DEFAULT '00:00',  -- HH:MM in `timezone`
    weekday      INTEGER,                               -- 0=Sun..6=Sat (weekly)
    day_of_month INTEGER,                               -- 1..31 (monthly)
    timezone     TEXT        NOT NULL DEFAULT 'UTC',    -- IANA name
    skip_ipdr    BOOLEAN     NOT NULL DEFAULT false,
    skip_ports   BOOLEAN     NOT NULL DEFAULT false,
    skip_certs   BOOLEAN     NOT NULL DEFAULT false,
    port_type    TEXT        NOT NULL DEFAULT '',       -- '', 'syn', 'connect'
    port_spec    TEXT        NOT NULL DEFAULT '',       -- '', '-', '1-1000', ...
    port_rate    INTEGER     NOT NULL DEFAULT 0,
    enabled      BOOLEAN     NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_run_at  TIMESTAMPTZ,
    next_run_at  TIMESTAMPTZ                            -- NULL = not scheduled
);
CREATE INDEX IF NOT EXISTS scan_configs_due_idx
    ON scan_configs (next_run_at) WHERE enabled AND next_run_at IS NOT NULL;

-- Link a scan back to the config that spawned it (NULL for ad-hoc quick scans).
ALTER TABLE scans ADD COLUMN IF NOT EXISTS config_id BIGINT
    REFERENCES scan_configs (id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS scans_config_idx ON scans (config_id);
