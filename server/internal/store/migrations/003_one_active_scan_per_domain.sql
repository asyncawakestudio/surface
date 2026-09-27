-- Migrations run at startup, before any scan can be active, so anything
-- still queued/running is left over from a previous process.
UPDATE scans
SET status = 'failed', error = 'interrupted by server restart', finished_at = now()
WHERE status IN ('queued', 'running');

-- Scans of a domain run one at a time so each diffs against the one before.
CREATE UNIQUE INDEX IF NOT EXISTS scans_one_active_per_domain
    ON scans (domain) WHERE status IN ('queued', 'running');

CREATE INDEX IF NOT EXISTS scans_domain_created_idx ON scans (domain, created_at DESC);
