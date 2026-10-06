-- Subdomains are append-only across a domain's scans: hosts that passive
-- sources didn't report this time are carried over from earlier scans.
ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS carried_over BOOLEAN NOT NULL DEFAULT false;
