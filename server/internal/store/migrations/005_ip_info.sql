-- IPDR: ipinfo.io responses for each public IP a scan resolved. The
-- response is stored as-is since its fields depend on the ipinfo plan.
CREATE TABLE IF NOT EXISTS ip_info (
    id      BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    ip      TEXT   NOT NULL,
    data    JSONB,
    error   TEXT,
    UNIQUE (scan_id, ip)
);
