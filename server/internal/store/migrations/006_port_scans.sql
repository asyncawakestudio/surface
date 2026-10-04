-- naabu port-scan results. One row per scanned IPv4 address (kept even when
-- no ports are open) plus one row per open port.
CREATE TABLE IF NOT EXISTS port_scan_targets (
    id      BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    ip      TEXT   NOT NULL,
    hosts   TEXT[] NOT NULL DEFAULT '{}',
    UNIQUE (scan_id, ip)
);

CREATE TABLE IF NOT EXISTS open_ports (
    id       BIGSERIAL PRIMARY KEY,
    scan_id  BIGINT  NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    ip       TEXT    NOT NULL,
    port     INTEGER NOT NULL,
    protocol TEXT    NOT NULL DEFAULT 'tcp'
);
CREATE INDEX IF NOT EXISTS open_ports_scan_ip_idx ON open_ports (scan_id, ip);
