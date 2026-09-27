CREATE TABLE IF NOT EXISTS scans (
    id          BIGSERIAL PRIMARY KEY,
    domain      TEXT        NOT NULL,
    status      TEXT        NOT NULL DEFAULT 'queued'
                CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    stage       TEXT,
    error       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS scans_domain_idx ON scans (domain);
CREATE INDEX IF NOT EXISTS scans_created_at_idx ON scans (created_at DESC);

CREATE TABLE IF NOT EXISTS subdomains (
    id      BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    host    TEXT   NOT NULL,
    sources TEXT[] NOT NULL DEFAULT '{}',
    UNIQUE (scan_id, host)
);

CREATE TABLE IF NOT EXISTS dns_records (
    id          BIGSERIAL PRIMARY KEY,
    scan_id     BIGINT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    host        TEXT   NOT NULL,
    record_type TEXT   NOT NULL,
    value       TEXT   NOT NULL
);
CREATE INDEX IF NOT EXISTS dns_records_scan_idx ON dns_records (scan_id, host);

CREATE TABLE IF NOT EXISTS tls_certificates (
    id                 BIGSERIAL PRIMARY KEY,
    scan_id            BIGINT  NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    host               TEXT    NOT NULL,
    ip                 TEXT    NOT NULL,
    port               INTEGER NOT NULL,
    tls_version        TEXT,
    cipher             TEXT,
    subject_cn         TEXT,
    subject_org        TEXT[]  NOT NULL DEFAULT '{}',
    sans               TEXT[]  NOT NULL DEFAULT '{}',
    issuer_cn          TEXT,
    issuer_org         TEXT[]  NOT NULL DEFAULT '{}',
    serial             TEXT,
    not_before         TIMESTAMPTZ,
    not_after          TIMESTAMPTZ,
    expired            BOOLEAN NOT NULL DEFAULT false,
    self_signed        BOOLEAN NOT NULL DEFAULT false,
    mismatched         BOOLEAN NOT NULL DEFAULT false,
    wildcard           BOOLEAN NOT NULL DEFAULT false,
    fingerprint_sha256 TEXT
);
CREATE INDEX IF NOT EXISTS tls_certificates_scan_idx ON tls_certificates (scan_id, host);
