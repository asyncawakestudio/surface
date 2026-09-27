export type ScanStatus = "queued" | "running" | "paused" | "completed" | "failed";

export interface Counts {
  subdomains: number;
  resolved_hosts: number;
  dns_records: number;
  tls_certs: number;
}

export interface Scan {
  id: number;
  domain: string;
  status: ScanStatus;
  stage: string | null;
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  counts: Counts;
}

export interface Domain {
  domain: string;
  scan_count: number;
  latest: Scan;
}

export interface Subdomain {
  host: string;
  sources: string[];
}

export interface DnsRecord {
  host: string;
  type: string;
  value: string;
}

export interface TlsCert {
  host: string;
  ip: string;
  port: number;
  tls_version: string;
  cipher: string;
  subject_cn: string;
  subject_org: string[];
  sans: string[];
  issuer_cn: string;
  issuer_org: string[];
  serial: string;
  not_before: string;
  not_after: string;
  expired: boolean;
  self_signed: boolean;
  mismatched: boolean;
  wildcard: boolean;
  fingerprint_sha256: string;
}

export interface ScanDetail extends Scan {
  subdomains: Subdomain[];
  dns_records: DnsRecord[];
  tls_certs: TlsCert[];
}

export interface SetDiff<T> {
  added: T[];
  removed: T[];
}

export interface CertChange {
  before: TlsCert;
  after: TlsCert;
}

/** Changes since the previous completed scan of the same domain. */
export type ScanDiff =
  | { base: null }
  | {
      base: Scan;
      subdomains: SetDiff<Subdomain>;
      dns_records: SetDiff<DnsRecord>;
      tls_certs: SetDiff<TlsCert> & { changed: CertChange[] };
    };

export const isActive = (s: Pick<Scan, "status">) =>
  s.status === "queued" || s.status === "running";

export const dnsKey = (r: DnsRecord) => `${r.host}\u0000${r.type}\u0000${r.value}`;
export const certKey = (c: Pick<TlsCert, "host" | "port">) => `${c.host}:${c.port}`;
