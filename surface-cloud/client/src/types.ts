export type ScanStatus = "queued" | "running" | "paused" | "completed" | "failed";

export interface Counts {
  subdomains: number;
  resolved_hosts: number;
  dns_records: number;
  tls_certs: number;
  ip_addresses: number;
  open_ports: number;
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
  /** Not reported by any source this scan; kept from an earlier scan. */
  carried_over: boolean;
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

export interface OpenPort {
  port: number;
  protocol: string;
}

/** naabu port-scan result for one IPv4 address. */
export interface PortScan {
  ip: string;
  hosts: string[];
  ports: OpenPort[];
}

/** IPDR: the ipinfo.io response for one IP, or the error if the lookup failed. */
export interface IpInfo {
  ip: string;
  data: Record<string, unknown> | null;
  error?: string;
}

export interface ScanDetail extends Scan {
  subdomains: Subdomain[];
  dns_records: DnsRecord[];
  tls_certs: TlsCert[];
  ip_info: IpInfo[];
  port_scans: PortScan[];
}

export interface SetDiff<T> {
  added: T[];
  removed: T[];
}

export interface CertChange {
  before: TlsCert;
  after: TlsCert;
}

export interface FieldChange {
  field: string;
  before: string;
  after: string;
}

export interface IpInfoChange {
  ip: string;
  fields: FieldChange[];
}

/** Changes since the previous completed scan of the same domain. */
export type ScanDiff =
  | { base: null }
  | {
      base: Scan;
      subdomains: SetDiff<Subdomain> & { no_longer_reported: Subdomain[] };
      dns_records: SetDiff<DnsRecord>;
      tls_certs: SetDiff<TlsCert> & { changed: CertChange[] };
      /** compared is false when the base scan predates IP lookups. */
      ip_info: SetDiff<IpInfo> & { compared: boolean; changed: IpInfoChange[] };
    };

export const isActive = (s: Pick<Scan, "status">) =>
  s.status === "queued" || s.status === "running";

export const dnsKey = (r: DnsRecord) => `${r.host}\u0000${r.type}\u0000${r.value}`;
export const certKey = (c: Pick<TlsCert, "host" | "port">) => `${c.host}:${c.port}`;

export type Frequency = "manual" | "daily" | "weekly" | "monthly";

export interface ScanOptions {
  skip_ipdr: boolean;
  skip_ports: boolean;
  skip_certs: boolean;
  port_type: string; // "", "syn", "connect"
  port_spec: string; // "", "-", "1-1000", "80,443"
  port_rate: number;
}

export interface ScanConfig {
  id: number;
  name: string;
  domains: string[];
  frequency: Frequency;
  time_of_day: string; // "HH:MM"
  weekday: number | null; // 0..6 (weekly)
  day_of_month: number | null; // 1..31 (monthly)
  timezone: string; // IANA
  options: ScanOptions;
  enabled: boolean;
  created_at: string;
  updated_at: string;
  last_run_at: string | null;
  next_run_at: string | null;
}

/** The editable subset of a config (what create/update accept). */
export type ScanConfigInput = Omit<
  ScanConfig,
  "id" | "created_at" | "updated_at" | "last_run_at" | "next_run_at"
>;
