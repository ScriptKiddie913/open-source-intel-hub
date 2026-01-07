// Core OSINT Types

export type ThreatLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type DataSource = 'dns' | 'ip' | 'cert' | 'whois' | 'breach' | 'paste' | 'upload' | 'social';

// Threat Intelligence Types for Database
export interface ThreatIntelligence {
  id: string;
  title: string;
  description: string;
  source_name: string;
  source_url?: string;
  threat_type: string;
  severity_level: ThreatLevel;
  confidence_level: number;
  indicators: string[];
  ttps: string[];
  first_seen: string;
  last_seen: string;
  tags: string[];
  raw_data?: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface ThreatActor {
  id: string;
  name: string;
  aliases: string[];
  description: string;
  country: string;
  motivations: string[];
  targeted_sectors: string[];
  targeted_countries: string[];
  tools: string[];
  ttps: string[];
  first_seen?: string;
  last_updated: string;
}

export interface IoC {
  id: string;
  type: 'hash' | 'ip' | 'domain' | 'url' | 'email' | 'file';
  value: string;
  source: string;
  threat_type?: string;
  malware_family?: string;
  severity: ThreatLevel;
  confidence: number;
  first_seen: string;
  last_seen: string;
  tags: string[];
}

export interface Campaign {
  id: string;
  name: string;
  description: string;
  actor?: string;
  targets: string[];
  start_date?: string;
  end_date?: string;
  ttps: string[];
  indicators: string[];
  severity: ThreatLevel;
}

export interface Malware {
  id: string;
  name: string;
  family: string;
  type: string;
  description: string;
  hashes: { md5?: string; sha1?: string; sha256?: string };
  capabilities: string[];
  ttps: string[];
  c2_servers: string[];
  first_seen: string;
  last_seen: string;
}

export interface IntelligenceRecord {
  id: string;
  target: string;
  type: DataSource;
  data: Record<string, unknown>;
  threatLevel: ThreatLevel;
  timestamp: Date;
  source: string;
  tags?: string[];
}

export interface DNSRecord {
  type: string;
  name: string;
  data: string;
  ttl?: number;
}

export interface DNSResults {
  domain: string;
  records: DNSRecord[];
  subdomains: string[];
  timestamp: Date;
}

export interface GeoLocation {
  ip: string;
  country: string;
  countryCode: string;
  region: string;
  city: string;
  lat: number;
  lon: number;
  isp: string;
  org: string;
  as: string;
  timezone: string;
}

export interface PortInfo {
  ip: string;
  ports: number[];
  hostnames: string[];
  cpes: string[];
  tags: string[];
  vulns: string[];
}

export interface Certificate {
  id: number;
  issuerCaId: number;
  issuerName: string;
  commonName: string;
  nameValue: string;
  notBefore: string;
  notAfter: string;
  serialNumber: string;
}

export interface WhoisData {
  domainName: string;
  registrar: string;
  createdDate: string;
  updatedDate: string;
  expiresDate: string;
  nameServers: string[];
  status: string[];
  registrantOrg?: string;
  registrantCountry?: string;
}

export interface BreachRecord {
  id: string;
  email: string;
  password?: string;
  source: string;
  date: string;
  dataTypes: string[];
}

export interface Monitor {
  id: string;
  target: string;
  type: 'domain' | 'ip' | 'email' | 'keyword';
  sources: DataSource[];
  interval: number; // in minutes
  lastCheck?: Date;
  nextCheck?: Date;
  status: 'active' | 'paused' | 'error';
  baseline?: Record<string, unknown>;
  alertCount: number;
  createdAt: Date;
}

export interface MonitoringAlert {
  id: string;
  monitorId: string;
  type: 'change' | 'threat' | 'new_data';
  severity: ThreatLevel;
  title: string;
  description: string;
  data: Record<string, unknown>;
  previousData?: Record<string, unknown>;
  timestamp: Date;
  read: boolean;
}

export interface Change {
  field: string;
  previous: unknown;
  current: unknown;
  type: 'added' | 'removed' | 'modified';
}

export interface SearchQuery {
  query: string;
  type: 'domain' | 'ip' | 'email' | 'keyword' | 'url';
  sources: DataSource[];
  dateRange?: { start: Date; end: Date };
}

export interface SearchResult {
  source: DataSource;
  data: Record<string, unknown>;
  threatLevel: ThreatLevel;
  timestamp: Date;
  loading: boolean;
  error?: string;
}

export interface DashboardMetrics {
  totalRecords: number;
  activeMonitors: number;
  alertsToday: number;
  threatScore: number;
  apiStatus: { [key: string]: 'online' | 'offline' | 'rate_limited' };
  recentActivity: ActivityItem[];
}

export interface ActivityItem {
  id: string;
  type: 'search' | 'upload' | 'monitor' | 'alert';
  title: string;
  description: string;
  timestamp: Date;
  icon: string;
}

export interface ImportedDataset {
  id: string;
  name: string;
  type: 'breach' | 'domains' | 'ips' | 'keywords';
  recordCount: number;
  importedAt: Date;
  size: number;
}
