// Core OSINT Types

export type ThreatLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type DataSource = 'dns' | 'ip' | 'cert' | 'whois' | 'breach' | 'paste' | 'upload' | 'social';

export interface IntelligenceRecord {
  id: string;
  target: string;
  type: DataSource;
  data: any;
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
  baseline?: any;
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
  data: any;
  previousData?: any;
  timestamp: Date;
  read: boolean;
}

export interface Change {
  field: string;
  previous: any;
  current: any;
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
  data: any;
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
