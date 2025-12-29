// src/services/graphService.ts
// Maltego-style Graph Intelligence Service
// Real data fetching for entities with relationship mapping

import { cacheAPIResponse, getCachedData } from '@/lib/database';

/* ============================================================================
   TYPES - MALTEGO-STYLE ENTITIES
============================================================================ */

export type EntityType = 
  | 'domain'
  | 'ip'
  | 'email'
  | 'person'
  | 'organization'
  | 'phone'
  | 'url'
  | 'hash'
  | 'malware'
  | 'vulnerability'
  | 'certificate'
  | 'netblock'
  | 'asn'
  | 'geolocation'
  | 'social_profile'
  | 'breach'
  | 'paste';

export type TransformType =
  | 'dns_resolve'
  | 'whois'
  | 'subdomain_enum'
  | 'reverse_ip'
  | 'ssl_cert'
  | 'breach_check'
  | 'social_search'
  | 'threat_intel'
  | 'geolocation'
  | 'port_scan'
  | 'related_domains'
  | 'email_enum'
  | 'paste_search';

export interface GraphNode {
  id: string;
  type: EntityType;
  label: string;
  value:  string;
  properties: Record<string, any>;
  position: { x: number; y:  number };
  color?:  string;
  icon?: string;
  size?: number;
  metadata?: {
    threatScore?: number;
    riskLevel?: 'low' | 'medium' | 'high' | 'critical';
    lastUpdated?: string;
    source?: string;
    confidence?: number;
  };
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  type: TransformType;
  weight?: number;
  color?: string;
  metadata?: Record<string, any>;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface Transform {
  id: TransformType;
  name: string;
  description: string;
  supportedTypes: EntityType[];
  icon: string;
}

/* ============================================================================
   ENTITY COLORS & ICONS (MALTEGO STYLE)
============================================================================ */

export const ENTITY_CONFIG:  Record<EntityType, { color:  string; icon: string }> = {
  domain: { color:  '#3b82f6', icon: '🌐' },
  ip: { color: '#10b981', icon: '📡' },
  email: { color: '#f59e0b', icon: '📧' },
  person: { color: '#8b5cf6', icon: '👤' },
  organization: { color: '#ec4899', icon: '🏢' },
  phone: { color: '#06b6d4', icon: '📞' },
  url:  { color: '#6366f1', icon: '🔗' },
  hash: { color: '#f97316', icon: '🔐' },
  malware: { color: '#ef4444', icon: '🦠' },
  vulnerability: { color: '#dc2626', icon: '⚠️' },
  certificate: { color: '#059669', icon: '📜' },
  netblock: { color: '#0891b2', icon: '🌐' },
  asn:  { color: '#7c3aed', icon: '🏗️' },
  geolocation: { color: '#14b8a6', icon: '📍' },
  social_profile: { color: '#d946ef', icon: '👥' },
  breach: { color: '#b91c1c', icon: '💥' },
  paste: { color: '#ea580c', icon: '📄' },
};

/* ============================================================================
   AVAILABLE TRANSFORMS (MALTEGO OPERATIONS)
============================================================================ */

export const AVAILABLE_TRANSFORMS: Transform[] = [
  {
    id: 'dns_resolve',
    name: 'DNS Resolve',
    description: 'Resolve domain to IP addresses',
    supportedTypes: ['domain'],
    icon:  '🔍',
  },
  {
    id: 'whois',
    name:  'WHOIS Lookup',
    description: 'Get domain registration info',
    supportedTypes:  ['domain', 'ip'],
    icon: '📋',
  },
  {
    id: 'subdomain_enum',
    name: 'Find Subdomains',
    description: 'Enumerate subdomains',
    supportedTypes: ['domain'],
    icon: '🌳',
  },
  {
    id: 'reverse_ip',
    name: 'Reverse IP Lookup',
    description: 'Find domains on same IP',
    supportedTypes:  ['ip'],
    icon: '🔄',
  },
  {
    id: 'ssl_cert',
    name: 'SSL Certificate',
    description: 'Get SSL certificate info',
    supportedTypes: ['domain'],
    icon: '🔒',
  },
  {
    id: 'breach_check',
    name: 'Breach Check',
    description: 'Check for data breaches',
    supportedTypes: ['email', 'domain'],
    icon: '💥',
  },
  {
    id: 'social_search',
    name: 'Social Media Search',
    description: 'Find social profiles',
    supportedTypes: ['email', 'person'],
    icon: '👥',
  },
  {
    id: 'threat_intel',
    name: 'Threat Intelligence',
    description:  'Check threat databases',
    supportedTypes: ['domain', 'ip', 'hash', 'url'],
    icon: '🛡️',
  },
  {
    id: 'geolocation',
    name: 'Geolocation',
    description: 'Get geographic location',
    supportedTypes:  ['ip'],
    icon: '📍',
  },
  {
    id: 'port_scan',
    name: 'Port Scan',
    description: 'Scan open ports',
    supportedTypes:  ['ip'],
    icon: '🔌',
  },
  {
    id: 'related_domains',
    name: 'Related Domains',
    description: 'Find related domains',
    supportedTypes: ['domain'],
    icon: '🔗',
  },
  {
    id: 'email_enum',
    name: 'Email Enumeration',
    description: 'Find emails for domain',
    supportedTypes:  ['domain', 'organization'],
    icon: '📧',
  },
  {
    id: 'paste_search',
    name: 'Paste Search',
    description: 'Search in pastes/leaks',
    supportedTypes:  ['email', 'domain'],
    icon: '📄',
  },
];

/* ============================================================================
   TRANSFORM EXECUTION - DNS RESOLVE
============================================================================ */

async function transformDnsResolve(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform: dns: ${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];

  try {
    const response = await fetch(`https://dns.google/resolve?name=${node.value}&type=A`);
    if (!response.ok) return [];

    const data = await response. json();

    if (data.Answer) {
      data.Answer.forEach((record: any, idx: number) => {
        if (record.type === 1) { // A record
          newNodes. push({
            id: `ip-${record.data}-${idx}`,
            type: 'ip',
            label:  record.data,
            value: record.data,
            properties: {
              ttl: record.TTL,
              recordType: 'A',
            },
            position: {
              x: node.position.x + 200 + (idx * 50),
              y: node.position.y + (idx * 100),
            },
            color:  ENTITY_CONFIG. ip.color,
            icon: ENTITY_CONFIG.ip.icon,
          });
        }
      });
    }

    await cacheAPIResponse(cacheKey, newNodes, 60);
    return newNodes;
  } catch (error) {
    console.error('DNS resolve error:', error);
    return [];
  }
}

/* ============================================================================
   TRANSFORM EXECUTION - WHOIS
============================================================================ */

async function transformWhois(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:whois:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];

  try {
    const response = await fetch(`https://who.is/whois/${node.value}`);
    if (!response.ok) return [];

    const html = await response.text();

    // Extract organization
    const orgMatch = html.match(/Registrant Organization:\s*([^\n<]+)/i);
    if (orgMatch) {
      newNodes.push({
        id: `org-${orgMatch[1]}`,
        type: 'organization',
        label: orgMatch[1]. trim(),
        value: orgMatch[1].trim(),
        properties: {
          source: 'whois',
          domain: node.value,
        },
        position: {
          x: node.position.x + 200,
          y: node. position.y - 100,
        },
        color:  ENTITY_CONFIG.organization.color,
        icon: ENTITY_CONFIG.organization.icon,
      });
    }

    // Extract registrant email
    const emailMatch = html.match(/Registrant Email:\s*([^\n<]+)/i);
    if (emailMatch) {
      newNodes.push({
        id: `email-${emailMatch[1]}`,
        type: 'email',
        label: emailMatch[1].trim(),
        value: emailMatch[1].trim(),
        properties: {
          source: 'whois',
          domain: node.value,
        },
        position: {
          x: node.position.x + 200,
          y: node.position.y + 100,
        },
        color:  ENTITY_CONFIG.email.color,
        icon: ENTITY_CONFIG.email.icon,
      });
    }

    await cacheAPIResponse(cacheKey, newNodes, 120);
    return newNodes;
  } catch (error) {
    console.error('WHOIS error:', error);
    return [];
  }
}

/* ============================================================================
   TRANSFORM EXECUTION - SUBDOMAIN ENUMERATION
============================================================================ */

async function transformSubdomainEnum(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:subdomains:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];

  try {
    const response = await fetch(`https://crt.sh/?q=%. ${node.value}&output=json`);
    if (!response.ok) return [];

    const data = await response.json();
    const subdomains = new Set<string>();

    data.forEach((cert: any) => {
      const names = cert.name_value.split('\n');
      names.forEach((name: string) => {
        if (name.endsWith(node.value) && name !== node.value) {
          subdomains.add(name);
        }
      });
    });

    Array.from(subdomains).slice(0, 20).forEach((subdomain, idx) => {
      newNodes.push({
        id: `domain-${subdomain}`,
        type: 'domain',
        label: subdomain,
        value: subdomain,
        properties: {
          parent: node.value,
          source: 'crt.sh',
        },
        position: {
          x: node.position.x + 300,
          y: node.position. y - 200 + (idx * 50),
        },
        color: ENTITY_CONFIG.domain.color,
        icon: ENTITY_CONFIG.domain.icon,
        size: 40,
      });
    });

    await cacheAPIResponse(cacheKey, newNodes, 120);
    return newNodes;
  } catch (error) {
    console.error('Subdomain enum error:', error);
    return [];
  }
}

/* ============================================================================
   TRANSFORM EXECUTION - GEOLOCATION
============================================================================ */

async function transformGeolocation(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:geo:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];

  try {
    const response = await fetch(`http://ip-api.com/json/${node.value}?fields=status,country,city,lat,lon,isp,as`);
    if (!response.ok) return [];

    const data = await response.json();

    if (data.status === 'success') {
      // Location node
      newNodes.push({
        id: `geo-${node.value}`,
        type: 'geolocation',
        label: `${data.city}, ${data.country}`,
        value: `${data.lat},${data.lon}`,
        properties: {
          country: data.country,
          city: data.city,
          latitude: data.lat,
          longitude: data.lon,
          isp: data.isp,
          asn: data.as,
        },
        position: {
          x: node.position.x + 200,
          y: node.position.y,
        },
        color:  ENTITY_CONFIG.geolocation. color,
        icon: ENTITY_CONFIG.geolocation.icon,
      });

      // Organization/ISP node
      if (data.isp) {
        newNodes.push({
          id: `org-${data.isp}`,
          type: 'organization',
          label: data. isp,
          value: data.isp,
          properties: {
            asn: data.as,
            type: 'ISP',
          },
          position: {
            x: node. position.x + 200,
            y: node.position.y + 150,
          },
          color:  ENTITY_CONFIG.organization.color,
          icon: ENTITY_CONFIG.organization.icon,
        });
      }
    }

    await cacheAPIResponse(cacheKey, newNodes, 60);
    return newNodes;
  } catch (error) {
    console.error('Geolocation error:', error);
    return [];
  }
}

/* ============================================================================
   TRANSFORM EXECUTION - BREACH CHECK
============================================================================ */

async function transformBreachCheck(node:  GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:breach:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];

  try {
    const response = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(node.value)}`, {
      headers: {
        'User-Agent': 'OSINT-Platform',
      },
    });

    if (response.ok) {
      const breaches = await response.json();

      breaches.slice(0, 10).forEach((breach: any, idx: number) => {
        newNodes.push({
          id: `breach-${breach.Name}`,
          type: 'breach',
          label: breach. Title,
          value: breach.Name,
          properties: {
            domain: breach.Domain,
            breachDate: breach.BreachDate,
            pwnCount: breach.PwnCount,
            dataClasses: breach.DataClasses,
            description: breach.Description,
          },
          position: {
            x: node.position.x + 250,
            y: node.position.y - 150 + (idx * 60),
          },
          color:  ENTITY_CONFIG.breach.color,
          icon: ENTITY_CONFIG.breach.icon,
          metadata: {
            riskLevel: 'high',
            threatScore:  85,
          },
        });
      });
    }

    await cacheAPIResponse(cacheKey, newNodes, 300);
    return newNodes;
  } catch (error) {
    console.error('Breach check error:', error);
    return [];
  }
}

/* ============================================================================
   TRANSFORM EXECUTION - SSL CERTIFICATE
============================================================================ */

async function transformSslCert(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:ssl:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];

  try {
    const response = await fetch(`https://crt.sh/?q=${node.value}&output=json`);
    if (!response.ok) return [];

    const certs = await response.json();

    if (certs.length > 0) {
      const cert = certs[0];

      newNodes.push({
        id: `cert-${cert.id}`,
        type: 'certificate',
        label: `SSL Certificate`,
        value: cert.id. toString(),
        properties: {
          issuer: cert.issuer_name,
          commonName: cert.common_name,
          notBefore: cert.not_before,
          notAfter: cert. not_after,
          serialNumber: cert.serial_number,
        },
        position: {
          x: node.position.x + 200,
          y: node.position.y - 100,
        },
        color: ENTITY_CONFIG.certificate.color,
        icon: ENTITY_CONFIG.certificate.icon,
      });

      // Issuer organization
      if (cert.issuer_name) {
        newNodes.push({
          id: `org-${cert.issuer_name}`,
          type: 'organization',
          label: cert.issuer_name,
          value:  cert.issuer_name,
          properties: {
            type: 'Certificate Authority',
          },
          position:  {
            x: node.position.x + 400,
            y: node.position.y - 100,
          },
          color:  ENTITY_CONFIG.organization.color,
          icon: ENTITY_CONFIG.organization.icon,
        });
      }
    }

    await cacheAPIResponse(cacheKey, newNodes, 120);
    return newNodes;
  } catch (error) {
    console.error('SSL cert error:', error);
    return [];
  }
}

/* ============================================================================
   TRANSFORM EXECUTION - PORT SCAN
============================================================================ */

async function transformPortScan(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:ports:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];

  try {
    // Using Shodan InternetDB (free, no API key)
    const response = await fetch(`https://internetdb.shodan.io/${node.value}`);
    if (!response.ok) return [];

    const data = await response.json();

    if (data.ports && data.ports.length > 0) {
      data.ports.slice(0, 10).forEach((port: number, idx: number) => {
        newNodes.push({
          id: `port-${node.value}-${port}`,
          type: 'netblock',
          label: `Port ${port}`,
          value: port.toString(),
          properties: {
            ip: node.value,
            port,
            service: getServiceName(port),
          },
          position: {
            x: node.position.x + 200,
            y: node. position.y - 100 + (idx * 40),
          },
          color:  ENTITY_CONFIG.netblock.color,
          icon: '🔌',
          size: 35,
        });
      });
    }

    await cacheAPIResponse(cacheKey, newNodes, 60);
    return newNodes;
  } catch (error) {
    console.error('Port scan error:', error);
    return [];
  }
}

function getServiceName(port: number): string {
  const services:  Record<number, string> = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    8080: 'HTTP-Alt',
  };
  return services[port] || 'Unknown';
}

/* ============================================================================
   TRANSFORM EXECUTION - PASTE SEARCH
============================================================================ */

async function transformPasteSearch(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:paste:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];

  try {
    const response = await fetch(`https://psbdmp.ws/api/search/${encodeURIComponent(node.value)}`);
    if (!response.ok) return [];

    const data = await response.json();

    if (data.data && Array.isArray(data.data)) {
      data.data.slice(0, 10).forEach((paste: any, idx: number) => {
        newNodes.push({
          id: `paste-${paste.id}`,
          type: 'paste',
          label: `Paste:  ${paste.id}`,
          value: paste.id,
          properties: {
            text: paste.text,
            time: paste.time,
            source: 'pastebin',
          },
          position: {
            x: node.position.x + 250,
            y: node.position.y - 150 + (idx * 50),
          },
          color:  ENTITY_CONFIG.paste.color,
          icon: ENTITY_CONFIG.paste.icon,
          metadata: {
            riskLevel: 'medium',
          },
        });
      });
    }

    await cacheAPIResponse(cacheKey, newNodes, 60);
    return newNodes;
  } catch (error) {
    console.error('Paste search error:', error);
    return [];
  }
}

/* ============================================================================
   MAIN TRANSFORM EXECUTOR
============================================================================ */

export async function executeTransform(
  transformId: TransformType,
  node: GraphNode
): Promise<{ nodes: GraphNode[]; edges: GraphEdge[] }> {
  let newNodes: GraphNode[] = [];

  switch (transformId) {
    case 'dns_resolve':
      newNodes = await transformDnsResolve(node);
      break;
    case 'whois':
      newNodes = await transformWhois(node);
      break;
    case 'subdomain_enum': 
      newNodes = await transformSubdomainEnum(node);
      break;
    case 'geolocation':
      newNodes = await transformGeolocation(node);
      break;
    case 'breach_check':
      newNodes = await transformBreachCheck(node);
      break;
    case 'ssl_cert':
      newNodes = await transformSslCert(node);
      break;
    case 'port_scan':
      newNodes = await transformPortScan(node);
      break;
    case 'paste_search':
      newNodes = await transformPasteSearch(node);
      break;
    default:
      return { nodes: [], edges: [] };
  }

  // Create edges from source node to new nodes
  const newEdges: GraphEdge[] = newNodes.map(newNode => ({
    id: `edge-${node.id}-${newNode.id}`,
    source: node.id,
    target: newNode.id,
    label:  AVAILABLE_TRANSFORMS. find(t => t.id === transformId)?.name || transformId,
    type: transformId,
    color: '#64748b',
    weight: 1,
  }));

  return { nodes:  newNodes, edges: newEdges };
}

/* ============================================================================
   CREATE NEW ENTITY
============================================================================ */

export function createEntity(
  type: EntityType,
  value: string,
  position: { x: number; y: number }
): GraphNode {
  return {
    id: `${type}-${value}-${Date.now()}`,
    type,
    label: value,
    value,
    properties: {},
    position,
    color:  ENTITY_CONFIG[type].color,
    icon: ENTITY_CONFIG[type].icon,
    size: 50,
  };
}
