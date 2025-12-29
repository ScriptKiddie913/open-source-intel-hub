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
  value: string;
  properties:  Record<string, any>;
  position: { x: number; y: number };
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
  weight?:  number;
  color?: string;
  metadata?: Record<string, any>;
}

export interface GraphData {
  nodes:  GraphNode[];
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

export const ENTITY_CONFIG:  Record<EntityType, { color: string; icon: string }> = {
  domain: { color: '#3b82f6', icon: '🌐' },
  ip: { color: '#10b981', icon: '📡' },
  email: { color: '#f59e0b', icon: '📧' },
  person:  { color: '#8b5cf6', icon: '👤' },
  organization:  { color: '#ec4899', icon: '🏢' },
  phone: { color: '#06b6d4', icon: '📞' },
  url:  { color: '#6366f1', icon: '🔗' },
  hash: { color: '#f97316', icon: '🔐' },
  malware: { color: '#ef4444', icon: '🦠' },
  vulnerability: { color: '#dc2626', icon: '⚠️' },
  certificate: { color: '#059669', icon: '📜' },
  netblock:  { color: '#0891b2', icon: '🌐' },
  asn:  { color: '#7c3aed', icon: '🏗️' },
  geolocation: { color: '#14b8a6', icon: '📍' },
  social_profile: { color: '#d946ef', icon: '👥' },
  breach: { color: '#b91c1c', icon: '💥' },
  paste: { color: '#ea580c', icon: '📄' },
};

/* ============================================================================
   AVAILABLE TRANSFORMS - MAPPED TO ENTITY TYPES
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
    description: 'Get registration info',
    supportedTypes: ['domain', 'ip'],
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
    name:  'SSL Certificate',
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
    id: 'geolocation',
    name: 'Geolocation',
    description: 'Get geographic location',
    supportedTypes:  ['ip'],
    icon: '📍',
  },
  {
    id: 'port_scan',
    name: 'Port Scan',
    description:  'Scan open ports',
    supportedTypes:  ['ip'],
    icon: '🔌',
  },
  {
    id: 'threat_intel',
    name: 'Threat Intelligence',
    description: 'Check threat databases',
    supportedTypes: ['domain', 'ip', 'hash', 'url'],
    icon: '🛡️',
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
   TRANSFORM EXECUTION - DNS RESOLVE (FOR DOMAINS)
============================================================================ */

async function transformDnsResolve(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:dns:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];

  try {
    const response = await fetch(`https://dns.google/resolve?name=${node.value}&type=A`);
    if (!response.ok) throw new Error('DNS lookup failed');

    const data = await response.json();

    if (data.Answer) {
      data.Answer.forEach((record: any, idx: number) => {
        if (record.type === 1) {
          newNodes.push({
            id: `ip-${record.data}-${Date.now()}-${idx}`,
            type: 'ip',
            label: record.data,
            value: record.data,
            properties: {
              ttl: record.TTL,
              recordType: 'A',
              domain: node.value,
            },
            position: {
              x: node.position.x + 250,
              y: node. position.y + (idx * 80) - 40,
            },
            color:  ENTITY_CONFIG.ip.color,
            icon: ENTITY_CONFIG.ip.icon,
            size: 50,
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
   TRANSFORM EXECUTION - WHOIS (FOR DOMAINS & IPs)
============================================================================ */

async function transformWhois(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:whois:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];

  try {
    // Using RDAP for structured data
    const apiUrl = node.type === 'ip' 
      ? `https://rdap.arin.net/registry/ip/${node.value}`
      : `https://rdap.verisign. com/com/v1/domain/${node.value}`;

    const response = await fetch(apiUrl);
    if (!response.ok) throw new Error('WHOIS lookup failed');

    const data = await response.json();

    // Extract organization
    if (data.entities) {
      data.entities.slice(0, 2).forEach((entity: any, idx: number) => {
        const orgName = entity.vcardArray?.[1]?.find((v: any) => v[0] === 'fn')?.[3] || 'Unknown Organization';
        
        newNodes.push({
          id: `org-${orgName}-${Date.now()}-${idx}`,
          type: 'organization',
          label:  orgName,
          value: orgName,
          properties: {
            handle: entity.handle,
            roles: entity.roles,
            source: 'whois',
          },
          position: {
            x:  node.position.x + 250,
            y: node.position.y - 100 + (idx * 120),
          },
          color:  ENTITY_CONFIG.organization.color,
          icon: ENTITY_CONFIG.organization.icon,
          size: 50,
        });
      });
    }

    await cacheAPIResponse(cacheKey, newNodes, 300);
    return newNodes;
  } catch (error) {
    console.error('WHOIS error:', error);
    return [];
  }
}

/* ============================================================================
   TRANSFORM EXECUTION - SUBDOMAIN ENUMERATION (FOR DOMAINS)
============================================================================ */

async function transformSubdomainEnum(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:subdomains:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];

  try {
    const response = await fetch(`https://crt.sh/?q=%.${node.value}&output=json`);
    if (!response.ok) throw new Error('Subdomain enum failed');

    const data = await response.json();
    const subdomains = new Set<string>();

    data.forEach((cert: any) => {
      const names = cert.name_value.split('\n');
      names.forEach((name: string) => {
        if (name.endsWith(node.value) && name !== node.value && ! name.includes('*')) {
          subdomains. add(name);
        }
      });
    });

    Array.from(subdomains).slice(0, 15).forEach((subdomain, idx) => {
      newNodes.push({
        id: `domain-${subdomain}-${Date. now()}`,
        type: 'domain',
        label: subdomain,
        value: subdomain,
        properties: {
          parent: node.value,
          source: 'crt.sh',
        },
        position: {
          x: node.position.x + 300,
          y: node.position.y - 350 + (idx * 50),
        },
        color:  ENTITY_CONFIG.domain.color,
        icon: ENTITY_CONFIG.domain.icon,
        size: 45,
      });
    });

    await cacheAPIResponse(cacheKey, newNodes, 300);
    return newNodes;
  } catch (error) {
    console.error('Subdomain enum error:', error);
    return [];
  }
}

/* ============================================================================
   TRANSFORM EXECUTION - GEOLOCATION (FOR IPs)
============================================================================ */

async function transformGeolocation(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:geo:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];

  try {
    const response = await fetch(`http://ip-api.com/json/${node.value}?fields=status,country,city,lat,lon,isp,as,org`);
    if (!response.ok) throw new Error('Geolocation failed');

    const data = await response.json();

    if (data.status === 'success') {
      // Location node
      newNodes.push({
        id: `geo-${node.value}-${Date.now()}`,
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
          x: node.position.x + 250,
          y: node.position.y - 80,
        },
        color:  ENTITY_CONFIG.geolocation.color,
        icon: ENTITY_CONFIG.geolocation. icon,
        size: 50,
      });

      // Organization/ISP node
      if (data.org || data.isp) {
        newNodes.push({
          id: `org-${data.org || data.isp}-${Date. now()}`,
          type: 'organization',
          label: data.org || data.isp,
          value: data.org || data.isp,
          properties: {
            asn: data.as,
            type: 'ISP',
          },
          position: {
            x: node.position.x + 250,
            y: node.position.y + 80,
          },
          color: ENTITY_CONFIG.organization.color,
          icon: ENTITY_CONFIG.organization.icon,
          size: 50,
        });
      }
    }

    await cacheAPIResponse(cacheKey, newNodes, 3600);
    return newNodes;
  } catch (error) {
    console.error('Geolocation error:', error);
    return [];
  }
}

/* ============================================================================
   TRANSFORM EXECUTION - PORT SCAN (FOR IPs)
============================================================================ */

async function transformPortScan(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:ports:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];

  try {
    const response = await fetch(`https://internetdb.shodan.io/${node.value}`);
    if (!response.ok) throw new Error('Port scan failed');

    const data = await response.json();

    if (data.ports && data.ports.length > 0) {
      data.ports. slice(0, 10).forEach((port: number, idx: number) => {
        const serviceName = getServiceName(port);
        
        newNodes.push({
          id: `port-${node.value}-${port}-${Date.now()}`,
          type: 'netblock',
          label: `Port ${port}`,
          value: port.toString(),
          properties: {
            ip: node.value,
            port,
            service: serviceName,
            protocol: 'TCP',
          },
          position: {
            x: node.position.x + 250,
            y: node.position.y - 200 + (idx * 45),
          },
          color:  ENTITY_CONFIG.netblock.color,
          icon: '🔌',
          size: 40,
        });
      });
    }

    await cacheAPIResponse(cacheKey, newNodes, 300);
    return newNodes;
  } catch (error) {
    console.error('Port scan error:', error);
    return [];
  }
}

function getServiceName(port: number): string {
  const services:  Record<number, string> = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5900: 'VNC', 8080: 'HTTP-Alt', 27017: 'MongoDB',
  };
  return services[port] || 'Unknown';
}

/* ============================================================================
   TRANSFORM EXECUTION - SSL CERTIFICATE (FOR DOMAINS)
============================================================================ */

async function transformSslCert(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:ssl:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];

  try {
    const response = await fetch(`https://crt.sh/?q=${node.value}&output=json`);
    if (!response.ok) throw new Error('SSL cert fetch failed');

    const certs = await response.json();

    if (certs.length > 0) {
      const cert = certs[0];

      newNodes.push({
        id: `cert-${cert.id}-${Date.now()}`,
        type: 'certificate',
        label: `SSL Certificate`,
        value: cert.id. toString(),
        properties: {
          issuer: cert.issuer_name,
          commonName: cert.common_name,
          notBefore: cert.not_before,
          notAfter: cert.not_after,
          serialNumber: cert.serial_number,
        },
        position: {
          x: node.position.x + 250,
          y: node.position.y - 100,
        },
        color:  ENTITY_CONFIG.certificate.color,
        icon: ENTITY_CONFIG.certificate.icon,
        size: 50,
      });

      // Issuer organization
      if (cert.issuer_name) {
        newNodes.push({
          id: `org-${cert.issuer_name}-${Date.now()}`,
          type: 'organization',
          label: cert.issuer_name. split(',')[0].replace('CN=', '').replace('O=', ''),
          value: cert.issuer_name,
          properties: {
            type: 'Certificate Authority',
          },
          position:  {
            x: node.position.x + 500,
            y: node.position.y - 100,
          },
          color: ENTITY_CONFIG.organization.color,
          icon: ENTITY_CONFIG.organization.icon,
          size: 50,
        });
      }
    }

    await cacheAPIResponse(cacheKey, newNodes, 3600);
    return newNodes;
  } catch (error) {
    console.error('SSL cert error:', error);
    return [];
  }
}

/* ============================================================================
   TRANSFORM EXECUTION - BREACH CHECK (FOR EMAILS)
============================================================================ */

async function transformBreachCheck(node:  GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:breach:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];

  try {
    const response = await fetch(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(node.value)}?truncateResponse=false`,
      { headers: { 'User-Agent': 'OSINT-Platform' } }
    );

    if (response.ok) {
      const breaches = await response.json();

      breaches.slice(0, 8).forEach((breach: any, idx: number) => {
        newNodes.push({
          id: `breach-${breach.Name}-${Date.now()}`,
          type: 'breach',
          label: breach.Title,
          value: breach.Name,
          properties: {
            domain: breach.Domain,
            breachDate: breach.BreachDate,
            pwnCount: breach.PwnCount,
            dataClasses: breach.DataClasses,
          },
          position: {
            x: node.position.x + 300,
            y: node.position.y - 200 + (idx * 60),
          },
          color:  ENTITY_CONFIG.breach.color,
          icon: ENTITY_CONFIG.breach.icon,
          size: 45,
          metadata: {
            riskLevel: 'high',
            threatScore: 80,
          },
        });
      });
    }

    await cacheAPIResponse(cacheKey, newNodes, 3600);
    return newNodes;
  } catch (error) {
    console.error('Breach check error:', error);
    return [];
  }
}

/* ============================================================================
   TRANSFORM EXECUTION - REVERSE IP (FOR IPs)
============================================================================ */

async function transformReverseIp(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:reverse_ip:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];

  try {
    // Using ViewDNS reverse IP API
    const response = await fetch(`https://viewdns.info/reverseip/? host=${node.value}&t=1`);
    if (!response.ok) throw new Error('Reverse IP failed');

    const html = await response.text();
    
    // Parse HTML for domains (simple regex extraction)
    const domainMatches = html.matchAll(/<td>([a-z0-9.-]+\.[a-z]{2,})<\/td>/gi);
    const domains = new Set<string>();
    
    for (const match of domainMatches) {
      if (match[1] && ! match[1].includes('viewdns')) {
        domains.add(match[1]);
      }
    }

    Array.from(domains).slice(0, 10).forEach((domain, idx) => {
      newNodes.push({
        id: `domain-${domain}-${Date.now()}`,
        type: 'domain',
        label: domain,
        value: domain,
        properties: {
          sharedIP: node.value,
          source: 'reverse_ip',
        },
        position: {
          x: node.position.x + 300,
          y: node.position.y - 200 + (idx * 50),
        },
        color:  ENTITY_CONFIG.domain.color,
        icon: ENTITY_CONFIG.domain.icon,
        size: 45,
      });
    });

    await cacheAPIResponse(cacheKey, newNodes, 3600);
    return newNodes;
  } catch (error) {
    console.error('Reverse IP error:', error);
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

  try {
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
      case 'port_scan':
        newNodes = await transformPortScan(node);
        break;
      case 'ssl_cert':
        newNodes = await transformSslCert(node);
        break;
      case 'breach_check': 
        newNodes = await transformBreachCheck(node);
        break;
      case 'reverse_ip':  
        newNodes = await transformReverseIp(node);
        break;
      default:  
        throw new Error(`Transform ${transformId} not implemented`);
    }
  } catch (error) {
    console.error(`Transform ${transformId} error:`, error);
    throw error;
  }

  if (newNodes.length === 0) {
    throw new Error('No results found for this transform');
  }

  // Create edges
  const newEdges: GraphEdge[] = newNodes.map(newNode => ({
    id: `edge-${node.id}-${newNode.id}`,
    source: node.id,
    target: newNode. id,
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
