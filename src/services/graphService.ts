// src/services/graphService.ts
// Maltego-style Graph Intelligence Service
// Real data fetching for entities with relationship mapping

import { cacheAPIResponse, getCachedData } from '@/lib/database';
import { searchDarkWebSignals } from '@/services/torService';
import { searchTelegramLeaks } from '@/services/telegramService';

/* ============================================================================
   CORS PROXY - Required for APIs that don't support browser CORS
============================================================================ */
const CORS_PROXY = 'https://api.allorigins.win/raw?url=';

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
  | 'paste_search'
  | 'darkweb_scan'
  | 'telegram_scan';

export interface GraphNode {
  id: string;
  type: EntityType;
  label: string;
  value: string;
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
  ip:  { color: '#10b981', icon: '📡' },
  email: { color: '#f59e0b', icon: '📧' },
  person: { color: '#8b5cf6', icon: '👤' },
  organization: { color: '#ec4899', icon: '🏢' },
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
  breach: { color:  '#b91c1c', icon: '💥' },
  paste: { color: '#ea580c', icon: '📄' },
};

/* ============================================================================
   AVAILABLE TRANSFORMS - MAPPED TO ENTITY TYPES
============================================================================ */

export const AVAILABLE_TRANSFORMS:  Transform[] = [
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
    description: 'Scan open ports',
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
    supportedTypes: ['email', 'domain'],
    icon: '📄',
  },
  {
    id: 'social_search',
    name: 'Social Profile Search',
    description: 'Find social media profiles',
    supportedTypes: ['email', 'person'],
    icon: '👥',
  },
  {
    id: 'darkweb_scan',
    name: 'Dark Web Scan',
    description: 'Search dark web sources for leaks',
    supportedTypes: ['email', 'domain', 'person'],
    icon: '🕸️',
  },
  {
    id: 'telegram_scan',
    name: 'Telegram Intel',
    description: 'Search Telegram leak channels',
    supportedTypes: ['email', 'domain', 'person', 'phone'],
    icon: '📱',
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
    // Google DNS-over-HTTPS (supports CORS)
    const response = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(node.value)}&type=A`, {
      headers: { 'Accept': 'application/dns-json' }
    });
    
    if (!response.ok) {
      console.warn(`DNS lookup failed with status ${response.status}`);
      throw new Error('DNS lookup failed');
    }

    const data = await response.json();
    console.log('[DNS] Response:', data);

    if (data.Answer && data.Answer.length > 0) {
      data.Answer.forEach((record: any, idx: number) => {
        // Type 1 = A record (IPv4)
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
              y: node.position.y + (idx * 80) - 40,
            },
            color: ENTITY_CONFIG.ip.color,
            icon: ENTITY_CONFIG.ip.icon,
            size: 50,
          });
        }
      });
    }
    
    // Also try to get AAAA (IPv6) records
    try {
      const ipv6Response = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(node.value)}&type=AAAA`);
      if (ipv6Response.ok) {
        const ipv6Data = await ipv6Response.json();
        if (ipv6Data.Answer) {
          ipv6Data.Answer.slice(0, 3).forEach((record: any, idx: number) => {
            if (record.type === 28) { // AAAA record
              newNodes.push({
                id: `ip-${record.data}-${Date.now()}-${idx}`,
                type: 'ip',
                label: `IPv6: ${record.data.substring(0, 20)}...`,
                value: record.data,
                properties: {
                  ttl: record.TTL,
                  recordType: 'AAAA',
                  domain: node.value,
                },
                position: {
                  x: node.position.x + 250,
                  y: node.position.y + ((newNodes.length + idx) * 80) - 40,
                },
                color: ENTITY_CONFIG.ip.color,
                icon: ENTITY_CONFIG.ip.icon,
                size: 45,
              });
            }
          });
        }
      }
    } catch { /* IPv6 is optional */ }

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
    let data: any = null;
    
    if (node.type === 'ip') {
      // IP WHOIS via RDAP (ARIN supports CORS)
      const apiUrl = `https://rdap.arin.net/registry/ip/${node.value}`;
      console.log('[WHOIS] Fetching IP info from ARIN RDAP');
      
      const response = await fetch(apiUrl, {
        headers: { 'Accept': 'application/rdap+json' }
      });
      
      if (response.ok) {
        data = await response.json();
      }
    } else {
      // Domain WHOIS - try multiple RDAP servers with CORS proxy
      const domain = node.value.toLowerCase();
      const tld = domain.split('.').pop();
      
      // Different RDAP servers for different TLDs
      const rdapServers: Record<string, string> = {
        'com': 'https://rdap.verisign.com/com/v1/domain/',
        'net': 'https://rdap.verisign.com/net/v1/domain/',
        'org': 'https://rdap.publicinterestregistry.org/rdap/domain/',
        'io': 'https://rdap.nic.io/domain/',
        'dev': 'https://rdap.nic.google/domain/',
        'app': 'https://rdap.nic.google/domain/',
      };
      
      const rdapUrl = rdapServers[tld || 'com'] || rdapServers['com'];
      const apiUrl = `${rdapUrl}${domain}`;
      
      console.log(`[WHOIS] Fetching domain info via CORS proxy: ${apiUrl}`);
      
      // RDAP needs CORS proxy for browser requests
      try {
        const response = await fetch(`${CORS_PROXY}${encodeURIComponent(apiUrl)}`);
        if (response.ok) {
          const text = await response.text();
          data = JSON.parse(text);
        }
      } catch (e) {
        console.warn('[WHOIS] CORS proxy failed, trying direct');
        // Fallback to direct (works in some browsers/extensions)
        const directRes = await fetch(apiUrl);
        if (directRes.ok) {
          data = await directRes.json();
        }
      }
    }

    if (!data) {
      console.warn('[WHOIS] No data returned');
      return [];
    }

    console.log('[WHOIS] Response received:', Object.keys(data));

    // Extract registrant/organization info
    if (data.entities && data.entities.length > 0) {
      data.entities.slice(0, 3).forEach((entity: any, idx: number) => {
        let orgName = 'Unknown Organization';
        
        // Try to extract from vCard
        if (entity.vcardArray && entity.vcardArray[1]) {
          const fn = entity.vcardArray[1].find((v: any) => v[0] === 'fn');
          if (fn) orgName = fn[3] || orgName;
          
          const org = entity.vcardArray[1].find((v: any) => v[0] === 'org');
          if (org) orgName = org[3]?.toString() || orgName;
        }
        
        // Fallback to handle or name
        if (orgName === 'Unknown Organization') {
          orgName = entity.handle || entity.name || `Entity ${idx + 1}`;
        }
        
        newNodes.push({
          id: `org-${orgName.replace(/[^a-zA-Z0-9]/g, '')}-${Date.now()}-${idx}`,
          type: 'organization',
          label: orgName.substring(0, 50),
          value: orgName,
          properties: {
            handle: entity.handle,
            roles: entity.roles,
            source: 'rdap_whois',
          },
          position: {
            x: node.position.x + 250,
            y: node.position.y - 100 + (idx * 120),
          },
          color: ENTITY_CONFIG.organization.color,
          icon: ENTITY_CONFIG.organization.icon,
          size: 50,
        });
      });
    }
    
    // Extract nameservers for domains
    if (data.nameservers && data.nameservers.length > 0) {
      data.nameservers.slice(0, 3).forEach((ns: any, idx: number) => {
        const nsName = ns.ldhName || ns.objectClassName || ns;
        newNodes.push({
          id: `ns-${nsName}-${Date.now()}-${idx}`,
          type: 'domain',
          label: `NS: ${nsName}`,
          value: nsName,
          properties: {
            type: 'nameserver',
            parent: node.value,
          },
          position: {
            x: node.position.x + 250,
            y: node.position.y + 100 + (idx * 60),
          },
          color: '#06b6d4',
          icon: '🌐',
          size: 40,
        });
      });
    }
    
    // Extract registration dates
    if (data.events && data.events.length > 0) {
      const regEvent = data.events.find((e: any) => e.eventAction === 'registration');
      const expEvent = data.events.find((e: any) => e.eventAction === 'expiration');
      
      if (regEvent || expEvent) {
        newNodes.push({
          id: `whois-dates-${node.value}-${Date.now()}`,
          type: 'certificate',
          label: `Registration Info`,
          value: node.value,
          properties: {
            registered: regEvent?.eventDate,
            expires: expEvent?.eventDate,
            status: data.status,
          },
          position: {
            x: node.position.x - 200,
            y: node.position.y,
          },
          color: ENTITY_CONFIG.certificate.color,
          icon: '📋',
          size: 45,
        });
      }
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
    // crt.sh requires CORS proxy for browser requests
    const crtshUrl = `https://crt.sh/?q=%25.${encodeURIComponent(node.value)}&output=json`;
    console.log(`[Subdomains] Fetching from crt.sh via CORS proxy`);
    
    let data: any[] = [];
    
    // Try via CORS proxy first
    try {
      const response = await fetch(`${CORS_PROXY}${encodeURIComponent(crtshUrl)}`);
      if (response.ok) {
        const text = await response.text();
        // crt.sh sometimes returns HTML error pages
        if (text.startsWith('[') || text.startsWith('{')) {
          data = JSON.parse(text);
        } else {
          console.warn('[Subdomains] crt.sh returned non-JSON, trying alternate source');
        }
      }
    } catch (e) {
      console.warn('[Subdomains] CORS proxy failed:', e);
    }
    
    // Fallback: Try HackerTarget subdomain finder
    if (data.length === 0) {
      console.log('[Subdomains] Trying HackerTarget API');
      try {
        const htResponse = await fetch(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(node.value)}`);
        if (htResponse.ok) {
          const text = await htResponse.text();
          if (!text.includes('error') && !text.includes('API count exceeded')) {
            const lines = text.split('\n').filter(l => l.trim());
            lines.forEach(line => {
              const [subdomain] = line.split(',');
              if (subdomain && subdomain.endsWith(node.value) && subdomain !== node.value) {
                data.push({ name_value: subdomain });
              }
            });
          }
        }
      } catch (e) {
        console.warn('[Subdomains] HackerTarget failed:', e);
      }
    }
    
    if (data.length === 0) {
      console.warn('[Subdomains] No data from any source');
      return [];
    }

    const subdomains = new Set<string>();

    data.forEach((cert: any) => {
      const nameValue = cert.name_value || cert.common_name || '';
      const names = nameValue.split('\n');
      names.forEach((name: string) => {
        const cleanName = name.trim().toLowerCase();
        if (cleanName.endsWith(node.value.toLowerCase()) && 
            cleanName !== node.value.toLowerCase() && 
            !cleanName.includes('*')) {
          subdomains.add(cleanName);
        }
      });
    });

    console.log(`[Subdomains] ✅ Found ${subdomains.size} unique subdomains`);

    Array.from(subdomains).slice(0, 20).forEach((subdomain, idx) => {
      newNodes.push({
        id: `domain-${subdomain}-${Date.now()}-${idx}`,
        type: 'domain',
        label: subdomain,
        value: subdomain,
        properties: {
          parent: node.value,
          source: 'crt.sh',
        },
        position: {
          x: node.position.x + 300,
          y: node.position.y - 400 + (idx * 45),
        },
        color: ENTITY_CONFIG.domain.color,
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
   TRANSFORM EXECUTION - GEOLOCATION (FOR IPs) - FIXED HTTPS
============================================================================ */

async function transformGeolocation(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:geo:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];

  try {
    // Use ip-api.com with HTTPS via CORS proxy or ipapi.co which has HTTPS
    const response = await fetch(`https://ipapi.co/${node.value}/json/`);
    if (!response.ok) throw new Error('Geolocation failed');

    const data = await response.json();

    if (!data.error) {
      // Location node
      newNodes.push({
        id: `geo-${node.value}-${Date.now()}`,
        type: 'geolocation',
        label: `${data.city || 'Unknown'}, ${data.country_name || data.country}`,
        value: `${data.latitude},${data.longitude}`,
        properties: {
          country: data.country_name || data.country,
          city: data.city,
          region: data.region,
          latitude: data.latitude,
          longitude: data.longitude,
          isp: data.org,
          asn: data.asn,
        },
        position: {
          x: node.position.x + 250,
          y: node.position.y - 80,
        },
        color: ENTITY_CONFIG.geolocation.color,
        icon: ENTITY_CONFIG.geolocation.icon,
        size: 50,
      });

      // Organization/ISP node
      if (data.org) {
        newNodes.push({
          id: `org-${data.org}-${Date.now()}`,
          type: 'organization',
          label: data.org,
          value: data.org,
          properties: {
            asn: data.asn,
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
    // crt.sh requires CORS proxy
    const crtshUrl = `https://crt.sh/?q=${encodeURIComponent(node.value)}&output=json`;
    console.log(`[SSL Cert] Fetching certificate info via CORS proxy`);
    
    let certs: any[] = [];
    
    try {
      const response = await fetch(`${CORS_PROXY}${encodeURIComponent(crtshUrl)}`);
      if (response.ok) {
        const text = await response.text();
        if (text.startsWith('[') || text.startsWith('{')) {
          certs = JSON.parse(text);
        }
      }
    } catch (e) {
      console.warn('[SSL Cert] CORS proxy failed:', e);
    }

    if (certs.length > 0) {
      const cert = certs[0];
      console.log(`[SSL Cert] ✅ Found certificate for ${node.value}`);

      newNodes.push({
        id: `cert-${cert.id}-${Date.now()}`,
        type: 'certificate',
        label: `SSL Certificate`,
        value: cert.id?.toString() || 'cert',
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
        color: ENTITY_CONFIG.certificate.color,
        icon: ENTITY_CONFIG.certificate.icon,
        size: 50,
      });

      // Issuer organization
      if (cert.issuer_name) {
        newNodes.push({
          id: `org-${cert.issuer_name.substring(0, 20)}-${Date.now()}`,
          type: 'organization',
          label: cert.issuer_name.split(',')[0].replace('CN=', '').replace('O=', ''),
          value: cert.issuer_name,
          properties: {
            type: 'Certificate Authority',
          },
          position: {
            x: node.position.x + 500,
            y: node.position.y - 100,
          },
          color: ENTITY_CONFIG.organization.color,
          icon: ENTITY_CONFIG.organization.icon,
          size: 50,
        });
      }
    } else {
      console.warn('[SSL Cert] No certificates found');
    }

    await cacheAPIResponse(cacheKey, newNodes, 3600);
    return newNodes;
  } catch (error) {
    console.error('SSL cert error:', error);
    return [];
  }
}

/* ============================================================================
   TRANSFORM EXECUTION - BREACH CHECK (FOR EMAILS) - USING ALTERNATIVE APIS
============================================================================ */

async function transformBreachCheck(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:breach:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];

  try {
    // Use LeakCheck.io public API (limited but free)
    // Also try XposedOrNot as fallback
    const sources = [
      `https://api.xposedornot.com/v1/check-email/${encodeURIComponent(node.value)}`,
    ];
    
    for (const apiUrl of sources) {
      try {
        const response = await fetch(apiUrl);
        if (response.ok) {
          const data = await response.json();
          
          // XposedOrNot response handling
          if (data.breaches && Array.isArray(data.breaches)) {
            data.breaches.slice(0, 8).forEach((breach: string, idx: number) => {
              newNodes.push({
                id: `breach-${breach}-${Date.now()}-${idx}`,
                type: 'breach',
                label: breach,
                value: breach,
                properties: {
                  email: node.value,
                  source: 'XposedOrNot',
                },
                position: {
                  x: node.position.x + 300,
                  y: node.position.y - 200 + (idx * 60),
                },
                color: ENTITY_CONFIG.breach.color,
                icon: ENTITY_CONFIG.breach.icon,
                size: 45,
                metadata: {
                  riskLevel: 'high',
                  threatScore: 80,
                },
              });
            });
          }
          
          if (newNodes.length > 0) break;
        }
      } catch {
        continue;
      }
    }
    
    // If no results, try Psbdmp for paste leaks
    if (newNodes.length === 0) {
      try {
        // Try direct first, then CORS proxy
        let pastes: any = null;
        try {
          const psbdmpRes = await fetch(`https://psbdmp.ws/api/v3/search/${encodeURIComponent(node.value)}`);
          if (psbdmpRes.ok) {
            pastes = await psbdmpRes.json();
          }
        } catch {
          // Try CORS proxy
          const proxyRes = await fetch(`${CORS_PROXY}${encodeURIComponent(`https://psbdmp.ws/api/v3/search/${encodeURIComponent(node.value)}`)}`);
          if (proxyRes.ok) {
            const text = await proxyRes.text();
            if (text.startsWith('[') || text.startsWith('{')) {
              pastes = JSON.parse(text);
            }
          }
        }
        
        if (pastes) {
          const items = Array.isArray(pastes) ? pastes : pastes.data || [];
          
          items.slice(0, 5).forEach((paste: any, idx: number) => {
            newNodes.push({
              id: `paste-${paste.id || idx}-${Date.now()}`,
              type: 'paste',
              label: paste.title || `Paste Leak #${idx + 1}`,
              value: paste.id || `paste-${idx}`,
              properties: {
                email: node.value,
                source: 'Psbdmp',
                date: paste.time,
              },
              position: {
                x: node.position.x + 300,
                y: node.position.y - 100 + (idx * 60),
              },
              color: ENTITY_CONFIG.paste.color,
              icon: ENTITY_CONFIG.paste.icon,
              size: 45,
              metadata: {
                riskLevel: 'medium',
                threatScore: 60,
              },
            });
          });
        }
      } catch {
        // Psbdmp also failed
      }
    }

    await cacheAPIResponse(cacheKey, newNodes, 3600);
    return newNodes;
  } catch (error) {
    console.error('Breach check error:', error);
    return [];
  }
}

/* ============================================================================
   TRANSFORM EXECUTION - REVERSE IP (FOR IPs) - FIXED
============================================================================ */

async function transformReverseIp(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:reverse_ip:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];

  try {
    // Use HackerTarget's free API for reverse IP
    const response = await fetch(`https://api.hackertarget.com/reverseiplookup/?q=${node.value}`);
    if (!response.ok) throw new Error('Reverse IP failed');

    const text = await response.text();
    
    // Check for errors in response
    if (text.includes('error') || text.includes('API count exceeded')) {
      console.warn('Reverse IP API limit or error');
      return [];
    }
    
    // Parse newline-separated domain list
    const domains = text.split('\n')
      .map(d => d.trim())
      .filter(d => d && d.includes('.') && !d.includes('error'));

    domains.slice(0, 10).forEach((domain, idx) => {
      newNodes.push({
        id: `domain-${domain}-${Date.now()}-${idx}`,
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
        color: ENTITY_CONFIG.domain.color,
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
   TRANSFORM EXECUTION - THREAT INTEL (FOR DOMAINS, IPs, HASHES)
============================================================================ */

async function transformThreatIntel(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:threat:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];

  try {
    // Use URLhaus for threat intel
    const response = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `host=${encodeURIComponent(node.value)}`,
    });

    if (response.ok) {
      const data = await response.json();
      
      if (data.query_status === 'ok' && data.urls) {
        data.urls.slice(0, 8).forEach((url: any, idx: number) => {
          newNodes.push({
            id: `malware-${url.id}-${Date.now()}`,
            type: 'malware',
            label: url.threat || 'Malware',
            value: url.url,
            properties: {
              threat: url.threat,
              tags: url.tags,
              dateAdded: url.date_added,
              status: url.url_status,
            },
            position: {
              x: node.position.x + 300,
              y: node.position.y - 150 + (idx * 50),
            },
            color: ENTITY_CONFIG.malware.color,
            icon: ENTITY_CONFIG.malware.icon,
            size: 45,
            metadata: {
              riskLevel: 'critical',
              threatScore: 95,
            },
          });
        });
      }
    }

    // Also check ThreatFox
    if (newNodes.length === 0) {
      const tfResponse = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: 'search_ioc', search_term: node.value }),
      });

      if (tfResponse.ok) {
        const tfData = await tfResponse.json();
        if (tfData.data && Array.isArray(tfData.data)) {
          tfData.data.slice(0, 5).forEach((ioc: any, idx: number) => {
            newNodes.push({
              id: `threat-${ioc.id}-${Date.now()}`,
              type: 'malware',
              label: ioc.threat_type || 'Threat',
              value: ioc.ioc,
              properties: {
                malware: ioc.malware,
                threatType: ioc.threat_type,
                confidence: ioc.confidence_level,
              },
              position: {
                x: node.position.x + 300,
                y: node.position.y - 100 + (idx * 50),
              },
              color: ENTITY_CONFIG.malware.color,
              icon: ENTITY_CONFIG.malware.icon,
              size: 45,
              metadata: {
                riskLevel: 'high',
                threatScore: ioc.confidence_level || 70,
              },
            });
          });
        }
      }
    }

    await cacheAPIResponse(cacheKey, newNodes, 1800);
    return newNodes;
  } catch (error) {
    console.error('Threat intel error:', error);
    return [];
  }
}

/* ============================================================================
   TRANSFORM EXECUTION - PASTE SEARCH (FOR EMAILS, DOMAINS)
============================================================================ */

async function transformPasteSearch(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:paste:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];

  try {
    const psbdmpUrl = `https://psbdmp.ws/api/v3/search/${encodeURIComponent(node.value)}`;
    console.log(`[Paste Search] Searching for: ${node.value}`);
    
    let data: any = null;
    
    // Try direct first (works sometimes)
    try {
      const response = await fetch(psbdmpUrl, {
        headers: { 'Accept': 'application/json' }
      });
      if (response.ok) {
        data = await response.json();
      }
    } catch {
      console.log('[Paste Search] Direct request failed, trying CORS proxy');
    }
    
    // Fallback to CORS proxy
    if (!data) {
      try {
        const proxyResponse = await fetch(`${CORS_PROXY}${encodeURIComponent(psbdmpUrl)}`);
        if (proxyResponse.ok) {
          const text = await proxyResponse.text();
          if (text.startsWith('[') || text.startsWith('{')) {
            data = JSON.parse(text);
          }
        }
      } catch (e) {
        console.warn('[Paste Search] CORS proxy also failed:', e);
      }
    }
    
    if (!data) {
      // Try Archive.org as alternative paste source
      console.log('[Paste Search] Trying Archive.org');
      try {
        const archiveUrl = `https://archive.org/advancedsearch.php?q=${encodeURIComponent(node.value)}&fl[]=identifier&fl[]=title&fl[]=description&output=json&rows=15`;
        const archiveRes = await fetch(archiveUrl);
        if (archiveRes.ok) {
          const archiveData = await archiveRes.json();
          const docs = archiveData.response?.docs || [];
          
          docs.slice(0, 8).forEach((doc: any, idx: number) => {
            newNodes.push({
              id: `archive-${doc.identifier}-${Date.now()}`,
              type: 'paste',
              label: doc.title || `Archive: ${doc.identifier}`,
              value: doc.identifier,
              properties: {
                source: 'Archive.org',
                description: doc.description?.substring(0, 150),
                url: `https://archive.org/details/${doc.identifier}`,
              },
              position: {
                x: node.position.x + 300,
                y: node.position.y - 150 + (idx * 50),
              },
              color: ENTITY_CONFIG.paste.color,
              icon: '📚',
              size: 40,
            });
          });
        }
      } catch (e) {
        console.warn('[Paste Search] Archive.org failed:', e);
      }
    } else {
      const pastes = Array.isArray(data) ? data : (data.data || data.results || []);
      console.log(`[Paste Search] ✅ Found ${pastes.length} results from Psbdmp`);
      
      pastes.slice(0, 12).forEach((paste: any, idx: number) => {
        newNodes.push({
          id: `paste-${paste.id || paste.key || idx}-${Date.now()}`,
          type: 'paste',
          label: paste.title || paste.tags || `Paste #${idx + 1}`,
          value: paste.id || paste.key,
          properties: {
            source: 'Psbdmp',
            date: paste.time || paste.date || paste.created,
            content: paste.text?.substring(0, 200),
            url: paste.id ? `https://pastebin.com/${paste.id}` : `https://psbdmp.ws/${paste.key || paste.id}`,
          },
          position: {
            x: node.position.x + 300,
            y: node.position.y - 250 + (idx * 45),
          },
          color: ENTITY_CONFIG.paste.color,
          icon: ENTITY_CONFIG.paste.icon,
          size: 40,
          metadata: {
            riskLevel: 'medium',
            threatScore: 50,
          },
        });
      });
    }

    await cacheAPIResponse(cacheKey, newNodes, 1800);
    return newNodes;
  } catch (error) {
    console.error('Paste search error:', error);
    return [];
  }
}

/* ============================================================================
   TRANSFORM EXECUTION - SOCIAL SEARCH (FOR USERNAMES/EMAILS)
============================================================================ */

async function transformSocialSearch(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:social:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];
  const username = node.value.includes('@') ? node.value.split('@')[0] : node.value;

  // Check common platforms with public APIs
  const platforms = [
    { name: 'GitHub', url: `https://api.github.com/users/${username}` },
    { name: 'Reddit', url: `https://www.reddit.com/user/${username}/about.json` },
    { name: 'GitLab', url: `https://gitlab.com/api/v4/users?username=${username}` },
  ];

  for (const platform of platforms) {
    try {
      const response = await fetch(platform.url, {
        headers: { 'User-Agent': 'OSINT-Hub/1.0' },
      });
      
      if (response.ok) {
        const data = await response.json();
        
        // Handle different API response formats
        let profileData = data;
        if (Array.isArray(data) && data.length > 0) profileData = data[0];
        if (data.data) profileData = data.data;
        
        if (profileData && !profileData.error) {
          newNodes.push({
            id: `social-${platform.name}-${username}-${Date.now()}`,
            type: 'social_profile',
            label: `${platform.name}: ${profileData.login || profileData.name || username}`,
            value: profileData.html_url || profileData.web_url || `https://${platform.name.toLowerCase()}.com/${username}`,
            properties: {
              platform: platform.name,
              username: profileData.login || profileData.username || username,
              displayName: profileData.name,
              bio: profileData.bio,
              followers: profileData.followers,
              avatar: profileData.avatar_url,
            },
            position: {
              x: node.position.x + 300,
              y: node.position.y - 80 + (newNodes.length * 80),
            },
            color: ENTITY_CONFIG.social_profile.color,
            icon: ENTITY_CONFIG.social_profile.icon,
            size: 50,
          });
        }
      }
    } catch {
      continue;
    }
  }

  await cacheAPIResponse(cacheKey, newNodes, 3600);
  return newNodes;
}

/* ============================================================================
   TRANSFORM EXECUTION - DARK WEB SCAN (FOR EMAILS, DOMAINS, USERNAMES)
============================================================================ */

async function transformDarkwebScan(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:darkweb:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];

  try {
    console.log(`[Dark Web] Scanning for: ${node.value}`);
    
    // Use torService's searchDarkWebSignals function
    const leakResults = await searchDarkWebSignals(node.value);
    
    if (leakResults && leakResults.length > 0) {
      console.log(`[Dark Web] ✅ Found ${leakResults.length} results`);
      
      leakResults.slice(0, 15).forEach((leak: any, idx: number) => {
        const nodeType = leak.source === 'psbdmp' || leak.source === 'ghostbin' ? 'paste' : 'breach';
        
        newNodes.push({
          id: `darkweb-${leak.id || idx}-${Date.now()}`,
          type: nodeType,
          label: leak.title || `${leak.source}: ${node.value}`,
          value: leak.url || leak.id,
          properties: {
            source: leak.source,
            indicator: leak.indicator,
            context: leak.context,
            timestamp: leak.timestamp,
            url: leak.url,
          },
          position: {
            x: node.position.x + 350,
            y: node.position.y - 300 + (idx * 45),
          },
          color: nodeType === 'breach' ? ENTITY_CONFIG.breach.color : ENTITY_CONFIG.paste.color,
          icon: '🕸️',
          size: 45,
          metadata: {
            riskLevel: leak.source === 'libraryofleaks' ? 'critical' : 'high',
            threatScore: leak.source === 'libraryofleaks' ? 90 : 75,
            source: 'darkweb_scan',
          },
        });
      });
    } else {
      // Fallback: Direct Ahmia search for onion mentions
      console.log('[Dark Web] No leaks found, trying Ahmia search');
      try {
        const ahmiaRes = await fetch(`https://ahmia.fi/search/?q=${encodeURIComponent(node.value)}`);
        if (ahmiaRes.ok) {
          const html = await ahmiaRes.text();
          const onionMatches = html.match(/([a-z2-7]{16,56}\.onion)/gi) || [];
          const uniqueOnions = [...new Set(onionMatches)].slice(0, 8);
          
          uniqueOnions.forEach((onion, idx) => {
            newNodes.push({
              id: `onion-${onion.substring(0, 10)}-${Date.now()}`,
              type: 'url',
              label: `Onion: ${onion.substring(0, 20)}...`,
              value: onion,
              properties: {
                type: 'onion_site',
                query: node.value,
                source: 'ahmia',
              },
              position: {
                x: node.position.x + 350,
                y: node.position.y - 150 + (idx * 50),
              },
              color: '#7c3aed',
              icon: '🧅',
              size: 40,
              metadata: {
                riskLevel: 'high',
                threatScore: 70,
              },
            });
          });
        }
      } catch (e) {
        console.warn('[Dark Web] Ahmia search failed:', e);
      }
    }

    await cacheAPIResponse(cacheKey, newNodes, 900);
    return newNodes;
  } catch (error) {
    console.error('Dark web scan error:', error);
    return [];
  }
}

/* ============================================================================
   TRANSFORM EXECUTION - TELEGRAM SCAN (FOR EMAILS, USERNAMES, PHONES)
============================================================================ */

async function transformTelegramScan(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:telegram:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];

  try {
    console.log(`[Telegram] Scanning for: ${node.value}`);
    
    // Determine scan type based on node type
    let scanType: 'email' | 'username' | 'phone' | 'keyword' = 'keyword';
    if (node.type === 'email') scanType = 'email';
    else if (node.type === 'phone') scanType = 'phone';
    else if (node.type === 'person') scanType = 'username';
    
    // Use telegramService's searchTelegramLeaks function
    const telegramResults = await searchTelegramLeaks(node.value, scanType);
    
    if (telegramResults && telegramResults.length > 0) {
      console.log(`[Telegram] ✅ Found ${telegramResults.length} results`);
      
      telegramResults.slice(0, 12).forEach((result: any, idx: number) => {
        newNodes.push({
          id: `telegram-${result.id || idx}-${Date.now()}`,
          type: 'breach',
          label: result.title || `Telegram: ${result.channel || 'Leak'}`,
          value: result.url || result.id,
          properties: {
            channel: result.channel,
            channelId: result.channelId,
            severity: result.severity,
            context: result.context,
            exposedData: result.exposedData,
            timestamp: result.timestamp,
            source: result.source,
            url: result.url,
          },
          position: {
            x: node.position.x + 350,
            y: node.position.y - 200 + (idx * 45),
          },
          color: result.severity === 'critical' ? '#dc2626' : 
                 result.severity === 'high' ? '#ef4444' : '#f97316',
          icon: '📱',
          size: 45,
          metadata: {
            riskLevel: result.severity || 'medium',
            threatScore: result.severity === 'critical' ? 95 : 
                        result.severity === 'high' ? 80 : 60,
            source: 'telegram_scan',
          },
        });
      });
    } else {
      // Fallback: Check via Reddit for Telegram leak mentions
      console.log('[Telegram] No direct results, checking Reddit for Telegram mentions');
      try {
        const redditRes = await fetch(
          `https://www.reddit.com/search.json?q=${encodeURIComponent(node.value + ' telegram leak')}&limit=10&sort=new`,
          { headers: { 'User-Agent': 'OSINT-Hub/1.0' } }
        );
        
        if (redditRes.ok) {
          const redditData = await redditRes.json();
          const posts = redditData.data?.children || [];
          
          posts.slice(0, 6).forEach((post: any, idx: number) => {
            const p = post.data;
            if (p.title?.toLowerCase().includes('telegram') || 
                p.selftext?.toLowerCase().includes('telegram')) {
              newNodes.push({
                id: `reddit-tg-${p.id}-${Date.now()}`,
                type: 'paste',
                label: `Reddit: ${p.title?.substring(0, 40)}...`,
                value: `https://reddit.com${p.permalink}`,
                properties: {
                  source: 'Reddit',
                  subreddit: p.subreddit,
                  author: p.author,
                  score: p.score,
                  created: new Date(p.created_utc * 1000).toISOString(),
                },
                position: {
                  x: node.position.x + 350,
                  y: node.position.y - 100 + (idx * 50),
                },
                color: '#ff4500',
                icon: '📱',
                size: 40,
              });
            }
          });
        }
      } catch (e) {
        console.warn('[Telegram] Reddit fallback failed:', e);
      }
    }

    await cacheAPIResponse(cacheKey, newNodes, 900);
    return newNodes;
  } catch (error) {
    console.error('Telegram scan error:', error);
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
      case 'threat_intel':
        newNodes = await transformThreatIntel(node);
        break;
      case 'paste_search':
        newNodes = await transformPasteSearch(node);
        break;
      case 'social_search':
        newNodes = await transformSocialSearch(node);
        break;
      case 'darkweb_scan':
        newNodes = await transformDarkwebScan(node);
        break;
      case 'telegram_scan':
        newNodes = await transformTelegramScan(node);
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
    id: `${type}-${value}-${Date. now()}`,
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
