// src/services/graphService.ts
// Maltego-style Graph Intelligence Service
// Real data fetching for entities with relationship mapping
// Enhanced with LLM analysis and deep search capabilities

import { cacheAPIResponse, getCachedData } from '@/lib/database';
import { searchDarkWebSignals, deepSearchDarkWeb, type DeepSearchResult } from '@/services/torService';
import { searchTelegramLeaks } from '@/services/telegramService';
import { getSubdomainsFromCerts, searchCertificates } from '@/services/certService';
import { getSubdomains } from '@/services/dnsService';
import { getIPGeolocation } from '@/services/ipService';
import { API_ENDPOINTS, getProxyUrl } from '@/data/publicApiEndpoints';
import { extractEntities, analyzeLeakIntelligence, mapEntityRelationships, type LeakAnalysis, type ExtractedEntity } from '@/services/llmAnalysisService';

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
    console.log(`[DNS Transform] Resolving: ${node.value}`);
    
    // Google DNS-over-HTTPS (supports CORS)
    const response = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(node.value)}&type=A`, {
      headers: { 'Accept': 'application/dns-json' }
    });
    
    if (!response.ok) {
      console.warn(`[DNS Transform] DNS lookup failed with status ${response.status}`);
      throw new Error(`DNS lookup failed with status ${response.status}`);
    }

    const data = await response.json();
    console.log('[DNS Transform] Response:', data);

    // Check if DNS query was successful
    if (data.Status !== 0) {
      console.warn(`[DNS Transform] DNS returned error status: ${data.Status}`);
      throw new Error(`DNS query failed with status ${data.Status}`);
    }

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
        if (ipv6Data.Status === 0 && ipv6Data.Answer) {
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
    } catch (ipv6Error) { 
      console.log('[DNS Transform] IPv6 lookup failed (optional):', ipv6Error);
    }

    if (newNodes.length === 0) {
      throw new Error('No A or AAAA records found for this domain');
    }

    console.log(`[DNS Transform] Found ${newNodes.length} IP addresses`);
    await cacheAPIResponse(cacheKey, newNodes, 60);
    return newNodes;
  } catch (error) {
    console.error('[DNS Transform] Error:', error);
    throw error;
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
        const response = await fetch(getProxyUrl(apiUrl));
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
   Uses the same technique as DomainIntelligence - certService & dnsService
============================================================================ */

async function transformSubdomainEnum(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:subdomains:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];
  const domain = node.value.toLowerCase();

  try {
    console.log(`[Subdomains] Fetching subdomains for: ${domain}`);
    
    let subdomains: string[] = [];
    
    // Method 1: Use getSubdomainsFromCerts from certService (same as DomainIntelligence)
    try {
      console.log('[Subdomains] Trying certService.getSubdomainsFromCerts...');
      const certSubdomains = await getSubdomainsFromCerts(domain);
      if (certSubdomains.length > 0) {
        console.log(`[Subdomains] ✅ certService found ${certSubdomains.length} subdomains`);
        subdomains = [...new Set([...subdomains, ...certSubdomains])];
      }
    } catch (e) {
      console.warn('[Subdomains] certService failed:', e);
    }
    
    // Method 2: Use getSubdomains from dnsService as additional source
    if (subdomains.length < 10) {
      try {
        console.log('[Subdomains] Trying dnsService.getSubdomains...');
        const dnsSubdomains = await getSubdomains(domain);
        if (dnsSubdomains.length > 0) {
          console.log(`[Subdomains] ✅ dnsService found ${dnsSubdomains.length} subdomains`);
          subdomains = [...new Set([...subdomains, ...dnsSubdomains])];
        }
      } catch (e) {
        console.warn('[Subdomains] dnsService failed:', e);
      }
    }
    
    // Method 3: Try HackerTarget API as fallback (has CORS support)
    if (subdomains.length === 0) {
      console.log('[Subdomains] Trying HackerTarget API...');
      try {
        const htResponse = await fetch(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`);
        if (htResponse.ok) {
          const text = await htResponse.text();
          if (!text.includes('error') && !text.includes('API count exceeded')) {
            const lines = text.split('\n').filter(l => l.trim());
            lines.forEach(line => {
              const [subdomain] = line.split(',');
              if (subdomain && subdomain.endsWith(domain) && subdomain !== domain) {
                subdomains.push(subdomain.toLowerCase());
              }
            });
            if (subdomains.length > 0) {
              console.log(`[Subdomains] ✅ HackerTarget found ${subdomains.length} subdomains`);
            }
          }
        }
      } catch (e) {
        console.warn('[Subdomains] HackerTarget failed:', e);
      }
    }
    
    // Method 4: Direct crt.sh with CORS proxy as last resort
    if (subdomains.length === 0) {
      console.log('[Subdomains] Trying crt.sh via CORS proxy...');
      try {
        const crtshUrl = `${API_ENDPOINTS.certs.base}/?q=%25.${encodeURIComponent(domain)}&output=json`;
        const response = await fetch(getProxyUrl(crtshUrl));
        if (response.ok) {
          const text = await response.text();
          if (text.startsWith('[') || text.startsWith('{')) {
            const data = JSON.parse(text);
            data.forEach((cert: any) => {
              const nameValue = cert.name_value || cert.common_name || '';
              const names = nameValue.split('\n');
              names.forEach((name: string) => {
                const cleanName = name.trim().toLowerCase().replace(/^\*\./, '');
                if (cleanName.endsWith(domain) && cleanName !== domain && !cleanName.includes('*')) {
                  subdomains.push(cleanName);
                }
              });
            });
            if (subdomains.length > 0) {
              console.log(`[Subdomains] ✅ crt.sh via proxy found ${subdomains.length} subdomains`);
            }
          }
        }
      } catch (e) {
        console.warn('[Subdomains] crt.sh proxy failed:', e);
      }
    }
    
    // Deduplicate and limit
    const uniqueSubdomains = [...new Set(subdomains)];
    console.log(`[Subdomains] Total unique subdomains: ${uniqueSubdomains.length}`);
    
    if (uniqueSubdomains.length === 0) {
      console.warn('[Subdomains] No subdomains found from any source');
      return [];
    }

    // Create nodes for each subdomain (limit to 25)
    uniqueSubdomains.slice(0, 25).forEach((subdomain, idx) => {
      newNodes.push({
        id: `domain-${subdomain}-${Date.now()}-${idx}`,
        type: 'domain',
        label: subdomain,
        value: subdomain,
        properties: {
          parent: domain,
          source: 'certificate_transparency',
        },
        position: {
          x: node.position.x + 300,
          y: node.position.y - 400 + (idx * 35),
        },
        color: ENTITY_CONFIG.domain.color,
        icon: ENTITY_CONFIG.domain.icon,
        size: 40,
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
    // Use basic IP geolocation service
    const data = await getIPGeolocation(node.value);

    if (data && data.city && data.country) {
      // Location node
      newNodes.push({
        id: `geo-${node.value}-${Date.now()}`,
        type: 'geolocation',
        label: `${data.city}, ${data.country}`,
        value: `${data.lat},${data.lon}`,
        properties: {
          country: data.country,
          countryCode: data.countryCode,
          city: data.city,
          region: data.region,
          latitude: data.lat,
          longitude: data.lon,
          isp: data.isp,
          org: data.org,
          asn: data.as,
          timezone: data.timezone,
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
      const orgName = data.org || data.isp;
      if (orgName) {
        newNodes.push({
          id: `org-${orgName.replace(/[^a-zA-Z0-9]/g, '')}-${Date.now()}`,
          type: 'organization',
          label: orgName.substring(0, 40),
          value: orgName,
          properties: {
            asn: data.as,
            type: 'ISP',
            ip: node.value,
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
   Uses certService like DomainIntelligence for consistency
============================================================================ */

async function transformSslCert(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:ssl:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];

  try {
    console.log(`[SSL Cert] Fetching certificate info for: ${node.value}`);
    
    // Use certService.searchCertificates (same as DomainIntelligence)
    let certs: any[] = [];
    
    try {
      const certResults = await searchCertificates(node.value);
      if (certResults.length > 0) {
        console.log(`[SSL Cert] ✅ certService found ${certResults.length} certificates`);
        certs = certResults;
      }
    } catch (e) {
      console.warn('[SSL Cert] certService failed, trying direct crt.sh:', e);
      
      // Fallback to direct crt.sh with CORS proxy
      const crtshUrl = `${API_ENDPOINTS.certs.base}/?q=${encodeURIComponent(node.value)}&output=json`;
      try {
        const response = await fetch(getProxyUrl(crtshUrl));
        if (response.ok) {
          const text = await response.text();
          if (text.startsWith('[') || text.startsWith('{')) {
            certs = JSON.parse(text);
          }
        }
      } catch (proxyErr) {
        console.warn('[SSL Cert] CORS proxy also failed:', proxyErr);
      }
    }

    if (certs.length > 0) {
      const cert = certs[0];
      console.log(`[SSL Cert] ✅ Found certificate for ${node.value}`);

      // Extract certificate properties safely
      const certId = cert.id || cert.serial_number || cert.serialNumber;
      const issuerName = cert.issuer_name || cert.issuerName || 'Unknown Issuer';
      const commonName = cert.common_name || cert.commonName || node.value;
      const notBefore = cert.not_before || cert.notBefore;
      const notAfter = cert.not_after || cert.notAfter;
      const serialNumber = cert.serial_number || cert.serialNumber;

      newNodes.push({
        id: `cert-${certId || Date.now()}`,
        type: 'certificate',
        label: `SSL Certificate`,
        value: certId?.toString() || serialNumber || 'cert',
        properties: {
          issuer: issuerName,
          commonName: commonName,
          notBefore: notBefore,
          notAfter: notAfter,
          serialNumber: serialNumber,
          validDays: notAfter ? Math.floor((new Date(notAfter).getTime() - Date.now()) / (1000 * 60 * 60 * 24)) : null,
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
      if (issuerName && issuerName !== 'Unknown Issuer') {
        const issuerLabel = issuerName.split(',')[0]
          .replace('CN=', '')
          .replace('O=', '')
          .replace('C=', '')
          .trim()
          .substring(0, 30);
          
        newNodes.push({
          id: `org-${issuerLabel.replace(/[^a-zA-Z0-9]/g, '')}-${Date.now()}`,
          type: 'organization',
          label: issuerLabel,
          value: issuerName,
          properties: {
            type: 'Certificate Authority',
            fullName: issuerName,
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
          const proxyRes = await fetch(getProxyUrl(`https://psbdmp.ws/api/v3/search/${encodeURIComponent(node.value)}`));
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
    console.log(`[Threat Intel] Checking ${node.value}`);
    
    // Use URLhaus for threat intel
    const response = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: `host=${encodeURIComponent(node.value)}`,
    });

    if (response.ok) {
      const data = await response.json();
      
      console.log(`[Threat Intel] URLhaus response status: ${data.query_status}`);
      
      if (data.query_status === 'ok' && data.urls && Array.isArray(data.urls)) {
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
      console.log('[Threat Intel] Trying ThreatFox');
      const tfResponse = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({ query: 'search_ioc', search_term: node.value }),
      });

      if (tfResponse.ok) {
        const tfData = await tfResponse.json();
        console.log(`[Threat Intel] ThreatFox response status: ${tfData.query_status}`);
        
        if (tfData.query_status === 'ok' && tfData.data && Array.isArray(tfData.data)) {
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

    console.log(`[Threat Intel] Found ${newNodes.length} threat indicators`);
    
    if (newNodes.length > 0) {
      await cacheAPIResponse(cacheKey, newNodes, 1800);
    }
    
    return newNodes;
  } catch (error) {
    console.error('[Threat Intel] Error:', error);
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
  const query = node.value.trim();
  
  // Helper to check relevance - must contain FULL query
  const isRelevant = (text: string): boolean => {
    if (!text) return false;
    return text.toLowerCase().includes(query.toLowerCase());
  };

  try {
    const psbdmpUrl = `https://psbdmp.ws/api/v3/search/${encodeURIComponent(query)}`;
    console.log(`[Paste Search] Searching for exact: "${query}"`);
    
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
        const proxyResponse = await fetch(getProxyUrl(psbdmpUrl));
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
      // Try Archive.org as alternative paste source - with EXACT query
      console.log('[Paste Search] Trying Archive.org with exact query');
      try {
        const archiveUrl = `https://archive.org/advancedsearch.php?q="${encodeURIComponent(query)}"&fl[]=identifier&fl[]=title&fl[]=description&output=json&rows=20`;
        const archiveRes = await fetch(archiveUrl);
        if (archiveRes.ok) {
          const archiveData = await archiveRes.json();
          const docs = archiveData.response?.docs || [];
          
          docs.forEach((doc: any, idx: number) => {
            const fullText = `${doc.title || ''} ${doc.description || ''} ${doc.identifier || ''}`;
            
            // STRICT: Only include if it actually contains the query
            if (!isRelevant(fullText)) return;
            
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
                y: node.position.y - 150 + (newNodes.length * 50),
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
      console.log(`[Paste Search] Processing ${pastes.length} results from Psbdmp`);
      
      pastes.forEach((paste: any, idx: number) => {
        const fullText = `${paste.text || ''} ${paste.content || ''} ${paste.title || ''} ${paste.tags || ''}`;
        
        // STRICT: Only include if it actually contains the query
        if (!isRelevant(fullText)) return;
        
        newNodes.push({
          id: `paste-${paste.id || paste.key || idx}-${Date.now()}`,
          type: 'paste',
          label: paste.title || paste.tags || `Paste #${newNodes.length + 1}`,
          value: paste.id || paste.key,
          properties: {
            source: 'Psbdmp',
            date: paste.time || paste.date || paste.created,
            content: paste.text?.substring(0, 200),
            url: paste.id ? `https://pastebin.com/${paste.id}` : `https://psbdmp.ws/${paste.key || paste.id}`,
          },
          position: {
            x: node.position.x + 300,
            y: node.position.y - 250 + (newNodes.length * 45),
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
   Comprehensive username enumeration across 25+ platforms
============================================================================ */

// Platform configuration for comprehensive username enumeration
const SOCIAL_PLATFORMS = [
  // Developer platforms
  { 
    name: 'GitHub', 
    url: 'https://api.github.com/users/{username}', 
    type: 'dev',
    checkType: 'json_api',
    profileUrl: 'https://github.com/{username}',
    icon: '💻'
  },
  {
    name: 'GitLab',
    url: 'https://gitlab.com/api/v4/users?username={username}',
    type: 'dev',
    checkType: 'json_array',
    profileUrl: 'https://gitlab.com/{username}',
    icon: '🦊'
  },
  {
    name: 'HackerNews',
    url: 'https://hacker-news.firebaseio.com/v0/user/{username}.json',
    type: 'dev',
    checkType: 'json_api',
    profileUrl: 'https://news.ycombinator.com/user?id={username}',
    icon: '📰'
  },
  {
    name: 'Dev.to',
    url: 'https://dev.to/api/users/by_username?url={username}',
    type: 'dev',
    checkType: 'json_api',
    profileUrl: 'https://dev.to/{username}',
    icon: '✍️'
  },
  {
    name: 'DockerHub',
    url: 'https://hub.docker.com/v2/users/{username}',
    type: 'dev',
    checkType: 'json_api',
    profileUrl: 'https://hub.docker.com/u/{username}',
    icon: '🐳'
  },
  {
    name: 'npm',
    url: 'https://registry.npmjs.org/-/user/org.couchdb.user:{username}',
    type: 'dev',
    checkType: 'json_api',
    profileUrl: 'https://www.npmjs.com/~{username}',
    icon: '📦'
  },
  {
    name: 'PyPI',
    url: 'https://pypi.org/pypi/{username}/json',
    type: 'dev',
    checkType: 'json_api',
    profileUrl: 'https://pypi.org/user/{username}',
    icon: '🐍'
  },
  // Social platforms
  { 
    name: 'Reddit', 
    url: 'https://www.reddit.com/user/{username}/about.json', 
    type: 'social',
    checkType: 'json_api',
    profileUrl: 'https://reddit.com/user/{username}',
    icon: '🤖'
  },
  {
    name: 'Gravatar',
    url: 'https://en.gravatar.com/{username}.json',
    type: 'social',
    checkType: 'json_api',
    profileUrl: 'https://gravatar.com/{username}',
    icon: '👤'
  },
  {
    name: 'Mastodon',
    url: 'https://mastodon.social/api/v1/accounts/lookup?acct={username}',
    type: 'social',
    checkType: 'json_api',
    profileUrl: 'https://mastodon.social/@{username}',
    icon: '🐘'
  },
  {
    name: 'Pinterest',
    url: 'https://pinterest.com/{username}',
    type: 'social',
    checkType: 'html_pattern',
    existsPattern: 'og:title',
    notExistsPattern: 'This page isn',
    profileUrl: 'https://pinterest.com/{username}',
    icon: '📌'
  },
  {
    name: 'Medium',
    url: 'https://medium.com/@{username}',
    type: 'blogging',
    checkType: 'html_pattern',
    existsPattern: 'og:title',
    notExistsPattern: '404',
    profileUrl: 'https://medium.com/@{username}',
    icon: '📝'
  },
  {
    name: 'About.me',
    url: 'https://about.me/{username}',
    type: 'professional',
    checkType: 'html_pattern',
    existsPattern: 'og:title',
    notExistsPattern: '404',
    profileUrl: 'https://about.me/{username}',
    icon: '👔'
  },
  // Security platforms
  {
    name: 'Keybase',
    url: 'https://keybase.io/_/api/1.0/user/lookup.json?username={username}',
    type: 'security',
    checkType: 'json_status',
    statusField: 'status.code',
    successValue: 0,
    profileUrl: 'https://keybase.io/{username}',
    icon: '🔐'
  },
  // Gaming platforms
  {
    name: 'Lichess',
    url: 'https://lichess.org/api/user/{username}',
    type: 'gaming',
    checkType: 'json_api',
    profileUrl: 'https://lichess.org/@/{username}',
    icon: '♟️'
  },
  {
    name: 'Chess.com',
    url: 'https://api.chess.com/pub/player/{username}',
    type: 'gaming',
    checkType: 'json_api',
    profileUrl: 'https://chess.com/member/{username}',
    icon: '♔'
  },
  {
    name: 'Roblox',
    url: 'https://users.roblox.com/v1/users/search?keyword={username}&limit=10',
    type: 'gaming',
    checkType: 'json_field',
    fieldPath: 'data',
    matchField: 'name',
    profileUrl: 'https://www.roblox.com/users/profile?username={username}',
    icon: '🎮'
  },
  // Messaging
  {
    name: 'Telegram',
    url: 'https://t.me/{username}',
    type: 'messaging',
    checkType: 'html_pattern',
    existsPattern: 'tgme_page_title',
    notExistsPattern: 'tgme_page_error',
    profileUrl: 'https://t.me/{username}',
    icon: '📱'
  },
  // Media
  {
    name: 'Imgur',
    url: 'https://api.imgur.com/account/v1/accounts/{username}?client_id=546c25a59c58ad7',
    type: 'media',
    checkType: 'json_api',
    profileUrl: 'https://imgur.com/user/{username}',
    icon: '🖼️'
  },
  {
    name: 'Spotify',
    url: 'https://open.spotify.com/user/{username}',
    type: 'music',
    checkType: 'html_pattern',
    existsPattern: 'og:title',
    notExistsPattern: 'Page not found',
    profileUrl: 'https://open.spotify.com/user/{username}',
    icon: '🎵'
  },
  // Education
  {
    name: 'Duolingo',
    url: 'https://www.duolingo.com/2017-06-30/users?username={username}',
    type: 'education',
    checkType: 'json_array',
    profileUrl: 'https://duolingo.com/profile/{username}',
    icon: '🦉'
  },
  // Code platforms
  {
    name: 'Replit',
    url: 'https://replit.com/@{username}',
    type: 'dev',
    checkType: 'html_pattern',
    existsPattern: 'og:title',
    notExistsPattern: '404',
    profileUrl: 'https://replit.com/@{username}',
    icon: '⚡'
  },
  {
    name: 'CodePen',
    url: 'https://codepen.io/{username}',
    type: 'dev',
    checkType: 'html_pattern',
    existsPattern: 'og:title',
    notExistsPattern: '404 - Page Not Found',
    profileUrl: 'https://codepen.io/{username}',
    icon: '✏️'
  },
  // Additional platforms
  {
    name: 'Patreon',
    url: 'https://www.patreon.com/{username}',
    type: 'creator',
    checkType: 'html_pattern',
    existsPattern: 'og:title',
    notExistsPattern: '404',
    profileUrl: 'https://www.patreon.com/{username}',
    icon: '💰'
  },
  {
    name: 'Linktree',
    url: 'https://linktr.ee/{username}',
    type: 'social',
    checkType: 'html_pattern',
    existsPattern: 'og:title',
    notExistsPattern: 'not found',
    profileUrl: 'https://linktr.ee/{username}',
    icon: '🌳'
  },
];

const SOCIAL_CORS_PROXY = 'https://api.allorigins.win/raw?url=';

// Helper to get nested object values like "status.code"
function getNestedValue(obj: any, path: string): any {
  return path.split('.').reduce((current, key) => current?.[key], obj);
}

// Extract profile data from API responses
function extractProfileData(data: any, platform: string): Record<string, any> {
  const profile: Record<string, any> = {};
  
  profile.displayName = data.name || data.login || data.username || data.display_name;
  profile.bio = data.bio || data.description || data.about;
  profile.avatar = data.avatar_url || data.avatar || data.profile_image || data.icon_url;
  
  if (platform === 'GitHub') {
    profile.followers = data.followers;
    profile.following = data.following;
    profile.repos = data.public_repos;
    profile.joinDate = data.created_at;
    profile.company = data.company;
    profile.location = data.location;
  } else if (platform === 'Reddit') {
    profile.karma = data.data?.total_karma || data.total_karma;
    profile.joinDate = data.data?.created_utc ? new Date(data.data.created_utc * 1000).toISOString() : undefined;
  } else if (platform === 'Chess.com' || platform === 'Lichess') {
    profile.rating = data.rating || data.perfs?.blitz?.rating;
    profile.games = data.count?.all || data.games;
  } else if (platform === 'Mastodon') {
    profile.followers = data.followers_count;
    profile.following = data.following_count;
    profile.posts = data.statuses_count;
  } else if (platform === 'GitLab') {
    profile.avatar = data.avatar_url;
    profile.state = data.state;
  }
  
  return profile;
}

async function transformSocialSearch(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:social:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];
  const username = node.value.includes('@') ? node.value.split('@')[0] : node.value;
  
  console.log(`[Social Search] Starting comprehensive scan for: ${username}`);
  
  const batchSize = 6;
  let foundCount = 0;

  // Process platforms in batches for performance
  for (let i = 0; i < SOCIAL_PLATFORMS.length; i += batchSize) {
    const batch = SOCIAL_PLATFORMS.slice(i, i + batchSize);
    
    await Promise.all(
      batch.map(async (platform: any) => {
        try {
          const url = platform.url.replace(/{username}/g, encodeURIComponent(username));
          const profileUrl = platform.profileUrl?.replace(/{username}/g, username) || url;
          
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 8000);
          
          let exists = false;
          let profileData: Record<string, any> = {};
          
          try {
            let response: Response | null = null;
            
            // Try direct fetch first
            try {
              response = await fetch(url, {
                method: 'GET',
                signal: controller.signal,
                headers: { 'User-Agent': 'OSINT-Hub/1.0' },
              });
            } catch {
              // Fallback to CORS proxy for HTML pattern checks
              if (platform.checkType === 'html_pattern') {
                response = await fetch(`${SOCIAL_CORS_PROXY}${encodeURIComponent(url)}`, {
                  signal: controller.signal,
                });
              }
            }
            
            clearTimeout(timeoutId);
            
            if (!response) return;
            
            // Handle different verification types
            switch (platform.checkType) {
              case 'json_api': {
                if (response.ok) {
                  try {
                    const data = await response.json();
                    if (data && !data.error && !data.message?.includes('Not Found')) {
                      exists = true;
                      profileData = extractProfileData(data, platform.name);
                    }
                  } catch { /* JSON parse failed */ }
                }
                break;
              }
              
              case 'json_array': {
                if (response.ok) {
                  try {
                    const data = await response.json();
                    if (Array.isArray(data) && data.length > 0) {
                      exists = true;
                      profileData = extractProfileData(data[0], platform.name);
                    } else if (data.users && data.users.length > 0) {
                      exists = true;
                      profileData = extractProfileData(data.users[0], platform.name);
                    }
                  } catch { /* JSON parse failed */ }
                }
                break;
              }
              
              case 'json_status': {
                if (response.ok) {
                  try {
                    const data = await response.json();
                    const statusField = platform.statusField || 'status';
                    const statusValue = getNestedValue(data, statusField);
                    if (statusValue === platform.successValue) {
                      exists = true;
                      profileData = extractProfileData(data.them || data, platform.name);
                    }
                  } catch { /* JSON parse failed */ }
                }
                break;
              }
              
              case 'json_field': {
                if (response.ok) {
                  try {
                    const data = await response.json();
                    const fieldData = getNestedValue(data, platform.fieldPath || 'data');
                    if (Array.isArray(fieldData)) {
                      const match = fieldData.find((item: any) => 
                        item[platform.matchField || 'name']?.toLowerCase() === username.toLowerCase()
                      );
                      if (match) {
                        exists = true;
                        profileData = extractProfileData(match, platform.name);
                      }
                    }
                  } catch { /* JSON parse failed */ }
                }
                break;
              }
              
              case 'html_pattern': {
                try {
                  const html = await response.text();
                  const existsPattern = platform.existsPattern || '';
                  const notExistsPattern = platform.notExistsPattern || '';
                  
                  if (notExistsPattern && html.includes(notExistsPattern)) {
                    exists = false;
                  } else if (existsPattern && html.includes(existsPattern)) {
                    exists = true;
                    const titleMatch = html.match(/<title>([^<]+)<\/title>/i);
                    if (titleMatch) {
                      profileData.displayName = titleMatch[1].split(' - ')[0].trim();
                    }
                  }
                } catch { /* HTML parse failed */ }
                break;
              }
            }
            
            if (exists) {
              console.log(`[Social Search] ✅ Found: ${platform.name}`);
              foundCount++;
              
              newNodes.push({
                id: `social-${platform.name}-${username}-${Date.now()}-${foundCount}`,
                type: 'social_profile',
                label: `${platform.icon || '👤'} ${platform.name}: ${profileData.displayName || username}`,
                value: profileUrl,
                properties: {
                  platform: platform.name,
                  platformType: platform.type,
                  username: profileData.displayName || username,
                  displayName: profileData.displayName,
                  bio: profileData.bio,
                  followers: profileData.followers,
                  avatar: profileData.avatar,
                  ...profileData,
                },
                position: {
                  x: node.position.x + 300 + Math.floor(foundCount / 8) * 200,
                  y: node.position.y - 300 + ((foundCount - 1) % 8) * 80,
                },
                color: ENTITY_CONFIG.social_profile.color,
                icon: platform.icon || ENTITY_CONFIG.social_profile.icon,
                size: 45,
                metadata: {
                  source: 'social_search',
                  confidence: platform.checkType === 'json_api' ? 95 : 80,
                },
              });
            }
          } catch {
            clearTimeout(timeoutId);
          }
        } catch {
          // Skip platform on error
        }
      })
    );
    
    // Small delay between batches to avoid rate limiting
    if (i + batchSize < SOCIAL_PLATFORMS.length) {
      await new Promise(resolve => setTimeout(resolve, 300));
    }
  }

  console.log(`[Social Search] Completed. Found ${newNodes.length} profiles for "${username}"`);
  
  await cacheAPIResponse(cacheKey, newNodes, 3600);
  return newNodes;
}

/* ============================================================================
   TRANSFORM EXECUTION - DARK WEB SCAN (STEALTHMOLE-STYLE DEEP SEARCH)
============================================================================ */

async function transformDarkwebScan(node: GraphNode): Promise<GraphNode[]> {
  const cacheKey = `transform:darkweb:${node.value}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const newNodes: GraphNode[] = [];
  const query = node.value.trim();
  
  // Helper to check relevance - must contain FULL query
  const isRelevant = (text: string): boolean => {
    if (!text) return false;
    return text.toLowerCase().includes(query.toLowerCase());
  };

  try {
    console.log(`[Dark Web] StealthMole-style DEEP scan for: "${query}"`);
    
    // Use enhanced deep search with all sources
    const deepResult: DeepSearchResult = await deepSearchDarkWeb({
      indicator: query,
      includeBreachDatabases: true,
      includeDarkWebSearch: true,
      includeCodeSearch: true,
      includePasteSites: true,
      includeLeakArchives: true,
      includeSocialMedia: true,
      maxResultsPerSource: 25,
      enableLLMAnalysis: true,
    });
    
    const { signals: leakResults, analysis, entities } = deepResult;
    
    if (leakResults && leakResults.length > 0) {
      console.log(`[Dark Web] Processing ${leakResults.length} deep search results`);
      
      // Add a summary node if LLM analysis is available
      if (analysis) {
        newNodes.push({
          id: `analysis-${Date.now()}`,
          type: 'breach',
          label: `🔍 Analysis: ${analysis.threatAssessment.severity.toUpperCase()}`,
          value: analysis.id,
          properties: {
            type: 'threat_analysis',
            summary: analysis.summary,
            threatScore: analysis.threatAssessment.score,
            severity: analysis.threatAssessment.severity,
            recommendations: analysis.threatAssessment.recommendations,
            indicators: analysis.threatAssessment.indicators,
            entityCount: entities.length,
          },
          position: {
            x: node.position.x + 250,
            y: node.position.y - 80,
          },
          color: analysis.threatAssessment.severity === 'critical' ? '#dc2626' : 
                 analysis.threatAssessment.severity === 'high' ? '#ea580c' : 
                 analysis.threatAssessment.severity === 'medium' ? '#ca8a04' : '#16a34a',
          icon: '🧠',
          size: 60,
          metadata: {
            riskLevel: analysis.threatAssessment.severity === 'info' ? 'low' : analysis.threatAssessment.severity,
            threatScore: analysis.threatAssessment.score,
            source: 'llm_analysis',
          },
        });
      }
      
      // Add extracted entities as nodes
      entities.slice(0, 10).forEach((entity, idx) => {
        const entityType: EntityType = 
          entity.type === 'email' ? 'email' :
          entity.type === 'ip' ? 'ip' :
          entity.type === 'domain' ? 'domain' :
          entity.type === 'hash' ? 'hash' : 'breach';
        
        newNodes.push({
          id: `entity-${entity.type}-${idx}-${Date.now()}`,
          type: entityType,
          label: `${entity.type.toUpperCase()}: ${entity.value.substring(0, 30)}`,
          value: entity.value,
          properties: {
            entityType: entity.type,
            confidence: entity.confidence,
            context: entity.context,
          },
          position: {
            x: node.position.x + 450,
            y: node.position.y - 200 + (idx * 50),
          },
          color: ENTITY_CONFIG[entityType]?.color || '#6366f1',
          icon: entity.type === 'email' ? '📧' : entity.type === 'password' ? '🔑' : '🔍',
          size: 35,
          metadata: {
            riskLevel: entity.confidence > 0.8 ? 'high' : 'medium',
            confidence: entity.confidence,
            source: 'entity_extraction',
          },
        });
      });
      
      // Add leak results as nodes
      leakResults.slice(0, 30).forEach((leak: any, idx: number) => {
        // STRICT: Double-check relevance (torService should already filter)
        const fullText = `${leak.title || ''} ${leak.context || ''} ${leak.indicator || ''}`;
        if (!isRelevant(fullText)) return;
        
        const nodeType: EntityType = 
          leak.source === 'breach_db' || leak.source === 'leaklookup' ? 'breach' :
          leak.source === 'psbdmp' || leak.source === 'pastebin' || leak.source === 'rentry' ? 'paste' :
          leak.source === 'github_gist' || leak.source === 'searchcode' || leak.source === 'grep_app' ? 'url' :
          'breach';
        
        const riskLevel = leak.severity || 
          (leak.source === 'breach_db' || leak.source === 'ddosecrets' ? 'critical' :
           leak.source === 'libraryofleaks' || leak.source === 'wikileaks' ? 'critical' :
           leak.source === 'intelx' ? 'high' : 'medium');
        
        newNodes.push({
          id: `darkweb-${leak.id || idx}-${Date.now()}`,
          type: nodeType,
          label: leak.title?.substring(0, 50) || `${leak.source}: ${query}`,
          value: leak.url || leak.id,
          properties: {
            source: leak.source,
            indicator: leak.indicator,
            context: leak.context,
            timestamp: leak.timestamp,
            url: leak.url,
            extractedEntities: leak.extractedData?.length || 0,
          },
          position: {
            x: node.position.x + 350,
            y: node.position.y - 400 + (newNodes.length * 40),
          },
          color: riskLevel === 'critical' ? '#dc2626' : 
                 riskLevel === 'high' ? '#ea580c' : 
                 ENTITY_CONFIG[nodeType]?.color || '#6366f1',
          icon: leak.source === 'breach_db' ? '💀' :
                leak.source === 'wikileaks' ? '📰' :
                leak.source === 'ddosecrets' ? '🔓' :
                leak.source === 'github_gist' ? '💻' : '🕸️',
          size: riskLevel === 'critical' ? 50 : 45,
          metadata: {
            riskLevel,
            threatScore: riskLevel === 'critical' ? 95 : riskLevel === 'high' ? 80 : 65,
            source: 'deep_darkweb_scan',
          },
        });
      });
      
      console.log(`[Dark Web] ✅ Added ${newNodes.length} nodes from deep scan`);
    } else {
      // Fallback: Direct Ahmia search for onion mentions
      console.log('[Dark Web] No leaks found, trying Ahmia search');
      try {
        const ahmiaRes = await fetch(`https://ahmia.fi/search/?q=${encodeURIComponent(query)}`);
        if (ahmiaRes.ok) {
          const html = await ahmiaRes.text();
          
          // Only get onions that appear in relevant context
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
                query: query,
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
  const query = node.value.trim();
  
  // Helper to check relevance - must contain FULL query
  const isRelevant = (text: string): boolean => {
    if (!text) return false;
    return text.toLowerCase().includes(query.toLowerCase());
  };

  try {
    console.log(`[Telegram] Scanning for exact: "${query}"`);
    
    // Determine scan type based on node type
    let scanType: 'email' | 'username' | 'phone' | 'keyword' = 'keyword';
    if (node.type === 'email') scanType = 'email';
    else if (node.type === 'phone') scanType = 'phone';
    else if (node.type === 'person') scanType = 'username';
    
    // Use telegramService's searchTelegramLeaks function
    const telegramResults = await searchTelegramLeaks(query, scanType);
    
    if (telegramResults && telegramResults.length > 0) {
      console.log(`[Telegram] Processing ${telegramResults.length} results`);
      
      telegramResults.forEach((result: any, idx: number) => {
        // STRICT: Double-check relevance (telegramService should already filter)
        const fullText = `${result.title || ''} ${result.context || ''} ${result.identifier || ''}`;
        if (!isRelevant(fullText)) return;
        
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
            y: node.position.y - 200 + (newNodes.length * 45),
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
      
      console.log(`[Telegram] ✅ Added ${newNodes.length} relevant nodes`);
    } else {
      // Fallback: Check via Reddit for Telegram leak mentions - with EXACT query
      console.log('[Telegram] No direct results, checking Reddit');
      try {
        const redditRes = await fetch(
          `https://www.reddit.com/search.json?q="${encodeURIComponent(query)}"&limit=15&sort=relevance`,
          { headers: { 'User-Agent': 'OSINT-Hub/1.0' } }
        );
        
        if (redditRes.ok) {
          const redditData = await redditRes.json();
          const posts = redditData.data?.children || [];
          
          posts.forEach((post: any, idx: number) => {
            const p = post.data;
            const fullText = `${p.title || ''} ${p.selftext || ''}`;
            
            // STRICT: Only include if it actually contains the query
            if (!isRelevant(fullText)) return;
            
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
                y: node.position.y - 100 + (newNodes.length * 50),
              },
              color: '#ff4500',
              icon: '📱',
              size: 40,
            });
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

  console.log(`[Transform] Executing ${transformId} on node:`, node.label);

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
    console.error(`[Transform] ${transformId} error:`, error);
    throw new Error(`Transform ${transformId} failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }

  if (!newNodes || newNodes.length === 0) {
    console.warn(`[Transform] ${transformId} returned no results for ${node.label}`);
    throw new Error(`No results found for this transform. The ${transformId} query did not return any data.`);
  }

  console.log(`[Transform] ${transformId} succeeded: ${newNodes.length} nodes found`);

  // Create edges
  const newEdges: GraphEdge[] = newNodes.map(newNode => ({
    id: `edge-${node.id}-${newNode.id}`,
    source: node.id,
    target: newNode.id,
    label: AVAILABLE_TRANSFORMS.find(t => t.id === transformId)?.name || transformId,
    type: transformId,
    color: '#64748b',
    weight: 1,
  }));

  return { nodes: newNodes, edges: newEdges };
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
