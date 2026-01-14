// ============================================================================
// entityDetectionService.ts
// AUTOMATIC ENTITY TYPE DETECTION FOR OSINT QUERIES
// ============================================================================
// Detects: IP, Domain, Hash (MD5/SHA1/SHA256), Email, Username, CVE, URL,
// Bitcoin/Crypto addresses, Phone numbers, and more
// ============================================================================

export type EntityType = 
  | 'ip'
  | 'ipv6'
  | 'domain'
  | 'url'
  | 'email'
  | 'md5'
  | 'sha1'
  | 'sha256'
  | 'sha512'
  | 'cve'
  | 'username'
  | 'bitcoin'
  | 'ethereum'
  | 'phone'
  | 'mac_address'
  | 'asn'
  | 'cidr'
  | 'unknown';

export interface DetectedEntity {
  type: EntityType;
  value: string;
  confidence: number; // 0-100
  normalized: string; // cleaned/normalized version
  metadata?: Record<string, any>;
}

// Regex patterns for entity detection
const PATTERNS = {
  // IPv4 address
  ipv4: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
  
  // IPv6 address
  ipv6: /^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/,
  
  // Domain (excluding IP addresses)
  domain: /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$/,
  
  // URL
  url: /^(https?:\/\/|ftp:\/\/|www\.)[^\s/$.?#].[^\s]*$/i,
  
  // Email
  email: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
  
  // MD5 hash (32 hex chars)
  md5: /^[a-fA-F0-9]{32}$/,
  
  // SHA1 hash (40 hex chars)
  sha1: /^[a-fA-F0-9]{40}$/,
  
  // SHA256 hash (64 hex chars)
  sha256: /^[a-fA-F0-9]{64}$/,
  
  // SHA512 hash (128 hex chars)
  sha512: /^[a-fA-F0-9]{128}$/,
  
  // CVE ID
  cve: /^CVE-\d{4}-\d{4,}$/i,
  
  // Bitcoin address (Legacy, SegWit, Bech32)
  bitcoin: /^(bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$/,
  
  // Ethereum address
  ethereum: /^0x[a-fA-F0-9]{40}$/,
  
  // Phone number (international format)
  phone: /^\+?[1-9]\d{6,14}$/,
  
  // MAC address
  mac: /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/,
  
  // ASN (Autonomous System Number)
  asn: /^AS\d+$/i,
  
  // CIDR notation
  cidr: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:3[0-2]|[12]?[0-9])$/,
  
  // Username (social media style)
  username: /^@?[a-zA-Z][a-zA-Z0-9_]{2,30}$/,
};

// Common TLDs for domain validation
const COMMON_TLDS = new Set([
  'com', 'org', 'net', 'edu', 'gov', 'io', 'co', 'ai', 'app', 'dev',
  'info', 'biz', 'me', 'us', 'uk', 'de', 'fr', 'jp', 'cn', 'ru',
  'xyz', 'online', 'site', 'tech', 'cloud', 'security', 'cyber'
]);

/**
 * Detect the entity type from a given input string
 */
export function detectEntityType(input: string): DetectedEntity {
  const value = input.trim();
  
  if (!value) {
    return { type: 'unknown', value, confidence: 0, normalized: value };
  }
  
  // Check CVE first (specific format)
  if (PATTERNS.cve.test(value)) {
    return {
      type: 'cve',
      value,
      confidence: 100,
      normalized: value.toUpperCase(),
      metadata: { year: parseInt(value.split('-')[1]) }
    };
  }
  
  // Check URL (before domain, as URLs contain domains)
  if (PATTERNS.url.test(value)) {
    try {
      const url = new URL(value.startsWith('www.') ? `https://${value}` : value);
      return {
        type: 'url',
        value,
        confidence: 95,
        normalized: url.href,
        metadata: { host: url.hostname, protocol: url.protocol }
      };
    } catch {
      // Not a valid URL, continue checking
    }
  }
  
  // Check email
  if (PATTERNS.email.test(value)) {
    return {
      type: 'email',
      value,
      confidence: 95,
      normalized: value.toLowerCase(),
      metadata: { domain: value.split('@')[1] }
    };
  }
  
  // Check hashes (by length)
  if (PATTERNS.sha512.test(value)) {
    return { type: 'sha512', value, confidence: 98, normalized: value.toLowerCase() };
  }
  if (PATTERNS.sha256.test(value)) {
    return { type: 'sha256', value, confidence: 98, normalized: value.toLowerCase() };
  }
  if (PATTERNS.sha1.test(value)) {
    return { type: 'sha1', value, confidence: 95, normalized: value.toLowerCase() };
  }
  if (PATTERNS.md5.test(value)) {
    return { type: 'md5', value, confidence: 90, normalized: value.toLowerCase() };
  }
  
  // Check Bitcoin address
  if (PATTERNS.bitcoin.test(value)) {
    return {
      type: 'bitcoin',
      value,
      confidence: 95,
      normalized: value,
      metadata: { 
        format: value.startsWith('bc1') ? 'bech32' : value.startsWith('3') ? 'segwit' : 'legacy'
      }
    };
  }
  
  // Check Ethereum address
  if (PATTERNS.ethereum.test(value)) {
    return {
      type: 'ethereum',
      value,
      confidence: 95,
      normalized: value.toLowerCase()
    };
  }
  
  // Check IP addresses
  if (PATTERNS.cidr.test(value)) {
    return {
      type: 'cidr',
      value,
      confidence: 100,
      normalized: value,
      metadata: { network: value.split('/')[0], prefix: parseInt(value.split('/')[1]) }
    };
  }
  
  if (PATTERNS.ipv4.test(value)) {
    return { type: 'ip', value, confidence: 100, normalized: value };
  }
  
  if (PATTERNS.ipv6.test(value)) {
    return { type: 'ipv6', value, confidence: 100, normalized: value.toLowerCase() };
  }
  
  // Check MAC address
  if (PATTERNS.mac.test(value)) {
    return {
      type: 'mac_address',
      value,
      confidence: 95,
      normalized: value.toUpperCase().replace(/-/g, ':')
    };
  }
  
  // Check ASN
  if (PATTERNS.asn.test(value)) {
    return {
      type: 'asn',
      value,
      confidence: 100,
      normalized: value.toUpperCase()
    };
  }
  
  // Check phone number
  const phoneClean = value.replace(/[\s\-().]/g, '');
  if (PATTERNS.phone.test(phoneClean)) {
    return { type: 'phone', value, confidence: 75, normalized: phoneClean };
  }
  
  // Check domain
  if (PATTERNS.domain.test(value)) {
    const tld = value.split('.').pop()?.toLowerCase() || '';
    const confidence = COMMON_TLDS.has(tld) ? 90 : 70;
    return {
      type: 'domain',
      value,
      confidence,
      normalized: value.toLowerCase(),
      metadata: { tld }
    };
  }
  
  // Check username (last, as it's most generic)
  const usernameClean = value.replace(/^@/, '');
  if (PATTERNS.username.test(usernameClean) && usernameClean.length >= 3) {
    return {
      type: 'username',
      value,
      confidence: 50,
      normalized: usernameClean.toLowerCase()
    };
  }
  
  // Unknown entity
  return {
    type: 'unknown',
    value,
    confidence: 0,
    normalized: value
  };
}

/**
 * Detect multiple entities from a text input
 */
export function detectMultipleEntities(text: string): DetectedEntity[] {
  const entities: DetectedEntity[] = [];
  const seen = new Set<string>();
  
  // Split by common delimiters
  const tokens = text.split(/[\s,;|]+/).filter(t => t.length > 0);
  
  for (const token of tokens) {
    const entity = detectEntityType(token);
    if (entity.type !== 'unknown' && !seen.has(entity.normalized)) {
      seen.add(entity.normalized);
      entities.push(entity);
    }
  }
  
  return entities;
}

/**
 * Get display label for entity type
 */
export function getEntityLabel(type: EntityType): string {
  const labels: Record<EntityType, string> = {
    ip: 'IP Address',
    ipv6: 'IPv6 Address',
    domain: 'Domain',
    url: 'URL',
    email: 'Email',
    md5: 'MD5 Hash',
    sha1: 'SHA1 Hash',
    sha256: 'SHA256 Hash',
    sha512: 'SHA512 Hash',
    cve: 'CVE ID',
    username: 'Username',
    bitcoin: 'Bitcoin Address',
    ethereum: 'Ethereum Address',
    phone: 'Phone Number',
    mac_address: 'MAC Address',
    asn: 'ASN',
    cidr: 'CIDR Range',
    unknown: 'Unknown'
  };
  return labels[type];
}

/**
 * Get icon suggestion for entity type
 */
export function getEntityIcon(type: EntityType): string {
  const icons: Record<EntityType, string> = {
    ip: 'server',
    ipv6: 'server',
    domain: 'globe',
    url: 'link',
    email: 'mail',
    md5: 'hash',
    sha1: 'hash',
    sha256: 'hash',
    sha512: 'hash',
    cve: 'bug',
    username: 'user',
    bitcoin: 'bitcoin',
    ethereum: 'ethereum',
    phone: 'phone',
    mac_address: 'network',
    asn: 'network',
    cidr: 'network',
    unknown: 'search'
  };
  return icons[type];
}

/**
 * Get recommended OSINT modules for entity type
 */
export function getRecommendedModules(type: EntityType): string[] {
  const moduleMap: Record<EntityType, string[]> = {
    ip: ['ip-analyzer', 'shodan', 'threat-intel', 'geolocation'],
    ipv6: ['ip-analyzer', 'threat-intel', 'geolocation'],
    domain: ['dns', 'certificates', 'whois', 'subdomains', 'threat-intel'],
    url: ['url-scanner', 'threat-intel', 'web-scraper'],
    email: ['breach-checker', 'username-search', 'dark-web'],
    md5: ['malware-bazaar', 'virus-total', 'threat-intel'],
    sha1: ['malware-bazaar', 'virus-total', 'threat-intel'],
    sha256: ['malware-bazaar', 'virus-total', 'threat-intel'],
    sha512: ['malware-bazaar', 'virus-total', 'threat-intel'],
    cve: ['cve-explorer', 'exploit-db', 'threat-intel'],
    username: ['username-enum', 'social-search', 'dark-web'],
    bitcoin: ['blockchain-explorer', 'crypto-trace', 'threat-intel'],
    ethereum: ['blockchain-explorer', 'crypto-trace', 'threat-intel'],
    phone: ['phone-lookup', 'social-search'],
    mac_address: ['vendor-lookup', 'device-id'],
    asn: ['asn-lookup', 'ip-range'],
    cidr: ['ip-analyzer', 'network-scan'],
    unknown: ['web-search', 'threat-intel']
  };
  return moduleMap[type];
}
