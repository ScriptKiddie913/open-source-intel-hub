// Public OSINT API Endpoints Configuration

export const API_ENDPOINTS = {
  // Google Public DNS - No auth required
  dns: {
    base: 'https://dns.google/resolve',
    description: 'Google Public DNS API',
    rateLimit: 1000, // requests per day (generous)
  },

  // ipapi.co - Free tier with HTTPS support, no key needed
  ipGeo: {
    base: 'https://ipapi.co',
    description: 'IP Geolocation API (ipapi.co)',
    rateLimit: 30000, // per month free tier
  },

  // Shodan InternetDB - Free, no auth
  shodan: {
    base: 'https://internetdb.shodan.io',
    description: 'Shodan Internet DB',
    rateLimit: 100, // per day
  },

  // crt.sh - Certificate Transparency
  certs: {
    base: 'https://crt.sh',
    description: 'Certificate Transparency Logs',
    rateLimit: 100, // per day
  },

  // CORS Proxies for restricted APIs
  corsProxies: [
    'https://api.allorigins.win/raw?url=',
    'https://corsproxy.io/?',
  ],
};

export const DNS_RECORD_TYPES = {
  A: 1,
  AAAA: 28,
  CNAME: 5,
  MX: 15,
  TXT: 16,
  NS: 2,
  SOA: 6,
  PTR: 12,
};

export const THREAT_INDICATORS = {
  suspiciousPorts: [22, 23, 3389, 5900, 445, 139],
  knownMaliciousTags: ['malware', 'botnet', 'c2', 'compromised', 'scanner'],
  recentBreachThresholdDays: 365,
};

export function getProxyUrl(targetUrl: string): string {
  const proxy = API_ENDPOINTS.corsProxies[0];
  return `${proxy}${encodeURIComponent(targetUrl)}`;
}
