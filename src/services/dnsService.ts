// DNS Intelligence Service using Google Public DNS API

import { API_ENDPOINTS, DNS_RECORD_TYPES } from '@/data/publicApiEndpoints';
import { DNSRecord, DNSResults } from '@/types/osint';
import { GoogleDNSResponse } from '@/types/api';
import { cacheAPIResponse, getCachedData } from '@/lib/database';

const DNS_CACHE_TTL = 30; // minutes

function dnsTypeToString(type: number): string {
  const typeMap: { [key: number]: string } = {
    1: 'A',
    28: 'AAAA',
    5: 'CNAME',
    15: 'MX',
    16: 'TXT',
    2: 'NS',
    6: 'SOA',
    12: 'PTR',
  };
  return typeMap[type] || `TYPE${type}`;
}

export async function resolveDNS(domain: string, type: string = 'A'): Promise<DNSRecord[]> {
  const cacheKey = `dns:${domain}:${type}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const typeNum = DNS_RECORD_TYPES[type as keyof typeof DNS_RECORD_TYPES] || 1;
  const url = `${API_ENDPOINTS.dns.base}?name=${encodeURIComponent(domain)}&type=${typeNum}`;

  try {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`DNS lookup failed: ${response.statusText}`);

    const data: GoogleDNSResponse = await response.json();
    
    if (data.Status !== 0) {
      return [];
    }

    const records: DNSRecord[] = (data.Answer || []).map((answer) => ({
      type: dnsTypeToString(answer.type),
      name: answer.name,
      data: answer.data,
      ttl: answer.TTL,
    }));

    await cacheAPIResponse(cacheKey, records, DNS_CACHE_TTL);
    return records;
  } catch (error) {
    console.error('DNS lookup error:', error);
    throw error;
  }
}

export async function getAllRecords(domain: string): Promise<DNSResults> {
  const cacheKey = `dns:all:${domain}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const recordTypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS'];
  const results: DNSRecord[] = [];

  await Promise.all(
    recordTypes.map(async (type) => {
      try {
        const records = await resolveDNS(domain, type);
        results.push(...records);
      } catch (e) {
        // Ignore individual type failures
      }
    })
  );

  const dnsResults: DNSResults = {
    domain,
    records: results,
    subdomains: [],
    timestamp: new Date(),
  };

  await cacheAPIResponse(cacheKey, dnsResults, DNS_CACHE_TTL);
  return dnsResults;
}

export async function getSubdomains(domain: string): Promise<string[]> {
  // Extract subdomains from certificate transparency logs
  const cacheKey = `subdomains:${domain}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const response = await fetch(
      `${API_ENDPOINTS.certs.base}/?q=%.${encodeURIComponent(domain)}&output=json`
    );
    
    if (!response.ok) return [];
    
    const certs = await response.json();
    const subdomains = new Set<string>();
    
    certs.forEach((cert: Record<string, unknown>) => {
      const names = cert.name_value?.split('\n') || [];
      names.forEach((name: string) => {
        const cleaned = name.replace(/^\*\./, '').toLowerCase();
        if (cleaned.endsWith(domain.toLowerCase()) && cleaned !== domain.toLowerCase()) {
          subdomains.add(cleaned);
        }
      });
    });

    const result = Array.from(subdomains);
    await cacheAPIResponse(cacheKey, result, 60);
    return result;
  } catch (error) {
    console.error('Subdomain enumeration error:', error);
    return [];
  }
}

export async function reverseDNS(ip: string): Promise<string | null> {
  const cacheKey = `rdns:${ip}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const octets = ip.split('.').reverse().join('.');
    const ptr = `${octets}.in-addr.arpa`;
    const records = await resolveDNS(ptr, 'PTR');
    
    const hostname = records[0]?.data?.replace(/\.$/, '') || null;
    if (hostname) {
      await cacheAPIResponse(cacheKey, hostname, DNS_CACHE_TTL);
    }
    return hostname;
  } catch (error) {
    return null;
  }
}
