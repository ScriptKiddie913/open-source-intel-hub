// IP Intelligence Service

import { API_ENDPOINTS } from '@/data/publicApiEndpoints';
import { GeoLocation, PortInfo } from '@/types/osint';
import { IPAPIResponse, ShodanInternetDBResponse } from '@/types/api';
import { cacheAPIResponse, getCachedData } from '@/lib/database';

const IP_CACHE_TTL = 60; // minutes

export async function getIPGeolocation(ip: string): Promise<GeoLocation | null> {
  const cacheKey = `ip:geo:${ip}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    // Using ipapi.co - free tier with HTTPS support
    const response = await fetch(`${API_ENDPOINTS.ipGeo.base}/${ip}/json/`);
    if (!response.ok) throw new Error(`IP lookup failed: ${response.statusText}`);

    const data = await response.json();
    
    // Check for error in response
    if (data.error) {
      console.error('IP lookup error:', data.reason);
      return null;
    }

    const geoData: GeoLocation = {
      ip: data.ip,
      country: data.country_name || data.country,
      countryCode: data.country_code || data.country,
      region: data.region,
      city: data.city,
      lat: data.latitude,
      lon: data.longitude,
      isp: data.org || 'Unknown',
      org: data.org || 'Unknown',
      as: data.asn || 'Unknown',
      timezone: data.timezone,
    };

    await cacheAPIResponse(cacheKey, geoData, IP_CACHE_TTL);
    return geoData;
  } catch (error) {
    console.error('IP geolocation error:', error);
    throw error;
  }
}

export async function getOpenPorts(ip: string): Promise<PortInfo | null> {
  const cacheKey = `ip:ports:${ip}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const response = await fetch(`${API_ENDPOINTS.shodan.base}/${ip}`);
    
    if (response.status === 404) {
      // No data in Shodan InternetDB
      return { ip, ports: [], hostnames: [], cpes: [], tags: [], vulns: [] };
    }
    
    if (!response.ok) throw new Error(`Port lookup failed: ${response.statusText}`);

    const data: ShodanInternetDBResponse = await response.json();
    
    const portInfo: PortInfo = {
      ip: data.ip,
      ports: data.ports || [],
      hostnames: data.hostnames || [],
      cpes: data.cpes || [],
      tags: data.tags || [],
      vulns: data.vulns || [],
    };

    await cacheAPIResponse(cacheKey, portInfo, IP_CACHE_TTL);
    return portInfo;
  } catch (error) {
    console.error('Port lookup error:', error);
    return null;
  }
}

export async function getFullIPAnalysis(ip: string): Promise<{
  geo: GeoLocation | null;
  ports: PortInfo | null;
  threatLevel: 'critical' | 'high' | 'medium' | 'low' | 'info';
}> {
  const [geo, ports] = await Promise.all([
    getIPGeolocation(ip).catch(() => null),
    getOpenPorts(ip).catch(() => null),
  ]);

  // Calculate threat level based on findings
  let threatLevel: 'critical' | 'high' | 'medium' | 'low' | 'info' = 'info';
  
  if (ports) {
    if (ports.vulns.length > 0) {
      threatLevel = 'critical';
    } else if (ports.tags.some(tag => ['malware', 'botnet', 'c2', 'compromised'].includes(tag.toLowerCase()))) {
      threatLevel = 'high';
    } else if (ports.ports.some(port => [22, 23, 3389, 5900].includes(port))) {
      threatLevel = 'medium';
    } else if (ports.ports.length > 10) {
      threatLevel = 'low';
    }
  }

  return { geo, ports, threatLevel };
}

export function isValidIP(ip: string): boolean {
  // IPv4 validation
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Regex.test(ip)) {
    return ip.split('.').every(octet => parseInt(octet) <= 255);
  }
  
  // Basic IPv6 validation
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
  return ipv6Regex.test(ip);
}
