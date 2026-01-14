// src/services/realTimeThreatService.ts
// REAL-TIME THREAT DATA SERVICE - 100% REAL DATA FROM LIVE ENDPOINTS
// NO MOCK DATA - Fetches from Feodo, URLhaus, ThreatFox, APTmap

import { fetchFeodoC2Servers, fetchURLhausRecent, fetchThreatFoxIOCs } from './mispFeedService';
import { getAPTThreatMapData } from './aptMapService';

export interface ThreatPoint {
  id: string;
  timestamp: Date;
  lat: number;
  lon: number;
  country: string;
  city?: string;
  threatType: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  indicator: string;
  source: string;
  count: number;
  port?: number;
  malware?: string;
  status?: string;
}

// IP Geolocation using ip-api.com (free, no API key required)
async function geolocateIP(ip: string): Promise<{ lat: number; lon: number; country: string; city: string } | null> {
  try {
    const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,city,lat,lon`, {
      signal: AbortSignal.timeout(5000) // 5 second timeout
    });
    
    if (!response.ok) return null;
    
    const data = await response.json();
    
    if (data.status === 'success' && data.lat && data.lon) {
      return {
        lat: data.lat,
        lon: data.lon,
        country: data.country || 'Unknown',
        city: data.city || 'Unknown'
      };
    }
  } catch (error) {
    console.error('[Geolocation] Failed for IP:', ip, error);
  }
  return null;
}

// Fetch REAL live threat map data from all sources
export async function fetchLiveThreatMap(): Promise<ThreatPoint[]> {
  const threats: ThreatPoint[] = [];
  
  try {
    console.log('[LiveThreatMap] Fetching REAL threat data from all sources...');

    // 1. Fetch REAL Feodo C2 Servers
    const feodoServers = await fetchFeodoC2Servers();
    console.log('[Feodo] Processing', feodoServers.length, 'real C2 servers');
    
    for (const server of feodoServers.slice(0, 100)) {
      const geo = await geolocateIP(server.ip);
      
      if (geo) {
        threats.push({
          id: server.id,
          timestamp: new Date(server.firstSeen),
          lat: geo.lat,
          lon: geo.lon,
          country: geo.country,
          city: geo.city,
          threatType: 'Botnet C2',
          severity: server.status === 'online' ? 'critical' : 'high',
          indicator: server.ip,
          source: 'Feodo Tracker',
          count: 1,
          port: server.port,
          malware: server.malwareFamily,
          status: server.status,
        });
      }
      
      // Rate limiting - ip-api.com allows 45 requests per minute
      await new Promise(resolve => setTimeout(resolve, 1500));
    }

    // 2. Fetch REAL URLhaus malware URLs
    const urlhausData = await fetchURLhausRecent();
    console.log('[URLhaus] Processing', urlhausData.length, 'real malware URLs');
    
    for (const entry of urlhausData.slice(0, 50)) {
      try {
        const url = new URL(entry.url);
        const hostname = url.hostname;
        
        // Skip localhost and private IPs
        if (hostname === 'localhost' || hostname.startsWith('192.168.') || hostname.startsWith('10.')) {
          continue;
        }
        
        const geo = await geolocateIP(hostname);
        
        if (geo) {
          threats.push({
            id: entry.id,
            timestamp: new Date(entry.dateAdded),
            lat: geo.lat,
            lon: geo.lon,
            country: geo.country,
            city: geo.city,
            threatType: 'Malware URL',
            severity: entry.urlStatus === 'online' ? 'high' : 'medium',
            indicator: entry.url,
            source: 'URLhaus',
            count: 1,
            malware: entry.threat,
            status: entry.urlStatus,
          });
        }
      } catch (e) {
        // Skip invalid URLs
      }
      
      await new Promise(resolve => setTimeout(resolve, 1500));
    }

    // 3. Fetch REAL ThreatFox IOCs
    const threatfoxData = await fetchThreatFoxIOCs(30);
    console.log('[ThreatFox] Processing', threatfoxData.length, 'real IOCs');
    
    for (const ioc of threatfoxData.slice(0, 50)) {
      // Only process IP-based IOCs
      if (ioc.iocType.includes('ip')) {
        const ip = ioc.ioc.split(':')[0];
        const geo = await geolocateIP(ip);
        
        if (geo) {
          threats.push({
            id: ioc.id,
            timestamp: new Date(ioc.firstSeen),
            lat: geo.lat,
            lon: geo.lon,
            country: geo.country,
            city: geo.city,
            threatType: ioc.threatType || 'IOC',
            severity: ioc.confidenceLevel > 80 ? 'critical' : ioc.confidenceLevel > 60 ? 'high' : 'medium',
            indicator: ioc.ioc,
            source: 'ThreatFox',
            count: 1,
            malware: ioc.malwarePrintable,
          });
        }
        
        await new Promise(resolve => setTimeout(resolve, 1500));
      }
    }

    // 4. Fetch REAL APT group locations
    const aptData = await getAPTThreatMapData();
    console.log('[APTmap] Processing', aptData.length, 'real APT groups');
    
    aptData.forEach(apt => {
      threats.push({
        id: apt.id,
        timestamp: new Date(),
        lat: apt.lat,
        lon: apt.lon,
        country: apt.country,
        threatType: 'APT Group',
        severity: apt.severity,
        indicator: apt.name,
        source: 'APTmap',
        count: 1,
        malware: apt.ttps.join(', ').substring(0, 50),
      });
    });

    console.log('[LiveThreatMap] Total REAL threats loaded:', threats.length);
    return threats;

  } catch (error) {
    console.error('[LiveThreatMap] Error fetching real threat data:', error);
    return threats; // Return whatever we managed to fetch
  }
}

// Fetch real-time threat updates (call this periodically)
export async function fetchThreatUpdates(): Promise<ThreatPoint[]> {
  console.log('[ThreatUpdates] Fetching latest real threat data...');
  return await fetchLiveThreatMap();
}

// Get threat statistics from real data
export async function getThreatStatistics() {
  const threats = await fetchLiveThreatMap();
  
  return {
    total: threats.length,
    critical: threats.filter(t => t.severity === 'critical').length,
    high: threats.filter(t => t.severity === 'high').length,
    medium: threats.filter(t => t.severity === 'medium').length,
    low: threats.filter(t => t.severity === 'low').length,
    bySource: threats.reduce((acc, t) => {
      acc[t.source] = (acc[t.source] || 0) + 1;
      return acc;
    }, {} as Record<string, number>),
    byCountry: threats.reduce((acc, t) => {
      acc[t.country] = (acc[t.country] || 0) + 1;
      return acc;
    }, {} as Record<string, number>),
    topMalware: [...new Set(threats.map(t => t.malware).filter(Boolean))]
      .slice(0, 10),
  };
}

export default {
  fetchLiveThreatMap,
  fetchThreatUpdates,
  getThreatStatistics,
};
