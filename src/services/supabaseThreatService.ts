// ============================================================================
// supabaseThreatService.ts
// THREAT INTELLIGENCE DATABASE SERVICE (localStorage-based)
// ============================================================================
// Note: Since the 'threats' table doesn't exist in the database,
// this service uses localStorage for threat storage.
// ============================================================================

import type { CleanedAPTData, ProcessedThreat, ThreatCorrelation } from './llmThreatProcessorService';
import type { MalwareIndicator, C2Server } from './mispFeedService';

/* ============================================================================
   TYPES
============================================================================ */

export interface StoredThreat {
  id: string;
  type: 'apt' | 'malware' | 'c2' | 'ioc';
  name: string;
  severity: string;
  country?: string;
  indicators: string[];
  metadata: Record<string, any>;
  source: string;
  first_seen: string;
  last_seen: string;
  created_at?: string;
  updated_at?: string;
}

export interface ThreatStats {
  total_threats: number;
  by_severity: Record<string, number>;
  by_type: Record<string, number>;
  by_country: { country: string; count: number }[];
  recent_threats: StoredThreat[];
  last_updated: string;
}

const STORAGE_KEY = 'threat_intelligence_db';

/* ============================================================================
   LOCAL STORAGE HELPERS
============================================================================ */

function getStoredThreats(): StoredThreat[] {
  try {
    const data = localStorage.getItem(STORAGE_KEY);
    return data ? JSON.parse(data) : [];
  } catch {
    return [];
  }
}

function saveStoredThreats(threats: StoredThreat[]): void {
  try {
    // Keep only the most recent 1000 threats
    const trimmed = threats.slice(0, 1000);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(trimmed));
  } catch (e) {
    console.error('[ThreatDB] Storage error:', e);
  }
}

/* ============================================================================
   APT GROUPS SYNC
============================================================================ */

export async function syncAPTGroups(aptGroups: CleanedAPTData[]): Promise<{ success: boolean; synced: number; errors: string[] }> {
  const errors: string[] = [];
  let synced = 0;
  
  console.log(`[ThreatDB] Syncing ${aptGroups.length} APT groups to localStorage...`);
  
  const existingThreats = getStoredThreats();
  const existingIds = new Set(existingThreats.map(t => t.id));
  const newThreats: StoredThreat[] = [];
  
  for (const apt of aptGroups) {
    try {
      const threat: StoredThreat = {
        id: `apt-${apt.name.toLowerCase().replace(/\s+/g, '-')}`,
        type: 'apt',
        name: apt.name,
        severity: apt.threatLevel,
        country: apt.country,
        indicators: apt.tools.map(t => t.name),
        metadata: {
          aliases: apt.aliases,
          sponsorship: apt.sponsorship,
          motivations: apt.motivations,
          targetSectors: apt.targetSectors,
          targetCountries: apt.targetCountries,
          activeSince: apt.activeSince,
          ttps: apt.ttps,
          summary: apt.summary,
        },
        source: 'APTmap',
        first_seen: apt.activeSince || new Date().toISOString(),
        last_seen: new Date().toISOString(),
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      
      if (existingIds.has(threat.id)) {
        // Update existing
        const idx = existingThreats.findIndex(t => t.id === threat.id);
        if (idx >= 0) {
          existingThreats[idx] = { ...existingThreats[idx], ...threat };
        }
      } else {
        newThreats.push(threat);
      }
      synced++;
    } catch (err) {
      errors.push(`APT ${apt.name}: ${err}`);
    }
  }
  
  saveStoredThreats([...newThreats, ...existingThreats]);
  console.log(`[ThreatDB] Synced ${synced}/${aptGroups.length} APT groups`);
  return { success: errors.length === 0, synced, errors };
}

/* ============================================================================
   MALWARE INDICATORS SYNC
============================================================================ */

export async function syncMalwareIndicators(indicators: MalwareIndicator[]): Promise<{ success: boolean; synced: number; errors: string[] }> {
  const errors: string[] = [];
  let synced = 0;
  
  console.log(`[ThreatDB] Syncing ${indicators.length} malware indicators to localStorage...`);
  
  const existingThreats = getStoredThreats();
  const existingIds = new Set(existingThreats.map(t => t.id));
  const newThreats: StoredThreat[] = [];
  
  for (const indicator of indicators) {
    try {
      const threat: StoredThreat = {
        id: indicator.id,
        type: indicator.type === 'c2' ? 'c2' : 'ioc',
        name: indicator.malwareFamily || indicator.value.slice(0, 50),
        severity: indicator.severity,
        country: indicator.metadata?.country,
        indicators: [indicator.value],
        metadata: {
          threatType: indicator.threatType,
          confidence: indicator.confidence,
          tags: indicator.tags,
          ...indicator.metadata,
        },
        source: indicator.source,
        first_seen: indicator.firstSeen,
        last_seen: indicator.lastSeen,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      
      if (!existingIds.has(threat.id)) {
        newThreats.push(threat);
        synced++;
      }
    } catch (err) {
      errors.push(`Indicator ${indicator.id}: ${err}`);
    }
  }
  
  saveStoredThreats([...newThreats, ...existingThreats]);
  console.log(`[ThreatDB] Synced ${synced}/${indicators.length} indicators`);
  return { success: errors.length === 0, synced, errors };
}

/* ============================================================================
   C2 SERVERS SYNC
============================================================================ */

export async function syncC2Servers(servers: C2Server[]): Promise<{ success: boolean; synced: number; errors: string[] }> {
  const errors: string[] = [];
  let synced = 0;
  
  console.log(`[ThreatDB] Syncing ${servers.length} C2 servers to localStorage...`);
  
  const existingThreats = getStoredThreats();
  const existingIds = new Set(existingThreats.map(t => t.id));
  const newThreats: StoredThreat[] = [];
  
  for (const server of servers) {
    try {
      const threat: StoredThreat = {
        id: server.id,
        type: 'c2',
        name: server.malwareFamily,
        severity: server.status === 'online' ? 'critical' : 'high',
        country: server.countryCode,
        indicators: [`${server.ip}:${server.port}`],
        metadata: {
          ip: server.ip,
          port: server.port,
          status: server.status,
          asn: server.asn,
          asName: server.asName,
        },
        source: 'FeodoTracker',
        first_seen: server.firstSeen,
        last_seen: server.lastOnline,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      
      if (!existingIds.has(threat.id)) {
        newThreats.push(threat);
        synced++;
      }
    } catch (err) {
      errors.push(`C2 ${server.id}: ${err}`);
    }
  }
  
  saveStoredThreats([...newThreats, ...existingThreats]);
  console.log(`[ThreatDB] Synced ${synced}/${servers.length} C2 servers`);
  return { success: errors.length === 0, synced, errors };
}

/* ============================================================================
   THREAT QUERIES
============================================================================ */

export async function getRecentThreats(limit: number = 100): Promise<StoredThreat[]> {
  const threats = getStoredThreats();
  return threats
    .sort((a, b) => new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime())
    .slice(0, limit);
}

export async function getThreatsBySeverity(severity: string): Promise<StoredThreat[]> {
  const threats = getStoredThreats();
  return threats
    .filter(t => t.severity === severity)
    .sort((a, b) => new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime())
    .slice(0, 100);
}

export async function getThreatsByCountry(country: string): Promise<StoredThreat[]> {
  const threats = getStoredThreats();
  return threats
    .filter(t => t.country === country)
    .sort((a, b) => new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime())
    .slice(0, 100);
}

export async function searchThreats(query: string): Promise<StoredThreat[]> {
  const threats = getStoredThreats();
  const lowerQuery = query.toLowerCase();
  
  return threats
    .filter(t => 
      t.name.toLowerCase().includes(lowerQuery) ||
      t.indicators.some(i => i.toLowerCase().includes(lowerQuery))
    )
    .sort((a, b) => new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime())
    .slice(0, 50);
}

/* ============================================================================
   STATISTICS
============================================================================ */

export async function getThreatStats(): Promise<ThreatStats> {
  const threats = getStoredThreats();
  
  const bySeverity: Record<string, number> = {};
  const byType: Record<string, number> = {};
  const countryCount: Record<string, number> = {};
  
  threats.forEach(threat => {
    bySeverity[threat.severity] = (bySeverity[threat.severity] || 0) + 1;
    byType[threat.type] = (byType[threat.type] || 0) + 1;
    if (threat.country) {
      countryCount[threat.country] = (countryCount[threat.country] || 0) + 1;
    }
  });
  
  const byCountry = Object.entries(countryCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([country, count]) => ({ country, count }));
  
  const recentThreats = await getRecentThreats(10);
  
  return {
    total_threats: threats.length,
    by_severity: bySeverity,
    by_type: byType,
    by_country: byCountry,
    recent_threats: recentThreats,
    last_updated: new Date().toISOString(),
  };
}

/* ============================================================================
   FULL SYNC
============================================================================ */

export async function syncAllThreatData(data: {
  aptGroups?: CleanedAPTData[];
  indicators?: MalwareIndicator[];
  c2Servers?: C2Server[];
}): Promise<{ success: boolean; summary: string }> {
  const results: string[] = [];
  let hasErrors = false;
  
  if (data.aptGroups && data.aptGroups.length > 0) {
    const aptResult = await syncAPTGroups(data.aptGroups);
    results.push(`APT Groups: ${aptResult.synced} synced`);
    if (!aptResult.success) hasErrors = true;
  }
  
  if (data.indicators && data.indicators.length > 0) {
    const indicatorResult = await syncMalwareIndicators(data.indicators);
    results.push(`Indicators: ${indicatorResult.synced} synced`);
    if (!indicatorResult.success) hasErrors = true;
  }
  
  if (data.c2Servers && data.c2Servers.length > 0) {
    const c2Result = await syncC2Servers(data.c2Servers);
    results.push(`C2 Servers: ${c2Result.synced} synced`);
    if (!c2Result.success) hasErrors = true;
  }
  
  return {
    success: !hasErrors,
    summary: results.join(' | '),
  };
}

/* ============================================================================
   REAL-TIME SUBSCRIPTION (simulated with polling for localStorage)
============================================================================ */

export function subscribeToThreats(callback: (threat: StoredThreat) => void): () => void {
  let lastCount = getStoredThreats().length;
  
  const interval = setInterval(() => {
    const threats = getStoredThreats();
    if (threats.length > lastCount) {
      // New threats added
      const newThreats = threats.slice(0, threats.length - lastCount);
      newThreats.forEach(callback);
      lastCount = threats.length;
    }
  }, 5000);
  
  return () => clearInterval(interval);
}

/* ============================================================================
   EXPORTS
============================================================================ */

export default {
  syncAPTGroups,
  syncMalwareIndicators,
  syncC2Servers,
  syncAllThreatData,
  getRecentThreats,
  getThreatsBySeverity,
  getThreatsByCountry,
  searchThreats,
  getThreatStats,
  subscribeToThreats,
};
