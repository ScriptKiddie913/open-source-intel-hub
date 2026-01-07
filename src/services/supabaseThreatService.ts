// ============================================================================
// supabaseThreatService.ts
// SUPABASE THREAT INTELLIGENCE DATABASE SERVICE
// ============================================================================
// ✔ Stores threat indicators in Supabase database
// ✔ Syncs APT groups and malware data
// ✔ Provides real-time threat queries
// ✔ Manages threat history and statistics
// ============================================================================

import { supabase } from '@/integrations/supabase/client';
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

/* ============================================================================
   APT GROUPS SYNC
============================================================================ */

export async function syncAPTGroups(aptGroups: CleanedAPTData[]): Promise<{ success: boolean; synced: number; errors: string[] }> {
  const errors: string[] = [];
  let synced = 0;
  
  console.log(`[Supabase] Syncing ${aptGroups.length} APT groups...`);
  
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
      };
      
      const { error } = await (supabase as any)
        .from('threats')
        .upsert(threat, { onConflict: 'id' });
      
      if (error) {
        // If table doesn't exist, try creating it
        if (error.code === '42P01') {
          console.log('[Supabase] Threats table not found, storing in local cache');
          break;
        }
        errors.push(`APT ${apt.name}: ${error.message}`);
      } else {
        synced++;
      }
    } catch (err) {
      errors.push(`APT ${apt.name}: ${err}`);
    }
  }
  
  console.log(`[Supabase] Synced ${synced}/${aptGroups.length} APT groups`);
  return { success: errors.length === 0, synced, errors };
}

/* ============================================================================
   MALWARE INDICATORS SYNC
============================================================================ */

export async function syncMalwareIndicators(indicators: MalwareIndicator[]): Promise<{ success: boolean; synced: number; errors: string[] }> {
  const errors: string[] = [];
  let synced = 0;
  
  console.log(`[Supabase] Syncing ${indicators.length} malware indicators...`);
  
  // Batch insert for efficiency
  const batchSize = 50;
  const batches = [];
  
  for (let i = 0; i < indicators.length; i += batchSize) {
    batches.push(indicators.slice(i, i + batchSize));
  }
  
  for (const batch of batches) {
    try {
      const threats: StoredThreat[] = batch.map(indicator => ({
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
      }));
      
      const { error } = await (supabase as any)
        .from('threats')
        .upsert(threats, { onConflict: 'id' });
      
      if (error) {
        if (error.code === '42P01') {
          console.log('[Supabase] Threats table not found');
          break;
        }
        errors.push(`Batch error: ${error.message}`);
      } else {
        synced += batch.length;
      }
    } catch (err) {
      errors.push(`Batch error: ${err}`);
    }
  }
  
  console.log(`[Supabase] Synced ${synced}/${indicators.length} indicators`);
  return { success: errors.length === 0, synced, errors };
}

/* ============================================================================
   C2 SERVERS SYNC
============================================================================ */

export async function syncC2Servers(servers: C2Server[]): Promise<{ success: boolean; synced: number; errors: string[] }> {
  const errors: string[] = [];
  let synced = 0;
  
  console.log(`[Supabase] Syncing ${servers.length} C2 servers...`);
  
  const threats: StoredThreat[] = servers.map(server => ({
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
  }));
  
  try {
    const { error } = await (supabase as any)
      .from('threats')
      .upsert(threats, { onConflict: 'id' });
    
    if (error) {
      if (error.code === '42P01') {
        console.log('[Supabase] Threats table not found');
        return { success: false, synced: 0, errors: ['Table not found'] };
      }
      errors.push(error.message);
    } else {
      synced = threats.length;
    }
  } catch (err) {
    errors.push(`${err}`);
  }
  
  console.log(`[Supabase] Synced ${synced}/${servers.length} C2 servers`);
  return { success: errors.length === 0, synced, errors };
}

/* ============================================================================
   THREAT QUERIES
============================================================================ */

export async function getRecentThreats(limit: number = 100): Promise<StoredThreat[]> {
  try {
    const { data, error } = await (supabase as any)
      .from('threats')
      .select('*')
      .order('last_seen', { ascending: false })
      .limit(limit);
    
    if (error) {
      console.error('[Supabase] Query error:', error);
      return [];
    }
    
    return data || [];
  } catch (err) {
    console.error('[Supabase] Query error:', err);
    return [];
  }
}

export async function getThreatsBySeverity(severity: string): Promise<StoredThreat[]> {
  try {
    const { data, error } = await (supabase as any)
      .from('threats')
      .select('*')
      .eq('severity', severity)
      .order('last_seen', { ascending: false })
      .limit(100);
    
    if (error) {
      console.error('[Supabase] Query error:', error);
      return [];
    }
    
    return data || [];
  } catch (err) {
    console.error('[Supabase] Query error:', err);
    return [];
  }
}

export async function getThreatsByCountry(country: string): Promise<StoredThreat[]> {
  try {
    const { data, error } = await (supabase as any)
      .from('threats')
      .select('*')
      .eq('country', country)
      .order('last_seen', { ascending: false })
      .limit(100);
    
    if (error) {
      console.error('[Supabase] Query error:', error);
      return [];
    }
    
    return data || [];
  } catch (err) {
    console.error('[Supabase] Query error:', err);
    return [];
  }
}

export async function searchThreats(query: string): Promise<StoredThreat[]> {
  try {
    const { data, error } = await (supabase as any)
      .from('threats')
      .select('*')
      .or(`name.ilike.%${query}%,indicators.cs.{${query}}`)
      .order('last_seen', { ascending: false })
      .limit(50);
    
    if (error) {
      console.error('[Supabase] Search error:', error);
      return [];
    }
    
    return data || [];
  } catch (err) {
    console.error('[Supabase] Search error:', err);
    return [];
  }
}

/* ============================================================================
   STATISTICS
============================================================================ */

export async function getThreatStats(): Promise<ThreatStats> {
  try {
    // Get total count
    const { count: totalCount } = await (supabase as any)
      .from('threats')
      .select('*', { count: 'exact', head: true });
    
    // Get by severity
    const { data: severityData } = await (supabase as any)
      .from('threats')
      .select('severity');
    
    const bySeverity: Record<string, number> = {};
    (severityData || []).forEach((item: { severity: string }) => {
      bySeverity[item.severity] = (bySeverity[item.severity] || 0) + 1;
    });
    
    // Get by type
    const { data: typeData } = await (supabase as any)
      .from('threats')
      .select('type');
    
    const byType: Record<string, number> = {};
    (typeData || []).forEach((item: { type: string }) => {
      byType[item.type] = (byType[item.type] || 0) + 1;
    });
    
    // Get by country (top 10)
    const { data: countryData } = await (supabase as any)
      .from('threats')
      .select('country');
    
    const countryCount: Record<string, number> = {};
    (countryData || []).forEach((item: { country?: string }) => {
      if (item.country) {
        countryCount[item.country] = (countryCount[item.country] || 0) + 1;
      }
    });
    
    const byCountry = Object.entries(countryCount)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([country, count]) => ({ country, count }));
    
    // Get recent threats
    const recentThreats = await getRecentThreats(10);
    
    return {
      total_threats: totalCount || 0,
      by_severity: bySeverity,
      by_type: byType,
      by_country: byCountry,
      recent_threats: recentThreats,
      last_updated: new Date().toISOString(),
    };
  } catch (err) {
    console.error('[Supabase] Stats error:', err);
    return {
      total_threats: 0,
      by_severity: {},
      by_type: {},
      by_country: [],
      recent_threats: [],
      last_updated: new Date().toISOString(),
    };
  }
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
   REAL-TIME SUBSCRIPTION
============================================================================ */

export function subscribeToThreats(callback: (threat: StoredThreat) => void): () => void {
  const subscription = supabase
    .channel('threats_channel')
    .on('postgres_changes', 
      { event: 'INSERT', schema: 'public', table: 'threats' },
      (payload) => {
        callback(payload.new as StoredThreat);
      }
    )
    .subscribe();
  
  return () => {
    subscription.unsubscribe();
  };
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
