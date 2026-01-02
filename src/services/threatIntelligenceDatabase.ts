// OpenCTI-style Threat Intelligence Database Service
// Uses localStorage since threat_intelligence table doesn't exist

import type { ThreatIntelligence, ThreatActor, IoC, Campaign, Malware } from '@/types/osint';

export interface ThreatIntelligenceRecord {
  id: string;
  source_id: string;
  source_name: string;
  threat_type: 'apt' | 'malware' | 'ransomware' | 'campaign' | 'ioc' | 'actor' | 'vulnerability';
  severity_level: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence_level: number;
  title: string;
  description: string;
  indicators: any[];
  ttps: any[];
  targets: any[];
  attribution: any;
  timeline: any;
  metadata: any;
  tags: string[];
  status: 'active' | 'inactive' | 'investigating';
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
  raw_data: any;
}

type ThreatType = 'apt' | 'malware' | 'ransomware' | 'campaign' | 'ioc' | 'actor' | 'vulnerability';
type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

const STORAGE_KEY = 'threat_intel_records';

function getStoredRecords(): ThreatIntelligenceRecord[] {
  try {
    const data = localStorage.getItem(STORAGE_KEY);
    return data ? JSON.parse(data) : [];
  } catch {
    return [];
  }
}

function saveStoredRecords(records: ThreatIntelligenceRecord[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(records.slice(0, 500)));
  } catch (e) {
    console.error('[ThreatDB] Storage error:', e);
  }
}

export class ThreatIntelligenceDatabase {
  private syncQueue: Map<string, any> = new Map();
  private isProcessing = false;

  constructor() {
    this.ensureSampleData();
  }

  private async ensureSampleData() {
    const stats = await this.getThreatStatistics();
    if (stats.total === 0) {
      console.log('[ThreatDB] No existing data, adding sample threats for dashboard');
      const samples = [
        { name: 'LockBit 3.0 Ransomware Campaign', type: 'ransomware' as ThreatType, severity: 'critical' as SeverityLevel, indicators: ['192.168.1.100', 'lockbit3.onion'], ttps: ['T1486', 'T1490', 'T1083'], attribution: 'LockBit Group' },
        { name: 'RedLine Stealer Infrastructure', type: 'malware' as ThreatType, severity: 'high' as SeverityLevel, indicators: ['stealer.exe', '185.225.73.244'], ttps: ['T1555', 'T1081', 'T1005'] },
        { name: 'BlackCat/ALPHV Ransomware', type: 'ransomware' as ThreatType, severity: 'critical' as SeverityLevel, indicators: ['alphv.exe', 'blackcat.onion'], ttps: ['T1486', 'T1083', 'T1082'] },
      ];
      for (const sample of samples) {
        await this.storeThreatIntelligence(sample);
      }
      console.log(`[ThreatDB] Added ${samples.length} sample threats`);
    }
  }

  initializeRealtimeSync() {
    console.log('[ThreatDB] Realtime sync initialized (localStorage mode)');
  }

  async storeThreatIntelligence(threat: any): Promise<ThreatIntelligenceRecord | null> {
    const records = getStoredRecords();
    const sourceId = `threat_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    const existing = records.find(r => r.source_id === sourceId && r.source_name === 'InitialData');
    if (existing) return existing;

    const record: ThreatIntelligenceRecord = {
      id: `rec_${Date.now()}`,
      source_id: sourceId,
      source_name: threat.source || 'InitialData',
      threat_type: threat.type || 'malware',
      severity_level: threat.severity || 'medium',
      confidence_level: threat.confidence || 60,
      title: threat.name || 'Unknown Threat',
      description: threat.description || '',
      indicators: threat.indicators || [],
      ttps: threat.ttps || [],
      targets: threat.targets || [],
      attribution: threat.attribution || null,
      timeline: null,
      metadata: threat,
      tags: threat.tags || [],
      status: 'active',
      first_seen: new Date().toISOString(),
      last_seen: new Date().toISOString(),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      raw_data: threat,
    };

    records.unshift(record);
    saveStoredRecords(records);
    return record;
  }

  async getThreatStatistics(): Promise<{ total: number; byType: Record<string, number>; bySeverity: Record<string, number>; bySource: Record<string, number>; recentThreats: number }> {
    const records = getStoredRecords();
    const byType: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};
    const bySource: Record<string, number> = {};

    records.forEach(r => {
      byType[r.threat_type] = (byType[r.threat_type] || 0) + 1;
      bySeverity[r.severity_level] = (bySeverity[r.severity_level] || 0) + 1;
      bySource[r.source_name] = (bySource[r.source_name] || 0) + 1;
    });

    const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;
    const recentThreats = records.filter(r => new Date(r.created_at).getTime() > oneDayAgo).length;

    return { total: records.length, byType, bySeverity, bySource, recentThreats };
  }

  async searchThreats(query: string, limit = 50): Promise<ThreatIntelligenceRecord[]> {
    const records = getStoredRecords();
    const lowerQuery = query.toLowerCase();
    return records
      .filter(r => r.title.toLowerCase().includes(lowerQuery) || r.description.toLowerCase().includes(lowerQuery))
      .slice(0, limit);
  }

  async getRecentThreats(limit = 20): Promise<ThreatIntelligenceRecord[]> {
    return getStoredRecords().slice(0, limit);
  }

  cleanup() {
    console.log('[ThreatDB] Cleanup complete');
  }
}

export const threatDatabase = new ThreatIntelligenceDatabase();
export default threatDatabase;
