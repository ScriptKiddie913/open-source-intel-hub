// OpenCTI-style Threat Intelligence Database Service
// Handles real-time storage and synchronization of threat intelligence data

import { supabase } from '@/integrations/supabase/client';
import type { ThreatIntelligence, ThreatActor, IoC, Campaign, Malware } from '@/types/osint';

// Database table definitions following OpenCTI schema patterns
export interface ThreatIntelligenceRecord {
  id: string;
  source_id: string;
  source_name: string;
  threat_type: 'apt' | 'malware' | 'ransomware' | 'campaign' | 'ioc' | 'actor' | 'vulnerability';
  severity_level: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence_level: number; // 0-100
  title: string;
  description: string;
  indicators: any[]; // IoCs array
  ttps: any[]; // Tactics, Techniques, Procedures
  targets: any[]; // Targeted industries/countries
  attribution: any; // Threat actor attribution
  timeline: any; // Attack timeline
  metadata: any; // Additional metadata
  tags: string[];
  status: 'active' | 'inactive' | 'investigating';
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
  raw_data: any; // Original API response
}

// Threat type union for strict typing
type ThreatType = 'apt' | 'malware' | 'ransomware' | 'campaign' | 'ioc' | 'actor' | 'vulnerability';
type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

// Real-time database synchronization class
export class ThreatIntelligenceDatabase {
  private syncQueue: Map<string, any> = new Map();
  private isProcessing = false;
  private syncInterval: ReturnType<typeof setInterval> | null = null;
  private realtimeSubscription: any = null;

  constructor() {
    this.initializeRealtimeSync();
    this.ensureSampleData();
  }

  // Ensure some sample threat data exists for initial dashboard display
  private async ensureSampleData() {
    try {
      const stats = await this.getThreatStatistics();
      if (stats.totalThreats === 0) {
        console.log('[ThreatDB] No existing data, adding sample threats for dashboard');
        
        const sampleThreats = [
          {
            name: 'LockBit 3.0 Ransomware Campaign',
            description: 'Active ransomware campaign targeting healthcare and financial institutions',
            type: 'ransomware',
            severity: 'critical',
            indicators: ['192.168.1.100', 'lockbit3.onion'],
            ttps: ['T1486', 'T1490', 'T1083'],
            attribution: 'LockBit Group'
          },
          {
            name: 'RedLine Stealer Infrastructure',
            description: 'Information stealing malware targeting credentials and crypto wallets',
            type: 'malware', 
            severity: 'high',
            indicators: ['stealer.exe', '185.225.73.244'],
            ttps: ['T1555', 'T1081', 'T1005']
          },
          {
            name: 'BlackCat/ALPHV Ransomware',
            description: 'Cross-platform ransomware written in Rust',
            type: 'ransomware',
            severity: 'critical',
            indicators: ['alphv.exe', 'blackcat.onion'],
            ttps: ['T1486', 'T1083', 'T1082']
          }
        ];
        
        for (const threat of sampleThreats) {
          await this.storeThreatIntelligence(threat, 'InitialData');
        }
        
        console.log('[ThreatDB] Added', sampleThreats.length, 'sample threats');
      }
    } catch (error) {
      console.error('[ThreatDB] Failed to ensure sample data:', error);
    }
  }

  // Initialize real-time database synchronization
  private async initializeRealtimeSync() {
    try {
      // Subscribe to real-time changes
      this.realtimeSubscription = supabase
        .channel('threat-intelligence-changes')
        .on('postgres_changes', {
          event: '*',
          schema: 'public',
          table: 'threat_intelligence'
        }, (payload) => {
          console.log('[ThreatDB] Real-time update received:', payload);
          this.handleRealtimeUpdate(payload);
        })
        .subscribe();

      // Start continuous sync process
      this.syncInterval = setInterval(() => {
        this.processSyncQueue();
      }, 30000); // Every 30 seconds

      console.log('[ThreatDB] Real-time synchronization initialized');
    } catch (error) {
      console.error('[ThreatDB] Failed to initialize real-time sync:', error);
    }
  }

  // Handle real-time database updates
  private handleRealtimeUpdate(payload: any) {
    const { eventType, new: newRecord, old: oldRecord } = payload;
    
    switch (eventType) {
      case 'INSERT':
        console.log('[ThreatDB] New threat intelligence record:', newRecord);
        break;
      case 'UPDATE':
        console.log('[ThreatDB] Updated threat intelligence record:', newRecord);
        break;
      case 'DELETE':
        console.log('[ThreatDB] Deleted threat intelligence record:', oldRecord);
        break;
    }
  }

  // Store threat intelligence following OpenCTI patterns
  async storeThreatIntelligence(data: any, source: string): Promise<string> {
    try {
      const record: Partial<ThreatIntelligenceRecord> = {
        source_id: data.id || data.uuid || this.generateUniqueId(),
        source_name: source,
        threat_type: this.classifyThreatType(data),
        severity_level: this.calculateSeverity(data),
        confidence_level: this.calculateConfidence(data, source),
        title: data.name || data.title || data.summary || 'Unknown Threat',
        description: data.description || data.details || data.summary || '',
        indicators: this.extractIndicators(data),
        ttps: this.extractTTPs(data),
        targets: this.extractTargets(data),
        attribution: this.extractAttribution(data),
        timeline: this.extractTimeline(data),
        metadata: this.extractMetadata(data),
        tags: this.extractTags(data),
        status: 'active',
        first_seen: data.first_seen || data.created || new Date().toISOString(),
        last_seen: data.last_seen || data.updated || new Date().toISOString(),
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        raw_data: data
      };

      // Check for existing record to avoid duplicates
      const existing = await this.findExistingRecord(record.source_id!, source);
      if (existing) {
        console.log('[ThreatDB] Updating existing record:', record.source_id);
        return this.updateThreatRecord(existing.id, record);
      }

      // Insert new record
      const { data: insertedRecord, error } = await supabase
        .from('threat_intelligence')
        .insert([record])
        .select()
        .single();

      if (error) {
        // Log but don't throw - allow system to continue with other threats
        console.warn('[ThreatDB] Failed to store threat intelligence:', error);
        return 'error_' + Date.now();
      }

      console.log('[ThreatDB] Stored new threat intelligence:', insertedRecord?.id || 'unknown');
      return insertedRecord?.id || 'stored_' + Date.now();

    } catch (error) {
      console.warn('[ThreatDB] Error storing threat intelligence (non-fatal):', error);
      return 'error_' + Date.now();
    }
  }

  // Update existing threat record
  async updateThreatRecord(id: string, updates: Partial<ThreatIntelligenceRecord>): Promise<string> {
    try {
      updates.updated_at = new Date().toISOString();

      const { data, error } = await supabase
        .from('threat_intelligence')
        .update(updates)
        .eq('id', id)
        .select()
        .single();

      if (error) throw error;

      console.log('[ThreatDB] Updated threat record:', id);
      return id;

    } catch (error) {
      console.error('[ThreatDB] Error updating threat record:', error);
      throw error;
    }
  }

  // Find existing record to prevent duplicates
  private async findExistingRecord(sourceId: string, sourceName: string): Promise<any> {
    try {
      const { data, error } = await supabase
        .from('threat_intelligence')
        .select('*')
        .eq('source_id', sourceId)
        .eq('source_name', sourceName)
        .single();

      if (error && error.code !== 'PGRST116') { // PGRST116 = no rows returned
        throw error;
      }

      return data;
    } catch (error) {
      console.error('[ThreatDB] Error finding existing record:', error);
      return null;
    }
  }

  // Bulk store multiple threat intelligence records
  async bulkStoreThreatIntelligence(records: any[], source: string): Promise<string[]> {
    const storedIds: string[] = [];
    
    try {
      // Process in batches to avoid overwhelming the database
      const batchSize = 50;
      for (let i = 0; i < records.length; i += batchSize) {
        const batch = records.slice(i, i + batchSize);
        
        const batchPromises = batch.map(record => 
          this.storeThreatIntelligence(record, source)
        );
        
        const batchResults = await Promise.allSettled(batchPromises);
        
        batchResults.forEach((result, index) => {
          if (result.status === 'fulfilled') {
            storedIds.push(result.value);
          } else {
            console.error(`[ThreatDB] Failed to store record ${i + index}:`, result.reason);
          }
        });

        // Small delay between batches
        await new Promise(resolve => setTimeout(resolve, 100));
      }

      console.log('[ThreatDB] Bulk storage completed:', storedIds.length, 'records stored');
      return storedIds;

    } catch (error) {
      console.error('[ThreatDB] Error in bulk storage:', error);
      throw error;
    }
  }

  // Query threat intelligence with filters
  async queryThreatIntelligence(filters: {
    threatType?: string;
    severityLevel?: string;
    source?: string;
    timeRange?: { from: string; to: string };
    tags?: string[];
    confidence?: number;
    limit?: number;
    offset?: number;
  } = {}): Promise<ThreatIntelligenceRecord[]> {
    try {
      let query = supabase.from('threat_intelligence').select('*');

      // Apply filters
      if (filters.threatType) {
        query = query.eq('threat_type', filters.threatType);
      }
      if (filters.severityLevel) {
        query = query.eq('severity_level', filters.severityLevel);
      }
      if (filters.source) {
        query = query.eq('source_name', filters.source);
      }
      if (filters.confidence) {
        query = query.gte('confidence_level', filters.confidence);
      }
      if (filters.timeRange) {
        query = query
          .gte('created_at', filters.timeRange.from)
          .lte('created_at', filters.timeRange.to);
      }
      if (filters.tags && filters.tags.length > 0) {
        query = query.contains('tags', filters.tags);
      }

      // Pagination
      const limit = filters.limit || 100;
      const offset = filters.offset || 0;
      query = query.range(offset, offset + limit - 1);

      // Order by most recent
      query = query.order('created_at', { ascending: false });

      const { data, error } = await query;

      if (error) throw error;

      console.log('[ThreatDB] Query completed:', data?.length, 'records found');
      return data || [];

    } catch (error) {
      console.error('[ThreatDB] Query error:', error);
      throw error;
    }
  }

  // Get threat intelligence statistics
  async getThreatStatistics(): Promise<{
    totalThreats: number;
    byType: Record<string, number>;
    bySeverity: Record<string, number>;
    bySource: Record<string, number>;
    recentCount: number;
  }> {
    try {
      const { data: totalData, error: totalError } = await supabase
        .from('threat_intelligence')
        .select('threat_type, severity_level, source_name, created_at');

      if (totalError) {
        console.warn('[ThreatDB] Database query failed, using default stats:', totalError);
        // Return default stats structure if database unavailable
        return {
          totalThreats: 0,
          byType: {},
          bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
          bySource: {},
          recentCount: 0
        };
      }

      const now = new Date();
      const last24Hours = new Date(now.getTime() - 24 * 60 * 60 * 1000);

      const stats = {
        totalThreats: totalData?.length || 0,
        byType: {} as Record<string, number>,
        bySeverity: { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>,
        bySource: {} as Record<string, number>,
        recentCount: 0
      };

      totalData?.forEach(record => {
        // Count by type
        stats.byType[record.threat_type] = (stats.byType[record.threat_type] || 0) + 1;
        
        // Count by severity
        stats.bySeverity[record.severity_level] = (stats.bySeverity[record.severity_level] || 0) + 1;
        
        // Count by source
        stats.bySource[record.source_name] = (stats.bySource[record.source_name] || 0) + 1;
        
        // Count recent (last 24 hours)
        if (new Date(record.created_at) > last24Hours) {
          stats.recentCount++;
        }
      });

      return stats;

    } catch (error) {
      console.warn('[ThreatDB] Error getting statistics (non-fatal):', error);
      // Return default stats if database completely unavailable
      return {
        totalThreats: 0,
        byType: {},
        bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
        bySource: {},
        recentCount: 0
      };
    }
  }

  // Search threat intelligence
  async searchThreatIntelligence(query: string): Promise<ThreatIntelligenceRecord[]> {
    try {
      const { data, error } = await supabase
        .from('threat_intelligence')
        .select('*')
        .or(`title.ilike.%${query}%,description.ilike.%${query}%,tags.cs.{${query}}`)
        .order('confidence_level', { ascending: false })
        .limit(50);

      if (error) throw error;

      return data || [];
    } catch (error) {
      console.error('[ThreatDB] Search error:', error);
      throw error;
    }
  }

  // Helper methods for data extraction and classification
  private generateUniqueId(): string {
    return 'threat_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
  }

  private classifyThreatType(data: any): ThreatType {
    const content = JSON.stringify(data).toLowerCase();
    
    if (content.includes('apt') || content.includes('advanced persistent')) return 'apt';
    if (content.includes('malware') || content.includes('virus') || content.includes('trojan')) return 'malware';
    if (content.includes('ransomware') || content.includes('crypto')) return 'ransomware';
    if (content.includes('campaign') || content.includes('operation')) return 'campaign';
    if (content.includes('ioc') || content.includes('indicator')) return 'ioc';
    if (content.includes('actor') || content.includes('group')) return 'actor';
    if (content.includes('cve') || content.includes('vulnerability')) return 'vulnerability';
    
    return 'malware'; // Default
  }

  private calculateSeverity(data: any): SeverityLevel {
    const content = JSON.stringify(data).toLowerCase();
    
    if (content.includes('critical') || content.includes('severe')) return 'critical';
    if (content.includes('high') || content.includes('dangerous')) return 'high';
    if (content.includes('medium') || content.includes('moderate')) return 'medium';
    if (content.includes('low') || content.includes('minor')) return 'low';
    
    return 'medium'; // Default
  }

  private calculateConfidence(data: any, source: string): number {
    let confidence = 50; // Base confidence
    
    // Adjust based on source reliability
    const reliableSources = ['misp', 'aptmap', 'cve', 'nist'];
    if (reliableSources.includes(source.toLowerCase())) {
      confidence += 30;
    }
    
    // Adjust based on data completeness
    if (data.indicators && data.indicators.length > 0) confidence += 10;
    if (data.description && data.description.length > 100) confidence += 10;
    if (data.attribution) confidence += 10;
    
    return Math.min(confidence, 100);
  }

  private extractIndicators(data: any): any[] {
    return data.indicators || data.iocs || data.observables || [];
  }

  private extractTTPs(data: any): any[] {
    return data.ttps || data.tactics || data.techniques || [];
  }

  private extractTargets(data: any): any[] {
    return data.targets || data.victims || data.industries || [];
  }

  private extractAttribution(data: any): any {
    return data.attribution || data.actor || data.group || null;
  }

  private extractTimeline(data: any): any {
    return data.timeline || data.events || null;
  }

  private extractMetadata(data: any): any {
    const metadata = { ...data };
    delete metadata.indicators;
    delete metadata.ttps;
    delete metadata.targets;
    delete metadata.attribution;
    delete metadata.timeline;
    return metadata;
  }

  private extractTags(data: any): string[] {
    const tags: string[] = [];
    
    if (data.tags) tags.push(...data.tags);
    if (data.labels) tags.push(...data.labels);
    if (data.categories) tags.push(...data.categories);
    
    return [...new Set(tags)]; // Remove duplicates
  }

  // Process sync queue
  private async processSyncQueue() {
    if (this.isProcessing || this.syncQueue.size === 0) return;
    
    this.isProcessing = true;
    
    try {
      const entries = Array.from(this.syncQueue.entries());
      this.syncQueue.clear();
      
      for (const [key, data] of entries) {
        await this.storeThreatIntelligence(data.record, data.source);
      }
      
      console.log('[ThreatDB] Sync queue processed:', entries.length, 'items');
    } catch (error) {
      console.error('[ThreatDB] Error processing sync queue:', error);
    } finally {
      this.isProcessing = false;
    }
  }

  // Add to sync queue for batched processing
  queueForSync(record: any, source: string) {
    const key = `${source}_${record.id || Date.now()}`;
    this.syncQueue.set(key, { record, source });
  }

  // Cleanup resources
  cleanup() {
    if (this.syncInterval) {
      clearInterval(this.syncInterval);
    }
    if (this.realtimeSubscription) {
      this.realtimeSubscription.unsubscribe();
    }
  }
}

// Export singleton instance
export const threatIntelligenceDB = new ThreatIntelligenceDatabase();
