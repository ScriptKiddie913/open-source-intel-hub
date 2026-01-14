// Threat Feeds API Client
// Fetches live malware data from the threat-feeds Edge Function

import { supabase } from '@/integrations/supabase/client';

export interface FeodoEntry {
  ip_address: string;
  port: number;
  status: 'online' | 'offline';
  hostname: string | null;
  as_number: number;
  as_name: string;
  country: string;
  first_seen: string;
  last_online: string;
  malware: string;
}

export interface URLhausEntry {
  id?: string;
  dateadded: string;
  url: string;
  url_status: 'online' | 'offline';
  last_online: string | null;
  threat: string;
  tags: string[];
  urlhaus_link: string;
  reporter: string;
  host?: string;
}

export interface ThreatFoxEntry {
  id?: string;
  ioc_value: string;
  ioc_type: string;
  threat_type: string;
  malware: string;
  malware_alias: string | null;
  malware_printable: string;
  first_seen_utc: string;
  last_seen_utc: string | null;
  confidence_level: number;
  reference: string | null;
  tags: string;
  reporter: string;
}

export interface MalwareBazaarEntry {
  sha256_hash: string;
  sha1_hash?: string;
  md5_hash?: string;
  file_name?: string;
  file_type?: string;
  file_type_mime?: string;
  file_size?: number;
  signature?: string;
  first_seen?: string;
  last_seen?: string;
  tags?: string[];
}

export interface ThreatFeedResponse {
  success: boolean;
  timestamp: string;
  sources: {
    feodo: { success: boolean; count: number; data: FeodoEntry[]; error?: string };
    urlhaus: { success: boolean; count: number; data: URLhausEntry[]; error?: string };
    threatfox: { success: boolean; count: number; data: ThreatFoxEntry[]; error?: string };
    malwarebazaar: { success: boolean; count: number; data: MalwareBazaarEntry[]; error?: string };
  };
  summary: {
    total_threats: number;
    c2_servers: number;
    malicious_urls: number;
    iocs: number;
    malware_samples: number;
  };
}

export interface SingleSourceResponse<T> {
  source: string;
  success: boolean;
  count: number;
  data: T[];
  error?: string;
}

class ThreatFeedsAPI {
  private baseUrl: string;
  private cache: Map<string, { data: any; timestamp: number }> = new Map();
  private cacheTTL = 60000; // 1 minute cache

  constructor() {
    // Use Supabase Edge Functions URL
    const projectId = import.meta.env.VITE_SUPABASE_PROJECT_ID || 'xpbcscgajcnxthokttoi';
    this.baseUrl = `https://${projectId}.supabase.co/functions/v1/threat-feeds`;
  }

  private async fetchFromEdge(params: URLSearchParams): Promise<any> {
    const cacheKey = params.toString();
    const cached = this.cache.get(cacheKey);
    
    if (cached && Date.now() - cached.timestamp < this.cacheTTL) {
      console.log('[ThreatFeedsAPI] Using cached data for:', cacheKey);
      return cached.data;
    }

    try {
      const { data: sessionData } = await supabase.auth.getSession();
      const token = sessionData?.session?.access_token;

      const response = await fetch(`${this.baseUrl}?${params.toString()}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          ...(token && { 'Authorization': `Bearer ${token}` }),
        },
      });

      if (!response.ok) {
        throw new Error(`Edge function error: ${response.status}`);
      }

      const data = await response.json();
      
      // Cache the response
      this.cache.set(cacheKey, { data, timestamp: Date.now() });
      
      return data;
    } catch (error) {
      console.error('[ThreatFeedsAPI] Fetch error:', error);
      throw error;
    }
  }

  // Fetch all threat feeds at once
  async fetchAllFeeds(days: number = 7, limit: number = 100): Promise<ThreatFeedResponse> {
    console.log('[ThreatFeedsAPI] Fetching all threat feeds...');
    
    const params = new URLSearchParams({
      source: 'all',
      days: days.toString(),
      limit: limit.toString()
    });

    return this.fetchFromEdge(params);
  }

  // Fetch Feodo C2 servers only
  async fetchFeodo(): Promise<SingleSourceResponse<FeodoEntry>> {
    console.log('[ThreatFeedsAPI] Fetching Feodo C2 servers...');
    
    const params = new URLSearchParams({ source: 'feodo' });
    return this.fetchFromEdge(params);
  }

  // Fetch URLhaus malicious URLs only
  async fetchURLhaus(): Promise<SingleSourceResponse<URLhausEntry>> {
    console.log('[ThreatFeedsAPI] Fetching URLhaus URLs...');
    
    const params = new URLSearchParams({ source: 'urlhaus' });
    return this.fetchFromEdge(params);
  }

  // Fetch ThreatFox IOCs only
  async fetchThreatFox(days: number = 7): Promise<SingleSourceResponse<ThreatFoxEntry>> {
    console.log('[ThreatFeedsAPI] Fetching ThreatFox IOCs...');
    
    const params = new URLSearchParams({ 
      source: 'threatfox',
      days: days.toString()
    });
    return this.fetchFromEdge(params);
  }

  // Fetch MalwareBazaar samples only
  async fetchMalwareBazaar(limit: number = 100): Promise<SingleSourceResponse<MalwareBazaarEntry>> {
    console.log('[ThreatFeedsAPI] Fetching MalwareBazaar samples...');
    
    const params = new URLSearchParams({ 
      source: 'malwarebazaar',
      limit: limit.toString()
    });
    return this.fetchFromEdge(params);
  }

  // Clear cache
  clearCache(): void {
    this.cache.clear();
    console.log('[ThreatFeedsAPI] Cache cleared');
  }
}

export const threatFeedsAPI = new ThreatFeedsAPI();
