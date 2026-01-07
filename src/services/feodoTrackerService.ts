// Real Feodo Tracker service - NO MOCK DATA
// Fetches live botnet C2 servers from abuse.ch

export interface C2Server {
  id: string;
  ip: string;
  port: string;
  status: string;
  hostname?: string;
  country?: string;
  first_seen: string;
  last_seen: string;
  malware: string;
  confidence?: string;
}

export interface FeodoResponse {
  data: C2Server[];
  total_count: number;
  last_update: string;
}

class FeodoTrackerService {
  private readonly baseUrl = 'https://feodotracker.abuse.ch/downloads/';

  // Fetch active botnet C2 servers
  async fetchActiveC2Servers(): Promise<FeodoResponse> {
    try {
      console.log('[Feodo] Fetching active C2 servers...');
      
      const response = await fetch(`${this.baseUrl}ipblocklist.json`, {
        headers: {
          'User-Agent': 'OSINT-Hub/1.0'
        }
      });

      if (!response.ok) {
        throw new Error(`Feodo API failed: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      console.log('[Feodo] Raw API response received');

      // Parse Feodo JSON format
      const c2Servers: C2Server[] = data.map((item: Record<string, unknown>, index: number) => ({
        id: `feodo-${item.ip_address}-${item.port}`,
        ip: item.ip_address,
        port: item.port?.toString() || '80',
        status: item.status || 'active',
        hostname: item.hostname,
        country: item.country,
        first_seen: item.first_seen || new Date().toISOString(),
        last_seen: item.last_seen || new Date().toISOString(),
        malware: item.malware_alias || 'Unknown',
        confidence: item.confidence_level?.toString() || '70'
      }));

      console.log('[Feodo] Successfully parsed', c2Servers.length, 'real C2 servers');

      return {
        data: c2Servers,
        total_count: c2Servers.length,
        last_update: new Date().toISOString()
      };

    } catch (error) {
      console.error('[Feodo] Failed to fetch C2 servers:', error);
      throw new Error(`Feodo fetch failed: ${error.message}`);
    }
  }

  // Get C2 servers by malware family
  async getC2ServersByMalware(malware: string): Promise<C2Server[]> {
    try {
      const response = await this.fetchActiveC2Servers();
      
      const filtered = response.data.filter(server => 
        server.malware.toLowerCase().includes(malware.toLowerCase())
      );

      console.log(`[Feodo] Found ${filtered.length} C2 servers for malware: ${malware}`);
      return filtered;

    } catch (error) {
      console.error(`[Feodo] Search for ${malware} failed:`, error);
      throw error;
    }
  }

  // Get recent C2 server additions
  async getRecentC2Servers(hours: number = 24): Promise<C2Server[]> {
    try {
      const response = await this.fetchActiveC2Servers();
      const cutoffTime = new Date(Date.now() - (hours * 60 * 60 * 1000));

      const recent = response.data.filter(server => {
        const firstSeen = new Date(server.first_seen);
        return firstSeen >= cutoffTime;
      });

      console.log(`[Feodo] Found ${recent.length} new C2 servers in last ${hours} hours`);
      return recent;

    } catch (error) {
      console.error('[Feodo] Failed to get recent C2 servers:', error);
      throw error;
    }
  }
}

export const feodoTrackerService = new FeodoTrackerService();
