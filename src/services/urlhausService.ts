// Real abuse.ch URLhaus service - NO MOCK DATA
// Fetches live malware URLs from abuse.ch

export interface MalwareUrl {
  id: string;
  url: string;
  host: string;
  threat: string;
  tags: string[];
  date_added: string;
  reporter: string;
  online?: string;
  country?: string;
}

export interface UrlhausResponse {
  query_status: string;
  urls: MalwareUrl[];
  total_count: number;
}

class UrlhausService {
  private readonly baseUrl = 'https://urlhaus-api.abuse.ch/v1/';

  // Fetch recent malware URLs from URLhaus
  async fetchRecentUrls(limit: number = 100): Promise<UrlhausResponse> {
    try {
      console.log('[URLhaus] Fetching recent malware URLs...');
      
      const response = await fetch(`${this.baseUrl}urls/recent/limit/${limit}/`, {
        method: 'GET',
        headers: {
          'User-Agent': 'OSINT-Hub/1.0'
        }
      });

      if (!response.ok) {
        throw new Error(`URLhaus API failed: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      console.log('[URLhaus] Raw API response:', data);
      
      if (data.query_status !== 'ok') {
        throw new Error(`URLhaus query failed: ${data.query_status}`);
      }

      console.log('[URLhaus] Successfully fetched', data.urls?.length || 0, 'real malware URLs');
      
      return {
        query_status: data.query_status,
        urls: data.urls || [],
        total_count: data.urls?.length || 0
      };

    } catch (error) {
      console.error('[URLhaus] Failed to fetch malware URLs:', error);
      throw new Error(`URLhaus fetch failed: ${error.message}`);
    }
  }

  // Search URLs by malware family
  async searchUrlsByTag(tag: string): Promise<UrlhausResponse> {
    try {
      console.log(`[URLhaus] Searching URLs for tag: ${tag}`);
      
      const response = await fetch(`${this.baseUrl}tag/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'OSINT-Hub/1.0'
        },
        body: `tag=${encodeURIComponent(tag)}`
      });

      if (!response.ok) {
        throw new Error(`URLhaus search failed: ${response.status}`);
      }

      const data = await response.json();
      
      if (data.query_status !== 'ok') {
        console.warn(`[URLhaus] No URLs found for tag ${tag}`);
        return { query_status: 'ok', urls: [], total_count: 0 };
      }

      console.log(`[URLhaus] Found ${data.urls?.length || 0} URLs for tag ${tag}`);
      
      return {
        query_status: data.query_status,
        urls: data.urls || [],
        total_count: data.urls?.length || 0
      };

    } catch (error) {
      console.error(`[URLhaus] Search for tag ${tag} failed:`, error);
      throw error;
    }
  }
}

export const urlhausService = new UrlhausService();
