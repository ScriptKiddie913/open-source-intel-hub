// Threat Intelligence Feed Aggregator Edge Function
// Fetches real-time malware data from abuse.ch APIs server-side to avoid CORS

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

// API endpoints for abuse.ch services
const ENDPOINTS = {
  feodo: 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json',
  urlhaus: 'https://urlhaus-api.abuse.ch/v1/urls/recent/limit/500/',
  urlhausPost: 'https://urlhaus-api.abuse.ch/v1/urls/recent/',
  threatfox: 'https://threatfox-api.abuse.ch/api/v1/',
  malwarebazaar: 'https://mb-api.abuse.ch/api/v1/',
};

async function fetchFeodoTracker(): Promise<any> {
  console.log('[ThreatFeeds] Fetching Feodo C2 servers...');
  
  try {
    const response = await fetch(ENDPOINTS.feodo, {
      headers: { 
        'Accept': 'application/json',
        'User-Agent': 'OSINT-Hub/1.0'
      }
    });
    
    if (!response.ok) {
      throw new Error(`Feodo API error: ${response.status}`);
    }
    
    const data = await response.json();
    const entries = Array.isArray(data) ? data : (data?.value || []);
    console.log(`[ThreatFeeds] Feodo returned ${entries.length} C2 servers`);
    
    return {
      source: 'feodo',
      success: true,
      count: entries.length,
      data: entries.slice(0, 500) // Limit to prevent payload issues
    };
  } catch (error: unknown) {
    console.error('[ThreatFeeds] Feodo error:', error);
    return { source: 'feodo', success: false, error: error instanceof Error ? error.message : 'Unknown error', data: [] };
  }
}

async function fetchURLhaus(): Promise<any> {
  console.log('[ThreatFeeds] Fetching URLhaus malicious URLs...');
  
  try {
    // Try GET endpoint first (faster)
    const response = await fetch(ENDPOINTS.urlhaus, {
      headers: { 
        'Accept': 'application/json',
        'User-Agent': 'OSINT-Hub/1.0'
      }
    });
    
    if (!response.ok) {
      throw new Error(`URLhaus API error: ${response.status}`);
    }
    
    const data = await response.json();
    
    // URLhaus returns { urls: [...] } for GET endpoint
    let entries: any[] = [];
    if (data.urls && Array.isArray(data.urls)) {
      entries = data.urls;
    } else if (data.data && Array.isArray(data.data)) {
      entries = data.data;
    } else if (typeof data === 'object') {
      // Export format returns object with numeric keys
      entries = Object.values(data).flat();
    }
    
    console.log(`[ThreatFeeds] URLhaus returned ${entries.length} URLs`);
    
    return {
      source: 'urlhaus',
      success: true,
      count: entries.length,
      data: entries.slice(0, 500)
    };
  } catch (error: unknown) {
    console.error('[ThreatFeeds] URLhaus error:', error);
    return { source: 'urlhaus', success: false, error: error instanceof Error ? error.message : 'Unknown error', data: [] };
  }
}

async function fetchThreatFox(days: number = 7): Promise<any> {
  console.log(`[ThreatFeeds] Fetching ThreatFox IOCs (${days} days)...`);
  
  try {
    const response = await fetch(ENDPOINTS.threatfox, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'OSINT-Hub/1.0'
      },
      body: JSON.stringify({ query: 'get_iocs', days })
    });
    
    if (!response.ok) {
      throw new Error(`ThreatFox API error: ${response.status}`);
    }
    
    const data = await response.json();
    
    if (data.query_status !== 'ok') {
      throw new Error(`ThreatFox query failed: ${data.query_status}`);
    }
    
    const entries = data.data || [];
    console.log(`[ThreatFeeds] ThreatFox returned ${entries.length} IOCs`);
    
    return {
      source: 'threatfox',
      success: true,
      count: entries.length,
      data: entries.slice(0, 500)
    };
  } catch (error: unknown) {
    console.error('[ThreatFeeds] ThreatFox error:', error);
    return { source: 'threatfox', success: false, error: error instanceof Error ? error.message : 'Unknown error', data: [] };
  }
}

async function fetchMalwareBazaar(limit: number = 100): Promise<any> {
  console.log(`[ThreatFeeds] Fetching MalwareBazaar samples (limit: ${limit})...`);
  
  try {
    const response = await fetch(ENDPOINTS.malwarebazaar, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'OSINT-Hub/1.0'
      },
      body: `query=get_recent&selector=${limit}`
    });
    
    if (!response.ok) {
      throw new Error(`MalwareBazaar API error: ${response.status}`);
    }
    
    const data = await response.json();
    
    if (data.query_status !== 'ok') {
      throw new Error(`MalwareBazaar query failed: ${data.query_status}`);
    }
    
    const entries = data.data || [];
    
    // Validate and filter entries with valid SHA256 hashes
    const validEntries = entries.filter((entry: any) => 
      entry.sha256_hash && /^[a-fA-F0-9]{64}$/.test(entry.sha256_hash)
    );
    
    console.log(`[ThreatFeeds] MalwareBazaar returned ${validEntries.length} valid samples`);
    
    return {
      source: 'malwarebazaar',
      success: true,
      count: validEntries.length,
      data: validEntries.slice(0, 200)
    };
  } catch (error: unknown) {
    console.error('[ThreatFeeds] MalwareBazaar error:', error);
    return { source: 'malwarebazaar', success: false, error: error instanceof Error ? error.message : 'Unknown error', data: [] };
  }
}

serve(async (req) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const url = new URL(req.url);
    const source = url.searchParams.get('source') || 'all';
    const days = parseInt(url.searchParams.get('days') || '7');
    const limit = parseInt(url.searchParams.get('limit') || '100');

    console.log(`[ThreatFeeds] Request for source: ${source}, days: ${days}, limit: ${limit}`);

    let result: any;

    switch (source) {
      case 'feodo':
        result = await fetchFeodoTracker();
        break;
      
      case 'urlhaus':
        result = await fetchURLhaus();
        break;
      
      case 'threatfox':
        result = await fetchThreatFox(days);
        break;
      
      case 'malwarebazaar':
        result = await fetchMalwareBazaar(limit);
        break;
      
      case 'all':
      default:
        // Fetch all sources in parallel
        const [feodo, urlhaus, threatfox, bazaar] = await Promise.all([
          fetchFeodoTracker(),
          fetchURLhaus(),
          fetchThreatFox(days),
          fetchMalwareBazaar(limit)
        ]);
        
        result = {
          success: true,
          timestamp: new Date().toISOString(),
          sources: {
            feodo,
            urlhaus,
            threatfox,
            malwarebazaar: bazaar
          },
          summary: {
            total_threats: (feodo.count || 0) + (urlhaus.count || 0) + (threatfox.count || 0) + (bazaar.count || 0),
            c2_servers: feodo.count || 0,
            malicious_urls: urlhaus.count || 0,
            iocs: threatfox.count || 0,
            malware_samples: bazaar.count || 0
          }
        };
        break;
    }

    return new Response(JSON.stringify(result), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      status: 200
    });

  } catch (error: unknown) {
    console.error('[ThreatFeeds] Handler error:', error);
    
    return new Response(JSON.stringify({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
      timestamp: new Date().toISOString()
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      status: 500
    });
  }
});
