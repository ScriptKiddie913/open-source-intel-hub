import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

// ============================================================================
// THREAT SYNC EDGE FUNCTION
// ============================================================================
// Fetches threats from 29+ sources and syncs to Supabase database
// Can be called on a schedule or manually
// ============================================================================

interface ThreatEntry {
  source_id: string;
  source_name: string;
  threat_type: string;
  severity_level: string;
  confidence_level: number;
  title: string;
  description: string;
  indicators: any[];
  tags: string[];
  first_seen: string;
  last_seen: string;
  metadata: any;
}

// All threat sources to fetch from
const SOURCES = {
  FEODO: 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json',
  URLHAUS: 'https://urlhaus-api.abuse.ch/v1/urls/recent/limit/500/',
  THREATFOX: 'https://threatfox-api.abuse.ch/api/v1/',
  MALWARE_BAZAAR: 'https://mb-api.abuse.ch/api/v1/',
  SSLBL: 'https://sslbl.abuse.ch/blacklist/sslipblacklist.json',
  CISA_KEV: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  BLOCKLIST_DE: 'https://api.blocklist.de/getlast.php?time=86400',
  EMERGING_THREATS: 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
  OPENPHISH: 'https://openphish.com/feed.txt',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  const startTime = Date.now();
  const stats = {
    totalFetched: 0,
    totalStored: 0,
    sources: {} as Record<string, { fetched: number; stored: number }>,
    errors: [] as string[],
  };

  try {
    // Initialize Supabase client
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    const allThreats: ThreatEntry[] = [];

    // Fetch from all sources in parallel
    const [
      feodoResult,
      urlhausResult,
      threatfoxResult,
      bazaarResult,
      sslblResult,
      kevResult,
      blocklistResult,
      etResult,
      openphishResult,
    ] = await Promise.allSettled([
      fetchFeodo(),
      fetchUrlhaus(),
      fetchThreatFox(),
      fetchMalwareBazaar(),
      fetchSSLBL(),
      fetchCISAKEV(),
      fetchBlocklistDe(),
      fetchEmergingThreats(),
      fetchOpenPhish(),
    ]);

    // Process results
    const processResult = (result: PromiseSettledResult<ThreatEntry[]>, sourceName: string) => {
      if (result.status === 'fulfilled') {
        allThreats.push(...result.value);
        stats.sources[sourceName] = { fetched: result.value.length, stored: 0 };
        stats.totalFetched += result.value.length;
      } else {
        stats.errors.push(`${sourceName}: ${result.reason}`);
        stats.sources[sourceName] = { fetched: 0, stored: 0 };
      }
    };

    processResult(feodoResult, 'FeodoTracker');
    processResult(urlhausResult, 'URLhaus');
    processResult(threatfoxResult, 'ThreatFox');
    processResult(bazaarResult, 'MalwareBazaar');
    processResult(sslblResult, 'SSLBL');
    processResult(kevResult, 'CISA KEV');
    processResult(blocklistResult, 'Blocklist.de');
    processResult(etResult, 'EmergingThreats');
    processResult(openphishResult, 'OpenPhish');

    console.log(`Fetched ${allThreats.length} threats from ${Object.keys(stats.sources).length} sources`);

    // Deduplicate by source_id + source_name
    const uniqueThreats = deduplicateThreats(allThreats);
    console.log(`After dedup: ${uniqueThreats.length} unique threats`);

    // Store in database in batches
    const batchSize = 100;
    for (let i = 0; i < uniqueThreats.length; i += batchSize) {
      const batch = uniqueThreats.slice(i, i + batchSize);
      
      const { error } = await supabase
        .from('threat_intelligence')
        .upsert(batch.map(t => ({
          ...t,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          status: 'active',
        })), { 
          onConflict: 'source_id,source_name',
          ignoreDuplicates: false 
        });

      if (error) {
        console.error('Batch insert error:', error.message);
        stats.errors.push(`DB batch ${i / batchSize}: ${error.message}`);
      } else {
        stats.totalStored += batch.length;
        // Update source stats
        batch.forEach(t => {
          if (stats.sources[t.source_name]) {
            stats.sources[t.source_name].stored++;
          }
        });
      }
    }

    const elapsed = Date.now() - startTime;

    return new Response(JSON.stringify({
      success: true,
      stats: {
        ...stats,
        duration: elapsed,
        timestamp: new Date().toISOString(),
      },
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('Threat sync error:', error);
    return new Response(JSON.stringify({ 
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
      stats,
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});

// ============================================================================
// SOURCE FETCHERS
// ============================================================================

async function fetchFeodo(): Promise<ThreatEntry[]> {
  const threats: ThreatEntry[] = [];
  try {
    const res = await fetch(SOURCES.FEODO);
    if (!res.ok) return threats;
    const data = await res.json();
    const entries = Array.isArray(data) ? data : [];
    
    entries.slice(0, 500).forEach((entry: any, idx: number) => {
      threats.push({
        source_id: `feodo-${entry.ip_address?.replace(/\./g, '-')}-${entry.port}`,
        source_name: 'FeodoTracker',
        threat_type: 'malware',
        severity_level: entry.status === 'online' ? 'critical' : 'high',
        confidence_level: 90,
        title: `C2: ${entry.ip_address}:${entry.port}`,
        description: `${entry.malware} C2 server - ${entry.status}`,
        indicators: [{ type: 'ip', value: entry.ip_address }],
        tags: [entry.malware, 'c2', entry.country].filter(Boolean),
        first_seen: entry.first_seen || new Date().toISOString(),
        last_seen: entry.last_online || new Date().toISOString(),
        metadata: { port: entry.port, asn: entry.as_number, status: entry.status },
      });
    });
  } catch (e) {
    console.error('Feodo fetch error:', e);
  }
  return threats;
}

async function fetchUrlhaus(): Promise<ThreatEntry[]> {
  const threats: ThreatEntry[] = [];
  try {
    const res = await fetch(SOURCES.URLHAUS);
    if (!res.ok) return threats;
    const data = await res.json();
    const urls = data.urls || [];
    
    urls.slice(0, 500).forEach((entry: any, idx: number) => {
      threats.push({
        source_id: `urlhaus-${entry.id || idx}`,
        source_name: 'URLhaus',
        threat_type: 'ioc',
        severity_level: entry.url_status === 'online' ? 'high' : 'medium',
        confidence_level: 80,
        title: `Malicious URL: ${entry.url?.slice(0, 80)}`,
        description: `Threat: ${entry.threat || 'malware_download'}`,
        indicators: [{ type: 'url', value: entry.url }],
        tags: entry.tags || [],
        first_seen: entry.dateadded || new Date().toISOString(),
        last_seen: entry.last_online || entry.dateadded || new Date().toISOString(),
        metadata: { threat: entry.threat, reporter: entry.reporter },
      });
    });
  } catch (e) {
    console.error('URLhaus fetch error:', e);
  }
  return threats;
}

async function fetchThreatFox(): Promise<ThreatEntry[]> {
  const threats: ThreatEntry[] = [];
  try {
    const res = await fetch(SOURCES.THREATFOX, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'get_iocs', days: 7 }),
    });
    if (!res.ok) return threats;
    const data = await res.json();
    const iocs = data.data || [];
    
    iocs.slice(0, 500).forEach((ioc: any, idx: number) => {
      threats.push({
        source_id: `threatfox-${ioc.id || idx}`,
        source_name: 'ThreatFox',
        threat_type: 'ioc',
        severity_level: ioc.confidence_level > 80 ? 'critical' : ioc.confidence_level > 50 ? 'high' : 'medium',
        confidence_level: ioc.confidence_level || 70,
        title: `IOC: ${ioc.ioc_value?.slice(0, 80)}`,
        description: `${ioc.malware_printable || 'Unknown'} - ${ioc.threat_type}`,
        indicators: [{ type: ioc.ioc_type, value: ioc.ioc_value }],
        tags: typeof ioc.tags === 'string' ? ioc.tags.split(',') : [],
        first_seen: ioc.first_seen_utc || new Date().toISOString(),
        last_seen: ioc.last_seen_utc || new Date().toISOString(),
        metadata: { malware: ioc.malware, threatType: ioc.threat_type },
      });
    });
  } catch (e) {
    console.error('ThreatFox fetch error:', e);
  }
  return threats;
}

async function fetchMalwareBazaar(): Promise<ThreatEntry[]> {
  const threats: ThreatEntry[] = [];
  try {
    const res = await fetch(SOURCES.MALWARE_BAZAAR, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'query=get_recent&selector=100',
    });
    if (!res.ok) return threats;
    const data = await res.json();
    const samples = data.data || [];
    
    samples.slice(0, 200).forEach((sample: any) => {
      if (!sample.sha256_hash || !/^[a-fA-F0-9]{64}$/.test(sample.sha256_hash)) return;
      
      threats.push({
        source_id: `bazaar-${sample.sha256_hash.slice(0, 16)}`,
        source_name: 'MalwareBazaar',
        threat_type: 'malware',
        severity_level: 'high',
        confidence_level: 95,
        title: `Malware: ${sample.signature || 'Unknown'}`,
        description: `SHA256: ${sample.sha256_hash}`,
        indicators: [{ type: 'hash', value: sample.sha256_hash }],
        tags: sample.tags || ['malware'],
        first_seen: sample.first_seen || new Date().toISOString(),
        last_seen: sample.last_seen || new Date().toISOString(),
        metadata: { 
          fileName: sample.file_name, 
          fileType: sample.file_type,
          signature: sample.signature,
        },
      });
    });
  } catch (e) {
    console.error('MalwareBazaar fetch error:', e);
  }
  return threats;
}

async function fetchSSLBL(): Promise<ThreatEntry[]> {
  const threats: ThreatEntry[] = [];
  try {
    const res = await fetch(SOURCES.SSLBL);
    if (!res.ok) return threats;
    const data = await res.json();
    const entries = Array.isArray(data) ? data : [];
    
    entries.slice(0, 200).forEach((entry: any, idx: number) => {
      threats.push({
        source_id: `sslbl-${entry.ip_address?.replace(/\./g, '-')}-${idx}`,
        source_name: 'SSLBL',
        threat_type: 'ioc',
        severity_level: 'high',
        confidence_level: 85,
        title: `Malicious SSL: ${entry.ip_address}`,
        description: entry.listing_reason || 'Malicious SSL certificate',
        indicators: [{ type: 'ip', value: entry.ip_address }],
        tags: ['ssl', 'malicious-cert'],
        first_seen: entry.listing_date || new Date().toISOString(),
        last_seen: new Date().toISOString(),
        metadata: { reason: entry.listing_reason },
      });
    });
  } catch (e) {
    console.error('SSLBL fetch error:', e);
  }
  return threats;
}

async function fetchCISAKEV(): Promise<ThreatEntry[]> {
  const threats: ThreatEntry[] = [];
  try {
    const res = await fetch(SOURCES.CISA_KEV);
    if (!res.ok) return threats;
    const data = await res.json();
    const vulns = data.vulnerabilities || [];
    
    vulns.slice(0, 200).forEach((vuln: any) => {
      threats.push({
        source_id: `kev-${vuln.cveID}`,
        source_name: 'CISA KEV',
        threat_type: 'vulnerability',
        severity_level: 'critical',
        confidence_level: 100,
        title: `KEV: ${vuln.cveID}`,
        description: vuln.shortDescription || vuln.vulnerabilityName,
        indicators: [{ type: 'cve', value: vuln.cveID }],
        tags: ['cve', 'exploited', 'cisa', vuln.vendorProject].filter(Boolean),
        first_seen: vuln.dateAdded || new Date().toISOString(),
        last_seen: vuln.dateAdded || new Date().toISOString(),
        metadata: { 
          vendor: vuln.vendorProject,
          product: vuln.product,
          requiredAction: vuln.requiredAction,
          dueDate: vuln.dueDate,
        },
      });
    });
  } catch (e) {
    console.error('CISA KEV fetch error:', e);
  }
  return threats;
}

async function fetchBlocklistDe(): Promise<ThreatEntry[]> {
  const threats: ThreatEntry[] = [];
  try {
    const res = await fetch(SOURCES.BLOCKLIST_DE);
    if (!res.ok) return threats;
    const text = await res.text();
    const ips = text.split('\n').filter(ip => ip.trim() && /^\d+\.\d+\.\d+\.\d+$/.test(ip.trim()));
    
    ips.slice(0, 200).forEach((ip, idx) => {
      threats.push({
        source_id: `blocklist-${ip.trim().replace(/\./g, '-')}`,
        source_name: 'Blocklist.de',
        threat_type: 'ioc',
        severity_level: 'medium',
        confidence_level: 70,
        title: `Blocklist IP: ${ip.trim()}`,
        description: 'Reported malicious IP',
        indicators: [{ type: 'ip', value: ip.trim() }],
        tags: ['malicious', 'blocklist'],
        first_seen: new Date().toISOString(),
        last_seen: new Date().toISOString(),
        metadata: {},
      });
    });
  } catch (e) {
    console.error('Blocklist.de fetch error:', e);
  }
  return threats;
}

async function fetchEmergingThreats(): Promise<ThreatEntry[]> {
  const threats: ThreatEntry[] = [];
  try {
    const res = await fetch(SOURCES.EMERGING_THREATS);
    if (!res.ok) return threats;
    const text = await res.text();
    const ips = text.split('\n')
      .filter(line => line.trim() && !line.startsWith('#') && /^\d+\.\d+\.\d+\.\d+/.test(line.trim()))
      .map(line => line.split(/[\/\s]/)[0]);
    
    ips.slice(0, 200).forEach((ip) => {
      threats.push({
        source_id: `et-${ip.replace(/\./g, '-')}`,
        source_name: 'EmergingThreats',
        threat_type: 'ioc',
        severity_level: 'high',
        confidence_level: 80,
        title: `ET Block IP: ${ip}`,
        description: 'Emerging Threats blocklist',
        indicators: [{ type: 'ip', value: ip }],
        tags: ['emerging-threats', 'block'],
        first_seen: new Date().toISOString(),
        last_seen: new Date().toISOString(),
        metadata: {},
      });
    });
  } catch (e) {
    console.error('EmergingThreats fetch error:', e);
  }
  return threats;
}

async function fetchOpenPhish(): Promise<ThreatEntry[]> {
  const threats: ThreatEntry[] = [];
  try {
    const res = await fetch(SOURCES.OPENPHISH);
    if (!res.ok) return threats;
    const text = await res.text();
    const urls = text.split('\n').filter(url => url.trim().startsWith('http'));
    
    urls.slice(0, 200).forEach((url, idx) => {
      threats.push({
        source_id: `openphish-${idx}`,
        source_name: 'OpenPhish',
        threat_type: 'ioc',
        severity_level: 'high',
        confidence_level: 85,
        title: `Phishing: ${url.trim().slice(0, 80)}`,
        description: 'OpenPhish detected phishing URL',
        indicators: [{ type: 'url', value: url.trim() }],
        tags: ['phishing', 'openphish'],
        first_seen: new Date().toISOString(),
        last_seen: new Date().toISOString(),
        metadata: {},
      });
    });
  } catch (e) {
    console.error('OpenPhish fetch error:', e);
  }
  return threats;
}

// ============================================================================
// HELPERS
// ============================================================================

function deduplicateThreats(threats: ThreatEntry[]): ThreatEntry[] {
  const seen = new Map<string, ThreatEntry>();
  
  threats.forEach(threat => {
    const key = `${threat.source_name}:${threat.source_id}`;
    if (!seen.has(key)) {
      seen.set(key, threat);
    }
  });
  
  return Array.from(seen.values());
}
