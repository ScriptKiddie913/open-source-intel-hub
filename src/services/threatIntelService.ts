export interface ThreatIntelResult {
  success: boolean;
  type: string;
  target: string;
  raw: Record<string, any>;
  formatted: FormattedThreatData | null;
  errors?: string[];
  timestamp: string;
}

export interface FormattedThreatData {
  summary: string;
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'info';
  riskScore: number;
  indicators: ThreatIndicator[];
  detections: {
    malicious: number;
    suspicious: number;
    clean: number;
    undetected: number;
  };
  categories: string[];
  recommendations: string[];
  metadata: {
    asn: string | null;
    country: string | null;
    owner: string | null;
    lastAnalysis: string | null;
  };
}

export interface ThreatIndicator {
  type: string;
  value: string;
  source: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

const CORS_PROXY = 'https://api.allorigins.win/raw?url=';
const VIRUSTOTAL_API_KEY = (import.meta as any)?.env?.VITE_VIRUSTOTAL_API_KEY || '5b1f66e34505cb0985f4954a22751ea024db382e6ab8d7522c3652a51aaf2ce0';

// Helper to fetch with timeout
async function fetchWithTimeout(url: string, options: RequestInit = {}, timeout = 30000): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  
  try {
    console.log(`[Fetch] Requesting: ${url}`);
    
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      mode: 'cors',
      credentials: 'omit',
      headers: {
        'User-Agent': 'OSINT-Hub/1.0 (Threat Intelligence Scanner)',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        ...options.headers,
      },
    });
    
    clearTimeout(id);
    console.log(`[Fetch] Response: ${response.status} ${response.statusText}`);
    return response;
  } catch (error: any) {
    clearTimeout(id);
    console.error(`[Fetch] Error for ${url}:`, error);
    
    if (error.name === 'AbortError') {
      throw new Error('Request timeout after 30 seconds');
    }
    if (error.message?.includes('Failed to fetch')) {
      throw new Error('Network connection failed - possible CORS or connectivity issue');
    }
    if (error.message?.includes('signal is aborted')) {
      throw new Error('Request was aborted due to timeout or cancellation');
    }
    throw error;
  }
}

// Query IP-API for geolocation (FREE, no CORS issues)
async function queryIPAPI(ip: string): Promise<any> {
  try {
    console.log(`[IP-API] Querying geolocation for: ${ip}`);
    // Use HTTPS to avoid mixed content issues
    const response = await fetchWithTimeout(`https://ipapi.co/${ip}/json/`, {
      headers: {
        'User-Agent': 'OSINT-Hub/1.0'
      }
    }, 15000);
    
    if (!response.ok) {
      // Fallback to ip-api.com
      const fallbackResponse = await fetchWithTimeout(`${CORS_PROXY}${encodeURIComponent(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query`)}`, {}, 15000);
      if (!fallbackResponse.ok) {
        return { error: `API error: ${fallbackResponse.status}` };
      }
      const fallbackData = await fallbackResponse.json();
      if (fallbackData.status === 'fail') {
        return { error: fallbackData.message || 'IP lookup failed' };
      }
      return {
        found: true,
        ip: fallbackData.query,
        country: fallbackData.country,
        countryCode: fallbackData.countryCode,
        region: fallbackData.regionName,
        city: fallbackData.city,
        lat: fallbackData.lat,
        lon: fallbackData.lon,
        isp: fallbackData.isp,
        org: fallbackData.org,
        as: fallbackData.as,
        timezone: fallbackData.timezone,
      };
    }
    
    const data = await response.json();
    if (data.error) {
      return { error: data.reason || 'IP lookup failed' };
    }
    
    return {
      found: true,
      ip: ip,
      country: data.country_name,
      countryCode: data.country_code,
      region: data.region,
      city: data.city,
      lat: data.latitude,
      lon: data.longitude,
      isp: data.org,
      org: data.org,
      as: data.asn,
      timezone: data.timezone,
    };
  } catch (error) {
    console.error('[IP-API] Error:', error);
    return { error: error instanceof Error ? error.message : 'Query failed' };
  }
}

// Query Shodan InternetDB (FREE, no API key required)
async function queryShodanInternetDB(ip: string): Promise<any> {
  try {
    console.log(`[Shodan InternetDB] Querying: ${ip}`);
    const response = await fetchWithTimeout(`https://internetdb.shodan.io/${ip}`);
    
    if (response.status === 404) {
      return { found: false, message: 'IP not found in Shodan database' };
    }
    
    if (!response.ok) {
      return { error: `API error: ${response.status}` };
    }
    
    const data = await response.json();
    return {
      found: true,
      ip: data.ip,
      ports: data.ports || [],
      hostnames: data.hostnames || [],
      cpes: data.cpes || [],
      tags: data.tags || [],
      vulns: data.vulns || [],
    };
  } catch (error) {
    console.error('[Shodan InternetDB] Error:', error);
    return { error: error instanceof Error ? error.message : 'Query failed' };
  }
}

// Query VirusTotal for any type of indicator
async function queryVirusTotal(type: string, target: string): Promise<any> {
  if (!VIRUSTOTAL_API_KEY) {
    return { error: 'VirusTotal API key not configured' };
  }

  try {
    console.log(`[VirusTotal] Querying ${type}: ${target}`);
    
    let endpoint = '';
    let urlPath = '';
    
    if (type === 'ip') {
      endpoint = 'ip-addresses';
      urlPath = target;
    } else if (type === 'domain') {
      endpoint = 'domains';
      urlPath = target;
    } else if (type === 'url') {
      // URL needs to be base64 encoded without padding
      const urlId = btoa(target).replace(/=/g, '');
      endpoint = 'urls';
      urlPath = urlId;
    } else if (type === 'hash') {
      endpoint = 'files';
      urlPath = target;
    } else {
      return { error: `Unsupported type: ${type}` };
    }
    
    // Use v3 API which is more reliable
    const url = `https://www.virustotal.com/api/v3/${endpoint}/${urlPath}`;
    const response = await fetchWithTimeout(url, {
      headers: {
        'x-apikey': VIRUSTOTAL_API_KEY,
        'Accept': 'application/json',
      },
    }, 20000);
    
    if (response.status === 429) {
      return { found: false, message: 'Rate limit exceeded' };
    }
    
    if (response.status === 404) {
      return { found: false, message: 'Not found in VirusTotal' };
    }
    
    if (!response.ok) {
      return { error: `API error: ${response.status}` };
    }
    
    const data = await response.json();
    
    if (!data.data) {
      return { found: false, message: 'Not found in VirusTotal' };
    }
    
    const attributes = data.data.attributes;
    const stats = attributes.last_analysis_stats || {};
    
    return {
      found: true,
      scans: attributes.last_analysis_results || {},
      positives: stats.malicious || 0,
      total: Object.values(stats).reduce((a: number, b: number) => a + b, 0),
      scanDate: attributes.last_analysis_date,
      permalink: `https://www.virustotal.com/gui/${endpoint}/${urlPath}`,
      resource: target,
      md5: attributes.md5,
      sha1: attributes.sha1,
      sha256: attributes.sha256,
      country: attributes.country,
      asn: attributes.asn,
      reputation: attributes.reputation || 0,
    };
  } catch (error) {
    console.error('[VirusTotal] Error:', error);
    return { error: error instanceof Error ? error.message : 'Query failed' };
  }
}

// Alternative DNS using Cloudflare (more reliable than Google)
async function queryCloudflareDNS(domain: string): Promise<any> {
  try {
    console.log(`[Cloudflare DNS] Resolving: ${domain}`);
    
    const response = await fetchWithTimeout(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`, {
      headers: {
        'Accept': 'application/dns-json',
      },
    }, 5000);
    
    if (!response.ok) {
      return { found: false };
    }
    
    const data = await response.json();
    
    return {
      found: data.Status === 0,
      resolves: data.Status === 0,
      answers: data.Answer?.map((a: any) => a.data) || [],
      authority: data.Authority || [],
    };
  } catch (error) {
    console.error('[Cloudflare DNS] Error:', error);
    return { error: error instanceof Error ? error.message : 'DNS query failed' };
  }
}

// Query ThreatFox for IOCs (with fallback to local mirror)
async function queryThreatFox(type: string, target: string): Promise<any> {
  try {
    console.log(`[ThreatFox] Searching for: ${target}`);
    
    // Prepare the search query based on type
    const searchValue = type === 'hash' ? target : target;
    const body = JSON.stringify({
      query: 'search_ioc',
      search_term: searchValue
    });
    
    // Try direct API first with enhanced headers
    let response = await fetchWithTimeout('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'OSINT-Hub/1.0'
      },
      body,
    }, 15000);
    
    // If failed with 503 or 429, try via CORS proxy
    if (response.status === 503 || response.status === 429 || !response.ok) {
      console.log('[ThreatFox] Direct API failed with status', response.status, ', trying via proxy...');
      const proxyUrl = `${CORS_PROXY}${encodeURIComponent('https://threatfox-api.abuse.ch/api/v1/')}`;
      response = await fetchWithTimeout(proxyUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body,
      }, 15000);
    }
    
    if (!response.ok) {
      console.error(`[ThreatFox] API error: ${response.status} ${response.statusText}`);
      return { found: false, message: 'ThreatFox unavailable' };
    }
    
    const data = await response.json();
    if (data.query_status === 'ok' && data.data && Array.isArray(data.data) && data.data.length > 0) {
      return {
        found: true,
        iocs: data.data.slice(0, 10).map((ioc: any) => ({
          id: ioc.id,
          type: ioc.ioc_type,
          value: ioc.ioc,
          threat: ioc.threat_type,
          threatDesc: ioc.threat_type_desc,
          malware: ioc.malware,
          malwareAlias: ioc.malware_alias,
          malwarePrintable: ioc.malware_printable,
          confidence: ioc.confidence_level,
          firstSeen: ioc.first_seen_utc || ioc.first_seen,
          lastSeen: ioc.last_seen_utc || ioc.last_seen,
          reporter: ioc.reporter,
          reference: ioc.reference,
          tags: ioc.tags || [],
        })),
      };
    }
    return { found: false, message: 'Not found in ThreatFox' };
  } catch (error) {
    console.error('[ThreatFox] Error:', error);
    return { error: error instanceof Error ? error.message : 'Query failed' };
  }
}

// Query URLhaus for URLs and hosts (with fallback)
async function queryURLhaus(type: string, target: string): Promise<any> {
  try {
    console.log(`[URLhaus] Searching for: ${target}`);
    
    let endpoint = 'https://urlhaus-api.abuse.ch/v1/';
    let body = '';
    
    if (type === 'url') {
      endpoint += 'url/';
      body = `url=${encodeURIComponent(target)}`;
    } else if (type === 'domain' || type === 'ip') {
      endpoint += 'host/';
      body = `host=${encodeURIComponent(target)}`;
    } else if (type === 'hash') {
      endpoint += 'payload/';
      if (target.length === 32) {
        body = `md5_hash=${encodeURIComponent(target)}`;
      } else {
        body = `sha256_hash=${encodeURIComponent(target)}`;
      }
    } else {
      return { found: false };
    }
    
    // Try direct API first
    let response = await fetchWithTimeout(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body,
    }, 10000);
    
    // If failed, try via proxy
    if (!response.ok) {
      console.log('[URLhaus] Direct API failed, trying via proxy...');
      const proxyUrl = `${CORS_PROXY}${encodeURIComponent(endpoint)}`;
      response = await fetchWithTimeout(proxyUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body,
      }, 10000);
    }
    
    if (!response.ok) {
      return { found: false, message: 'URLhaus unavailable' };
    }
    
    const data = await response.json();
    
    if (data.query_status === 'ok' || data.query_status === 'no_results') {
      if (type === 'url') {
        return {
          found: data.query_status === 'ok',
          status: data.url_status,
          threat: data.threat,
          dateAdded: data.date_added,
          tags: data.tags || [],
          payloads: data.payloads?.slice(0, 5) || [],
        };
      } else if (type === 'domain' || type === 'ip') {
        return {
          found: data.query_status === 'ok' && data.url_count > 0,
          urlCount: data.url_count || 0,
          blacklists: data.blacklists || {},
          urls: data.urls?.slice(0, 10).map((u: any) => ({
            url: u.url,
            status: u.url_status,
            threat: u.threat,
            dateAdded: u.date_added,
            tags: u.tags,
          })) || [],
        };
      } else if (type === 'hash') {
        return {
          found: data.query_status === 'ok',
          signature: data.signature,
          fileType: data.file_type,
          fileSize: data.file_size,
          firstSeen: data.firstseen,
          lastSeen: data.lastseen,
          urlCount: data.url_count || 0,
          urls: data.urls?.slice(0, 5) || [],
        };
      }
    }
    
    return { found: false };
  } catch (error) {
    console.error('[URLhaus] Error:', error);
    return { error: error instanceof Error ? error.message : 'Query failed' };
  }
}

// Query MalwareBazaar for hashes (with fallback)
async function queryMalwareBazaar(hash: string): Promise<any> {
  try {
    console.log(`[MalwareBazaar] Searching for hash: ${hash}`);
    
    const body = `query=get_info&hash=${encodeURIComponent(hash)}`;
    
    // Try direct API first
    let response = await fetchWithTimeout('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body,
    }, 10000);
    
    // If failed, try via proxy
    if (!response.ok && response.status === 503) {
      console.log('[MalwareBazaar] Direct API failed, trying via proxy...');
      const proxyUrl = `${CORS_PROXY}${encodeURIComponent('https://mb-api.abuse.ch/api/v1/')}`;
      response = await fetchWithTimeout(proxyUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body,
      }, 10000);
    }
    
    if (!response.ok) {
      return { found: false, message: 'MalwareBazaar unavailable' };
    }
    
    const data = await response.json();
    
    if (data.query_status === 'ok' && data.data && data.data.length > 0) {
      const sample = data.data[0];
      return {
        found: true,
        sha256: sample.sha256_hash,
        sha1: sample.sha1_hash,
        md5: sample.md5_hash,
        filename: sample.file_name,
        fileType: sample.file_type,
        fileSize: sample.file_size,
        signature: sample.signature,
        firstSeen: sample.first_seen,
        lastSeen: sample.last_seen,
        reporter: sample.reporter,
        tags: sample.tags || [],
        deliveryMethod: sample.delivery_method,
        intelligence: sample.intelligence || {},
      };
    }
    
    return { found: false, message: 'Hash not found in MalwareBazaar' };
  } catch (error) {
    console.error('[MalwareBazaar] Error:', error);
    return { error: error instanceof Error ? error.message : 'Query failed' };
  }
}

// Query CIRCL Hashlookup (with fallback)
async function queryCirclHashlookup(hash: string): Promise<any> {
  try {
    console.log(`[CIRCL] Searching for hash: ${hash}`);
    
    let hashType = 'sha256';
    if (hash.length === 32) hashType = 'md5';
    else if (hash.length === 40) hashType = 'sha1';
    
    // Try direct API first
    let response = await fetchWithTimeout(`https://hashlookup.circl.lu/lookup/${hashType}/${hash}`, {
      headers: {
        'Accept': 'application/json',
      },
    }, 8000);
    
    // If failed, try via proxy
    if (!response.ok && response.status !== 404) {
      console.log('[CIRCL] Direct API failed, trying via proxy...');
      const proxyUrl = `${CORS_PROXY}${encodeURIComponent(`https://hashlookup.circl.lu/lookup/${hashType}/${hash}`)}`;
      response = await fetchWithTimeout(proxyUrl, {
        headers: {
          'Accept': 'application/json',
        },
      }, 8000);
    }
    
    if (response.status === 404) {
      return { found: false, message: 'Hash not found in CIRCL database' };
    }
    
    if (!response.ok) {
      return { found: false, message: 'CIRCL unavailable' };
    }
    
    const data = await response.json();
    return {
      found: true,
      filename: data.FileName,
      filesize: data.FileSize,
      knownSource: data.KnownMalicious ? 'malicious' : (data.source || 'known'),
      md5: data.MD5,
      sha1: data['SHA-1'],
      sha256: data['SHA-256'],
      source: data.source,
      packageName: data.PackageName,
      packageVersion: data.PackageVersion,
    };
  } catch (error) {
    console.error('[CIRCL] Error:', error);
    return { error: error instanceof Error ? error.message : 'Query failed' };
  }
}

// Query Feodo Tracker for C2 IPs (FREE)
async function queryFeodoTracker(ip: string): Promise<any> {
  try {
    console.log(`[FeodoTracker] Checking IP: ${ip}`);
    
    // Download the JSON blocklist and check if IP is in it
    const response = await fetchWithTimeout('https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json', {}, 15000);
    
    if (!response.ok) {
      return { found: false };
    }
    
    const data = await response.json();
    const entries = Array.isArray(data) ? data : [];
    
    const match = entries.find((entry: any) => entry.ip_address === ip || entry.dst_ip === ip);
    
    if (match) {
      return {
        found: true,
        matched: true,
        malware: match.malware,
        port: match.dst_port,
        firstSeen: match.first_seen,
        lastOnline: match.last_online,
        status: match.status,
        source: 'Feodo Tracker',
        risk: 'critical',
      };
    }
    
    return { found: false, matched: false };
  } catch (error) {
    console.error('[FeodoTracker] Error:', error);
    return { error: error instanceof Error ? error.message : 'Query failed' };
  }
}

// Query SSL Blacklist (FREE)
async function querySSLBL(ip: string): Promise<any> {
  try {
    console.log(`[SSLBL] Checking IP: ${ip}`);
    
    const response = await fetchWithTimeout('https://sslbl.abuse.ch/blacklist/sslipblacklist.txt', {}, 10000);
    
    if (!response.ok) {
      return { found: false };
    }
    
    const text = await response.text();
    const lines = text.split('\n').filter(line => !line.startsWith('#') && line.trim());
    
    if (lines.some(line => line.includes(ip))) {
      return {
        found: true,
        matched: true,
        source: 'SSL Blacklist',
        type: 'Malicious SSL Certificate',
        risk: 'high',
      };
    }
    
    return { found: false, matched: false };
  } catch (error) {
    console.error('[SSLBL] Error:', error);
    return { error: error instanceof Error ? error.message : 'Query failed' };
  }
}

// Query Google Safe Browsing (via transparency report - limited)
async function checkDomainReputation(domain: string): Promise<any> {
  try {
    console.log(`[DomainCheck] Checking: ${domain}`);
    
    // Use Cloudflare DNS instead of Google
    const dnsResponse = await queryCloudflareDNS(domain);
    
    return dnsResponse;
  } catch (error) {
    console.error('[DomainCheck] Error:', error);
    return { error: error instanceof Error ? error.message : 'Query failed' };
  }
}

// Format raw results into structured threat data
function formatThreatData(type: string, target: string, results: Record<string, any>): FormattedThreatData {
  let riskScore = 0;
  let riskLevel: FormattedThreatData['riskLevel'] = 'info';
  const indicators: ThreatIndicator[] = [];
  const categories: string[] = [];
  const recommendations: string[] = [];
  let malicious = 0;
  let suspicious = 0;
  let clean = 0;
  let undetected = 0;
  
  // Process IP-API geolocation
  if (results.ipapi?.found) {
    clean++;
    indicators.push({
      type: 'Geolocation',
      value: `${results.ipapi.city || 'Unknown'}, ${results.ipapi.country || 'Unknown'}`,
      source: 'IP-API',
      severity: 'info',
    });
  }

  // Process VirusTotal
  if (results.virustotal?.found) {
    const vt = results.virustotal;
    const detectionRatio = vt.positives / vt.total;
    
    if (vt.positives > 0) {
      const vtScore = Math.min(vt.positives * 8, 70); // Scale positives
      riskScore += vtScore;
      
      if (vt.positives >= 5) {
        malicious++;
        indicators.push({
          type: 'VirusTotal Detection',
          value: `${vt.positives}/${vt.total} engines`,
          source: 'VirusTotal',
          severity: vt.positives >= 10 ? 'critical' : 'high',
        });
      } else {
        suspicious++;
        indicators.push({
          type: 'VirusTotal Detection',
          value: `${vt.positives}/${vt.total} engines`,
          source: 'VirusTotal',
          severity: 'medium',
        });
      }
      categories.push('Malware Detection');
    } else {
      clean++;
      indicators.push({
        type: 'VirusTotal Scan',
        value: `Clean (0/${vt.total} engines)`,
        source: 'VirusTotal',
        severity: 'info',
      });
    }
  } else if (results.virustotal && !results.virustotal.error) {
    undetected++;
  }
  
  // Process Shodan InternetDB
  if (results.shodan?.found) {
    const shodan = results.shodan;
    
    // Check for vulnerabilities
    if (shodan.vulns && shodan.vulns.length > 0) {
      riskScore += 40;
      malicious++;
      indicators.push({
        type: 'Vulnerabilities',
        value: `${shodan.vulns.length} CVE(s) found`,
        source: 'Shodan InternetDB',
        severity: 'critical',
      });
      categories.push('Vulnerable');
      shodan.vulns.slice(0, 3).forEach((cve: string) => {
        indicators.push({
          type: 'CVE',
          value: cve,
          source: 'Shodan InternetDB',
          severity: 'high',
        });
      });
    }
    
    // Check for risky tags
    const riskyTags = ['malware', 'botnet', 'c2', 'compromised', 'honeypot'];
    const foundRiskyTags = shodan.tags?.filter((t: string) => 
      riskyTags.some(rt => t.toLowerCase().includes(rt))
    ) || [];
    
    if (foundRiskyTags.length > 0) {
      riskScore += 50;
      malicious++;
      foundRiskyTags.forEach((tag: string) => {
        indicators.push({
          type: 'Tag',
          value: tag,
          source: 'Shodan InternetDB',
          severity: 'critical',
        });
        categories.push(tag);
      });
    }
    
    // Check for risky ports
    const riskyPorts = [22, 23, 3389, 5900, 445, 139, 1433, 3306, 5432];
    const openRiskyPorts = shodan.ports?.filter((p: number) => riskyPorts.includes(p)) || [];
    
    if (openRiskyPorts.length > 0) {
      riskScore += 15;
      suspicious++;
      indicators.push({
        type: 'Open Ports',
        value: openRiskyPorts.join(', '),
        source: 'Shodan InternetDB',
        severity: 'medium',
      });
    }
    
    if (!shodan.vulns?.length && !foundRiskyTags.length && !openRiskyPorts.length) {
      clean++;
    }
  } else if (results.shodan && !results.shodan.error) {
    undetected++;
  }
  
  // Process ThreatFox
  if (results.threatfox?.found) {
    riskScore += 60;
    for (const ioc of results.threatfox.iocs || []) {
      malicious++;
      indicators.push({
        type: ioc.threat || 'IOC',
        value: ioc.malware || target,
        source: 'ThreatFox',
        severity: ioc.confidence >= 75 ? 'critical' : 'high',
      });
      if (ioc.malware) categories.push(ioc.malware);
      if (ioc.threat) categories.push(ioc.threat);
    }
  } else if (results.threatfox && !results.threatfox.error) {
    clean++;
  }
  
  // Process URLhaus
  if (results.urlhaus?.found) {
    if (results.urlhaus.urlCount > 0 || results.urlhaus.threat) {
      riskScore += 50;
      malicious++;
      indicators.push({
        type: results.urlhaus.threat || 'Malicious URL/Host',
        value: results.urlhaus.urlCount ? `${results.urlhaus.urlCount} malicious URLs` : target,
        source: 'URLhaus',
        severity: 'high',
      });
      if (results.urlhaus.threat) categories.push(results.urlhaus.threat);
      categories.push('Malware Distribution');
    } else {
      clean++;
    }
  } else if (results.urlhaus && !results.urlhaus.error) {
    clean++;
  }
  
  // Process MalwareBazaar
  if (results.malwarebazaar?.found) {
    riskScore += 70;
    malicious++;
    indicators.push({
      type: results.malwarebazaar.signature || 'Malware Sample',
      value: results.malwarebazaar.filename || target,
      source: 'MalwareBazaar',
      severity: 'critical',
    });
    categories.push('Malware');
    if (results.malwarebazaar.tags) {
      categories.push(...results.malwarebazaar.tags.slice(0, 3));
    }
  } else if (results.malwarebazaar && !results.malwarebazaar.error) {
    clean++;
  }
  
  // Process CIRCL
  if (results.circl?.found) {
    if (results.circl.knownSource === 'malicious') {
      riskScore += 50;
      malicious++;
      indicators.push({
        type: 'Known Malicious',
        value: results.circl.filename || target,
        source: 'CIRCL Hashlookup',
        severity: 'high',
      });
      categories.push('Malware');
    } else {
      clean++;
      indicators.push({
        type: 'Known File',
        value: results.circl.filename || results.circl.packageName || target,
        source: 'CIRCL Hashlookup',
        severity: 'info',
      });
    }
  } else if (results.circl && !results.circl.error) {
    undetected++;
  }
  
  // Process Feodo Tracker
  if (results.feodo?.matched) {
    riskScore += 80;
    malicious++;
    indicators.push({
      type: 'Botnet C2',
      value: results.feodo.malware || 'C2 Server',
      source: 'Feodo Tracker',
      severity: 'critical',
    });
    categories.push('Botnet');
    categories.push('C2');
  }
  
  // Process SSL Blacklist
  if (results.sslbl?.matched) {
    riskScore += 60;
    malicious++;
    indicators.push({
      type: 'Malicious SSL',
      value: target,
      source: 'SSL Blacklist',
      severity: 'high',
    });
    categories.push('Malicious SSL');
  }
  
  // Cap risk score at 100
  riskScore = Math.min(riskScore, 100);
  
  // Determine risk level
  if (riskScore >= 80) riskLevel = 'critical';
  else if (riskScore >= 60) riskLevel = 'high';
  else if (riskScore >= 40) riskLevel = 'medium';
  else if (riskScore >= 20) riskLevel = 'low';
  else riskLevel = 'info';
  
  // Generate recommendations
  if (riskLevel === 'critical' || riskLevel === 'high') {
    recommendations.push('Block this indicator immediately in your security controls');
    recommendations.push('Investigate any systems that have communicated with this target');
    recommendations.push('Review logs for signs of compromise');
    recommendations.push('Consider reporting to relevant authorities if criminal activity is suspected');
  } else if (riskLevel === 'medium') {
    recommendations.push('Monitor traffic to/from this target closely');
    recommendations.push('Consider implementing additional controls');
    recommendations.push('Update threat detection signatures');
  } else if (riskLevel === 'low') {
    recommendations.push('Continue routine monitoring');
    recommendations.push('No immediate action required');
  } else {
    recommendations.push('No threats detected based on current intelligence');
    recommendations.push('Continue monitoring for new threat intelligence');
  }
  
  // Generate summary
  let summary = '';
  if (malicious > 0) {
    summary = `${target} was flagged as malicious by ${malicious} threat intelligence source(s). `;
  } else if (suspicious > 0) {
    summary = `${target} shows suspicious characteristics in ${suspicious} source(s). `;
  } else if (clean > 0) {
    summary = `${target} appears clean across ${clean} checked source(s). `;
  } else {
    summary = `${target} was not found in threat intelligence feeds. `;
  }
  summary += `Risk score: ${riskScore}/100.`;
  
  // Build metadata
  const metadata: FormattedThreatData['metadata'] = {
    asn: results.ipapi?.as || results.shodan?.asn || null,
    country: results.ipapi?.country || null,
    owner: results.ipapi?.org || results.ipapi?.isp || null,
    lastAnalysis: new Date().toISOString(),
  };
  
  return {
    summary,
    riskLevel,
    riskScore,
    indicators,
    detections: {
      malicious,
      suspicious,
      clean,
      undetected,
    },
    categories: [...new Set(categories)],
    recommendations,
    metadata,
  };
}

export async function queryThreatIntel(
  type: 'ip' | 'domain' | 'url' | 'hash' | 'email',
  target: string,
  sources: string[] = ['virustotal', 'shodan', 'threatfox', 'urlhaus', 'malwarebazaar', 'circl', 'feodo', 'sslbl']
): Promise<ThreatIntelResult> {
  const results: Record<string, any> = {};
  const errors: string[] = [];

  console.log(`[ThreatIntel] Starting analysis for ${type}: ${target}`);

  try {
    const queries: Promise<void>[] = [];

    // VirusTotal for all types (primary source)
    if (sources.includes('virustotal') && VIRUSTOTAL_API_KEY) {
      queries.push(
        queryVirusTotal(type, target).then(r => {
          if (r.error) errors.push(`VirusTotal: ${r.error}`);
          else results.virustotal = r;
        }).catch(e => { errors.push(`VirusTotal: ${e.message}`); })
      );
    }

    // IP-specific queries
    if (type === 'ip') {
      // Always get geolocation for IPs
      queries.push(
        queryIPAPI(target).then(r => {
          if (r.error) errors.push(`IP-API: ${r.error}`);
          else results.ipapi = r;
        }).catch(e => { errors.push(`IP-API: ${e.message}`); })
      );
      
      // Shodan InternetDB
      if (sources.includes('shodan')) {
        queries.push(
          queryShodanInternetDB(target).then(r => {
            if (r.error) errors.push(`Shodan: ${r.error}`);
            else results.shodan = r;
          }).catch(e => { errors.push(`Shodan: ${e.message}`); })
        );
      }
      
      // Feodo Tracker for C2 IPs
      if (sources.includes('feodo')) {
        queries.push(
          queryFeodoTracker(target).then(r => {
            if (r.error) errors.push(`FeodoTracker: ${r.error}`);
            else results.feodo = r;
          }).catch(e => { errors.push(`FeodoTracker: ${e.message}`); })
        );
      }
      
      // SSL Blacklist
      if (sources.includes('sslbl')) {
        queries.push(
          querySSLBL(target).then(r => {
            if (r.error) errors.push(`SSLBL: ${r.error}`);
            else results.sslbl = r;
          }).catch(e => { errors.push(`SSLBL: ${e.message}`); })
        );
      }
    }

    // Domain-specific queries
    if (type === 'domain') {
      queries.push(
        checkDomainReputation(target).then(r => {
          if (r.error) errors.push(`DNS: ${r.error}`);
          else results.dns = r;
        }).catch(e => { errors.push(`DNS: ${e.message}`); })
      );
    }

    // URL and Domain queries - URLhaus
    if ((type === 'url' || type === 'domain' || type === 'ip') && sources.includes('urlhaus')) {
      queries.push(
        queryURLhaus(type, target).then(r => {
          if (r.error) errors.push(`URLhaus: ${r.error}`);
          else results.urlhaus = r;
        }).catch(e => { errors.push(`URLhaus: ${e.message}`); })
      );
    }

    // Hash-specific queries
    if (type === 'hash') {
      // MalwareBazaar
      if (sources.includes('malwarebazaar')) {
        queries.push(
          queryMalwareBazaar(target).then(r => {
            if (r.error) errors.push(`MalwareBazaar: ${r.error}`);
            else results.malwarebazaar = r;
          }).catch(e => { errors.push(`MalwareBazaar: ${e.message}`); })
        );
      }
      
      // CIRCL Hashlookup
      if (sources.includes('circl')) {
        queries.push(
          queryCirclHashlookup(target).then(r => {
            if (r.error) errors.push(`CIRCL: ${r.error}`);
            else results.circl = r;
          }).catch(e => { errors.push(`CIRCL: ${e.message}`); })
        );
      }
      
      // URLhaus for hash payloads
      if (sources.includes('urlhaus')) {
        queries.push(
          queryURLhaus('hash', target).then(r => {
            if (r.error) errors.push(`URLhaus: ${r.error}`);
            else results.urlhaus = r;
          }).catch(e => { errors.push(`URLhaus: ${e.message}`); })
        );
      }
    }

    // ThreatFox for all types
    if (sources.includes('threatfox')) {
      queries.push(
        queryThreatFox(type, target).then(r => {
          if (r.error) errors.push(`ThreatFox: ${r.error}`);
          else results.threatfox = r;
        }).catch(e => { errors.push(`ThreatFox: ${e.message}`); })
      );
    }

    // Wait for all queries to complete
    await Promise.all(queries);

    console.log(`[ThreatIntel] Completed. Results from ${Object.keys(results).length} sources, ${errors.length} errors`);

    // Format the results
    const formatted = formatThreatData(type, target, results);

    return {
      success: true,
      type,
      target,
      raw: results,
      formatted,
      errors: errors.length > 0 ? errors : undefined,
      timestamp: new Date().toISOString(),
    };
  } catch (error) {
    console.error('[ThreatIntel] Fatal error:', error);
    return {
      success: false,
      type,
      target,
      raw: results,
      formatted: null,
      errors: [error instanceof Error ? error.message : 'Unknown error'],
      timestamp: new Date().toISOString(),
    };
  }
}

// Free OSINT feeds - no API key required
export async function queryFreeThreatFeeds(type: string, target: string): Promise<Record<string, any>> {
  const results: Record<string, any> = {};

  try {
    if (type === 'ip') {
      // Get IP geolocation
      const geoResult = await queryIPAPI(target);
      if (!geoResult.error) {
        results.geolocation = geoResult;
      }
      
      // Check Shodan InternetDB
      const shodanResult = await queryShodanInternetDB(target);
      if (!shodanResult.error) {
        results.shodan = shodanResult;
      }
    }
  } catch (error) {
    console.error('Free threat feeds query failed:', error);
  }

  return results;
}

export function getRiskColor(level: string): string {
  switch (level) {
    case 'critical': return 'text-red-500';
    case 'high': return 'text-orange-500';
    case 'medium': return 'text-yellow-500';
    case 'low': return 'text-blue-500';
    default: return 'text-muted-foreground';
  }
}

export function getRiskBgColor(level: string): string {
  switch (level) {
    case 'critical': return 'bg-red-500/20 border-red-500';
    case 'high': return 'bg-orange-500/20 border-orange-500';
    case 'medium': return 'bg-yellow-500/20 border-yellow-500';
    case 'low': return 'bg-blue-500/20 border-blue-500';
    default: return 'bg-muted border-border';
  }
}
