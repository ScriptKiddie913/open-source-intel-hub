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

// Query Abuse.ch feeds directly (free, no API key required)
async function queryAbuseCh(type: string, target: string): Promise<any> {
  try {
    const results: any = { matched: false, sources: [] };
    
    // Check Feodo Tracker for IPs
    if (type === 'ip') {
      try {
        const feodoResponse = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist.txt');
        if (feodoResponse.ok) {
          const feodoData = await feodoResponse.text();
          if (feodoData.includes(target)) {
            results.matched = true;
            results.sources.push({
              name: 'Feodo Tracker',
              type: 'Botnet C2',
              risk: 'high',
            });
          }
        }
      } catch (e) {
        console.warn('Feodo Tracker query failed:', e);
      }
    }
    
    // Check SSL Blacklist
    if (type === 'ip') {
      try {
        const sslResponse = await fetch('https://sslbl.abuse.ch/blacklist/sslipblacklist.txt');
        if (sslResponse.ok) {
          const sslData = await sslResponse.text();
          if (sslData.includes(target)) {
            results.matched = true;
            results.sources.push({
              name: 'SSL Blacklist',
              type: 'Malicious SSL',
              risk: 'high',
            });
          }
        }
      } catch (e) {
        console.warn('SSL Blacklist query failed:', e);
      }
    }
    
    return results;
  } catch (error) {
    console.error('Abuse.ch query error:', error);
    return { error: error instanceof Error ? error.message : 'Query failed' };
  }
}

// Query CIRCL Hashlookup (free, no API key required)
async function queryCirclHashlookup(hash: string): Promise<any> {
  try {
    // Determine hash type
    let hashType = 'sha256';
    if (hash.length === 32) hashType = 'md5';
    else if (hash.length === 40) hashType = 'sha1';
    
    const response = await fetch(`https://hashlookup.circl.lu/lookup/${hashType}/${hash}`);
    
    if (!response.ok) {
      if (response.status === 404) {
        return { found: false, message: 'Hash not found in CIRCL database' };
      }
      return { error: `API error: ${response.status}` };
    }
    
    const data = await response.json();
    return {
      found: true,
      filename: data.FileName,
      filesize: data.FileSize,
      knownSource: data.KnownMalicious ? 'malicious' : 'benign',
      md5: data.MD5,
      sha1: data.SHA1,
      sha256: data.SHA256,
    };
  } catch (error) {
    console.error('CIRCL query error:', error);
    return { error: error instanceof Error ? error.message : 'Query failed' };
  }
}

// Query URLhaus (free, no API key required)
async function queryUrlhaus(url: string): Promise<any> {
  try {
    const response = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `url=${encodeURIComponent(url)}`,
    });
    
    if (!response.ok) {
      return { error: `API error: ${response.status}` };
    }
    
    const data = await response.json();
    return {
      found: data.query_status === 'ok',
      status: data.url_status,
      threat: data.threat,
      dateAdded: data.date_added,
      tags: data.tags,
    };
  } catch (error) {
    console.error('URLhaus query error:', error);
    return { error: error instanceof Error ? error.message : 'Query failed' };
  }
}

// Query URLhaus by host (for domains)
async function queryUrlhausByHost(host: string): Promise<any> {
  try {
    const response = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `host=${encodeURIComponent(host)}`,
    });
    
    if (!response.ok) {
      return { error: `API error: ${response.status}` };
    }
    
    const data = await response.json();
    return {
      found: data.query_status === 'ok',
      urlCount: data.url_count || 0,
      urls: data.urls?.slice(0, 10) || [],
    };
  } catch (error) {
    console.error('URLhaus host query error:', error);
    return { error: error instanceof Error ? error.message : 'Query failed' };
  }
}

// Query MalwareBazaar for hashes (free, no API key required)
async function queryMalwareBazaar(hash: string): Promise<any> {
  try {
    const response = await fetch('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `query=get_info&hash=${encodeURIComponent(hash)}`,
    });
    
    if (!response.ok) {
      return { error: `API error: ${response.status}` };
    }
    
    const data = await response.json();
    if (data.query_status === 'ok' && data.data && data.data.length > 0) {
      const sample = data.data[0];
      return {
        found: true,
        filename: sample.file_name,
        fileType: sample.file_type,
        signature: sample.signature,
        tags: sample.tags,
        firstSeen: sample.first_seen,
        reporter: sample.reporter,
      };
    }
    return { found: false, message: 'Hash not found in MalwareBazaar' };
  } catch (error) {
    console.error('MalwareBazaar query error:', error);
    return { error: error instanceof Error ? error.message : 'Query failed' };
  }
}

// Query ThreatFox for IOCs (free, no API key required)
async function queryThreatFox(type: string, target: string): Promise<any> {
  try {
    let searchType = 'search_ioc';
    let body = `query=${searchType}&search_term=${encodeURIComponent(target)}`;
    
    const response = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body,
    });
    
    if (!response.ok) {
      return { error: `API error: ${response.status}` };
    }
    
    const data = await response.json();
    if (data.query_status === 'ok' && data.data && data.data.length > 0) {
      return {
        found: true,
        iocs: data.data.slice(0, 10).map((ioc: any) => ({
          type: ioc.ioc_type,
          value: ioc.ioc,
          threat: ioc.threat_type,
          malware: ioc.malware,
          confidence: ioc.confidence_level,
          firstSeen: ioc.first_seen,
        })),
      };
    }
    return { found: false, message: 'Not found in ThreatFox' };
  } catch (error) {
    console.error('ThreatFox query error:', error);
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
  
  // Process Abuse.ch results
  if (results.abuse?.matched) {
    riskScore += 40;
    for (const source of results.abuse.sources || []) {
      malicious++;
      indicators.push({
        type: source.type,
        value: target,
        source: source.name,
        severity: source.risk === 'critical' ? 'critical' : 'high',
      });
      categories.push(source.type);
    }
  } else if (results.abuse && !results.abuse.error) {
    clean++;
  }
  
  // Process CIRCL results
  if (results.circl?.found) {
    if (results.circl.knownSource === 'malicious') {
      riskScore += 50;
      malicious++;
      indicators.push({
        type: 'Known Malicious File',
        value: results.circl.filename || target,
        source: 'CIRCL Hashlookup',
        severity: 'high',
      });
      categories.push('Malware');
    } else {
      clean++;
    }
  } else if (results.circl && !results.circl.error) {
    undetected++;
  }
  
  // Process URLhaus results
  if (results.urlhaus?.found) {
    riskScore += 45;
    malicious++;
    indicators.push({
      type: results.urlhaus.threat || 'Malicious URL',
      value: target,
      source: 'URLhaus',
      severity: 'high',
    });
    if (results.urlhaus.threat) {
      categories.push(results.urlhaus.threat);
    }
  } else if (results.urlhaus && !results.urlhaus.error) {
    clean++;
  }
  
  // Process URLhaus host results
  if (results.urlhausHost?.found && results.urlhausHost.urlCount > 0) {
    riskScore += 35;
    suspicious++;
    indicators.push({
      type: 'Associated Malicious URLs',
      value: `${results.urlhausHost.urlCount} URLs found`,
      source: 'URLhaus',
      severity: 'medium',
    });
    categories.push('Malware Distribution');
  }
  
  // Process MalwareBazaar results
  if (results.malwarebazaar?.found) {
    riskScore += 60;
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
  
  // Process ThreatFox results
  if (results.threatfox?.found) {
    riskScore += 50;
    for (const ioc of results.threatfox.iocs || []) {
      malicious++;
      indicators.push({
        type: ioc.threat || 'Threat Indicator',
        value: ioc.malware || target,
        source: 'ThreatFox',
        severity: ioc.confidence >= 75 ? 'high' : 'medium',
      });
      if (ioc.malware) {
        categories.push(ioc.malware);
      }
    }
  }
  
  // Process OpenPhish results
  if (results.openphish?.matched) {
    riskScore += 55;
    malicious++;
    indicators.push({
      type: 'Phishing URL',
      value: target,
      source: 'OpenPhish',
      severity: 'critical',
    });
    categories.push('Phishing');
  }
  
  // Cap risk score at 100
  riskScore = Math.min(riskScore, 100);
  
  // Determine risk level
  if (riskScore >= 80) riskLevel = 'critical';
  else if (riskScore >= 60) riskLevel = 'high';
  else if (riskScore >= 40) riskLevel = 'medium';
  else if (riskScore >= 20) riskLevel = 'low';
  else riskLevel = 'info';
  
  // Generate recommendations based on findings
  if (riskLevel === 'critical' || riskLevel === 'high') {
    recommendations.push('Block this indicator immediately in your security controls');
    recommendations.push('Investigate any systems that have communicated with this target');
    recommendations.push('Review logs for signs of compromise');
  } else if (riskLevel === 'medium') {
    recommendations.push('Monitor traffic to/from this target closely');
    recommendations.push('Consider implementing additional controls');
  } else {
    recommendations.push('No immediate action required based on current intelligence');
    recommendations.push('Continue monitoring for new threat intelligence');
  }
  
  // Generate summary
  let summary = '';
  if (malicious > 0) {
    summary = `${target} was flagged as malicious by ${malicious} threat intelligence source(s). `;
  } else if (suspicious > 0) {
    summary = `${target} shows suspicious activity in ${suspicious} source(s). `;
  } else {
    summary = `${target} was not found in any threat intelligence feeds checked. `;
  }
  summary += `Risk score: ${riskScore}/100.`;
  
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
    metadata: {
      asn: null,
      country: null,
      owner: null,
      lastAnalysis: new Date().toISOString(),
    },
  };
}

export async function queryThreatIntel(
  type: 'ip' | 'domain' | 'url' | 'hash' | 'email',
  target: string,
  sources: string[] = ['abuse', 'circl', 'urlhaus', 'malwarebazaar', 'threatfox']
): Promise<ThreatIntelResult> {
  const results: Record<string, any> = {};
  const errors: string[] = [];

  try {
    // Run queries in parallel based on type
    const queries: Promise<void>[] = [];

    // Abuse.ch feeds for IPs
    if (sources.includes('abuse') && type === 'ip') {
      queries.push(
        queryAbuseCh(type, target).then(r => {
          if (r.error) errors.push(`Abuse.ch: ${r.error}`);
          else results.abuse = r;
        })
      );
    }

    // CIRCL Hashlookup for hashes
    if (sources.includes('circl') && type === 'hash') {
      queries.push(
        queryCirclHashlookup(target).then(r => {
          if (r.error) errors.push(`CIRCL: ${r.error}`);
          else results.circl = r;
        })
      );
    }

    // URLhaus for URLs
    if (sources.includes('urlhaus') && type === 'url') {
      queries.push(
        queryUrlhaus(target).then(r => {
          if (r.error) errors.push(`URLhaus: ${r.error}`);
          else results.urlhaus = r;
        })
      );
    }

    // URLhaus by host for domains/IPs
    if (sources.includes('urlhaus') && (type === 'domain' || type === 'ip')) {
      queries.push(
        queryUrlhausByHost(target).then(r => {
          if (r.error) errors.push(`URLhaus Host: ${r.error}`);
          else results.urlhausHost = r;
        })
      );
    }

    // MalwareBazaar for hashes
    if (sources.includes('malwarebazaar') && type === 'hash') {
      queries.push(
        queryMalwareBazaar(target).then(r => {
          if (r.error) errors.push(`MalwareBazaar: ${r.error}`);
          else results.malwarebazaar = r;
        })
      );
    }

    // ThreatFox for all types
    if (sources.includes('threatfox')) {
      queries.push(
        queryThreatFox(type, target).then(r => {
          if (r.error) errors.push(`ThreatFox: ${r.error}`);
          else results.threatfox = r;
        })
      );
    }

    // OpenPhish for URLs/domains
    if (type === 'url' || type === 'domain') {
      queries.push(
        queryFreeThreatFeeds(type, target).then(r => {
          if (r.openphish) results.openphish = r.openphish;
        })
      );
    }

    // Wait for all queries to complete
    await Promise.all(queries);

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
    console.error('Threat intel query error:', error);
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
    // OpenPhish for phishing URLs
    if (type === 'url' || type === 'domain') {
      const openPhishResponse = await fetch('https://openphish.com/feed.txt');
      if (openPhishResponse.ok) {
        const phishData = await openPhishResponse.text();
        const phishUrls = phishData.split('\n').filter(u => u.includes(target));
        results.openphish = {
          matched: phishUrls.length > 0,
          matchedUrls: phishUrls.slice(0, 10),
        };
      }
    }
  } catch (error) {
    console.error('OpenPhish query failed:', error);
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
