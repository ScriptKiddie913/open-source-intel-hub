// ============================================================================
// CAMPAIGN CORRELATION SERVICE
// ============================================================================
// Correlates malware samples, infrastructure, and TTPs into campaigns
// Links operators across time via shared artifacts
// ============================================================================

// Generate UUID without external dependency
const uuidv4 = (): string => {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
};

/* ============================================================================
   TYPES
============================================================================ */

export interface MalwareSampleSignal {
  id: string;
  hash: string;
  hashType: 'sha256' | 'md5' | 'sha1';
  family: string;
  type: 'infostealer' | 'ransomware' | 'rat' | 'loader' | 'dropper' | 'backdoor' | 'botnet' | 'miner';
  capabilities: string[];
  firstSeen: string;
  lastSeen: string;
  source: string;
  tags: string[];
  confidence: number;
}

export interface InfrastructureNode {
  id: string;
  type: 'c2' | 'dropper' | 'staging' | 'exfil' | 'proxy' | 'bulletproof';
  value: string; // IP or domain
  port?: number;
  protocol?: string;
  asn?: string;
  asnOrg?: string;
  country?: string;
  hosting?: string;
  tlsCertHash?: string;
  firstSeen: string;
  lastSeen: string;
  status: 'active' | 'inactive' | 'sinkholed' | 'seized';
  rotationRate?: number; // days between changes
  linkedSamples: string[];
  linkedCampaigns: string[];
}

export interface Campaign {
  id: string;
  name: string;
  codename?: string;
  families: string[];
  targetSectors: string[];
  targetRegions: string[];
  ttps: string[];
  infrastructure: InfrastructureNode[];
  samples: MalwareSampleSignal[];
  timeline: CampaignEvent[];
  attribution: AttributionSignal[];
  status: 'active' | 'dormant' | 'concluded';
  firstSeen: string;
  lastSeen: string;
  confidence: number;
  riskScore: number;
  sources: { name: string; url: string }[];
  description?: string;
  actor?: string;
  threatLevel?: string;
}

export interface CampaignEvent {
  id: string;
  timestamp: string;
  type: 'sample_detected' | 'infra_change' | 'new_variant' | 'takedown' | 'victim_spike' | 'ttp_evolution';
  description: string;
  indicators: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface AttributionSignal {
  type: 'language' | 'timezone' | 'toolchain' | 'infrastructure' | 'ttp_overlap' | 'historical';
  value: string;
  confidence: number;
  evidence: string;
}

export interface CorrelationResult {
  campaigns: Campaign[];
  newCorrelations: CampaignCorrelation[];
  infraOverlaps: InfraOverlap[];
  timeline: TimelineEvent[];
  stats: {
    totalSamples: number;
    totalCampaigns: number;
    activeThreats: number;
    correlationStrength: number;
  };
}

export interface CampaignCorrelation {
  campaignA: string;
  campaignB: string;
  correlationType: 'infra_reuse' | 'toolchain' | 'ttp_match' | 'timeline_overlap' | 'wallet_match';
  confidence: number;
  evidence: string[];
}

export interface InfraOverlap {
  indicator: string;
  campaigns: string[];
  families: string[];
  timeRange: { start: string; end: string };
}

export interface TimelineEvent {
  timestamp: string;
  campaignId: string;
  type: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

/* ============================================================================
   KNOWN MALWARE FAMILIES DATABASE
============================================================================ */

const MALWARE_FAMILIES: Record<string, {
  type: string;
  capabilities: string[];
  killChain: string[];
  ttps: string[];
  indicators: { type: string; pattern: string }[];
}> = {
  'RedLine': {
    type: 'infostealer',
    capabilities: ['browser_creds', 'crypto_wallets', 'ftp_creds', 'discord_tokens', 'telegram_sessions', 'steam_sessions', 'vpn_configs'],
    killChain: ['phishing', 'cracked_software', 'malvertising'],
    ttps: ['T1555', 'T1539', 'T1552', 'T1056.001', 'T1113'],
    indicators: [
      { type: 'mutex', pattern: 'RedLine.*' },
      { type: 'string', pattern: 'RedLine Stealer' },
      { type: 'c2_path', pattern: '/api/check' },
    ],
  },
  'Raccoon': {
    type: 'infostealer',
    capabilities: ['browser_creds', 'crypto_wallets', 'system_info', 'screenshots', 'file_grabber'],
    killChain: ['malspam', 'exploit_kit', 'cracked_software'],
    ttps: ['T1555', 'T1539', 'T1082', 'T1113', 'T1005'],
    indicators: [
      { type: 'mutex', pattern: 'raccoon_.*' },
      { type: 'ua', pattern: 'Raccoon Stealer' },
    ],
  },
  'Vidar': {
    type: 'infostealer',
    capabilities: ['browser_creds', 'crypto_wallets', '2fa_codes', 'file_grabber', 'screenshot'],
    killChain: ['malspam', 'seo_poisoning', 'youtube_malvertising'],
    ttps: ['T1555', 'T1539', 'T1552', 'T1113', 'T1560'],
    indicators: [
      { type: 'c2_path', pattern: '/[0-9]+$' },
      { type: 'config', pattern: 'profile_id=' },
    ],
  },
  'LummaC2': {
    type: 'infostealer',
    capabilities: ['browser_creds', 'crypto_wallets', 'crypto_extensions', '2fa_bypass', 'session_hijack'],
    killChain: ['malvertising', 'fake_updates', 'cracked_software'],
    ttps: ['T1555', 'T1539', 'T1528', 'T1550.004'],
    indicators: [
      { type: 'string', pattern: 'LummaC2' },
      { type: 'c2_path', pattern: '/c2conf' },
    ],
  },
  'Stealc': {
    type: 'infostealer',
    capabilities: ['browser_creds', 'crypto_wallets', 'discord', 'telegram', 'outlook'],
    killChain: ['cracked_software', 'malspam'],
    ttps: ['T1555', 'T1539', 'T1552'],
    indicators: [
      { type: 'string', pattern: 'Stealc' },
    ],
  },
  'LockBit': {
    type: 'ransomware',
    capabilities: ['encryption', 'exfiltration', 'lateral_movement', 'shadow_delete', 'service_stop'],
    killChain: ['initial_access_broker', 'rdp_brute', 'phishing', 'exploit'],
    ttps: ['T1486', 'T1490', 'T1489', 'T1021.001', 'T1078'],
    indicators: [
      { type: 'extension', pattern: '.lockbit' },
      { type: 'ransom_note', pattern: 'Restore-My-Files.txt' },
    ],
  },
  'BlackCat': {
    type: 'ransomware',
    capabilities: ['cross_platform', 'encryption', 'exfiltration', 'esxi_targeting'],
    killChain: ['initial_access_broker', 'exploit', 'rdp'],
    ttps: ['T1486', 'T1490', 'T1489', 'T1048'],
    indicators: [
      { type: 'extension', pattern: '.alphv' },
      { type: 'string', pattern: 'ALPHV' },
    ],
  },
  'Qakbot': {
    type: 'loader',
    capabilities: ['banking', 'loader', 'lateral_movement', 'email_hijack'],
    killChain: ['malspam', 'thread_hijack'],
    ttps: ['T1566.001', 'T1059.001', 'T1021.002', 'T1055'],
    indicators: [
      { type: 'mutex', pattern: 'qbot.*' },
      { type: 'config', pattern: 'campaign_id=' },
    ],
  },
  'Emotet': {
    type: 'loader',
    capabilities: ['loader', 'spam_bot', 'lateral_movement', 'persistence'],
    killChain: ['malspam', 'macro_docs'],
    ttps: ['T1566.001', 'T1059.005', 'T1547.001', 'T1055'],
    indicators: [
      { type: 'c2_port', pattern: '443|447|449|8080' },
    ],
  },
  'Cobalt Strike': {
    type: 'rat',
    capabilities: ['c2', 'lateral_movement', 'credential_theft', 'process_injection'],
    killChain: ['phishing', 'exploit', 'supply_chain'],
    ttps: ['T1059.001', 'T1055', 'T1003', 'T1021'],
    indicators: [
      { type: 'ja3', pattern: '72a589da586844d7f0818ce684948eea' },
      { type: 'beacon', pattern: 'sleeptime=' },
    ],
  },
};

/* ============================================================================
   CAMPAIGN CORRELATION ENGINE
============================================================================ */

/**
 * Main correlation function - takes indicators and builds campaign graph
 */
export async function correlateCampaigns(query: string): Promise<CorrelationResult> {
  console.log(`[CampaignCorrelation] Analyzing: ${query}`);
  
  const result: CorrelationResult = {
    campaigns: [],
    newCorrelations: [],
    infraOverlaps: [],
    timeline: [],
    stats: {
      totalSamples: 0,
      totalCampaigns: 0,
      activeThreats: 0,
      correlationStrength: 0,
    },
  };
  
  // Gather data from multiple sources in parallel
  const [
    threatFoxData,
    urlhausData,
    malwareBazaarData,
    feodoData,
  ] = await Promise.all([
    fetchThreatFoxCampaigns(query),
    fetchURLhausCampaigns(query),
    fetchMalwareBazaarCampaigns(query),
    fetchFeodoCampaigns(query),
  ]);
  
  // Merge and deduplicate samples
  const allSamples = [
    ...threatFoxData.samples,
    ...urlhausData.samples,
    ...malwareBazaarData.samples,
    ...feodoData.samples,
  ];
  
  // Merge infrastructure
  const allInfra = [
    ...threatFoxData.infrastructure,
    ...urlhausData.infrastructure,
    ...feodoData.infrastructure,
  ];
  
  // Build campaigns from correlated data
  result.campaigns = buildCampaignsFromSignals(allSamples, allInfra, query);
  
  // Find cross-campaign correlations
  result.newCorrelations = findCampaignCorrelations(result.campaigns);
  
  // Find infrastructure overlaps
  result.infraOverlaps = findInfrastructureOverlaps(allInfra, result.campaigns);
  
  // Build timeline
  result.timeline = buildCampaignTimeline(result.campaigns);
  
  // Calculate stats
  result.stats = {
    totalSamples: allSamples.length,
    totalCampaigns: result.campaigns.length,
    activeThreats: result.campaigns.filter(c => c.status === 'active').length,
    correlationStrength: calculateCorrelationStrength(result.newCorrelations),
  };
  
  console.log(`[CampaignCorrelation] Found ${result.campaigns.length} campaigns, ${allSamples.length} samples`);
  
  return result;
}

/* ============================================================================
   DATA FETCHERS
============================================================================ */

async function fetchThreatFoxCampaigns(query: string): Promise<{
  samples: MalwareSampleSignal[];
  infrastructure: InfrastructureNode[];
}> {
  const samples: MalwareSampleSignal[] = [];
  const infrastructure: InfrastructureNode[] = [];
  
  try {
    // Search ThreatFox for IOCs
    const response = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'search_ioc', search_term: query }),
    });
    
    if (response.ok) {
      const data = await response.json();
      if (data.data && Array.isArray(data.data)) {
        for (const ioc of data.data) {
          // Add infrastructure
          if (ioc.ioc_type?.includes('ip') || ioc.ioc_type?.includes('domain') || ioc.ioc_type?.includes('url')) {
            infrastructure.push({
              id: `tf-${ioc.id}`,
              type: ioc.threat_type === 'botnet_cc' ? 'c2' : 'dropper',
              value: ioc.ioc,
              country: ioc.reporter_country || 'Unknown',
              firstSeen: ioc.first_seen || new Date().toISOString(),
              lastSeen: ioc.last_seen || new Date().toISOString(),
              status: ioc.is_active ? 'active' : 'inactive',
              linkedSamples: [],
              linkedCampaigns: [],
            });
          }
          
          // Add sample signal
          if (ioc.malware) {
            const familyInfo = MALWARE_FAMILIES[ioc.malware] || {
              type: 'unknown',
              capabilities: [],
              killChain: [],
              ttps: [],
              indicators: [],
            };
            
            samples.push({
              id: `tf-sample-${ioc.id}`,
              hash: ioc.ioc_type?.includes('hash') ? ioc.ioc : '',
              hashType: 'sha256',
              family: ioc.malware,
              type: familyInfo.type as any,
              capabilities: familyInfo.capabilities,
              firstSeen: ioc.first_seen || new Date().toISOString(),
              lastSeen: ioc.last_seen || new Date().toISOString(),
              source: 'ThreatFox',
              tags: ioc.tags || [],
              confidence: ioc.confidence_level || 75,
            });
          }
        }
      }
    }
  } catch (err) {
    console.error('[ThreatFox Campaign] Error:', err);
  }
  
  return { samples, infrastructure };
}

async function fetchURLhausCampaigns(query: string): Promise<{
  samples: MalwareSampleSignal[];
  infrastructure: InfrastructureNode[];
}> {
  const samples: MalwareSampleSignal[] = [];
  const infrastructure: InfrastructureNode[] = [];
  
  try {
    // Search URLhaus
    const response = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `url=${encodeURIComponent(query)}`,
    });
    
    if (response.ok) {
      const data = await response.json();
      if (data.urls && Array.isArray(data.urls)) {
        for (const url of data.urls) {
          infrastructure.push({
            id: `uh-${url.id}`,
            type: 'dropper',
            value: url.url,
            firstSeen: url.date_added || new Date().toISOString(),
            lastSeen: url.date_added || new Date().toISOString(),
            status: url.url_status === 'online' ? 'active' : 'inactive',
            linkedSamples: [],
            linkedCampaigns: [],
          });
          
          if (url.threat) {
            samples.push({
              id: `uh-sample-${url.id}`,
              hash: url.payloads?.[0]?.sha256_hash || '',
              hashType: 'sha256',
              family: url.threat,
              type: url.threat.toLowerCase().includes('stealer') ? 'infostealer' : 'loader',
              capabilities: [],
              firstSeen: url.date_added || new Date().toISOString(),
              lastSeen: url.date_added || new Date().toISOString(),
              source: 'URLhaus',
              tags: url.tags || [],
              confidence: 80,
            });
          }
        }
      }
    }
  } catch (err) {
    console.error('[URLhaus Campaign] Error:', err);
  }
  
  return { samples, infrastructure };
}

async function fetchMalwareBazaarCampaigns(query: string): Promise<{
  samples: MalwareSampleSignal[];
  infrastructure: InfrastructureNode[];
}> {
  const samples: MalwareSampleSignal[] = [];
  
  try {
    // Search by tag or signature
    const response = await fetch('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `query=get_taginfo&tag=${encodeURIComponent(query)}&limit=50`,
    });
    
    if (response.ok) {
      const data = await response.json();
      if (data.data && Array.isArray(data.data)) {
        for (const sample of data.data) {
          const familyInfo = MALWARE_FAMILIES[sample.signature] || {
            type: 'unknown',
            capabilities: [],
            killChain: [],
            ttps: [],
            indicators: [],
          };
          
          samples.push({
            id: `mb-${sample.sha256_hash}`,
            hash: sample.sha256_hash,
            hashType: 'sha256',
            family: sample.signature || 'Unknown',
            type: familyInfo.type as any,
            capabilities: familyInfo.capabilities,
            firstSeen: sample.first_seen || new Date().toISOString(),
            lastSeen: sample.last_seen || sample.first_seen || new Date().toISOString(),
            source: 'MalwareBazaar',
            tags: sample.tags || [],
            confidence: sample.intelligence?.downloads > 10 ? 90 : 70,
          });
        }
      }
    }
  } catch (err) {
    console.error('[MalwareBazaar Campaign] Error:', err);
  }
  
  return { samples, infrastructure: [] };
}

async function fetchFeodoCampaigns(query: string): Promise<{
  samples: MalwareSampleSignal[];
  infrastructure: InfrastructureNode[];
}> {
  const infrastructure: InfrastructureNode[] = [];
  
  try {
    // Feodo Tracker for botnet C2s
    const response = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json');
    
    if (response.ok) {
      const data = await response.json();
      if (Array.isArray(data)) {
        const filtered = data.filter((item: any) => 
          item.ip_address?.includes(query) || 
          item.malware?.toLowerCase().includes(query.toLowerCase())
        );
        
        for (const c2 of filtered) {
          infrastructure.push({
            id: `feodo-${c2.ip_address}`,
            type: 'c2',
            value: c2.ip_address,
            port: c2.port,
            country: c2.country || 'Unknown',
            asn: c2.as_number?.toString(),
            asnOrg: c2.as_name,
            firstSeen: c2.first_seen || new Date().toISOString(),
            lastSeen: c2.last_online || new Date().toISOString(),
            status: c2.status === 'online' ? 'active' : 'inactive',
            linkedSamples: [],
            linkedCampaigns: [],
          });
        }
      }
    }
  } catch (err) {
    console.error('[Feodo Campaign] Error:', err);
  }
  
  return { samples: [], infrastructure };
}

/* ============================================================================
   CORRELATION LOGIC
============================================================================ */

function buildCampaignsFromSignals(
  samples: MalwareSampleSignal[],
  infrastructure: InfrastructureNode[],
  query: string
): Campaign[] {
  const campaigns: Campaign[] = [];
  
  // Group samples by family
  const familyGroups = new Map<string, MalwareSampleSignal[]>();
  for (const sample of samples) {
    const family = sample.family || 'Unknown';
    if (!familyGroups.has(family)) {
      familyGroups.set(family, []);
    }
    familyGroups.get(family)!.push(sample);
  }
  
  // Create campaign for each active family
  for (const [family, familySamples] of familyGroups) {
    if (familySamples.length === 0) continue;
    
    const familyInfo = MALWARE_FAMILIES[family];
    const relatedInfra = infrastructure.filter(i => 
      familySamples.some(s => s.tags?.some(t => i.value.includes(t)))
    );
    
    // Calculate timeline
    const timestamps = familySamples.map(s => new Date(s.firstSeen).getTime()).filter(t => !isNaN(t));
    const firstSeen = timestamps.length > 0 
      ? new Date(Math.min(...timestamps)).toISOString() 
      : new Date().toISOString();
    const lastSeen = timestamps.length > 0
      ? new Date(Math.max(...timestamps)).toISOString()
      : new Date().toISOString();
    
    // Determine status
    const daysSinceLastSeen = (Date.now() - new Date(lastSeen).getTime()) / (1000 * 60 * 60 * 24);
    const status = daysSinceLastSeen < 7 ? 'active' : daysSinceLastSeen < 30 ? 'dormant' : 'concluded';
    
    // Build timeline events
    const timeline: CampaignEvent[] = familySamples.map(s => ({
      id: uuidv4(),
      timestamp: s.firstSeen,
      type: 'sample_detected' as const,
      description: `New ${family} sample detected from ${s.source}`,
      indicators: [s.hash].filter(Boolean),
      severity: s.confidence > 80 ? 'high' : 'medium' as const,
    }));
    
    // Attribution signals
    const attribution: AttributionSignal[] = [];
    if (familyInfo) {
      attribution.push({
        type: 'toolchain',
        value: family,
        confidence: 85,
        evidence: `Known ${familyInfo.type} family with documented TTPs`,
      });
    }
    
    // Calculate risk score
    const riskScore = calculateRiskScore(familySamples, relatedInfra, status);
    
    // Determine sources from samples
    const sampleSources = [...new Set(familySamples.map(s => s.source))];
    const sources: { name: string; url: string }[] = sampleSources.map(src => {
      switch (src) {
        case 'ThreatFox': return { name: 'ThreatFox', url: `https://threatfox.abuse.ch/browse/?search=${encodeURIComponent(family)}` };
        case 'MalwareBazaar': return { name: 'MalwareBazaar', url: `https://bazaar.abuse.ch/browse.php?search=${encodeURIComponent(family)}` };
        case 'URLhaus': return { name: 'URLhaus', url: `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(family)}` };
        case 'FeodoTracker': return { name: 'Feodo Tracker', url: 'https://feodotracker.abuse.ch/browse/' };
        default: return { name: src, url: `https://www.virustotal.com/gui/search/${encodeURIComponent(family)}` };
      }
    });
    
    // Add MITRE ATT&CK source if TTPs present
    if (familyInfo?.ttps && familyInfo.ttps.length > 0) {
      sources.push({ 
        name: 'MITRE ATT&CK', 
        url: `https://attack.mitre.org/techniques/${familyInfo.ttps[0]}/` 
      });
    }
    
    // Generate description
    const description = familyInfo 
      ? `${family} is a known ${familyInfo.type} targeting ${inferTargetSectors(family).join(', ')} sectors. Capabilities include ${familyInfo.capabilities.slice(0, 3).join(', ')}.`
      : `Active campaign leveraging ${family} malware family with ${familySamples.length} detected samples.`;

    campaigns.push({
      id: uuidv4(),
      name: `${family} Campaign - ${new Date(firstSeen).toLocaleDateString()}`,
      codename: generateCodename(),
      families: [family],
      targetSectors: inferTargetSectors(family),
      targetRegions: inferTargetRegions(relatedInfra),
      ttps: familyInfo?.ttps || [],
      infrastructure: relatedInfra,
      samples: familySamples,
      timeline,
      attribution,
      status,
      firstSeen,
      lastSeen,
      confidence: Math.round(familySamples.reduce((sum, s) => sum + s.confidence, 0) / familySamples.length),
      riskScore,
      sources,
      description,
      actor: attribution.length > 0 ? attribution[0].value : 'Unknown Actor',
      threatLevel: riskScore > 70 ? 'critical' : riskScore > 50 ? 'high' : 'medium',
    });
  }
  
  return campaigns;
}

function findCampaignCorrelations(campaigns: Campaign[]): CampaignCorrelation[] {
  const correlations: CampaignCorrelation[] = [];
  
  for (let i = 0; i < campaigns.length; i++) {
    for (let j = i + 1; j < campaigns.length; j++) {
      const a = campaigns[i];
      const b = campaigns[j];
      
      // Check infrastructure reuse
      const sharedInfra = a.infrastructure.filter(ia =>
        b.infrastructure.some(ib => ia.value === ib.value)
      );
      if (sharedInfra.length > 0) {
        correlations.push({
          campaignA: a.id,
          campaignB: b.id,
          correlationType: 'infra_reuse',
          confidence: Math.min(90, 50 + sharedInfra.length * 10),
          evidence: sharedInfra.map(i => i.value),
        });
      }
      
      // Check TTP overlap
      const sharedTTPs = a.ttps.filter(t => b.ttps.includes(t));
      if (sharedTTPs.length >= 3) {
        correlations.push({
          campaignA: a.id,
          campaignB: b.id,
          correlationType: 'ttp_match',
          confidence: Math.min(80, 40 + sharedTTPs.length * 8),
          evidence: sharedTTPs,
        });
      }
      
      // Check timeline overlap
      const aStart = new Date(a.firstSeen).getTime();
      const aEnd = new Date(a.lastSeen).getTime();
      const bStart = new Date(b.firstSeen).getTime();
      const bEnd = new Date(b.lastSeen).getTime();
      
      if (aStart <= bEnd && bStart <= aEnd) {
        const overlapDays = Math.min(aEnd, bEnd) - Math.max(aStart, bStart);
        if (overlapDays > 7 * 24 * 60 * 60 * 1000) { // > 7 days overlap
          correlations.push({
            campaignA: a.id,
            campaignB: b.id,
            correlationType: 'timeline_overlap',
            confidence: 60,
            evidence: [`${Math.round(overlapDays / (24 * 60 * 60 * 1000))} days overlap`],
          });
        }
      }
    }
  }
  
  return correlations;
}

function findInfrastructureOverlaps(
  infrastructure: InfrastructureNode[],
  campaigns: Campaign[]
): InfraOverlap[] {
  const overlaps: InfraOverlap[] = [];
  const infraMap = new Map<string, { campaigns: Set<string>; families: Set<string>; times: number[] }>();
  
  for (const campaign of campaigns) {
    for (const infra of campaign.infrastructure) {
      if (!infraMap.has(infra.value)) {
        infraMap.set(infra.value, { campaigns: new Set(), families: new Set(), times: [] });
      }
      const entry = infraMap.get(infra.value)!;
      entry.campaigns.add(campaign.name);
      campaign.families.forEach(f => entry.families.add(f));
      entry.times.push(new Date(infra.firstSeen).getTime());
      entry.times.push(new Date(infra.lastSeen).getTime());
    }
  }
  
  for (const [indicator, data] of infraMap) {
    if (data.campaigns.size > 1 || data.families.size > 1) {
      overlaps.push({
        indicator,
        campaigns: Array.from(data.campaigns),
        families: Array.from(data.families),
        timeRange: {
          start: new Date(Math.min(...data.times)).toISOString(),
          end: new Date(Math.max(...data.times)).toISOString(),
        },
      });
    }
  }
  
  return overlaps;
}

function buildCampaignTimeline(campaigns: Campaign[]): TimelineEvent[] {
  const events: TimelineEvent[] = [];
  
  for (const campaign of campaigns) {
    for (const event of campaign.timeline) {
      events.push({
        timestamp: event.timestamp,
        campaignId: campaign.id,
        type: event.type,
        description: `[${campaign.name}] ${event.description}`,
        severity: event.severity,
      });
    }
  }
  
  return events.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
}

/* ============================================================================
   UTILITY FUNCTIONS
============================================================================ */

function calculateRiskScore(
  samples: MalwareSampleSignal[],
  infrastructure: InfrastructureNode[],
  status: string
): number {
  let score = 0;
  
  // Sample count
  score += Math.min(30, samples.length * 3);
  
  // Active infrastructure
  const activeInfra = infrastructure.filter(i => i.status === 'active').length;
  score += Math.min(25, activeInfra * 5);
  
  // Campaign status
  if (status === 'active') score += 25;
  else if (status === 'dormant') score += 10;
  
  // Sample confidence
  const avgConfidence = samples.length > 0
    ? samples.reduce((sum, s) => sum + s.confidence, 0) / samples.length
    : 0;
  score += Math.round(avgConfidence * 0.2);
  
  return Math.min(100, score);
}

function calculateCorrelationStrength(correlations: CampaignCorrelation[]): number {
  if (correlations.length === 0) return 0;
  return Math.round(correlations.reduce((sum, c) => sum + c.confidence, 0) / correlations.length);
}

function generateCodename(): string {
  const adjectives = ['PHANTOM', 'SHADOW', 'GHOST', 'SILENT', 'DARK', 'CYBER', 'IRON', 'STEEL', 'STORM', 'NIGHT'];
  const nouns = ['SPIDER', 'WOLF', 'HAWK', 'VIPER', 'COBRA', 'DRAGON', 'TIGER', 'BEAR', 'EAGLE', 'SERPENT'];
  return `${adjectives[Math.floor(Math.random() * adjectives.length)]} ${nouns[Math.floor(Math.random() * nouns.length)]}`;
}

function inferTargetSectors(family: string): string[] {
  const sectorMap: Record<string, string[]> = {
    'RedLine': ['finance', 'gaming', 'crypto', 'enterprise'],
    'Raccoon': ['finance', 'retail', 'crypto'],
    'Vidar': ['finance', 'crypto', 'gaming'],
    'LummaC2': ['crypto', 'finance', 'tech'],
    'LockBit': ['healthcare', 'manufacturing', 'government', 'education'],
    'BlackCat': ['energy', 'finance', 'legal', 'technology'],
    'Qakbot': ['finance', 'legal', 'government'],
    'Emotet': ['enterprise', 'government', 'healthcare'],
  };
  return sectorMap[family] || ['general'];
}

function inferTargetRegions(infrastructure: InfrastructureNode[]): string[] {
  const regions = new Set<string>();
  for (const infra of infrastructure) {
    if (infra.country && infra.country !== 'Unknown') {
      regions.add(infra.country);
    }
  }
  return Array.from(regions);
}

export { MALWARE_FAMILIES };
