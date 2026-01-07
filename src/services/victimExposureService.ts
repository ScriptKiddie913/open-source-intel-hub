// ============================================================================
// VICTIM EXPOSURE SERVICE
// ============================================================================
// Tracks exposure probability via PUBLIC signals only
// NO credential storage, NO log access, NO illegal scraping
// ============================================================================

/* ============================================================================
   TYPES
============================================================================ */

export interface ExposureSignal {
  id: string;
  indicator: string;
  indicatorType: 'email' | 'domain' | 'username' | 'ip' | 'phone' | 'organization';
  exposureType: 'breach_mention' | 'paste_reference' | 'config_leak' | 'code_exposure' | 'forum_mention' | 'stealer_campaign';
  source: string;
  sourceUrl?: string;
  timestamp: string;
  context: string;
  associatedFamily?: string;
  associatedCampaign?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  evidenceCount: number;
}

export interface ExposureAssessment {
  indicator: string;
  indicatorType: string;
  possibleExposure: boolean;
  confidence: number;
  riskScore: number;
  riskLevel: 'minimal' | 'low' | 'medium' | 'high' | 'critical';
  signals: ExposureSignal[];
  associatedFamilies: string[];
  associatedCampaigns: string[];
  timeline: ExposureEvent[];
  recommendations: string[];
  lastUpdated: string;
}

export interface ExposureEvent {
  timestamp: string;
  type: string;
  description: string;
  source: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface ExposureSearchResult {
  assessments: ExposureAssessment[];
  aggregateRisk: {
    overallScore: number;
    level: string;
    totalSignals: number;
    criticalSignals: number;
    affectedIndicators: number;
  };
  malwareFamiliesInvolved: string[];
  activeCampaigns: string[];
  timeline: ExposureEvent[];
}

/* ============================================================================
   CONSTANTS
============================================================================ */

// Known stealer campaigns with active periods
const STEALER_CAMPAIGNS = [
  { family: 'RedLine', activePeriods: [{ start: '2020-01', end: '2025-12' }] },
  { family: 'Raccoon', activePeriods: [{ start: '2019-04', end: '2025-12' }] },
  { family: 'Vidar', activePeriods: [{ start: '2018-12', end: '2025-12' }] },
  { family: 'LummaC2', activePeriods: [{ start: '2022-08', end: '2025-12' }] },
  { family: 'Stealc', activePeriods: [{ start: '2023-01', end: '2025-12' }] },
  { family: 'Meta', activePeriods: [{ start: '2022-03', end: '2025-12' }] },
  { family: 'RisePro', activePeriods: [{ start: '2022-12', end: '2025-12' }] },
  { family: 'Mystic', activePeriods: [{ start: '2023-04', end: '2025-12' }] },
];

// Public breach databases for reference checking
const PUBLIC_BREACH_SOURCES = [
  { name: 'HaveIBeenPwned', type: 'breach_aggregator', url: 'https://haveibeenpwned.com' },
  { name: 'DeHashed', type: 'breach_search', url: 'https://dehashed.com' },
  { name: 'LeakCheck', type: 'breach_search', url: 'https://leakcheck.io' },
  { name: 'IntelX', type: 'intelligence', url: 'https://intelx.io' },
  { name: 'Breach.directory', type: 'breach_aggregator', url: 'https://breachdirectory.org' },
];

// Domain categories that increase exposure risk
const HIGH_RISK_DOMAINS = [
  'banking', 'crypto', 'exchange', 'wallet', 'finance', 'paypal', 'stripe',
  'aws', 'azure', 'gcp', 'cloud', 'admin', 'vpn', 'corp', 'internal',
];

/* ============================================================================
   MAIN EXPOSURE TRACKING
============================================================================ */

/**
 * Analyze exposure signals for a given indicator
 * Uses only PUBLIC sources - no credential access
 */
export async function analyzeExposure(indicator: string): Promise<ExposureSearchResult> {
  console.log(`[ExposureService] Analyzing exposure for: ${indicator}`);
  
  const indicatorType = detectIndicatorType(indicator);
  const signals: ExposureSignal[] = [];
  const timeline: ExposureEvent[] = [];
  
  // Gather signals from multiple public sources
  const [
    psbdmpSignals,
    archiveSignals,
    githubSignals,
    redditSignals,
    pasteSignals,
    forumSignals,
  ] = await Promise.all([
    checkPsbdmp(indicator, indicatorType),
    checkArchiveOrg(indicator, indicatorType),
    checkGitHubExposure(indicator, indicatorType),
    checkRedditMentions(indicator, indicatorType),
    checkPasteSites(indicator, indicatorType),
    checkPublicForumMentions(indicator, indicatorType),
  ]);
  
  signals.push(...psbdmpSignals, ...archiveSignals, ...githubSignals, ...redditSignals, ...pasteSignals, ...forumSignals);
  
  // Analyze stealer campaign overlap
  const stealerOverlap = analyzeStealerCampaignOverlap(indicator, signals);
  signals.push(...stealerOverlap.signals);
  
  // Build assessment
  const assessment = buildExposureAssessment(indicator, indicatorType, signals);
  
  // Build timeline
  for (const signal of signals) {
    timeline.push({
      timestamp: signal.timestamp,
      type: signal.exposureType,
      description: signal.context,
      source: signal.source,
      severity: signal.severity,
    });
  }
  
  // Sort timeline
  timeline.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  
  // Calculate aggregate risk
  const aggregateRisk = calculateAggregateRisk([assessment]);
  
  return {
    assessments: [assessment],
    aggregateRisk,
    malwareFamiliesInvolved: [...new Set(signals.filter(s => s.associatedFamily).map(s => s.associatedFamily!))],
    activeCampaigns: [...new Set(signals.filter(s => s.associatedCampaign).map(s => s.associatedCampaign!))],
    timeline,
  };
}

/**
 * Bulk exposure check for multiple indicators
 */
export async function analyzeMultipleExposures(indicators: string[]): Promise<ExposureSearchResult> {
  const allAssessments: ExposureAssessment[] = [];
  const allTimeline: ExposureEvent[] = [];
  const allFamilies = new Set<string>();
  const allCampaigns = new Set<string>();
  
  // Process in batches to avoid rate limiting
  const batchSize = 5;
  for (let i = 0; i < indicators.length; i += batchSize) {
    const batch = indicators.slice(i, i + batchSize);
    const results = await Promise.all(batch.map(ind => analyzeExposure(ind)));
    
    for (const result of results) {
      allAssessments.push(...result.assessments);
      allTimeline.push(...result.timeline);
      result.malwareFamiliesInvolved.forEach(f => allFamilies.add(f));
      result.activeCampaigns.forEach(c => allCampaigns.add(c));
    }
  }
  
  // Sort and dedupe timeline
  allTimeline.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  
  return {
    assessments: allAssessments,
    aggregateRisk: calculateAggregateRisk(allAssessments),
    malwareFamiliesInvolved: Array.from(allFamilies),
    activeCampaigns: Array.from(allCampaigns),
    timeline: allTimeline.slice(0, 100),
  };
}

/* ============================================================================
   SIGNAL COLLECTORS (PUBLIC SOURCES ONLY)
============================================================================ */

async function checkPsbdmp(indicator: string, type: string): Promise<ExposureSignal[]> {
  const signals: ExposureSignal[] = [];
  
  try {
    // Psbdmp public search
    const response = await fetch(`https://psbdmp.ws/api/v3/search/${encodeURIComponent(indicator)}`, {
      headers: { 'Accept': 'application/json' },
    });
    
    if (response.ok) {
      const data = await response.json();
      if (data.data && Array.isArray(data.data)) {
        for (const paste of data.data.slice(0, 20)) {
          signals.push({
            id: `psbdmp-${paste.id}`,
            indicator,
            indicatorType: type as any,
            exposureType: 'paste_reference',
            source: 'Psbdmp',
            sourceUrl: `https://psbdmp.ws/${paste.id}`,
            timestamp: paste.time || new Date().toISOString(),
            context: `Found in paste dump: ${paste.text?.substring(0, 200) || 'Content preview unavailable'}...`,
            severity: determineSeverity(paste.text, indicator),
            confidence: 75,
            evidenceCount: 1,
          });
        }
      }
    }
  } catch (err) {
    console.error('[Psbdmp] Error:', err);
  }
  
  return signals;
}

async function checkArchiveOrg(indicator: string, type: string): Promise<ExposureSignal[]> {
  const signals: ExposureSignal[] = [];
  
  try {
    // Check if indicator appears in archived pages
    const response = await fetch(
      `https://web.archive.org/cdx/search/cdx?url=*${encodeURIComponent(indicator)}*&output=json&limit=10`
    );
    
    if (response.ok) {
      const data = await response.json();
      if (Array.isArray(data) && data.length > 1) {
        for (const record of data.slice(1, 10)) {
          signals.push({
            id: `archive-${record[1]}-${record[0]}`,
            indicator,
            indicatorType: type as any,
            exposureType: 'breach_mention',
            source: 'Archive.org',
            sourceUrl: `https://web.archive.org/web/${record[1]}/${record[2]}`,
            timestamp: parseArchiveTimestamp(record[1]),
            context: `Archived web reference found: ${record[2]}`,
            severity: 'low',
            confidence: 60,
            evidenceCount: 1,
          });
        }
      }
    }
  } catch (err) {
    console.error('[Archive.org] Error:', err);
  }
  
  return signals;
}

async function checkGitHubExposure(indicator: string, type: string): Promise<ExposureSignal[]> {
  const signals: ExposureSignal[] = [];
  
  try {
    // GitHub code search (limited without auth)
    const response = await fetch(
      `https://api.github.com/search/code?q=${encodeURIComponent(indicator)}+in:file&per_page=10`,
      {
        headers: {
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'OSINT-Hub',
        },
      }
    );
    
    if (response.ok) {
      const data = await response.json();
      if (data.items && Array.isArray(data.items)) {
        for (const item of data.items) {
          const isCredentialFile = /password|secret|key|token|credential|config|env/i.test(item.path);
          
          signals.push({
            id: `github-${item.sha}`,
            indicator,
            indicatorType: type as any,
            exposureType: 'code_exposure',
            source: 'GitHub',
            sourceUrl: item.html_url,
            timestamp: new Date().toISOString(),
            context: `Found in ${item.repository.full_name}/${item.path}`,
            severity: isCredentialFile ? 'high' : 'medium',
            confidence: isCredentialFile ? 85 : 65,
            evidenceCount: 1,
          });
        }
      }
    }
  } catch (err) {
    console.error('[GitHub] Error:', err);
  }
  
  return signals;
}

async function checkRedditMentions(indicator: string, type: string): Promise<ExposureSignal[]> {
  const signals: ExposureSignal[] = [];
  
  try {
    // Reddit search via Pushshift alternative
    const response = await fetch(
      `https://www.reddit.com/search.json?q=${encodeURIComponent(indicator)}&sort=new&limit=10`,
      { headers: { 'User-Agent': 'OSINT-Hub/1.0' } }
    );
    
    if (response.ok) {
      const data = await response.json();
      if (data.data?.children) {
        for (const post of data.data.children) {
          const isSecurityRelated = /breach|hack|leak|exposed|stolen|dump|data/i.test(
            post.data.title + ' ' + (post.data.selftext || '')
          );
          
          if (isSecurityRelated) {
            signals.push({
              id: `reddit-${post.data.id}`,
              indicator,
              indicatorType: type as any,
              exposureType: 'forum_mention',
              source: 'Reddit',
              sourceUrl: `https://reddit.com${post.data.permalink}`,
              timestamp: new Date(post.data.created_utc * 1000).toISOString(),
              context: post.data.title.substring(0, 200),
              severity: isSecurityRelated ? 'medium' : 'low',
              confidence: 55,
              evidenceCount: 1,
            });
          }
        }
      }
    }
  } catch (err) {
    console.error('[Reddit] Error:', err);
  }
  
  return signals;
}

async function checkPasteSites(indicator: string, type: string): Promise<ExposureSignal[]> {
  const signals: ExposureSignal[] = [];
  
  // Note: Many paste sites require authentication
  // We only check public endpoints
  
  try {
    // Check Ghostbin public pastes
    const response = await fetch(
      `https://api.paste.ee/v1/pastes/search?q=${encodeURIComponent(indicator)}`,
      { headers: { 'Accept': 'application/json' } }
    );
    
    if (response.ok) {
      const data = await response.json();
      if (data.pastes && Array.isArray(data.pastes)) {
        for (const paste of data.pastes.slice(0, 10)) {
          signals.push({
            id: `pasteee-${paste.id}`,
            indicator,
            indicatorType: type as any,
            exposureType: 'paste_reference',
            source: 'Paste.ee',
            sourceUrl: `https://paste.ee/p/${paste.id}`,
            timestamp: paste.created_at || new Date().toISOString(),
            context: 'Found in public paste',
            severity: 'medium',
            confidence: 70,
            evidenceCount: 1,
          });
        }
      }
    }
  } catch (err) {
    // Paste.ee may not be available
  }
  
  return signals;
}

async function checkPublicForumMentions(indicator: string, type: string): Promise<ExposureSignal[]> {
  const signals: ExposureSignal[] = [];
  
  // Check HackerNews for mentions
  try {
    const response = await fetch(
      `https://hn.algolia.com/api/v1/search?query=${encodeURIComponent(indicator)}&tags=story&hitsPerPage=10`
    );
    
    if (response.ok) {
      const data = await response.json();
      if (data.hits && Array.isArray(data.hits)) {
        for (const hit of data.hits) {
          const isSecurityRelated = /breach|hack|leak|security|exposed|vulnerability/i.test(hit.title);
          
          if (isSecurityRelated) {
            signals.push({
              id: `hn-${hit.objectID}`,
              indicator,
              indicatorType: type as any,
              exposureType: 'forum_mention',
              source: 'HackerNews',
              sourceUrl: hit.url || `https://news.ycombinator.com/item?id=${hit.objectID}`,
              timestamp: new Date(hit.created_at).toISOString(),
              context: hit.title,
              severity: 'low',
              confidence: 50,
              evidenceCount: hit.num_comments || 1,
            });
          }
        }
      }
    }
  } catch (err) {
    console.error('[HackerNews] Error:', err);
  }
  
  return signals;
}

/* ============================================================================
   STEALER CAMPAIGN CORRELATION
============================================================================ */

function analyzeStealerCampaignOverlap(
  indicator: string,
  existingSignals: ExposureSignal[]
): { signals: ExposureSignal[]; overlap: boolean } {
  const signals: ExposureSignal[] = [];
  let hasOverlap = false;
  
  // Check if indicator matches stealer target patterns
  const indicatorType = detectIndicatorType(indicator);
  
  // High-value target check
  const isHighValueTarget = HIGH_RISK_DOMAINS.some(domain => 
    indicator.toLowerCase().includes(domain)
  );
  
  // Check against known stealer campaign timelines
  for (const campaign of STEALER_CAMPAIGNS) {
    // If we have signals during this campaign's active period
    const campaignSignals = existingSignals.filter(s => {
      const signalTime = new Date(s.timestamp);
      return campaign.activePeriods.some(period => {
        const start = new Date(period.start);
        const end = new Date(period.end);
        return signalTime >= start && signalTime <= end;
      });
    });
    
    if (campaignSignals.length > 0 || (isHighValueTarget && indicatorType === 'domain')) {
      hasOverlap = true;
      
      signals.push({
        id: `stealer-${campaign.family}-${Date.now()}`,
        indicator,
        indicatorType: indicatorType as any,
        exposureType: 'stealer_campaign',
        source: 'Campaign Intelligence',
        timestamp: new Date().toISOString(),
        context: `Indicator profile matches ${campaign.family} stealer targeting patterns. ${campaignSignals.length} signals during active campaign period.`,
        associatedFamily: campaign.family,
        associatedCampaign: `${campaign.family} Campaign`,
        severity: isHighValueTarget ? 'high' : 'medium',
        confidence: Math.min(90, 50 + campaignSignals.length * 10),
        evidenceCount: campaignSignals.length,
      });
    }
  }
  
  return { signals, overlap: hasOverlap };
}

/* ============================================================================
   ASSESSMENT BUILDING
============================================================================ */

function buildExposureAssessment(
  indicator: string,
  indicatorType: string,
  signals: ExposureSignal[]
): ExposureAssessment {
  // Calculate risk score
  let riskScore = 0;
  
  // Base score from signal count
  riskScore += Math.min(30, signals.length * 3);
  
  // Severity multipliers
  const criticalCount = signals.filter(s => s.severity === 'critical').length;
  const highCount = signals.filter(s => s.severity === 'high').length;
  const mediumCount = signals.filter(s => s.severity === 'medium').length;
  
  riskScore += criticalCount * 15;
  riskScore += highCount * 8;
  riskScore += mediumCount * 3;
  
  // Confidence boost
  const avgConfidence = signals.length > 0
    ? signals.reduce((sum, s) => sum + s.confidence, 0) / signals.length
    : 0;
  riskScore += Math.round(avgConfidence * 0.2);
  
  // Cap at 100
  riskScore = Math.min(100, riskScore);
  
  // Determine risk level
  const riskLevel: ExposureAssessment['riskLevel'] = 
    riskScore >= 80 ? 'critical' :
    riskScore >= 60 ? 'high' :
    riskScore >= 40 ? 'medium' :
    riskScore >= 20 ? 'low' : 'minimal';
  
  // Calculate confidence
  const confidence = signals.length > 0
    ? Math.round(signals.reduce((sum, s) => sum + s.confidence, 0) / signals.length)
    : 0;
  
  // Build timeline
  const timeline: ExposureEvent[] = signals.map(s => ({
    timestamp: s.timestamp,
    type: s.exposureType,
    description: s.context,
    source: s.source,
    severity: s.severity,
  })).sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  
  // Generate recommendations
  const recommendations = generateRecommendations(riskLevel, signals);
  
  return {
    indicator,
    indicatorType,
    possibleExposure: signals.length > 0,
    confidence,
    riskScore,
    riskLevel,
    signals,
    associatedFamilies: [...new Set(signals.filter(s => s.associatedFamily).map(s => s.associatedFamily!))],
    associatedCampaigns: [...new Set(signals.filter(s => s.associatedCampaign).map(s => s.associatedCampaign!))],
    timeline,
    recommendations,
    lastUpdated: new Date().toISOString(),
  };
}

function calculateAggregateRisk(assessments: ExposureAssessment[]): ExposureSearchResult['aggregateRisk'] {
  if (assessments.length === 0) {
    return {
      overallScore: 0,
      level: 'minimal',
      totalSignals: 0,
      criticalSignals: 0,
      affectedIndicators: 0,
    };
  }
  
  const totalSignals = assessments.reduce((sum, a) => sum + a.signals.length, 0);
  const criticalSignals = assessments.reduce(
    (sum, a) => sum + a.signals.filter(s => s.severity === 'critical').length,
    0
  );
  const overallScore = Math.round(
    assessments.reduce((sum, a) => sum + a.riskScore, 0) / assessments.length
  );
  
  const level = 
    overallScore >= 80 ? 'critical' :
    overallScore >= 60 ? 'high' :
    overallScore >= 40 ? 'medium' :
    overallScore >= 20 ? 'low' : 'minimal';
  
  return {
    overallScore,
    level,
    totalSignals,
    criticalSignals,
    affectedIndicators: assessments.filter(a => a.possibleExposure).length,
  };
}

/* ============================================================================
   UTILITY FUNCTIONS
============================================================================ */

function detectIndicatorType(indicator: string): string {
  if (/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(indicator)) {
    return 'email';
  }
  if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(indicator)) {
    return 'ip';
  }
  if (/^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}/.test(indicator)) {
    return 'domain';
  }
  if (/^\+?[0-9]{10,15}$/.test(indicator)) {
    return 'phone';
  }
  if (/^[a-zA-Z0-9_-]{3,32}$/.test(indicator)) {
    return 'username';
  }
  return 'organization';
}

function determineSeverity(content: string | undefined, indicator: string): ExposureSignal['severity'] {
  if (!content) return 'medium';
  
  const contentLower = content.toLowerCase();
  
  // Critical indicators
  if (/password\s*[:=]|passwd|secret_key|api_key|private_key|token\s*[:=]/i.test(contentLower)) {
    return 'critical';
  }
  
  // High indicators
  if (/credential|login|auth|session|cookie/i.test(contentLower)) {
    return 'high';
  }
  
  // Medium indicators
  if (/email|user|account|profile/i.test(contentLower)) {
    return 'medium';
  }
  
  return 'low';
}

function parseArchiveTimestamp(timestamp: string): string {
  try {
    // Format: YYYYMMDDhhmmss
    const year = timestamp.substring(0, 4);
    const month = timestamp.substring(4, 6);
    const day = timestamp.substring(6, 8);
    return `${year}-${month}-${day}T00:00:00Z`;
  } catch {
    return new Date().toISOString();
  }
}

function generateRecommendations(riskLevel: string, signals: ExposureSignal[]): string[] {
  const recommendations: string[] = [];
  
  if (riskLevel === 'critical' || riskLevel === 'high') {
    recommendations.push('🚨 IMMEDIATE: Force password reset for all associated accounts');
    recommendations.push('🔐 Enable MFA on all critical services');
    recommendations.push('🔍 Audit active sessions and revoke suspicious access');
    recommendations.push('📧 Check for unauthorized email forwarding rules');
  }
  
  if (signals.some(s => s.associatedFamily)) {
    recommendations.push('🦠 Monitor for infostealer indicators on endpoints');
    recommendations.push('🔒 Review browser saved passwords and consider credential manager');
    recommendations.push('💳 Check financial accounts for unauthorized transactions');
  }
  
  if (signals.some(s => s.exposureType === 'code_exposure')) {
    recommendations.push('🔑 Rotate any API keys or secrets found in code');
    recommendations.push('📝 Review Git history for committed credentials');
    recommendations.push('🛡️ Implement pre-commit hooks to prevent secret exposure');
  }
  
  if (riskLevel === 'medium' || riskLevel === 'low') {
    recommendations.push('📊 Continue monitoring for new exposure signals');
    recommendations.push('🔄 Consider periodic credential rotation');
    recommendations.push('📋 Document findings for security awareness');
  }
  
  return recommendations;
}

export { PUBLIC_BREACH_SOURCES, STEALER_CAMPAIGNS };
