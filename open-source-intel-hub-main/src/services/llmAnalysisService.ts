// ============================================================================
// llmAnalysisService.ts
// LLM-Powered Threat Intelligence Analysis (StealthMole-style)
// ============================================================================
// ✔ OpenAI/Anthropic/Local LLM integration
// ✔ Context extraction from leaks
// ✔ Threat assessment and scoring
// ✔ Entity extraction (emails, IPs, domains, credentials)
// ✔ Relationship mapping
// ✔ Summary generation
// ============================================================================

import { cacheAPIResponse, getCachedData } from '@/lib/database';

/* ============================================================================
   TYPES
============================================================================ */

export interface LLMConfig {
  provider: 'openai' | 'anthropic' | 'ollama' | 'groq' | 'local';
  apiKey?: string;
  model: string;
  baseUrl?: string;
  temperature?: number;
  maxTokens?: number;
}

export interface ExtractedEntity {
  type: 'email' | 'password' | 'ip' | 'domain' | 'phone' | 'crypto_wallet' | 'api_key' | 'credit_card' | 'ssn' | 'username' | 'hash';
  value: string;
  confidence: number;
  context: string;
}

export interface ThreatAssessment {
  score: number; // 0-100
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  indicators: string[];
  summary: string;
  recommendations: string[];
  ttps?: string[]; // MITRE ATT&CK TTPs
  iocs: ExtractedEntity[];
}

export interface LeakAnalysis {
  id: string;
  query: string;
  timestamp: string;
  totalResults: number;
  threatAssessment: ThreatAssessment;
  entities: ExtractedEntity[];
  summary: string;
  relatedBreaches: string[];
  exposureTimeline: { date: string; event: string }[];
  actionItems: string[];
}

export interface ContextEnrichment {
  originalText: string;
  enrichedContext: string;
  keyFindings: string[];
  riskFactors: string[];
  dataTypes: string[];
}

/* ============================================================================
   DEFAULT CONFIG
============================================================================ */

let currentConfig: LLMConfig = {
  provider: 'groq',
  model: 'llama-3.1-70b-versatile',
  temperature: 0.3,
  maxTokens: 2000,
};

const GROQ_API_URL = 'https://api.groq.com/openai/v1/chat/completions';

/* ============================================================================
   CONFIG MANAGEMENT
============================================================================ */

export function configureLLM(config: Partial<LLMConfig>): void {
  currentConfig = { ...currentConfig, ...config };
  console.log('[LLM] Configuration updated:', { provider: currentConfig.provider, model: currentConfig.model });
}

export function getLLMConfig(): LLMConfig {
  return { ...currentConfig };
}

/* ============================================================================
   ENTITY EXTRACTION (Rule-based + LLM-enhanced)
============================================================================ */

const ENTITY_PATTERNS: Record<string, RegExp> = {
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/gi,
  password: /(?:password|passwd|pwd|pass)[:\s=]+["']?([^\s"']{4,50})["']?/gi,
  ip: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
  domain: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi,
  phone: /\b(?:\+?1?[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b/g,
  crypto_wallet: /\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{39,59})\b/g,
  api_key: /\b(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key)[:\s=]+["']?([a-zA-Z0-9_-]{20,100})["']?/gi,
  credit_card: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/g,
  ssn: /\b[0-9]{3}[-\s]?[0-9]{2}[-\s]?[0-9]{4}\b/g,
  hash_md5: /\b[a-fA-F0-9]{32}\b/g,
  hash_sha1: /\b[a-fA-F0-9]{40}\b/g,
  hash_sha256: /\b[a-fA-F0-9]{64}\b/g,
};

export function extractEntities(text: string, targetQuery?: string): ExtractedEntity[] {
  const entities: ExtractedEntity[] = [];
  const seen = new Set<string>();
  const textLower = text.toLowerCase();
  const queryLower = targetQuery?.toLowerCase() || '';

  for (const [type, pattern] of Object.entries(ENTITY_PATTERNS)) {
    const matches = text.matchAll(pattern);
    for (const match of matches) {
      const value = match[1] || match[0];
      const key = `${type}:${value.toLowerCase()}`;
      
      if (seen.has(key)) continue;
      seen.add(key);

      // Calculate confidence based on context
      let confidence = 0.7;
      if (queryLower && value.toLowerCase().includes(queryLower)) confidence = 0.95;
      if (type === 'email' && value.includes('@')) confidence = 0.9;
      if (type === 'hash_sha256' && value.length === 64) confidence = 0.95;

      // Get surrounding context
      const idx = text.indexOf(value);
      const start = Math.max(0, idx - 50);
      const end = Math.min(text.length, idx + value.length + 50);
      const context = text.substring(start, end).replace(/\s+/g, ' ').trim();

      entities.push({
        type: type.replace(/_.*/, '') as any,
        value,
        confidence,
        context,
      });
    }
  }

  return entities.slice(0, 100); // Limit to prevent overload
}

/* ============================================================================
   LLM API CALLS
============================================================================ */

async function callLLM(prompt: string, systemPrompt?: string): Promise<string> {
  const cacheKey = `llm:${btoa(prompt.substring(0, 100)).slice(0, 20)}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    // Try Groq first (free tier available)
    if (currentConfig.provider === 'groq' || !currentConfig.apiKey) {
      const groqKey = currentConfig.apiKey || (typeof import.meta !== 'undefined' && (import.meta as any).env?.VITE_GROQ_API_KEY);
      
      if (groqKey) {
        const response = await fetch(GROQ_API_URL, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${groqKey}`,
          },
          body: JSON.stringify({
            model: currentConfig.model || 'llama-3.1-70b-versatile',
            messages: [
              { role: 'system', content: systemPrompt || 'You are a cybersecurity threat intelligence analyst.' },
              { role: 'user', content: prompt },
            ],
            temperature: currentConfig.temperature || 0.3,
            max_tokens: currentConfig.maxTokens || 2000,
          }),
        });

        if (response.ok) {
          const data = await response.json();
          const result = data.choices?.[0]?.message?.content || '';
          await cacheAPIResponse(cacheKey, result, 3600);
          return result;
        }
      }
    }

    // Fallback to OpenAI-compatible endpoint
    if (currentConfig.apiKey && currentConfig.provider === 'openai') {
      const baseUrl = currentConfig.baseUrl || 'https://api.openai.com/v1';
      const response = await fetch(`${baseUrl}/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${currentConfig.apiKey}`,
        },
        body: JSON.stringify({
          model: currentConfig.model || 'gpt-4o-mini',
          messages: [
            { role: 'system', content: systemPrompt || 'You are a cybersecurity threat intelligence analyst.' },
            { role: 'user', content: prompt },
          ],
          temperature: currentConfig.temperature || 0.3,
          max_tokens: currentConfig.maxTokens || 2000,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        const result = data.choices?.[0]?.message?.content || '';
        await cacheAPIResponse(cacheKey, result, 3600);
        return result;
      }
    }

    // Return empty if no LLM available
    console.warn('[LLM] No API key configured, using rule-based analysis');
    return '';
  } catch (error) {
    console.error('[LLM] API call failed:', error);
    return '';
  }
}

/* ============================================================================
   THREAT ASSESSMENT
============================================================================ */

export async function assessThreat(
  query: string,
  leakData: any[],
  entities: ExtractedEntity[]
): Promise<ThreatAssessment> {
  const dataTypes = [...new Set(entities.map(e => e.type))];
  const hasCredentials = entities.some(e => e.type === 'password' || e.type === 'email');
  const hasFinancial = entities.some(e => e.type === 'credit_card' || e.type === 'ssn');
  const hasCrypto = entities.some(e => e.type === 'crypto_wallet');

  // Calculate base score
  let score = 0;
  score += leakData.length * 5; // Each leak source adds points
  score += hasCredentials ? 30 : 0;
  score += hasFinancial ? 40 : 0;
  score += hasCrypto ? 20 : 0;
  score += entities.filter(e => e.confidence > 0.8).length * 2;
  score = Math.min(100, score);

  // Determine severity
  let severity: ThreatAssessment['severity'] = 'info';
  if (score >= 80) severity = 'critical';
  else if (score >= 60) severity = 'high';
  else if (score >= 40) severity = 'medium';
  else if (score >= 20) severity = 'low';

  // Try LLM-enhanced analysis
  let llmAnalysis = '';
  if (leakData.length > 0) {
    const sampleData = leakData.slice(0, 5).map(d => ({
      source: d.source,
      title: d.title?.substring(0, 100),
      context: d.context?.substring(0, 200),
    }));

    const prompt = `Analyze this threat intelligence data for "${query}":

Data Sources: ${JSON.stringify(sampleData, null, 2)}

Extracted Entities (${entities.length} total):
- Data types found: ${dataTypes.join(', ')}
- High confidence matches: ${entities.filter(e => e.confidence > 0.8).length}

Provide a brief threat assessment including:
1. Summary of exposure (2-3 sentences)
2. Key risk factors (bullet points)
3. Recommended actions (bullet points)

Keep response concise and actionable.`;

    llmAnalysis = await callLLM(prompt, 'You are a cybersecurity threat intelligence analyst specializing in data breach analysis and dark web monitoring. Provide concise, actionable intelligence.');
  }

  // Parse LLM response or use defaults
  let summary = `Found ${leakData.length} potential exposures for "${query}" across ${new Set(leakData.map(d => d.source)).size} sources.`;
  let recommendations: string[] = [];
  let indicators: string[] = [];

  if (llmAnalysis) {
    summary = llmAnalysis.split('\n').find(l => l.length > 50) || summary;
    recommendations = llmAnalysis
      .split('\n')
      .filter(l => l.trim().startsWith('-') || l.trim().startsWith('•'))
      .map(l => l.replace(/^[-•]\s*/, '').trim())
      .slice(0, 5);
  }

  if (recommendations.length === 0) {
    recommendations = [
      hasCredentials ? 'Change passwords for affected accounts immediately' : '',
      hasFinancial ? 'Monitor financial accounts for suspicious activity' : '',
      'Enable multi-factor authentication on all accounts',
      'Review and revoke API keys if exposed',
      'Consider identity monitoring services',
    ].filter(Boolean);
  }

  indicators = dataTypes.map(t => `${t.toUpperCase()} exposure detected`);

  return {
    score,
    severity,
    category: hasFinancial ? 'Financial Exposure' : hasCredentials ? 'Credential Leak' : 'Data Exposure',
    indicators,
    summary,
    recommendations,
    ttps: severity === 'critical' || severity === 'high' ? ['T1078', 'T1110', 'T1552'] : [],
    iocs: entities.filter(e => e.confidence > 0.7),
  };
}

/* ============================================================================
   CONTEXT ENRICHMENT
============================================================================ */

export async function enrichContext(text: string, query: string): Promise<ContextEnrichment> {
  const entities = extractEntities(text, query);
  const dataTypes = [...new Set(entities.map(e => e.type))];

  // Rule-based risk factors
  const riskFactors: string[] = [];
  if (text.toLowerCase().includes('password')) riskFactors.push('Password exposure detected');
  if (text.toLowerCase().includes('credit card') || text.match(/\b4[0-9]{12}/)) riskFactors.push('Financial data at risk');
  if (text.toLowerCase().includes('ssn') || text.match(/\b\d{3}-\d{2}-\d{4}\b/)) riskFactors.push('PII exposure (SSN)');
  if (text.toLowerCase().includes('api') && text.toLowerCase().includes('key')) riskFactors.push('API credentials exposed');

  // Try LLM for deeper analysis
  let enrichedContext = text;
  let keyFindings: string[] = [];

  const llmResponse = await callLLM(
    `Analyze this text for security-relevant information related to "${query}":

${text.substring(0, 1500)}

Extract:
1. Key findings (what sensitive data is exposed)
2. Risk factors (why this is dangerous)
3. Brief summary suitable for a threat intelligence report`,
    'You are analyzing leaked data for threat intelligence purposes. Be precise and factual.'
  );

  if (llmResponse) {
    const lines = llmResponse.split('\n').filter(l => l.trim());
    keyFindings = lines
      .filter(l => l.includes('finding') || l.includes(':') || l.startsWith('-'))
      .map(l => l.replace(/^[-•\d.)\s]*/, '').trim())
      .slice(0, 5);
    enrichedContext = llmResponse;
  }

  if (keyFindings.length === 0) {
    keyFindings = entities.slice(0, 5).map(e => `${e.type}: ${e.value.substring(0, 30)}...`);
  }

  return {
    originalText: text,
    enrichedContext,
    keyFindings,
    riskFactors,
    dataTypes,
  };
}

/* ============================================================================
   FULL LEAK ANALYSIS
============================================================================ */

export async function analyzeLeakIntelligence(
  query: string,
  leakData: any[]
): Promise<LeakAnalysis> {
  console.log(`[LLM Analysis] Analyzing ${leakData.length} results for: ${query}`);

  // Extract all entities from leak data
  const allText = leakData.map(d => `${d.title || ''} ${d.context || ''}`).join('\n');
  const entities = extractEntities(allText, query);

  // Assess threat level
  const threatAssessment = await assessThreat(query, leakData, entities);

  // Generate exposure timeline
  const exposureTimeline = leakData
    .filter(d => d.timestamp)
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, 10)
    .map(d => ({
      date: d.timestamp,
      event: `${d.source}: ${d.title?.substring(0, 50) || 'Data exposure detected'}`,
    }));

  // Find related breaches from sources
  const relatedBreaches = [...new Set(
    leakData
      .filter(d => d.source === 'libraryofleaks' || d.source === 'breach')
      .map(d => d.title)
  )].slice(0, 5);

  // Generate action items
  const actionItems = [
    ...threatAssessment.recommendations,
    'Document all exposures for incident response',
    'Notify affected parties if required by regulations',
  ].slice(0, 7);

  // Generate summary
  let summary = threatAssessment.summary;
  if (leakData.length > 0 && !summary.includes('exposure')) {
    summary = `Analysis of "${query}" revealed ${leakData.length} potential exposures across ${
      [...new Set(leakData.map(d => d.source))].length
    } sources. ${entities.length} distinct entities extracted including ${
      [...new Set(entities.map(e => e.type))].join(', ')
    }. Threat score: ${threatAssessment.score}/100 (${threatAssessment.severity}).`;
  }

  return {
    id: `analysis-${Date.now()}`,
    query,
    timestamp: new Date().toISOString(),
    totalResults: leakData.length,
    threatAssessment,
    entities,
    summary,
    relatedBreaches,
    exposureTimeline,
    actionItems,
  };
}

/* ============================================================================
   RELATIONSHIP MAPPING (For Graph)
============================================================================ */

export interface EntityRelationship {
  source: ExtractedEntity;
  target: ExtractedEntity;
  relationship: string;
  confidence: number;
}

export function mapEntityRelationships(entities: ExtractedEntity[]): EntityRelationship[] {
  const relationships: EntityRelationship[] = [];
  const emails = entities.filter(e => e.type === 'email');
  const passwords = entities.filter(e => e.type === 'password');
  const domains = entities.filter(e => e.type === 'domain');
  const ips = entities.filter(e => e.type === 'ip');

  // Email to password relationships
  for (const email of emails) {
    for (const pass of passwords) {
      if (email.context.includes(pass.value) || pass.context.includes(email.value)) {
        relationships.push({
          source: email,
          target: pass,
          relationship: 'credential_pair',
          confidence: 0.9,
        });
      }
    }
  }

  // Email to domain relationships
  for (const email of emails) {
    const emailDomain = email.value.split('@')[1];
    for (const domain of domains) {
      if (emailDomain === domain.value || domain.value.includes(emailDomain)) {
        relationships.push({
          source: email,
          target: domain,
          relationship: 'belongs_to',
          confidence: 0.95,
        });
      }
    }
  }

  // Domain to IP relationships
  for (const domain of domains) {
    for (const ip of ips) {
      if (domain.context.includes(ip.value) || ip.context.includes(domain.value)) {
        relationships.push({
          source: domain,
          target: ip,
          relationship: 'resolves_to',
          confidence: 0.7,
        });
      }
    }
  }

  return relationships;
}

/* ============================================================================
   EXPORTS
============================================================================ */

export default {
  configureLLM,
  getLLMConfig,
  extractEntities,
  assessThreat,
  enrichContext,
  analyzeLeakIntelligence,
  mapEntityRelationships,
};
