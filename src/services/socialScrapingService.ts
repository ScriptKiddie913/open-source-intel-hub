// ============================================================================
// socialScrapingService.ts
// LINKEDIN & GOOGLE OSINT SCRAPING VIA FIRECRAWL
// ============================================================================

import { firecrawlApi } from '@/lib/api/firecrawl';

export interface LinkedInResult {
  id: string;
  source: 'linkedin';
  type: 'profile' | 'company' | 'post' | 'job';
  title: string;
  url: string;
  snippet: string;
  timestamp: string;
  metadata: {
    name?: string;
    headline?: string;
    location?: string;
    connections?: string;
    companySize?: string;
    industry?: string;
  };
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  relevanceScore: number;
}

export interface GoogleResult {
  id: string;
  source: 'google';
  type: 'web' | 'news' | 'pastebin' | 'github' | 'forum';
  title: string;
  url: string;
  snippet: string;
  timestamp: string;
  metadata: {
    domain?: string;
    cachedUrl?: string;
    relatedSearches?: string[];
  };
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  relevanceScore: number;
}

export interface SocialScrapeResult {
  linkedin: LinkedInResult[];
  google: GoogleResult[];
  stats: {
    linkedinHits: number;
    googleHits: number;
    totalResults: number;
    exposureLevel: 'none' | 'low' | 'medium' | 'high' | 'critical';
    sourcesScanned: number;
  };
  searchTime: number;
}

// Severity keywords for OSINT
const CRITICAL_KEYWORDS = ['leaked', 'breach', 'hacked', 'exposed', 'credentials', 'password', 'dump', 'vulnerability'];
const HIGH_KEYWORDS = ['exploit', 'malware', 'phishing', 'threat', 'attack', 'compromised', 'ransomware'];
const MEDIUM_KEYWORDS = ['security', 'risk', 'warning', 'alert', 'suspicious', 'investigation'];

function calculateSeverity(text: string): 'info' | 'low' | 'medium' | 'high' | 'critical' {
  const lowerText = text.toLowerCase();
  
  if (CRITICAL_KEYWORDS.some(k => lowerText.includes(k))) return 'critical';
  if (HIGH_KEYWORDS.some(k => lowerText.includes(k))) return 'high';
  if (MEDIUM_KEYWORDS.some(k => lowerText.includes(k))) return 'medium';
  
  return 'info';
}

function determineLinkedInType(url: string, title: string): LinkedInResult['type'] {
  if (url.includes('/company/') || title.toLowerCase().includes('company')) return 'company';
  if (url.includes('/jobs/') || title.toLowerCase().includes('job')) return 'job';
  if (url.includes('/posts/') || url.includes('/pulse/')) return 'post';
  return 'profile';
}

function determineGoogleType(url: string): GoogleResult['type'] {
  if (url.includes('pastebin') || url.includes('ghostbin') || url.includes('hastebin')) return 'pastebin';
  if (url.includes('github.com') || url.includes('gitlab.com')) return 'github';
  if (url.includes('news.') || url.includes('/news/')) return 'news';
  if (url.includes('forum') || url.includes('reddit.com') || url.includes('stackoverflow')) return 'forum';
  return 'web';
}

// Search LinkedIn via Firecrawl
export async function searchLinkedIn(query: string, limit: number = 15): Promise<LinkedInResult[]> {
  console.log(`[LinkedIn] Searching for: "${query}"`);
  
  try {
    // Use site-specific Google search for LinkedIn
    const searchQuery = `site:linkedin.com "${query}"`;
    
    const response = await firecrawlApi.search(searchQuery, {
      limit,
      scrapeOptions: {
        formats: ['markdown'],
      },
    });
    
    if (!response.success || !response.data) {
      console.warn('[LinkedIn] Search failed or no results');
      return [];
    }
    
    const results: LinkedInResult[] = response.data.map((item: any, index: number) => {
      const combinedText = `${item.title || ''} ${item.description || ''} ${item.markdown || ''}`;
      const severity = calculateSeverity(combinedText);
      
      return {
        id: `linkedin-${Date.now()}-${index}`,
        source: 'linkedin' as const,
        type: determineLinkedInType(item.url || '', item.title || ''),
        title: item.title || 'LinkedIn Result',
        url: item.url || '',
        snippet: item.description || item.markdown?.slice(0, 300) || '',
        timestamp: new Date().toISOString(),
        metadata: {
          name: extractNameFromTitle(item.title),
          headline: extractHeadlineFromContent(item.markdown),
          location: extractLocationFromContent(item.markdown),
        },
        severity,
        relevanceScore: calculateRelevance(query, combinedText),
      };
    });
    
    console.log(`[LinkedIn] Found ${results.length} results`);
    return results;
  } catch (error) {
    console.error('[LinkedIn] Search error:', error);
    return [];
  }
}

// Search Google for OSINT intelligence
export async function searchGoogle(query: string, limit: number = 20): Promise<GoogleResult[]> {
  console.log(`[Google] Searching for: "${query}"`);
  
  try {
    // Multiple targeted searches for OSINT
    const searchQueries = [
      query, // General search
      `"${query}" breach OR leak OR exposed`, // Breach search
      `"${query}" site:pastebin.com OR site:github.com`, // Code/paste search
    ];
    
    const allResults: GoogleResult[] = [];
    
    for (const searchQuery of searchQueries) {
      try {
        const response = await firecrawlApi.search(searchQuery, {
          limit: Math.ceil(limit / searchQueries.length),
          tbs: 'qdr:m', // Results from past month
          scrapeOptions: {
            formats: ['markdown'],
          },
        });
        
        if (response.success && response.data) {
          const results = response.data.map((item: any, index: number) => {
            const combinedText = `${item.title || ''} ${item.description || ''} ${item.markdown || ''}`;
            const severity = calculateSeverity(combinedText);
            
            let domain = 'unknown';
            try {
              domain = new URL(item.url || '').hostname;
            } catch {}
            
            return {
              id: `google-${Date.now()}-${index}-${Math.random().toString(36).slice(2)}`,
              source: 'google' as const,
              type: determineGoogleType(item.url || ''),
              title: item.title || 'Web Result',
              url: item.url || '',
              snippet: item.description || item.markdown?.slice(0, 300) || '',
              timestamp: new Date().toISOString(),
              metadata: {
                domain,
              },
              severity,
              relevanceScore: calculateRelevance(query, combinedText),
            };
          });
          
          allResults.push(...results);
        }
      } catch (err) {
        console.warn(`[Google] Partial search failed for: ${searchQuery}`);
      }
    }
    
    // Deduplicate by URL
    const uniqueResults = Array.from(
      new Map(allResults.map(r => [r.url, r])).values()
    );
    
    console.log(`[Google] Found ${uniqueResults.length} unique results`);
    return uniqueResults;
  } catch (error) {
    console.error('[Google] Search error:', error);
    return [];
  }
}

// Combined social scraping function
export async function runSocialScraping(query: string): Promise<SocialScrapeResult> {
  const startTime = Date.now();
  console.log(`\n${'='.repeat(50)}`);
  console.log(`[SocialScraping] Starting unified search for: "${query}"`);
  console.log(`${'='.repeat(50)}\n`);
  
  // Run searches in parallel
  const [linkedinResults, googleResults] = await Promise.all([
    searchLinkedIn(query),
    searchGoogle(query),
  ]);
  
  // Calculate exposure level
  const allResults = [...linkedinResults, ...googleResults];
  const criticalCount = allResults.filter(r => r.severity === 'critical').length;
  const highCount = allResults.filter(r => r.severity === 'high').length;
  
  let exposureLevel: SocialScrapeResult['stats']['exposureLevel'] = 'none';
  if (criticalCount > 0) exposureLevel = 'critical';
  else if (highCount > 2) exposureLevel = 'high';
  else if (highCount > 0 || allResults.length > 10) exposureLevel = 'medium';
  else if (allResults.length > 0) exposureLevel = 'low';
  
  const result: SocialScrapeResult = {
    linkedin: linkedinResults,
    google: googleResults,
    stats: {
      linkedinHits: linkedinResults.length,
      googleHits: googleResults.length,
      totalResults: allResults.length,
      exposureLevel,
      sourcesScanned: 2,
    },
    searchTime: Date.now() - startTime,
  };
  
  console.log(`[SocialScraping] Complete - LinkedIn: ${linkedinResults.length}, Google: ${googleResults.length}`);
  
  return result;
}

// Helper functions
function extractNameFromTitle(title: string | undefined): string | undefined {
  if (!title) return undefined;
  // LinkedIn titles often follow pattern: "Name - Title | LinkedIn"
  const match = title.match(/^([^-|]+)/);
  return match ? match[1].trim() : undefined;
}

function extractHeadlineFromContent(markdown: string | undefined): string | undefined {
  if (!markdown) return undefined;
  // Try to extract professional headline
  const lines = markdown.split('\n').filter(l => l.trim());
  return lines.length > 1 ? lines[1].slice(0, 100) : undefined;
}

function extractLocationFromContent(markdown: string | undefined): string | undefined {
  if (!markdown) return undefined;
  // Look for location patterns
  const locationMatch = markdown.match(/(?:located in|location:|based in)\s*([^,\n.]+)/i);
  return locationMatch ? locationMatch[1].trim() : undefined;
}

function calculateRelevance(query: string, text: string): number {
  const queryTerms = query.toLowerCase().split(/\s+/);
  const textLower = text.toLowerCase();
  
  let matchCount = 0;
  for (const term of queryTerms) {
    if (textLower.includes(term)) matchCount++;
  }
  
  return Math.round((matchCount / queryTerms.length) * 100);
}
