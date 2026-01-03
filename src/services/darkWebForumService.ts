// ============================================================================
// DARK WEB FORUM SERVICE
// ============================================================================
// Monitors public dark web forums and leak sites for intelligence
// Uses LEGAL aggregators and public mirrors only
// ============================================================================

/* ============================================================================
   TYPES
============================================================================ */

export interface ForumPost {
  id: string;
  forum: string;
  forumUrl: string;
  thread: string;
  threadUrl?: string;
  author: string;
  authorReputation?: number;
  content: string;
  contentPreview: string;
  timestamp: string;
  category: 'database_leak' | 'credentials' | 'malware_sale' | 'exploit' | 'service' | 'discussion' | 'tutorial';
  tags: string[];
  attachments: ForumAttachment[];
  reactions: number;
  replies: number;
  views: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  relevanceScore: number;
}

export interface ForumAttachment {
  name: string;
  type: 'database' | 'sample' | 'screenshot' | 'document' | 'archive';
  size?: string;
  hash?: string;
}

export interface LeakPost {
  id: string;
  source: string;
  sourceUrl: string;
  title: string;
  description: string;
  victimOrg?: string;
  victimSector?: string;
  victimCountry?: string;
  dataType: 'full_database' | 'partial_dump' | 'credentials' | 'documents' | 'source_code' | 'mixed';
  recordCount?: number;
  fileSize?: string;
  leakDate: string;
  discoveryDate: string;
  threatActor?: string;
  ransomwareGroup?: string;
  price?: string;
  isFree: boolean;
  sampleAvailable: boolean;
  verified: boolean;
  tags: string[];
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface ForumSearchResult {
  posts: ForumPost[];
  leaks: LeakPost[];
  stats: {
    totalPosts: number;
    totalLeaks: number;
    criticalFindings: number;
    activeForums: number;
    recentActivity: number;
  };
  sources: ForumSource[];
  searchTime: number;
}

export interface ForumSource {
  name: string;
  type: 'forum' | 'marketplace' | 'leak_site' | 'paste' | 'telegram';
  status: 'active' | 'down' | 'seized' | 'unknown';
  description: string;
  lastChecked: string;
  resultCount: number;
}

export interface RansomwareVictim {
  id: string;
  group: string;
  groupUrl?: string;
  victimName: string;
  victimDomain?: string;
  victimSector?: string;
  victimCountry?: string;
  announcementDate: string;
  deadlineDate?: string;
  dataSize?: string;
  dataDescription?: string;
  status: 'announced' | 'countdown' | 'published' | 'negotiating' | 'removed';
  proofUrls: string[];
  source: string;
}

/* ============================================================================
   CONSTANTS - PUBLIC AGGREGATORS ONLY
============================================================================ */

// These are LEGAL public aggregators that index dark web content
const PUBLIC_AGGREGATORS = [
  {
    name: 'Ransomware.live',
    url: 'https://api.ransomware.live',
    type: 'ransomware_tracker',
    description: 'Public ransomware victim tracking',
  },
  {
    name: 'Ransomwatch',
    url: 'https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json',
    type: 'ransomware_tracker',
    description: 'Open source ransomware monitoring',
  },
  {
    name: 'DDoSecrets',
    url: 'https://ddosecrets.com',
    type: 'leak_archive',
    description: 'Public interest leak archive',
  },
  {
    name: 'Ahmia.fi',
    url: 'https://ahmia.fi',
    type: 'onion_search',
    description: 'Tor hidden service search engine',
  },
  {
    name: 'IntelX (Public)',
    url: 'https://intelx.io',
    type: 'intelligence',
    description: 'Public intelligence search',
  },
];

// Known ransomware groups for tracking
const RANSOMWARE_GROUPS = [
  { name: 'LockBit', aliases: ['LockBit 3.0', 'LockBit Black'], status: 'active' },
  { name: 'BlackCat', aliases: ['ALPHV', 'Noberus'], status: 'active' },
  { name: 'Cl0p', aliases: ['Clop', 'TA505'], status: 'active' },
  { name: 'Play', aliases: ['PlayCrypt'], status: 'active' },
  { name: 'Royal', aliases: [], status: 'active' },
  { name: '8Base', aliases: [], status: 'active' },
  { name: 'BianLian', aliases: [], status: 'active' },
  { name: 'Medusa', aliases: ['MedusaLocker'], status: 'active' },
  { name: 'Akira', aliases: [], status: 'active' },
  { name: 'NoEscape', aliases: [], status: 'active' },
  { name: 'Rhysida', aliases: [], status: 'active' },
  { name: 'BlackBasta', aliases: ['Black Basta'], status: 'active' },
  { name: 'Vice Society', aliases: [], status: 'active' },
  { name: 'Hunters', aliases: ['Hunters International'], status: 'active' },
  { name: 'INC Ransom', aliases: ['INC'], status: 'active' },
];

// Forum categories for classification
const FORUM_CATEGORIES = {
  database_leak: ['database', 'dump', 'leak', 'breach', 'combo', 'collection'],
  credentials: ['login', 'password', 'credential', 'account', 'combo', 'logs'],
  malware_sale: ['rat', 'stealer', 'ransomware', 'crypter', 'loader', 'botnet'],
  exploit: ['0day', 'exploit', 'rce', 'cve', 'vulnerability', 'poc'],
  service: ['service', 'ddos', 'spam', 'hosting', 'bulletproof', 'carding'],
  discussion: ['discussion', 'news', 'question', 'help'],
  tutorial: ['tutorial', 'guide', 'howto', 'method'],
};

/* ============================================================================
   MAIN SEARCH FUNCTIONS
============================================================================ */

/**
 * Search dark web forums and leak sites for intelligence
 * Uses only PUBLIC, LEGAL aggregators
 */
export async function searchDarkWebForums(query: string): Promise<ForumSearchResult> {
  console.log(`[ForumService] Searching: ${query}`);
  const startTime = Date.now();
  
  const posts: ForumPost[] = [];
  const leaks: LeakPost[] = [];
  const sources: ForumSource[] = [];
  
  // Search multiple sources in parallel
  const [
    ransomwatchResults,
    ransomwareLiveResults,
    ahmiaResults,
    ddosecretsResults,
  ] = await Promise.all([
    searchRansomwatch(query),
    searchRansomwareLive(query),
    searchAhmia(query),
    searchDDoSecrets(query),
  ]);
  
  // Merge results
  leaks.push(...ransomwatchResults.leaks, ...ransomwareLiveResults.leaks);
  posts.push(...ahmiaResults.posts, ...ddosecretsResults.posts);
  
  // Add sources
  sources.push(
    { name: 'Ransomwatch', type: 'leak_site', status: 'active', description: 'Ransomware victim tracker', lastChecked: new Date().toISOString(), resultCount: ransomwatchResults.leaks.length },
    { name: 'Ransomware.live', type: 'leak_site', status: 'active', description: 'Real-time ransomware tracking', lastChecked: new Date().toISOString(), resultCount: ransomwareLiveResults.leaks.length },
    { name: 'Ahmia.fi', type: 'forum', status: 'active', description: 'Tor search engine', lastChecked: new Date().toISOString(), resultCount: ahmiaResults.posts.length },
    { name: 'DDoSecrets', type: 'leak_site', status: 'active', description: 'Public leak archive', lastChecked: new Date().toISOString(), resultCount: ddosecretsResults.posts.length },
  );
  
  // Generate simulated forum posts based on query (for demo/testing)
  const simulatedPosts = generateSimulatedForumIntel(query);
  posts.push(...simulatedPosts);
  
  // Calculate stats
  const stats = {
    totalPosts: posts.length,
    totalLeaks: leaks.length,
    criticalFindings: posts.filter(p => p.severity === 'critical').length + leaks.filter(l => l.severity === 'critical').length,
    activeForums: sources.filter(s => s.status === 'active').length,
    recentActivity: posts.filter(p => {
      const postDate = new Date(p.timestamp);
      const weekAgo = new Date();
      weekAgo.setDate(weekAgo.getDate() - 7);
      return postDate >= weekAgo;
    }).length,
  };
  
  console.log(`[ForumService] Found ${posts.length} posts, ${leaks.length} leaks`);
  
  return {
    posts: posts.sort((a, b) => b.relevanceScore - a.relevanceScore),
    leaks: leaks.sort((a, b) => new Date(b.leakDate).getTime() - new Date(a.leakDate).getTime()),
    stats,
    sources,
    searchTime: Date.now() - startTime,
  };
}

/**
 * Get recent ransomware victims
 */
export async function getRansomwareVictims(
  options: { group?: string; sector?: string; country?: string; days?: number } = {}
): Promise<RansomwareVictim[]> {
  const victims: RansomwareVictim[] = [];
  
  try {
    // Fetch from ransomwatch
    const response = await fetch(
      'https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json'
    );
    
    if (response.ok) {
      const data = await response.json();
      
      for (const post of data) {
        // Filter by options
        if (options.group && !post.group_name?.toLowerCase().includes(options.group.toLowerCase())) {
          continue;
        }
        
        const victim: RansomwareVictim = {
          id: `rw-${post.post_title?.replace(/[^a-z0-9]/gi, '-') || Date.now()}`,
          group: post.group_name || 'Unknown',
          victimName: post.post_title || 'Unknown',
          victimDomain: extractDomain(post.post_title),
          announcementDate: post.discovered || new Date().toISOString(),
          status: 'announced',
          proofUrls: [],
          source: 'Ransomwatch',
        };
        
        victims.push(victim);
      }
    }
  } catch (err) {
    console.error('[RansomwareVictims] Error:', err);
  }
  
  // Fetch from ransomware.live
  try {
    const response = await fetch('https://api.ransomware.live/recentvictims');
    
    if (response.ok) {
      const data = await response.json();
      
      for (const item of (data || [])) {
        victims.push({
          id: `rl-${item.victim?.replace(/[^a-z0-9]/gi, '-') || Date.now()}`,
          group: item.group_name || 'Unknown',
          victimName: item.victim || 'Unknown',
          victimDomain: item.website,
          victimCountry: item.country,
          announcementDate: item.published || new Date().toISOString(),
          deadlineDate: item.deadline,
          status: item.published ? 'published' : 'announced',
          proofUrls: [],
          source: 'Ransomware.live',
        });
      }
    }
  } catch (err) {
    console.error('[RansomwareLive Victims] Error:', err);
  }
  
  // Filter by days
  if (options.days) {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - options.days);
    return victims.filter(v => new Date(v.announcementDate) >= cutoff);
  }
  
  return victims;
}

/* ============================================================================
   SOURCE-SPECIFIC SEARCH FUNCTIONS
============================================================================ */

async function searchRansomwatch(query: string): Promise<{ leaks: LeakPost[] }> {
  const leaks: LeakPost[] = [];
  
  try {
    const response = await fetch(
      'https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json'
    );
    
    if (response.ok) {
      const data = await response.json();
      const queryLower = query.toLowerCase();
      
      const filtered = data.filter((post: any) =>
        post.post_title?.toLowerCase().includes(queryLower) ||
        post.group_name?.toLowerCase().includes(queryLower)
      );
      
      for (const post of filtered) {
        leaks.push({
          id: `ransomwatch-${post.post_title?.replace(/[^a-z0-9]/gi, '-')}`,
          source: 'Ransomwatch',
          sourceUrl: 'https://ransomwatch.telemetry.ltd',
          title: post.post_title || 'Unknown Victim',
          description: `Ransomware attack by ${post.group_name}`,
          victimOrg: post.post_title,
          ransomwareGroup: post.group_name,
          dataType: 'mixed',
          leakDate: post.discovered || new Date().toISOString(),
          discoveryDate: post.discovered || new Date().toISOString(),
          threatActor: post.group_name,
          isFree: false,
          sampleAvailable: false,
          verified: true,
          tags: ['ransomware', post.group_name?.toLowerCase()].filter(Boolean),
          severity: 'critical',
        });
      }
    }
  } catch (err) {
    console.error('[Ransomwatch] Error:', err);
  }
  
  return { leaks };
}

async function searchRansomwareLive(query: string): Promise<{ leaks: LeakPost[] }> {
  const leaks: LeakPost[] = [];
  
  try {
    const response = await fetch('https://api.ransomware.live/recentvictims');
    
    if (response.ok) {
      const data = await response.json();
      const queryLower = query.toLowerCase();
      
      const filtered = (data || []).filter((item: any) =>
        item.victim?.toLowerCase().includes(queryLower) ||
        item.group_name?.toLowerCase().includes(queryLower) ||
        item.country?.toLowerCase().includes(queryLower)
      );
      
      for (const item of filtered) {
        leaks.push({
          id: `rl-${item.victim?.replace(/[^a-z0-9]/gi, '-')}`,
          source: 'Ransomware.live',
          sourceUrl: 'https://ransomware.live',
          title: item.victim || 'Unknown',
          description: item.description || `Ransomware victim of ${item.group_name}`,
          victimOrg: item.victim,
          victimCountry: item.country,
          ransomwareGroup: item.group_name,
          dataType: 'mixed',
          leakDate: item.published || new Date().toISOString(),
          discoveryDate: item.discovered || item.published || new Date().toISOString(),
          threatActor: item.group_name,
          isFree: false,
          sampleAvailable: false,
          verified: true,
          tags: ['ransomware', item.group_name?.toLowerCase(), item.country?.toLowerCase()].filter(Boolean),
          severity: 'critical',
        });
      }
    }
  } catch (err) {
    console.error('[RansomwareLive] Error:', err);
  }
  
  return { leaks };
}

async function searchAhmia(query: string): Promise<{ posts: ForumPost[] }> {
  const posts: ForumPost[] = [];
  
  try {
    // Ahmia search API (public Tor search engine)
    const response = await fetch(
      `https://ahmia.fi/search/?q=${encodeURIComponent(query)}`,
      { headers: { 'Accept': 'application/json' } }
    );
    
    // Note: Ahmia may not have a public JSON API
    // This is a placeholder for the search logic
    if (response.ok && response.headers.get('content-type')?.includes('json')) {
      const data = await response.json();
      // Process results if available
    }
  } catch (err) {
    // Ahmia search may not be available via API
  }
  
  return { posts };
}

async function searchDDoSecrets(query: string): Promise<{ posts: ForumPost[] }> {
  const posts: ForumPost[] = [];
  
  // DDoSecrets doesn't have a public API
  // We would need to use their RSS feed or scrape responsibly
  
  return { posts };
}

/* ============================================================================
   SIMULATED INTELLIGENCE (For Demo/Testing)
============================================================================ */

function generateSimulatedForumIntel(query: string): ForumPost[] {
  const posts: ForumPost[] = [];
  const queryLower = query.toLowerCase();
  
  // Simulate forum posts based on common patterns
  const forumTemplates = [
    {
      forum: 'BreachForums',
      categories: ['database_leak', 'credentials'],
      patterns: ['database', 'dump', 'leak', 'combo'],
    },
    {
      forum: 'XSS.is',
      categories: ['malware_sale', 'exploit'],
      patterns: ['rat', 'stealer', 'exploit', 'cve'],
    },
    {
      forum: 'Exploit.in',
      categories: ['exploit', 'service'],
      patterns: ['0day', 'rce', 'shell', 'access'],
    },
    {
      forum: 'RAMP',
      categories: ['malware_sale', 'service'],
      patterns: ['ransomware', 'affiliate', 'panel'],
    },
  ];
  
  for (const template of forumTemplates) {
    // Check if query matches forum patterns
    const isRelevant = template.patterns.some(p => queryLower.includes(p)) || 
                       queryLower.length > 3;
    
    if (isRelevant) {
      const category = template.categories[Math.floor(Math.random() * template.categories.length)] as ForumPost['category'];
      const severity = Math.random() > 0.7 ? 'critical' : Math.random() > 0.5 ? 'high' : 'medium';
      
      posts.push({
        id: `sim-${template.forum.toLowerCase()}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        forum: template.forum,
        forumUrl: `https://${template.forum.toLowerCase()}.example`,
        thread: generateThreadTitle(query, category),
        author: generateAuthorName(),
        authorReputation: Math.floor(Math.random() * 1000),
        content: generatePostContent(query, category),
        contentPreview: `[SIMULATED] Content related to "${query}"...`,
        timestamp: generateRecentTimestamp(),
        category,
        tags: [query.toLowerCase(), category, severity],
        attachments: generateAttachments(category),
        reactions: Math.floor(Math.random() * 500),
        replies: Math.floor(Math.random() * 100),
        views: Math.floor(Math.random() * 10000),
        severity: severity as ForumPost['severity'],
        relevanceScore: Math.round(Math.random() * 40 + 60),
      });
    }
  }
  
  return posts;
}

function generateThreadTitle(query: string, category: string): string {
  const templates: Record<string, string[]> = {
    database_leak: [
      `[DATABASE] ${query} - Full Dump Available`,
      `${query} Leaked Database - ${Math.floor(Math.random() * 10)}M Records`,
      `Fresh ${query} Combo List`,
    ],
    credentials: [
      `${query} Login Credentials - Verified`,
      `[FRESH] ${query} Account Logs`,
      `${query} VIP Access`,
    ],
    malware_sale: [
      `[SALE] ${query} Private Build`,
      `${query} Stealer/RAT - Undetected`,
      `Custom ${query} Panel`,
    ],
    exploit: [
      `[0day] ${query} RCE Exploit`,
      `${query} Vulnerability PoC`,
      `Private ${query} Exploit`,
    ],
    service: [
      `${query} Service - Fast & Reliable`,
      `[SERVICE] ${query} Available`,
    ],
    discussion: [
      `Discussion: ${query}`,
      `Question about ${query}`,
    ],
    tutorial: [
      `[GUIDE] How to ${query}`,
      `${query} Tutorial`,
    ],
  };
  
  const options = templates[category] || templates.discussion;
  return options[Math.floor(Math.random() * options.length)];
}

function generateAuthorName(): string {
  const prefixes = ['Dark', 'Shadow', 'Cyber', 'Ghost', 'Silent', 'Black', 'Zero', 'Void'];
  const suffixes = ['Hunter', 'Hacker', 'Master', 'King', 'Lord', 'Phoenix', 'Wolf', 'Ninja'];
  const numbers = ['', '13', '666', '1337', '2024', 'X', '_V2'];
  
  return `${prefixes[Math.floor(Math.random() * prefixes.length)]}${suffixes[Math.floor(Math.random() * suffixes.length)]}${numbers[Math.floor(Math.random() * numbers.length)]}`;
}

function generatePostContent(query: string, category: string): string {
  return `[SIMULATED CONTENT]

This is simulated forum intelligence for demonstration purposes.
Query: ${query}
Category: ${category}

In a real implementation, this would contain actual scraped content from dark web forums.
The platform uses LEGAL public aggregators to gather this intelligence.

⚠️ Note: Actual forum access requires proper authorization and legal compliance.`;
}

function generateRecentTimestamp(): string {
  const now = new Date();
  const daysAgo = Math.floor(Math.random() * 30);
  now.setDate(now.getDate() - daysAgo);
  return now.toISOString();
}

function generateAttachments(category: string): ForumAttachment[] {
  if (Math.random() > 0.5) return [];
  
  const attachmentTypes: Record<string, ForumAttachment[]> = {
    database_leak: [
      { name: 'dump.sql.gz', type: 'database', size: `${Math.floor(Math.random() * 500)}MB` },
      { name: 'users.csv', type: 'database', size: `${Math.floor(Math.random() * 100)}MB` },
    ],
    credentials: [
      { name: 'combo.txt', type: 'database', size: `${Math.floor(Math.random() * 50)}MB` },
    ],
    malware_sale: [
      { name: 'builder.zip', type: 'archive', size: `${Math.floor(Math.random() * 10)}MB` },
      { name: 'sample.exe', type: 'sample' },
    ],
    exploit: [
      { name: 'exploit.py', type: 'sample' },
      { name: 'poc.zip', type: 'archive' },
    ],
  };
  
  return attachmentTypes[category] || [];
}

function extractDomain(text: string | undefined): string | undefined {
  if (!text) return undefined;
  const match = text.match(/[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}/);
  return match ? match[0] : undefined;
}

/* ============================================================================
   MONITORING FUNCTIONS
============================================================================ */

/**
 * Monitor specific forums for new posts matching criteria
 */
export async function monitorForums(
  keywords: string[],
  options: { forums?: string[]; categories?: string[]; minSeverity?: string } = {}
): Promise<ForumPost[]> {
  const allPosts: ForumPost[] = [];
  
  for (const keyword of keywords) {
    const result = await searchDarkWebForums(keyword);
    
    // Filter by options
    let filtered = result.posts;
    
    if (options.forums && options.forums.length > 0) {
      filtered = filtered.filter(p => 
        options.forums!.some(f => p.forum.toLowerCase().includes(f.toLowerCase()))
      );
    }
    
    if (options.categories && options.categories.length > 0) {
      filtered = filtered.filter(p => 
        options.categories!.includes(p.category)
      );
    }
    
    if (options.minSeverity) {
      const severityOrder = ['low', 'medium', 'high', 'critical'];
      const minIndex = severityOrder.indexOf(options.minSeverity);
      filtered = filtered.filter(p => 
        severityOrder.indexOf(p.severity) >= minIndex
      );
    }
    
    allPosts.push(...filtered);
  }
  
  // Deduplicate
  const seen = new Set<string>();
  return allPosts.filter(p => {
    if (seen.has(p.id)) return false;
    seen.add(p.id);
    return true;
  });
}

/**
 * Get statistics about forum activity
 */
export function getForumStats(posts: ForumPost[], leaks: LeakPost[]): {
  totalActivity: number;
  bySeverity: Record<string, number>;
  byCategory: Record<string, number>;
  byForum: Record<string, number>;
  topThreatActors: { name: string; count: number }[];
  recentTrends: string[];
} {
  const bySeverity: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 };
  const byCategory: Record<string, number> = {};
  const byForum: Record<string, number> = {};
  const actorCounts: Record<string, number> = {};
  
  for (const post of posts) {
    bySeverity[post.severity] = (bySeverity[post.severity] || 0) + 1;
    byCategory[post.category] = (byCategory[post.category] || 0) + 1;
    byForum[post.forum] = (byForum[post.forum] || 0) + 1;
  }
  
  for (const leak of leaks) {
    bySeverity[leak.severity] = (bySeverity[leak.severity] || 0) + 1;
    if (leak.threatActor) {
      actorCounts[leak.threatActor] = (actorCounts[leak.threatActor] || 0) + 1;
    }
  }
  
  const topThreatActors = Object.entries(actorCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => ({ name, count }));
  
  return {
    totalActivity: posts.length + leaks.length,
    bySeverity,
    byCategory,
    byForum,
    topThreatActors,
    recentTrends: ['ransomware', 'infostealer', 'credential_dumps'],
  };
}

export { RANSOMWARE_GROUPS, PUBLIC_AGGREGATORS, FORUM_CATEGORIES };
