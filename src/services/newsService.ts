// ============================================================================
// newsService.ts
// Real-time News Intelligence Service with Reddit Integration
// Sources: Reddit (WORKING), Bing News RSS, HackerNews, Google News RSS
// ============================================================================

import { cacheAPIResponse, getCachedData } from '@/lib/database';

/* ============================================================================
   TYPES
============================================================================ */

export interface NewsArticle {
  id: string;
  title: string;
  description: string;
  content: string;
  url: string;
  imageUrl?: string;
  source: {
    name: string;
    url?: string;
  };
  author?: string;
  publishedAt: string;
  category: string;
  relevanceScore: number;
  sentiment?: 'positive' | 'negative' | 'neutral';
  keywords: string[];
  language: string;
  country?: string;
  upvotes?: number;
  comments?: number;
}

export interface NewsSearchParams {
  query: string;
  category?: 'cybersecurity' | 'crime' | 'technology' | 'business' | 'politics' | 'general';
  country?: string;
  language?: string;
  dateFrom?: string;
  dateTo?: string;
  sortBy?: 'relevance' | 'date' | 'popularity';
  sources?: string[];
}

export interface NewsStats {
  totalArticles: number;
  sources: number;
  dateRange: {
    from: string;
    to: string;
  };
  topSources: Array<{ name: string; count: number }>;
  sentiment: {
    positive: number;
    negative: number;
    neutral: number;
  };
}

export interface SavedSearch {
  id: string;
  name: string;
  params: NewsSearchParams;
  alertEnabled: boolean;
  lastChecked?: string;
  createdAt: string;
}

/* ============================================================================
   CONSTANTS
============================================================================ */

const CORS_PROXY = 'https://api.allorigins.win/raw?url=';

// Reddit subreddits for different categories
const REDDIT_SUBREDDITS = {
  cybersecurity: ['netsec', 'cybersecurity', 'hacking', 'privacy', 'AskNetsec', 'malware', 'ReverseEngineering'],
  technology: ['technology', 'tech', 'gadgets', 'programming', 'webdev', 'linux'],
  general: ['news', 'worldnews', 'UpliftingNews'],
  business: ['business', 'economics', 'finance', 'wallstreetbets'],
};

/* ============================================================================
   REDDIT NEWS (VERIFIED WORKING - NO API KEY NEEDED)
============================================================================ */

async function fetchFromReddit(params: NewsSearchParams): Promise<NewsArticle[]> {
  const cacheKey = `reddit:${JSON.stringify(params)}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const articles: NewsArticle[] = [];

  try {
    // Determine which subreddits to search
    const category = params.category || 'cybersecurity';
    const subreddits = REDDIT_SUBREDDITS[category] || REDDIT_SUBREDDITS.cybersecurity;

    // Search Reddit
    let url: string;
    if (params.query) {
      // Search across relevant subreddits
      url = `https://www.reddit.com/search.json?q=${encodeURIComponent(params.query)}&sort=${params.sortBy === 'date' ? 'new' : 'relevance'}&limit=50&t=week`;
    } else {
      // Get hot posts from cybersecurity subreddits
      url = `https://www.reddit.com/r/${subreddits.join('+')}/hot.json?limit=50`;
    }

    console.log(`[Reddit News] Fetching: ${url}`);

    const res = await fetch(url, {
      headers: { 'User-Agent': 'OSINT-Hub/1.0' }
    });

    if (!res.ok) {
      console.warn(`[Reddit News] HTTP ${res.status}`);
      return [];
    }

    const data = await res.json();
    const posts = data.data?.children || [];

    posts.forEach((post: any) => {
      const p = post.data;

      // Skip if no title or is a self post without much content
      if (!p.title) return;

      const article: NewsArticle = {
        id: `reddit-${p.id}`,
        title: p.title,
        description: p.selftext?.substring(0, 300) || p.title,
        content: p.selftext || p.title,
        url: p.url?.startsWith('http') ? p.url : `https://reddit.com${p.permalink}`,
        imageUrl: p.thumbnail && p.thumbnail.startsWith('http') ? p.thumbnail : undefined,
        source: {
          name: `r/${p.subreddit}`,
          url: `https://reddit.com/r/${p.subreddit}`,
        },
        author: p.author,
        publishedAt: new Date(p.created_utc * 1000).toISOString(),
        category: categorizeArticle(p.title + ' ' + p.subreddit),
        relevanceScore: calculateRedditRelevance(p, params.query || ''),
        sentiment: analyzeSentiment(p.title),
        keywords: extractKeywords(p.title),
        language: 'en',
        upvotes: p.score,
        comments: p.num_comments,
      };

      articles.push(article);
    });

    console.log(`[Reddit News] ✅ Found ${articles.length} articles`);
    await cacheAPIResponse(cacheKey, articles, 15); // Cache for 15 minutes
    return articles;
  } catch (err) {
    console.error('[Reddit News] ❌ Error:', err);
    return [];
  }
}

function calculateRedditRelevance(post: any, query: string): number {
  let score = 0;

  // Upvote score (logarithmic scale)
  score += Math.min(40, Math.log10(Math.max(1, post.score)) * 15);

  // Comment engagement
  score += Math.min(20, Math.log10(Math.max(1, post.num_comments)) * 10);

  // Recency (posts from last 24h get bonus)
  const hoursOld = (Date.now() - post.created_utc * 1000) / (1000 * 60 * 60);
  if (hoursOld < 24) score += 20;
  else if (hoursOld < 48) score += 10;

  // Query match
  if (query) {
    const text = post.title.toLowerCase();
    const keywords = query.toLowerCase().split(/\s+/);
    keywords.forEach(kw => {
      if (text.includes(kw)) score += 10;
    });
  }

  return Math.min(100, score);
}

/* ============================================================================
   HACKER NEWS (VERIFIED WORKING)
============================================================================ */

async function fetchFromHackerNews(params: NewsSearchParams): Promise<NewsArticle[]> {
  const cacheKey = `hn:${JSON.stringify(params)}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const articles: NewsArticle[] = [];

  try {
    let url: string;
    if (params.query) {
      url = `https://hn.algolia.com/api/v1/search?query=${encodeURIComponent(params.query)}&tags=story&hitsPerPage=30`;
    } else {
      url = 'https://hn.algolia.com/api/v1/search?tags=front_page&hitsPerPage=30';
    }

    // Fetching HackerNews data...

    const res = await fetch(url);
    if (!res.ok) return [];

    const data = await res.json();

    (data.hits || []).forEach((hit: any) => {
      const article: NewsArticle = {
        id: `hn-${hit.objectID}`,
        title: hit.title || 'HackerNews Story',
        description: hit.title,
        content: hit.title,
        url: hit.url || `https://news.ycombinator.com/item?id=${hit.objectID}`,
        source: {
          name: 'Hacker News',
          url: 'https://news.ycombinator.com',
        },
        author: hit.author,
        publishedAt: hit.created_at || new Date().toISOString(),
        category: categorizeArticle(hit.title),
        relevanceScore: Math.min(100, (hit.points || 0) / 10 + 50),
        sentiment: analyzeSentiment(hit.title),
        keywords: extractKeywords(hit.title),
        language: 'en',
        upvotes: hit.points,
        comments: hit.num_comments,
      };
      articles.push(article);
    });

    // Found HackerNews articles
    await cacheAPIResponse(cacheKey, articles, 15);
    return articles;
  } catch (err) {
    // HackerNews error handled
    return [];
  }
}

/* ============================================================================
   BING NEWS RSS (VERIFIED WORKING via CORS proxy)
============================================================================ */

async function fetchFromBingNews(params: NewsSearchParams): Promise<NewsArticle[]> {
  const cacheKey = `bing:${JSON.stringify(params)}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const articles: NewsArticle[] = [];

  try {
    const query = params.query || 'cybersecurity';
    const rssUrl = `https://www.bing.com/news/search?q=${encodeURIComponent(query)}&format=rss`;

    console.log(`[Bing News] Fetching...`);

    const response = await fetch(`${CORS_PROXY}${encodeURIComponent(rssUrl)}`);
    if (!response.ok) return [];

    const xml = await response.text();
    const parser = new DOMParser();
    const doc = parser.parseFromString(xml, 'text/xml');
    const items = doc.querySelectorAll('item');

    items.forEach((item, idx) => {
      if (idx >= 30) return;

      const title = item.querySelector('title')?.textContent || '';
      const description = item.querySelector('description')?.textContent || '';
      const link = item.querySelector('link')?.textContent || '';
      const pubDate = item.querySelector('pubDate')?.textContent || '';
      const source = item.querySelector('source')?.textContent || 'Bing News';

      if (title && link) {
        articles.push({
          id: `bing-${link.replace(/[^a-z0-9]/gi, '').substring(0, 20)}`,
          title,
          description: stripHtml(description),
          content: stripHtml(description),
          url: link,
          source: { name: source },
          publishedAt: pubDate || new Date().toISOString(),
          category: categorizeArticle(title + ' ' + description),
          relevanceScore: calculateRelevance({ title, description }, params.query || ''),
          sentiment: analyzeSentiment(title + ' ' + description),
          keywords: extractKeywords(title + ' ' + description),
          language: params.language || 'en',
        });
      }
    });

    console.log(`[Bing News] ✅ Found ${articles.length} articles`);
    await cacheAPIResponse(cacheKey, articles, 30);
    return articles;
  } catch (err) {
    console.error('[Bing News] ❌ Error:', err);
    return [];
  }
}

/* ============================================================================
   GOOGLE NEWS RSS (VERIFIED WORKING via CORS proxy)
============================================================================ */

async function fetchFromGoogleNews(params: NewsSearchParams): Promise<NewsArticle[]> {
  const cacheKey = `gnews:${JSON.stringify(params)}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const articles: NewsArticle[] = [];

  try {
    const query = params.query || 'cybersecurity';
    const rssUrl = `https://news.google.com/rss/search?q=${encodeURIComponent(query)}&hl=en-US&gl=US&ceid=US:en`;

    console.log(`[Google News] Fetching...`);

    const response = await fetch(`${CORS_PROXY}${encodeURIComponent(rssUrl)}`);
    if (!response.ok) return [];

    const xml = await response.text();
    const parser = new DOMParser();
    const doc = parser.parseFromString(xml, 'text/xml');
    const items = doc.querySelectorAll('item');

    items.forEach((item, idx) => {
      if (idx >= 30) return;

      const title = item.querySelector('title')?.textContent || '';
      const link = item.querySelector('link')?.textContent || '';
      const pubDate = item.querySelector('pubDate')?.textContent || '';
      const source = item.querySelector('source')?.textContent || 'Google News';

      if (title && link) {
        articles.push({
          id: `google-${link.replace(/[^a-z0-9]/gi, '').substring(0, 20)}`,
          title: stripHtml(title),
          description: title,
          content: title,
          url: link,
          source: { name: source },
          publishedAt: pubDate || new Date().toISOString(),
          category: categorizeArticle(title),
          relevanceScore: 70,
          sentiment: analyzeSentiment(title),
          keywords: extractKeywords(title),
          language: params.language || 'en',
        });
      }
    });

    console.log(`[Google News] ✅ Found ${articles.length} articles`);
    await cacheAPIResponse(cacheKey, articles, 30);
    return articles;
  } catch (err) {
    console.error('[Google News] ❌ Error:', err);
    return [];
  }
}

/* ============================================================================
   AGGREGATOR - COMBINE ALL SOURCES
============================================================================ */

export async function searchNews(params: NewsSearchParams): Promise<NewsArticle[]> {
  console.log(`\n========================================`);
  console.log(`[News Search] Searching for: "${params.query}"`);
  console.log(`========================================\n`);

  try {
    const results = await Promise.allSettled([
      fetchFromReddit(params),
      fetchFromHackerNews(params),
      fetchFromBingNews(params),
      fetchFromGoogleNews(params),
    ]);

    const allArticles: NewsArticle[] = [];
    const sourceNames = ['Reddit', 'HackerNews', 'Bing', 'Google'];

    results.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        console.log(`[${sourceNames[index]}] ✅ ${result.value.length} articles`);
        allArticles.push(...result.value);
      } else {
        console.warn(`[${sourceNames[index]}] ❌ Failed`);
      }
    });

    const uniqueArticles = deduplicateArticles(allArticles);

    // Sort by relevance or date
    const sorted = uniqueArticles.sort((a, b) => {
      if (params.sortBy === 'popularity') {
        return (b.upvotes || 0) - (a.upvotes || 0);
      }
      if (params.sortBy === 'relevance') {
        return b.relevanceScore - a.relevanceScore;
      }
      return new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime();
    });

    console.log(`\n[News Search] Total unique articles: ${sorted.length}\n`);
    return sorted;
  } catch (err) {
    console.error('[News Search] ❌ Error:', err);
    return [];
  }
}

/* ============================================================================
   TRENDING NEWS - Cybersecurity Focus + General Hot
============================================================================ */

export async function getTrendingNews(category?: string): Promise<NewsArticle[]> {
  console.log(`\n========================================`);
  console.log(`[Trending News] Fetching trending ${category || 'all'} news`);
  console.log(`========================================\n`);

  try {
    // Fetch from multiple sources in parallel
    const results = await Promise.allSettled([
      // Cybersecurity trending from Reddit
      fetchFromReddit({
        query: '',
        category: 'cybersecurity',
        sortBy: 'popularity',
      }),
      // HackerNews front page
      fetchFromHackerNews({ query: '' }),
      // General trending from Reddit
      fetchFromReddit({
        query: 'breaking news today',
        category: 'general',
        sortBy: 'popularity',
      }),
      // Latest cybersecurity news from Google/Bing
      fetchFromGoogleNews({ query: 'cybersecurity breach hack 2024' }),
    ]);

    const allArticles: NewsArticle[] = [];

    results.forEach((result) => {
      if (result.status === 'fulfilled') {
        allArticles.push(...result.value);
      }
    });

    // Deduplicate
    const unique = deduplicateArticles(allArticles);

    // Sort by a combined score of relevance + upvotes + recency
    const sorted = unique.sort((a, b) => {
      const scoreA = a.relevanceScore + (a.upvotes ? Math.log10(a.upvotes) * 10 : 0);
      const scoreB = b.relevanceScore + (b.upvotes ? Math.log10(b.upvotes) * 10 : 0);
      return scoreB - scoreA;
    });

    // Prioritize cybersecurity at top, but include others
    const cyberArticles = sorted.filter(a => a.category === 'cybersecurity').slice(0, 15);
    const otherArticles = sorted.filter(a => a.category !== 'cybersecurity').slice(0, 10);

    const final = [...cyberArticles, ...otherArticles];

    console.log(`[Trending News] ✅ Total: ${final.length} (${cyberArticles.length} cyber, ${otherArticles.length} other)`);
    return final;
  } catch (err) {
    console.error('[Trending News] ❌ Error:', err);
    return [];
  }
}

/* ============================================================================
   NEWS STATISTICS
============================================================================ */

export function calculateNewsStats(articles: NewsArticle[]): NewsStats {
  const sources = new Map<string, number>();
  const sentiments = { positive: 0, negative: 0, neutral: 0 };

  articles.forEach(article => {
    const count = sources.get(article.source.name) || 0;
    sources.set(article.source.name, count + 1);

    if (article.sentiment) {
      sentiments[article.sentiment]++;
    }
  });

  const sortedSources = Array.from(sources.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  const dates = articles
    .map(a => new Date(a.publishedAt))
    .filter(d => !isNaN(d.getTime()))
    .sort((a, b) => a.getTime() - b.getTime());

  return {
    totalArticles: articles.length,
    sources: sources.size,
    dateRange: {
      from: dates[0]?.toISOString() || new Date().toISOString(),
      to: dates[dates.length - 1]?.toISOString() || new Date().toISOString(),
    },
    topSources: sortedSources,
    sentiment: sentiments,
  };
}

/* ============================================================================
   UTILITY FUNCTIONS
============================================================================ */

function stripHtml(html: string): string {
  return html.replace(/<[^>]*>/g, '').trim();
}

function deduplicateArticles(articles: NewsArticle[]): NewsArticle[] {
  const seen = new Set<string>();
  return articles.filter(article => {
    const key = article.title.toLowerCase().slice(0, 50);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function calculateRelevance(article: any, query: string): number {
  const text = `${article.title} ${article.description}`.toLowerCase();
  const keywords = query.toLowerCase().split(/\s+/);

  let score = 50;
  keywords.forEach(keyword => {
    if (keyword.length < 3) return;
    const count = (text.match(new RegExp(keyword, 'g')) || []).length;
    score += count * 10;
  });

  return Math.min(100, score);
}

function analyzeSentiment(text: string): 'positive' | 'negative' | 'neutral' {
  const lower = text.toLowerCase();

  const negative = ['breach', 'hack', 'attack', 'threat', 'malware', 'ransomware', 'vulnerability', 'exploit', 'critical', 'severe', 'leak', 'stolen', 'compromised'];
  const positive = ['secure', 'patch', 'fix', 'protect', 'defense', 'success', 'recover', 'update', 'improved'];

  let score = 0;
  negative.forEach(word => { if (lower.includes(word)) score -= 1; });
  positive.forEach(word => { if (lower.includes(word)) score += 1; });

  if (score < -1) return 'negative';
  if (score > 1) return 'positive';
  return 'neutral';
}

function categorizeArticle(text: string): string {
  const lower = text.toLowerCase();

  if (lower.match(/cyber|hack|breach|malware|ransomware|security|vulnerability|exploit|phishing|netsec/)) {
    return 'cybersecurity';
  }
  if (lower.match(/crime|arrest|fraud|scam|illegal/)) {
    return 'crime';
  }
  if (lower.match(/tech|software|app|digital|ai|cloud|programming/)) {
    return 'technology';
  }
  if (lower.match(/business|company|market|finance|economy/)) {
    return 'business';
  }
  if (lower.match(/government|politics|policy|election/)) {
    return 'politics';
  }

  return 'general';
}

function extractKeywords(text: string): string[] {
  const commonWords = new Set(['the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'from', 'as', 'is', 'was', 'are', 'were', 'been', 'be', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'may', 'might', 'can', 'this', 'that', 'these', 'those', 'its', 'your', 'our']);

  const words = text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length > 3 && !commonWords.has(w));

  const freq = new Map<string, number>();
  words.forEach(word => {
    freq.set(word, (freq.get(word) || 0) + 1);
  });

  return Array.from(freq.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([word]) => word);
}

/* ============================================================================
   SAVED SEARCHES & ALERTS
============================================================================ */

export async function saveSaveSearch(search: Omit<SavedSearch, 'id' | 'createdAt'>): Promise<void> {
  const saved: SavedSearch = {
    ...search,
    id: `search-${Date.now()}`,
    createdAt: new Date().toISOString(),
  };

  const existing = await getCachedData('saved_searches') || [];
  await cacheAPIResponse('saved_searches', [...existing, saved], Infinity);
}

export async function getSavedSearches(): Promise<SavedSearch[]> {
  return await getCachedData('saved_searches') || [];
}

export async function deleteSavedSearch(id: string): Promise<void> {
  const existing = await getCachedData('saved_searches') || [];
  await cacheAPIResponse(
    'saved_searches',
    existing.filter((s: SavedSearch) => s.id !== id),
    Infinity
  );
}
