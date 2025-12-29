// src/services/newsService.ts
// Real-time News Intelligence Service
// Sources: NewsAPI, GNews, Bing News API

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
  author?:  string;
  publishedAt:  string;
  category: string;
  relevanceScore: number;
  sentiment?: 'positive' | 'negative' | 'neutral';
  keywords: string[];
  language: string;
  country?: string;
}

export interface NewsSearchParams {
  query: string;
  category?: 'cybersecurity' | 'crime' | 'technology' | 'business' | 'politics' | 'general';
  country?: string;
  language?:  string;
  dateFrom?: string;
  dateTo?: string;
  sortBy?: 'relevance' | 'date' | 'popularity';
  sources?:  string[];
}

export interface NewsStats {
  totalArticles:  number;
  sources: number;
  dateRange: {
    from: string;
    to:  string;
  };
  topSources: Array<{ name:  string; count: number }>;
  sentiment: {
    positive:  number;
    negative: number;
    neutral: number;
  };
}

export interface SavedSearch {
  id: string;
  name: string;
  params: NewsSearchParams;
  alertEnabled: boolean;
  lastChecked?:  string;
  createdAt:  string;
}

/* ============================================================================
   API KEYS (PUBLIC TIER - REPLACE WITH YOUR OWN)
============================================================================ */

const NEWS_API_KEY = '8d6b467f5f5a4aa9a8c8f1e3d9a6c9c0';
const GNEWS_API_KEY = 'e7c4b5a9d6f8e3c2a1b5d8e7f9c3a2b1';

/* ============================================================================
   NEWS API INTEGRATION
============================================================================ */

async function fetchFromNewsAPI(params: NewsSearchParams): Promise<NewsArticle[]> {
  const cacheKey = `newsapi:${JSON.stringify(params)}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const articles: NewsArticle[] = [];

  try {
    const baseUrl = 'https://newsapi.org/v2/everything';
    const queryParams = new URLSearchParams({
      q: params.query,
      apiKey: NEWS_API_KEY,
      language: params.language || 'en',
      sortBy: params.sortBy || 'publishedAt',
      pageSize: '50',
    });

    if (params.dateFrom) queryParams.append('from', params.dateFrom);
    if (params.dateTo) queryParams.append('to', params.dateTo);
    if (params.sources?. length) queryParams.append('sources', params.sources.join(','));

    const response = await fetch(`${baseUrl}?${queryParams}`);
    
    if (!response.ok) {
      console.error('NewsAPI error:', response.statusText);
      return [];
    }

    const data = await response.json();

    if (data.articles) {
      data.articles.forEach((article: any) => {
        articles. push({
          id: `newsapi-${article.url}`,
          title: article.title || 'Untitled',
          description: article.description || '',
          content: article.content || article.description || '',
          url: article.url,
          imageUrl: article.urlToImage,
          source: {
            name:  article.source?.name || 'Unknown',
            url: article. url,
          },
          author: article.author,
          publishedAt: article.publishedAt || new Date().toISOString(),
          category: categorizeArticle(article.title + ' ' + article.description),
          relevanceScore: calculateRelevance(article, params.query),
          sentiment: analyzeSentiment(article.title + ' ' + article. description),
          keywords: extractKeywords(article.title + ' ' + article.description),
          language: params.language || 'en',
        });
      });
    }

    await cacheAPIResponse(cacheKey, articles, 30);
    return articles;
  } catch (error) {
    console.error('NewsAPI fetch error:', error);
    return [];
  }
}

/* ============================================================================
   GNEWS API INTEGRATION
============================================================================ */

async function fetchFromGNews(params: NewsSearchParams): Promise<NewsArticle[]> {
  const cacheKey = `gnews:${JSON.stringify(params)}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const articles: NewsArticle[] = [];

  try {
    const baseUrl = 'https://gnews.io/api/v4/search';
    const queryParams = new URLSearchParams({
      q: params. query,
      token: GNEWS_API_KEY,
      lang: params.language || 'en',
      max: '50',
    });

    if (params.country) queryParams.append('country', params.country);
    if (params.category) queryParams.append('topic', params.category);

    const response = await fetch(`${baseUrl}?${queryParams}`);
    
    if (!response.ok) {
      console.error('GNews error:', response. statusText);
      return [];
    }

    const data = await response.json();

    if (data.articles) {
      data.articles.forEach((article: any) => {
        articles.push({
          id: `gnews-${article.url}`,
          title: article.title || 'Untitled',
          description: article.description || '',
          content: article.content || article. description || '',
          url: article.url,
          imageUrl: article.image,
          source: {
            name: article.source?.name || 'Unknown',
            url: article.source?.url,
          },
          author: article.source?.name,
          publishedAt: article. publishedAt || new Date().toISOString(),
          category:  categorizeArticle(article.title + ' ' + article.description),
          relevanceScore: calculateRelevance(article, params.query),
          sentiment: analyzeSentiment(article.title + ' ' + article.description),
          keywords: extractKeywords(article.title + ' ' + article.description),
          language: params.language || 'en',
        });
      });
    }

    await cacheAPIResponse(cacheKey, articles, 30);
    return articles;
  } catch (error) {
    console.error('GNews fetch error:', error);
    return [];
  }
}

/* ============================================================================
   BING NEWS API (Via Bing Search)
============================================================================ */

async function fetchFromBingNews(params:  NewsSearchParams): Promise<NewsArticle[]> {
  const cacheKey = `bing:${JSON.stringify(params)}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const articles: NewsArticle[] = [];

  try {
    const rssUrl = `https://www.bing.com/news/search?q=${encodeURIComponent(params.query)}&format=rss`;
    
    const response = await fetch(
      `https://api.allorigins.win/get?url=${encodeURIComponent(rssUrl)}`
    );

    if (!response.ok) return [];

    const { contents } = await response.json();
    
    const parser = new DOMParser();
    const xml = parser.parseFromString(contents, 'text/xml');
    const items = xml.querySelectorAll('item');

    items.forEach((item, idx) => {
      if (idx >= 50) return;

      const title = item.querySelector('title')?.textContent || '';
      const description = item.querySelector('description')?.textContent || '';
      const link = item.querySelector('link')?.textContent || '';
      const pubDate = item.querySelector('pubDate')?.textContent || '';
      const source = item.querySelector('source')?.textContent || 'Bing News';

      if (title && link) {
        articles.push({
          id: `bing-${link}`,
          title,
          description:  stripHtml(description),
          content: stripHtml(description),
          url: link,
          source: {
            name: source,
          },
          publishedAt: pubDate || new Date().toISOString(),
          category: categorizeArticle(title + ' ' + description),
          relevanceScore: calculateRelevance({ title, description }, params.query),
          sentiment: analyzeSentiment(title + ' ' + description),
          keywords: extractKeywords(title + ' ' + description),
          language: params.language || 'en',
        });
      }
    });

    await cacheAPIResponse(cacheKey, articles, 30);
    return articles;
  } catch (error) {
    console.error('Bing News fetch error:', error);
    return [];
  }
}

/* ============================================================================
   AGGREGATOR - COMBINE ALL SOURCES
============================================================================ */

export async function searchNews(params: NewsSearchParams): Promise<NewsArticle[]> {
  try {
    const [newsapi, gnews, bing] = await Promise. all([
      fetchFromNewsAPI(params),
      fetchFromGNews(params),
      fetchFromBingNews(params),
    ]);

    const allArticles = [...newsapi, ... gnews, ...bing];
    const uniqueArticles = deduplicateArticles(allArticles);

    return uniqueArticles. sort((a, b) => {
      if (params.sortBy === 'relevance') {
        return b. relevanceScore - a.relevanceScore;
      }
      return new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime();
    });
  } catch (error) {
    console.error('News search error:', error);
    return [];
  }
}

/* ============================================================================
   TRENDING NEWS
============================================================================ */

export async function getTrendingNews(
  category?:  string,
  country?: string
): Promise<NewsArticle[]> {
  return searchNews({
    query: category || 'cybersecurity OR breach OR hack OR malware',
    category: category as any,
    country,
    sortBy: 'date',
  });
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
    const key = article.title. toLowerCase().slice(0, 50);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function calculateRelevance(article: any, query: string): number {
  const text = `${article.title} ${article. description}`.toLowerCase();
  const keywords = query.toLowerCase().split(/\s+/);
  
  let score = 0;
  keywords.forEach(keyword => {
    const count = (text.match(new RegExp(keyword, 'g')) || []).length;
    score += count * 10;
  });

  const age = Date.now() - new Date(article.publishedAt || Date.now()).getTime();
  const daysSince = age / (1000 * 60 * 60 * 24);
  score += Math.max(0, 50 - daysSince * 2);

  return Math.min(100, score);
}

function analyzeSentiment(text: string): 'positive' | 'negative' | 'neutral' {
  const lower = text.toLowerCase();
  
  const negative = ['breach', 'hack', 'attack', 'threat', 'malware', 'ransomware', 'vulnerability', 'exploit', 'critical', 'severe'];
  const positive = ['secure', 'patch', 'fix', 'protect', 'defense', 'success', 'recover'];

  let score = 0;
  negative.forEach(word => {
    if (lower.includes(word)) score -= 1;
  });
  positive.forEach(word => {
    if (lower.includes(word)) score += 1;
  });

  if (score < -1) return 'negative';
  if (score > 1) return 'positive';
  return 'neutral';
}

function categorizeArticle(text: string): string {
  const lower = text.toLowerCase();

  if (lower.match(/cyber|hack|breach|malware|ransomware|security|vulnerability/)) {
    return 'cybersecurity';
  }
  if (lower.match(/crime|arrest|fraud|scam|illegal/)) {
    return 'crime';
  }
  if (lower.match(/tech|software|app|digital|ai|cloud/)) {
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
  const commonWords = new Set(['the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'from', 'as', 'is', 'was', 'are', 'were', 'been', 'be', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'may', 'might', 'can', 'this', 'that', 'these', 'those']);

  const words = text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .split(/\s+/)
    .filter(w => w. length > 3 && ! commonWords.has(w));

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

export async function saveSaveSearch(search:  Omit<SavedSearch, 'id' | 'createdAt'>): Promise<void> {
  const saved:  SavedSearch = {
    ... search,
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
