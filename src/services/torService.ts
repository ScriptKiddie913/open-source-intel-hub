// ============================================================================
// torService.ts
// ADVANCED Dark Web Intelligence — Multi-Tool Integration
// Combines:  TorBot, DarkScrape, FreshOnions, Onioff, TorCrawl concepts
// + Intel Techniques APIs:  PSBDMP, Rentry, Pastebin, Ghostbin, GitHub
// + Telegram OSINT via Telemetr & t.me/s/
// + Dark. fail market status
// SERVER-SAFE | VERCEL-READY | NO TOR DAEMON REQUIRED
// ============================================================================

import { cacheAPIResponse, getCachedData } from '@/lib/database';

/* ============================================================================
   TYPES
============================================================================ */

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low';

export interface OnionSite {
  url:  string;
  title: string;
  description: string;
  category: string;
  riskLevel: RiskLevel;
  lastSeen: string;
  status: 'online' | 'offline' | 'unknown';
  tags: string[];
  discoveredFrom: string;
  sshFingerprint?:  string;
  bitcoinAddresses?: string[];
  emailAddresses?: string[];
  ports?: number[];
  language?: string;
}

export interface LeakSignal {
  id:  string;
  title: string;
  indicator: string;
  source: 
    | 'pastebin'
    | 'ghostbin'
    | 'rentry'
    | 'github_gist'
    | 'psbdmp'
    | 'telegram'
    | 'onionland'
    | 'ahmia'
    | 'paste_rs'
    | 'dpaste'
    | 'intelx';
  timestamp: string;
  url: string;
  context:  string;
  metadata?: {
    channelName?: string;
    subscribers?: number;
    views?: number;
    messageId?: number;
    emails?: string[];
    bitcoins?:  string[];
    author?: string;
    pasteId?: string;
  };
}

export interface TelegramChannel {
  id: string;
  username: string;
  title: string;
  description: string;
  subscribers: number;
  category: string;
  riskLevel: RiskLevel;
  verified: boolean;
  tags: string[];
}

export interface TelegramMessage {
  id: string;
  channelUsername: string;
  messageId: number;
  text: string;
  date: string;
  views: number;
  forwards: number;
  hasMedia: boolean;
  mediaType?:  string;
  link: string;
}

export interface DarkWebMarket {
  name: string;
  url: string;
  status: 'online' | 'offline' | 'unknown';
  uptime?:  number;
  lastChecked:  string;
  mirrors?: string[];
  v3Onion?: string;
}

/* ============================================================================
   CONSTANTS
============================================================================ */

const TOR2WEB_PROXIES = ['onion.ws', 'onion.pet', 'onion.ly'];

const ONION_REGEX = /([a-z2-7]{16,56}\.onion)/gi;
const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const BITCOIN_REGEX = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\bbc1[a-z0-9]{39,59}\b/g;
const SSH_FINGERPRINT_REGEX = /([0-9a-f]{2}: ){15}[0-9a-f]{2}/gi;

const TIMEOUTS = {
  ONION_DISCOVERY: 8000,
  PASTE_SCAN: 5000,
  UPTIME_CHECK: 10000,
  TELEGRAM_SCAN: 7000,
  DEEP_SCAN: 12000,
  API_CALL: 6000,
};

const MAX_RESULTS = {
  ONIONS: 30,
  TELEGRAM_CHANNELS: 20,
  TELEGRAM_MESSAGES: 25,
  PASTES: 20,
  GITHUB: 15,
};

/**
 * Multiple Tor Search Engines (Clearnet Proxies)
 * NOTE:  Torch (. onion) CANNOT be fetched on Vercel
 */
const TOR_SEARCH_ENGINES = [
  { name: 'ahmia', type: 'clearnet', url:  'https://ahmia.fi/search/? q=' },
  { name: 'onionland', type: 'clearnet', url: 'https://onionlandsearchengine.net/search?q=' },
] as const;

/**
 * Public Paste Sites for Scraping
 */
const PASTE_SITES = [
  { name: 'pastebin', url: 'https://pastebin.com/archive' },
  { name: 'ghostbin', url: 'https://ghostbin.com/browse' },
  { name: 'paste_rs', url: 'https://paste.rs/' },
  { name: 'dpaste', url: 'https://dpaste.org/recent' },
] as const;

/**
 * Public APIs (Intel Techniques)
 */
const INTEL_APIS = {
  psbdmp: 'https://psbdmp.ws/api/search/',
  rentry:  'https://rentry.co/api/search?q=',
  github: 'https://api.github.com/search/code?q=',
} as const;

/* ============================================================================
   UTILITIES
============================================================================ */

function stripHtml(input: string): string {
  if (!input) return '';
  return input.replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
}

function nowISO(): string {
  return new Date().toISOString();
}

function unique<T>(arr: T[]): T[] {
  return Array.from(new Set(arr));
}

async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs = 5000
): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(id);
  }
}

/* ============================================================================
   ADVANCED EXTRACTION (TorBot / TorCrawl features)
============================================================================ */

function extractEmails(text: string): string[] {
  return unique((text. match(EMAIL_REGEX) || []).map(e => e.toLowerCase()));
}

function extractBitcoinAddresses(text: string): string[] {
  return unique(text.match(BITCOIN_REGEX) || []);
}

function extractSSHFingerprints(text:  string): string[] {
  return unique(text.match(SSH_FINGERPRINT_REGEX) || []);
}

function detectLanguage(text: string): string {
  const samples:  Record<string, RegExp> = {
    en: /\b(the|and|is|in|to|of|for|with|on|at)\b/gi,
    ru: /[а-яА-ЯёЁ]{3,}/g,
    zh: /[\u4e00-\u9fff]{2,}/g,
    es: /\b(el|la|de|en|y|que|es|por|para)\b/gi,
    fr:  /\b(le|la|de|et|est|pour|dans|avec)\b/gi,
    de: /\b(der|die|das|und|ist|in|zu|den|mit)\b/gi,
  };

  let best = 'unknown';
  let max = 0;

  for (const [lang, rx] of Object.entries(samples)) {
    const count = (text.match(rx) || []).length;
    if (count > max) {
      max = count;
      best = lang;
    }
  }

  return best;
}

/* ============================================================================
   RISK SCORING & CATEGORIZATION
============================================================================ */

function calculateRisk(text: string): RiskLevel {
  const t = text.toLowerCase();

  const criticalKeywords = [
    'malware', 'exploit', 'ransomware', 'weapon', 'drugs', 'csam', 
    'cp', 'hitman', 'murder', 'bomb', 'terrorist'
  ];
  
  const highKeywords = [
    'leak', 'dump', 'database', 'breach', 'credentials', 'cvv', 
    'fullz', 'combolist', 'credit card', 'ssn', 'passport'
  ];
  
  const mediumKeywords = [
    'market', 'forum', 'selling', 'phishing', 'carding', 'fraud',
    'vendor', 'escrow', 'btc', 'crypto'
  ];

  if (criticalKeywords.some(k => t.includes(k))) return 'critical';
  if (highKeywords.some(k => t.includes(k))) return 'high';
  if (mediumKeywords.some(k => t.includes(k))) return 'medium';

  return 'low';
}

function extractTags(text: string): string[] {
  const keywords = [
    'market', 'forum', 'leak', 'dump', 'database', 'malware', 'exploit',
    'credentials', 'phishing', 'carding', 'fraud', 'breach', 'ransomware',
    'combolist', 'cvv', 'fullz', 'vendor', 'escrow', 'crypto', 'bitcoin',
    'darknet', 'tor', 'vpn', 'hosting', 'email', 'ssh', 'api'
  ];

  const t = text.toLowerCase();
  return keywords.filter(k => t. includes(k)).slice(0, 10);
}

function categorize(text: string): string {
  const t = text.toLowerCase();

  if (t.includes('market') || t.includes('shop') || t.includes('vendor')) return 'Marketplace';
  if (t. includes('forum') || t.includes('board') || t.includes('discussion')) return 'Forum';
  if (t.includes('leak') || t.includes('dump') || t.includes('breach')) return 'Data Leak';
  if (t.includes('mail') || t.includes('email') || t.includes('webmail')) return 'Email Service';
  if (t.includes('hosting') || t.includes('vpn') || t.includes('proxy')) return 'Hosting/VPN';
  if (t.includes('directory') || t.includes('links') || t.includes('index')) return 'Directory';
  if (t.includes('wiki') || t.includes('info') || t.includes('knowledge')) return 'Wiki/Info';
  if (t. includes('channel') || t.includes('group') || t.includes('chat')) return 'Communication';
  if (t.includes('bitcoin') || t.includes('crypto') || t.includes('wallet')) return 'Cryptocurrency';
  if (t.includes('news') || t.includes('blog') || t.includes('article')) return 'News/Blog';
  if (t.includes('file') || t.includes('upload') || t.includes('storage')) return 'File Storage';

  return 'Unknown';
}

/* ============================================================================
   MULTI-ENGINE ONION DISCOVERY (FreshOnions + TorBot approach)
============================================================================ */

export async function discoverOnionSites(query: string): Promise<OnionSite[]> {
  const cacheKey = `onion:multi:${query}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const collected: OnionSite[] = [];

  // Search across multiple clearnet engines
  for (const engine of TOR_SEARCH_ENGINES) {
    try {
      const res = await fetchWithTimeout(
        engine.url + encodeURIComponent(query),
        { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' } },
        TIMEOUTS. ONION_DISCOVERY
      );

      if (!res.ok) continue;

      const html = await res.text();
      const onions = unique(html.match(ONION_REGEX) || []);

      onions.forEach(onion => {
        const idx = html.indexOf(onion);
        const contextStart = Math.max(0, idx - 300);
        const contextEnd = Math.min(html.length, idx + 300);
        const context = html. substring(contextStart, contextEnd);
        
        const title = extractTitle(context) || 'Unknown Onion Service';
        const description = extractDescription(context) || 'Discovered via search engine';
        const fullContext = `${title} ${description} ${stripHtml(context)}`;

        collected.push({
          url: onion,
          title,
          description,
          category: categorize(fullContext),
          riskLevel: calculateRisk(fullContext),
          lastSeen:  nowISO(),
          status: 'unknown',
          tags: extractTags(fullContext),
          discoveredFrom: engine.name,
          emailAddresses: extractEmails(fullContext),
          bitcoinAddresses: extractBitcoinAddresses(fullContext),
          sshFingerprint: extractSSHFingerprints(fullContext)[0],
          language: detectLanguage(fullContext),
        });
      });
    } catch (err) {
      console.error(`Error searching ${engine.name}:`, err);
    }
  }

  // Deduplicate by URL
  const uniqueSites = Array.from(
    new Map(collected.map(s => [s.url, s])).values()
  ).slice(0, MAX_RESULTS. ONIONS);

  await cacheAPIResponse(cacheKey, uniqueSites, 300);
  return uniqueSites;
}

function extractTitle(html: string): string {
  const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i) ||
                      html.match(/<h1[^>]*>([^<]+)<\/h1>/i) ||
                      html.match(/<h2[^>]*>([^<]+)<\/h2>/i) ||
                      html.match(/<h3[^>]*>([^<]+)<\/h3>/i);
  return titleMatch ? stripHtml(titleMatch[1]) : '';
}

function extractDescription(html: string): string {
  const descMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']+)["']/i) ||
                     html.match(/<meta[^>]*content=["']([^"']+)["'][^>]*name=["']description["']/i) ||
                     html.match(/<p[^>]*>([^<]{30,200})<\/p>/i);
  return descMatch ? stripHtml(descMatch[1]) : '';
}

/* ============================================================================
   DEEP ONION SCAN (TorCrawl features)
============================================================================ */

export async function deepScanOnion(onionUrl: string): Promise<OnionSite | null> {
  const cacheKey = `onion:deep:${onionUrl}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const host = onionUrl.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const proxy = TOR2WEB_PROXIES[0];
    const url = `https://${host}.${proxy}`;

    const res = await fetchWithTimeout(
      url,
      { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' } },
      TIMEOUTS.DEEP_SCAN
    );

    if (!res.ok) return null;

    const html = await res.text();
    const title = extractTitle(html) || 'Unknown Service';
    const description = extractDescription(html) || 'No description available';
    const fullText = stripHtml(html);

    // Extract all possible open ports (if mentioned)
    const portMatches = fullText.match(/port[:\s]+(\d{1,5})/gi) || [];
    const ports = unique(portMatches.map(p => parseInt(p.replace(/\D/g, '')))).filter(p => p > 0 && p < 65536);

    const site: OnionSite = {
      url:  onionUrl,
      title,
      description,
      category:  categorize(fullText),
      riskLevel: calculateRisk(fullText),
      lastSeen: nowISO(),
      status: 'online',
      tags: extractTags(fullText),
      discoveredFrom: 'deep_scan',
      emailAddresses: extractEmails(fullText),
      bitcoinAddresses: extractBitcoinAddresses(fullText),
      sshFingerprint:  extractSSHFingerprints(fullText)[0],
      ports:  ports. slice(0, 10),
      language: detectLanguage(fullText),
    };

    await cacheAPIResponse(cacheKey, site, 600);
    return site;
  } catch (err) {
    console.error('Deep scan error:', err);
    return null;
  }
}

/* ============================================================================
   ONION UPTIME CHECK (Onioff approach)
============================================================================ */

export async function checkOnionUptime(onion: string): Promise<{
  status: 'online' | 'offline';
  responseTime?:  number;
  checkedAt:  string;
  httpStatus?:  number;
  headers?: Record<string, string>;
}> {
  try {
    const host = onion.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const proxy = TOR2WEB_PROXIES[0];
    const url = `https://${host}.${proxy}`;

    const start = Date.now();
    const res = await fetchWithTimeout(
      url,
      { 
        method: 'HEAD', 
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' } 
      },
      TIMEOUTS.UPTIME_CHECK
    );

    const headers:  Record<string, string> = {};
    res.headers.forEach((value, key) => {
      headers[key] = value;
    });

    return {
      status: res.ok ? 'online' : 'offline',
      responseTime: Date.now() - start,
      httpStatus: res.status,
      checkedAt: nowISO(),
      headers,
    };
  } catch {
    return { 
      status: 'offline', 
      checkedAt: nowISO() 
    };
  }
}

/* ============================================================================
   TELEGRAM OSINT (h8mail + OSINT-SPY approach)
============================================================================ */

export async function searchTelegramChannels(query: string): Promise<TelegramChannel[]> {
  const cacheKey = `telegram:channels:${query}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const channels:  TelegramChannel[] = [];

  try {
    const url = `https://telemetr.io/en/channels/search?query=${encodeURIComponent(query)}`;
    const res = await fetchWithTimeout(
      url,
      { headers:  { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' } },
      TIMEOUTS.TELEGRAM_SCAN
    );

    if (!res.ok) return [];

    const html = await res. text();
    const matches = Array.from(
      html.matchAll(
        /<a href="\/en\/channels\/([^"]+)"[\s\S]*? <h3[^>]*>([^<]+)<\/h3>[\s\S]*?<div class="subscribers[^"]*">([^<]+)<\/div>[\s\S]*?<p[^>]*>([^<]+)<\/p>/g
      )
    );

    matches.slice(0, MAX_RESULTS.TELEGRAM_CHANNELS).forEach(match => {
      const username = match[1]. replace('@', '');
      const title = stripHtml(match[2]);
      const subs = parseInt(match[3]. replace(/\D/g, '')) || 0;
      const desc = stripHtml(match[4]);
      const ctx = `${title} ${desc}`;

      channels.push({
        id: `tg-${username}`,
        username,
        title,
        description: desc,
        subscribers: subs,
        category:  categorize(ctx),
        riskLevel: calculateRisk(ctx),
        verified: title.includes('✓') || title.includes('verified'),
        tags: extractTags(ctx),
      });
    });

    await cacheAPIResponse(cacheKey, channels, 180);
    return channels;
  } catch (err) {
    console.error('Telegram channel search error:', err);
    return [];
  }
}

export async function scrapeTelegramChannel(
  channelUsername: string,
  limit = 25
): Promise<TelegramMessage[]> {
  const cacheKey = `telegram:messages:${channelUsername}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const messages: TelegramMessage[] = [];

  try {
    const url = `https://t.me/s/${channelUsername. replace('@', '')}`;
    const res = await fetchWithTimeout(
      url,
      { headers: { 'User-Agent':  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' } },
      TIMEOUTS. TELEGRAM_SCAN
    );

    if (!res.ok) return [];

    const html = await res.text();
    const matches = Array.from(
      html.matchAll(
        /data-post="[^/]+\/(\d+)"[\s\S]*?<div class="tgme_widget_message_text[^"]*">([\s\S]*?)<\/div>[\s\S]*? <time datetime="([^"]+)"[\s\S]*?(? : <span class="tgme_widget_message_views">([^<]*)<\/span>)?/g
      )
    );

    matches.slice(0, limit).forEach(m => {
      const id = parseInt(m[1]);
      const text = stripHtml(m[2]);
      const date = m[3];
      const views = parseInt((m[4] || '').replace(/\D/g, '')) || 0;

      messages.push({
        id:  `tg-${channelUsername}-${id}`,
        channelUsername,
        messageId: id,
        text,
        date,
        views,
        forwards: 0,
        hasMedia: /tgme_widget_message_(photo|video|document|audio)/. test(m[0]),
        mediaType: m[0]. includes('photo') ? 'photo' : m[0].includes('video') ? 'video' : undefined,
        link: `https://t.me/${channelUsername}/${id}`,
      });
    });

    await cacheAPIResponse(cacheKey, messages, 60);
    return messages;
  } catch (err) {
    console.error('Telegram message scrape error:', err);
    return [];
  }
}

async function scanTelegramMessages(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `telegram:scan:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals: LeakSignal[] = [];
  
  try {
    const channels = await searchTelegramChannels(indicator);
    const top = channels.slice(0, 3);

    for (const ch of top) {
      try {
        const msgs = await scrapeTelegramChannel(ch.username, 10);

        msgs.forEach(msg => {
          if (msg.text. toLowerCase().includes(indicator.toLowerCase())) {
            const emails = extractEmails(msg.text);
            const bitcoins = extractBitcoinAddresses(msg.text);

            signals.push({
              id: msg.id,
              title: msg.text. slice(0, 120) + (msg.text.length > 120 ? '...' : ''),
              indicator,
              source: 'telegram',
              timestamp: msg.date,
              url: msg.link,
              context: `@${ch.username} (${ch.subscribers} subscribers)`,
              metadata: {
                channelName: ch.title,
                subscribers: ch.subscribers,
                views: msg.views,
                messageId: msg.messageId,
                emails,
                bitcoins,
              },
            });
          }
        });
      } catch (err) {
        console.error(`Error scraping channel ${ch.username}:`, err);
      }
    }

    await cacheAPIResponse(cacheKey, signals, 90);
    return signals;
  } catch (err) {
    console.error('Telegram scan error:', err);
    return [];
  }
}

/* ============================================================================
   INTEL TECHNIQUES APIs — Public Leak & Paste Search
============================================================================ */

/**
 * PSBDMP API — Search leaked credentials
 * Free public API:  https://psbdmp.ws/api/search/<query>
 */
async function scanPsbdmp(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `psbdmp:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals:  LeakSignal[] = [];

  try {
    const url = `${INTEL_APIS.psbdmp}${encodeURIComponent(indicator)}`;
    const res = await fetchWithTimeout(
      url,
      { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' } },
      TIMEOUTS.API_CALL
    );

    if (!res.ok) return [];

    const data = await res.json();

    if (data.data && Array.isArray(data.data)) {
      data.data.slice(0, 15).forEach((paste: any) => {
        signals.push({
          id: `psbdmp-${paste. id}`,
          title: paste.text || 'Pastebin dump',
          indicator,
          source: 'psbdmp',
          timestamp: paste.time || nowISO(),
          url: `https://pastebin.com/${paste.id}`,
          context: 'PSBDMP credential dump',
          metadata: {
            pasteId: paste.id,
            author: paste.author,
          },
        });
      });
    }

    await cacheAPIResponse(cacheKey, signals, 120);
    return signals;
  } catch (err) {
    console.error('PSBDMP scan error:', err);
    return [];
  }
}

/**
 * Rentry. co API — Search public Rentry notes
 * API: https://rentry.co/api/search? q=<query>
 */
async function scanRentry(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `rentry:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals:  LeakSignal[] = [];

  try {
    const url = `${INTEL_APIS.rentry}${encodeURIComponent(indicator)}`;
    const res = await fetchWithTimeout(
      url,
      { headers:  { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' } },
      TIMEOUTS.API_CALL
    );

    if (!res.ok) return [];

    const data = await res.json();

    if (data.results && Array.isArray(data. results)) {
      data.results.slice(0, 15).forEach((result: any) => {
        signals.push({
          id: `rentry-${result.id}`,
          title: result.title || 'Rentry note',
          indicator,
          source:  'rentry',
          timestamp: result.created_at || nowISO(),
          url: `https://rentry.co/${result.id}`,
          context: 'Public Rentry note',
          metadata: {
            pasteId: result.id,
            author: result.author,
          },
        });
      });
    }

    await cacheAPIResponse(cacheKey, signals, 120);
    return signals;
  } catch (err) {
    console.error('Rentry scan error:', err);
    return [];
  }
}

/**
 * GitHub Code Search API — Find accidental leaks
 * API: https://api.github.com/search/code?q=<query>+in:file
 */
async function scanGitHubGists(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `github:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals:  LeakSignal[] = [];

  try {
    const url = `${INTEL_APIS.github}${encodeURIComponent(indicator)}+in:file&per_page=${MAX_RESULTS. GITHUB}`;
    const res = await fetchWithTimeout(
      url,
      {
        headers: {
          'Accept': 'application/vnd. github.v3+json',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        },
      },
      TIMEOUTS.API_CALL
    );

    if (!res.ok) return [];

    const data = await res.json();

    if (data.items && Array.isArray(data.items)) {
      data.items.forEach((item: any) => {
        signals.push({
          id: `gh-${item.sha}`,
          title: item.name || 'GitHub code match',
          indicator,
          source: 'github_gist',
          timestamp: nowISO(),
          url: item.html_url,
          context: `Found in ${item.repository?. full_name || 'unknown repo'}`,
          metadata: {
            author: item.repository?.owner?.login,
          },
        });
      });
    }

    await cacheAPIResponse(cacheKey, signals, 180);
    return signals;
  } catch (err) {
    console.error('GitHub scan error:', err);
    return [];
  }
}

/* ============================================================================
   PASTE SITES — HTML Scraping
============================================================================ */

/**
 * Pastebin Archive — Scrape recent pastes
 * URL: https://pastebin.com/archive
 */
async function scanPastebin(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `pastebin:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals: LeakSignal[] = [];

  try {
    const res = await fetchWithTimeout(
      'https://pastebin.com/archive',
      { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' } },
      TIMEOUTS. PASTE_SCAN
    );

    if (!res.ok) return [];

    const html = await res.text();
    const matches = Array.from(html.matchAll(/href="\/([A-Za-z0-9]{8})">([^<]+)<\/a>/g));

    matches.slice(0, MAX_RESULTS. PASTES).forEach(m => {
      const title = stripHtml(m[2]);
      if (title.toLowerCase().includes(indicator.toLowerCase())) {
        signals.push({
          id: `pb-${m[1]}`,
          title,
          indicator,
          source: 'pastebin',
          timestamp: nowISO(),
          url: `https://pastebin.com/${m[1]}`,
          context: 'Pastebin archive match',
          metadata: {
            pasteId: m[1],
          },
        });
      }
    });

    await cacheAPIResponse(cacheKey, signals, 90);
    return signals;
  } catch (err) {
    console.error('Pastebin scan error:', err);
    return [];
  }
}

/**
 * Ghostbin — Scrape public pastes
 * URL: https://ghostbin.com/browse
 */
async function scanGhostbin(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `ghostbin:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals: LeakSignal[] = [];

  try {
    const res = await fetchWithTimeout(
      'https://ghostbin.com/browse',
      { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' } },
      TIMEOUTS.PASTE_SCAN
    );

    if (!res.ok) return [];

    const html = await res.text();
    const matches = Array.from(html. matchAll(/href="\/paste\/([A-Za-z0-9]+)">([^<]+)<\/a>/g));

    matches.forEach(m => {
      const title = stripHtml(m[2]);
      if (title.toLowerCase().includes(indicator.toLowerCase())) {
        signals.push({
          id: `gb-${m[1]}`,
          title,
          indicator,
          source:  'ghostbin',
          timestamp: nowISO(),
          url: `https://ghostbin.com/paste/${m[1]}`,
          context: 'Ghostbin browse match',
          metadata: {
            pasteId: m[1],
          },
        });
      }
    });

    await cacheAPIResponse(cacheKey, signals, 120);
    return signals;
  } catch (err) {
    console.error('Ghostbin scan error:', err);
    return [];
  }
}

/**
 * Paste.rs — Scrape pastes (if available)
 */
async function scanPasteRs(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `paste_rs:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals: LeakSignal[] = [];

  try {
    const res = await fetchWithTimeout(
      'https://paste.rs/',
      { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' } },
      TIMEOUTS.PASTE_SCAN
    );

    if (!res.ok) return [];

    const html = await res.text();
    const matches = Array.from(html.matchAll(/href="\/([A-Za-z0-9-_]+)">([^<]*)<\/a>/g));

    matches.forEach(m => {
      const title = stripHtml(m[2]) || 'Paste.rs entry';
      if (title.toLowerCase().includes(indicator.toLowerCase())) {
        signals.push({
          id: `paste_rs-${m[1]}`,
          title,
          indicator,
          source: 'paste_rs',
          timestamp: nowISO(),
          url: `https://paste.rs/${m[1]}`,
          context: 'Paste.rs match',
          metadata: {
            pasteId: m[1],
          },
        });
      }
    });

    await cacheAPIResponse(cacheKey, signals, 120);
    return signals;
  } catch (err) {
    console.error('Paste.rs scan error:', err);
    return [];
  }
}

/**
 * DPaste — Scrape recent pastes
 */
async function scanDPaste(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `dpaste:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals: LeakSignal[] = [];

  try {
    const res = await fetchWithTimeout(
      'https://dpaste.org/recent',
      { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' } },
      TIMEOUTS.PASTE_SCAN
    );

    if (!res.ok) return [];

    const html = await res.text();
    const matches = Array.from(html.matchAll(/href="\/([A-Za-z0-9]+)">([^<]*)<\/a>/g));

    matches.forEach(m => {
      const title = stripHtml(m[2]) || 'DPaste entry';
      if (title.toLowerCase().includes(indicator. toLowerCase())) {
        signals.push({
          id: `dpaste-${m[1]}`,
          title,
          indicator,
          source: 'dpaste',
          timestamp: nowISO(),
          url: `https://dpaste.org/${m[1]}`,
          context: 'DPaste match',
          metadata: {
            pasteId:  m[1],
          },
        });
      }
    });

    await cacheAPIResponse(cacheKey, signals, 120);
    return signals;
  } catch (err) {
    console.error('DPaste scan error:', err);
    return [];
  }
}

/* ============================================================================
   AGGREGATOR — Combine All Sources
============================================================================ */

export async function searchDarkWebSignals(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `signals:all:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const results = (
    await Promise.allSettled([
      // Intel Techniques APIs
      scanPsbdmp(indicator),
      scanRentry(indicator),
      scanGitHubGists(indicator),
      // Paste Sites
      scanPastebin(indicator),
      scanGhostbin(indicator),
      scanPasteRs(indicator),
      scanDPaste(indicator),
      // Telegram
      scanTelegramMessages(indicator),
    ])
  )
    .filter((r): r is PromiseFulfilledResult<LeakSignal[]> => r.status === 'fulfilled')
    .flatMap(r => r.value);

  // Deduplicate by ID
  const uniqueResults = Array.from(
    new Map(results.map(s => [s.id, s])).values()
  );

  await cacheAPIResponse(cacheKey, uniqueResults, 90);
  return uniqueResults;
}

/* ============================================================================
   DARKNET MARKET STATUS (dark.fail)
============================================================================ */

export async function checkDarknetMarketStatus(): Promise<DarkWebMarket[]> {
  const cacheKey = 'darknet: markets';
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const markets:  DarkWebMarket[] = [];

  try {
    const res = await fetchWithTimeout(
      'https://dark.fail/',
      { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' } },
      TIMEOUTS. ONION_DISCOVERY
    );

    if (!res.ok) return [];

    const html = await res.text();

    // Extract market information
    const matches = Array.from(
      html.matchAll(
        /<div[^>]*class="[^"]*market[^"]*"[^>]*>[\s\S]*?<h3[^>]*>([^<]+)<\/h3>[\s\S]*?<code[^>]*>([^<]+)<\/code>[\s\S]*?<span[^>]*class="[^"]*status[^"]*([^"]*)"[^>]*>/g
      )
    );

    matches.forEach(m => {
      const name = stripHtml(m[1]);
      const url = stripHtml(m[2]);
      const statusClass = m[3];
      const status = statusClass.includes('online') ? 'online' : 
                     statusClass.includes('offline') ? 'offline' : 'unknown';

      // Extract mirrors (v3 onions)
      const mirrorMatches = Array.from(
        html.matchAll(new RegExp(`${name}[\\s\\S]{0,500}<code[^>]*>([a-z2-7]{56}\\. onion)<\\/code>`, 'gi'))
      );
      const mirrors = unique(mirrorMatches.map(mm => mm[1]));

      markets.push({
        name,
        url,
        status:  status as 'online' | 'offline' | 'unknown',
        lastChecked: nowISO(),
        mirrors:  mirrors.length > 0 ?  mirrors : undefined,
        v3Onion: mirrors.find(m => m. length === 62), // v3 onions are 56 chars + . onion
      });
    });

    await cacheAPIResponse(cacheKey, markets, 300);
    return markets;
  } catch (err) {
    console.error('Dark.fail scan error:', err);
    return [];
  }
}

/* ============================================================================
   EXPORT ALL FUNCTIONS
============================================================================ */

export {
  // Main discovery
  discoverOnionSites,
  deepScanOnion,
  checkOnionUptime,
  
  // Telegram
  searchTelegramChannels,
  scrapeTelegramChannel,
  
  // Aggregator
  searchDarkWebSignals,
  
  // Markets
  checkDarknetMarketStatus,
  
  // Individual scanners (if needed)
  scanPsbdmp,
  scanRentry,
  scanGitHubGists,
  scanPastebin,
  scanGhostbin,
};
