// ============================================================================
// torService.ts
// REAL Dark Web Intelligence — Optimized for Speed + Telegram Integration
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
}

export interface LeakSignal {
  id: string;
  title: string;
  indicator: string;
  source: 
    | 'pastebin'
    | 'ghostbin'
    | 'rentry'
    | 'github_gist'
    | 'psbdmp'
    | 'telegram'
    | 'intelx';
  timestamp: string;
  url: string;
  context:  string;
  metadata?: {
    channelName?: string;
    subscribers?: number;
    views?: number;
    messageId?: number;
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
  link:  string;
}

/* ============================================================================
   CONSTANTS
============================================================================ */

const TOR2WEB_PROXIES = [
  'onion. ws',
  'onion.pet',
  'onion.ly',
];

const ONION_REGEX = /([a-z2-7]{16,56}\.onion)/gi;

// Timeout configurations (in milliseconds)
const TIMEOUTS = {
  ONION_DISCOVERY: 8000,
  PASTE_SCAN: 5000,
  UPTIME_CHECK: 10000,
  TELEGRAM_SCAN: 7000,
};

// Telegram API Configuration
const TELEGRAM_BOT_TOKEN = '';
const TELEGRAM_API_BASE = 'https://api.telegram.org/bot';

// Public Telegram scraping endpoints
const TELEGRAM_SCRAPER_ENDPOINTS = [
  'https://t.me/s/',
  'https://telemetr.io/en/channels/',
];

/* ============================================================================
   UTILITIES
============================================================================ */

function stripHtml(input: string): string {
  const div = document.createElement('div');
  div.innerHTML = input;
  return div.textContent || div.innerText || '';
}

function nowISO(): string {
  return new Date().toISOString();
}

function unique<T>(arr: T[]): T[] {
  return Array.from(new Set(arr));
}

// Fetch with timeout utility
async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs: number = 5000
): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    clearTimeout(timeout);
    return response;
  } catch (error) {
    clearTimeout(timeout);
    throw error;
  }
}

/* ============================================================================
   RISK & TAGGING
============================================================================ */

function calculateRisk(text: string): RiskLevel {
  const t = text.toLowerCase();

  if (
    t.includes('malware') ||
    t.includes('exploit') ||
    t.includes('ransom') ||
    t.includes('weapon') ||
    t.includes('drug') ||
    t.includes('child')
  ) {
    return 'critical';
  }

  if (
    t.includes('leak') ||
    t.includes('dump') ||
    t.includes('database') ||
    t.includes('hack') ||
    t.includes('breach')
  ) {
    return 'high';
  }

  if (
    t.includes('market') ||
    t.includes('forum') ||
    t.includes('selling')
  ) {
    return 'medium';
  }

  return 'low';
}

function extractTags(text: string): string[] {
  const keywords = [
    'market',
    'forum',
    'leak',
    'dump',
    'database',
    'malware',
    'exploit',
    'credentials',
    'phishing',
    'carding',
    'fraud',
    'drugs',
    'weapons',
    'breach',
    'ransomware',
    'combolist',
    'cvv',
    'fullz',
  ];

  const lower = text.toLowerCase();
  return keywords.filter(k => lower.includes(k)).slice(0, 6);
}

function categorize(text: string): string {
  const t = text.toLowerCase();

  if (t.includes('market')) return 'Marketplace';
  if (t.includes('forum')) return 'Forum';
  if (t.includes('leak') || t.includes('dump') || t.includes('breach')) return 'Data Leak';
  if (t.includes('mail')) return 'Email Service';
  if (t.includes('hosting')) return 'Hosting';
  if (t.includes('directory')) return 'Directory';
  if (t.includes('wiki')) return 'Wiki/Info';
  if (t.includes('channel') || t.includes('group')) return 'Communication';

  return 'Unknown';
}

/* ============================================================================
   TELEGRAM SCRAPER - PUBLIC CHANNELS
============================================================================ */

// Search Telegram channels by keyword
export async function searchTelegramChannels(query: string): Promise<TelegramChannel[]> {
  const cacheKey = `telegram:channels:${query}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const channels: TelegramChannel[] = [];

  try {
    const telemetrUrl = `https://telemetr.io/en/channels/search?query=${encodeURIComponent(query)}`;
    
    const response = await fetchWithTimeout(
      telemetrUrl,
      {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        },
      },
      TIMEOUTS.TELEGRAM_SCAN
    );

    if (!response.ok) {
      console.error('Telemetr fetch failed:', response.statusText);
      return [];
    }

    const html = await response.text();

    // Extract channel data from HTML
    const channelMatches = Array.from(
      html.matchAll(/<div class="channel-card"[^>]*>.*? <a href="\/en\/channels\/([^"]+)"[^>]*>.*?<h3[^>]*>([^<]+)<\/h3>.*?<div class="subscribers"[^>]*>([^<]+)<\/div>.*?<p[^>]*>([^<]+)<\/p>/gs)
    );

    channelMatches.slice(0, 20).forEach(([_, username, title, subscribers, description]) => {
      const cleanTitle = stripHtml(title);
      const cleanDesc = stripHtml(description);
      const context = `${cleanTitle} ${cleanDesc}`.trim();

      channels.push({
        id: `tg-${username}`,
        username:  username.replace('@', ''),
        title: cleanTitle,
        description: cleanDesc,
        subscribers:  parseInt(subscribers. replace(/[^0-9]/g, '')) || 0,
        category:  categorize(context),
        riskLevel: calculateRisk(context),
        verified: false,
        tags: extractTags(context),
      });
    });

    await cacheAPIResponse(cacheKey, channels, 120);
    return channels;
  } catch (error) {
    console.error('Telegram channel search error:', error);
    return [];
  }
}

// Scrape messages from a public Telegram channel
export async function scrapeTelegramChannel(
  channelUsername: string,
  limit: number = 20
): Promise<TelegramMessage[]> {
  const cacheKey = `telegram:messages:${channelUsername}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const messages: TelegramMessage[] = [];

  try {
    const channelUrl = `https://t.me/s/${channelUsername. replace('@', '')}`;
    
    const response = await fetchWithTimeout(
      channelUrl,
      {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        },
      },
      TIMEOUTS.TELEGRAM_SCAN
    );

    if (!response. ok) {
      console.error('Telegram channel fetch failed:', response.statusText);
      return [];
    }

    const html = await response.text();

    // Extract message data from public web view
    const messageMatches = Array.from(
      html.matchAll(/<div class="tgme_widget_message[^"]*"[^>]*data-post="[^\/]+\/(\d+)"[^>]*>.*? <div class="tgme_widget_message_text[^"]*"[^>]*>([^<]*(? :<[^>]+>[^<]*)*)<\/div>.*?<time[^>]*datetime="([^"]+)"[^>]*>.*?<span class="tgme_widget_message_views">([^<]+)<\/span>/gs)
    );

    messageMatches.slice(0, limit).forEach(([_, messageId, text, datetime, views]) => {
      const cleanText = stripHtml(text);
      
      messages.push({
        id: `tg-msg-${channelUsername}-${messageId}`,
        channelUsername:  channelUsername.replace('@', ''),
        messageId: parseInt(messageId),
        text: cleanText,
        date: datetime,
        views: parseInt(views. replace(/[^0-9]/g, '')) || 0,
        forwards: 0,
        hasMedia: html.includes(`data-post="${channelUsername}/${messageId}"`) && html.includes('tgme_widget_message_photo'),
        link: `https://t.me/${channelUsername. replace('@', '')}/${messageId}`,
      });
    });

    await cacheAPIResponse(cacheKey, messages, 30);
    return messages;
  } catch (error) {
    console.error('Telegram message scrape error:', error);
    return [];
  }
}

// Search for specific keyword in Telegram messages across channels
async function scanTelegramMessages(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `telegram:scan:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals: LeakSignal[] = [];

  try {
    // First, find relevant channels
    const channels = await searchTelegramChannels(indicator);

    // Scrape messages from top 5 relevant channels
    const topChannels = channels.slice(0, 5);

    for (const channel of topChannels) {
      try {
        const messages = await scrapeTelegramChannel(channel. username, 10);
        
        messages.forEach(msg => {
          if (msg. text.toLowerCase().includes(indicator.toLowerCase())) {
            signals.push({
              id: msg.id,
              title: msg.text. substring(0, 100) + (msg.text.length > 100 ? '...' : ''),
              indicator,
              source:  'telegram',
              timestamp:  msg.date,
              url: msg.link,
              context: `Found in @${channel.username} (${channel.subscribers} subscribers)`,
              metadata: {
                channelName: channel.title,
                subscribers: channel.subscribers,
                views: msg.views,
                messageId: msg. messageId,
              },
            });
          }
        });
      } catch (err) {
        console.error(`Error scraping channel ${channel.username}:`, err);
      }
    }

    await cacheAPIResponse(cacheKey, signals, 60);
    return signals;
  } catch (error) {
    console.error('Telegram message scan error:', error);
    return [];
  }
}

// Telegram Bot API integration (if bot token is provided)
export async function searchTelegramWithBot(
  query: string
): Promise<LeakSignal[]> {
  if (!TELEGRAM_BOT_TOKEN) {
    console.warn('Telegram Bot Token not configured');
    return [];
  }

  const cacheKey = `telegram:bot:${query}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals: LeakSignal[] = [];

  try {
    // Search in indexed public messages
    const searchUrl = `${TELEGRAM_API_BASE}${TELEGRAM_BOT_TOKEN}/searchMessages`;
    
    const response = await fetchWithTimeout(
      searchUrl,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON. stringify({
          query,
          limit: 20,
        }),
      },
      TIMEOUTS.TELEGRAM_SCAN
    );

    if (!response. ok) return [];

    const data = await response.json();

    if (data.result && Array.isArray(data.result. messages)) {
      data.result.messages.forEach((msg: any) => {
        signals.push({
          id: `tg-bot-${msg.message_id}`,
          title: msg.text || 'Telegram message',
          indicator: query,
          source: 'telegram',
          timestamp: new Date(msg.date * 1000).toISOString(),
          url: `https://t.me/${msg.chat.username}/${msg.message_id}`,
          context: `Found in ${msg.chat.title || msg.chat.username}`,
          metadata: {
            channelName: msg.chat. title,
            messageId: msg.message_id,
          },
        });
      });
    }

    await cacheAPIResponse(cacheKey, signals, 60);
    return signals;
  } catch (error) {
    console.error('Telegram bot search error:', error);
    return [];
  }
}

/* ============================================================================
   ONION DISCOVERY - AHMIA. FI (Real Tor Search Engine) - OPTIMIZED
============================================================================ */

export async function discoverOnionSites(query: string): Promise<OnionSite[]> {
  const cacheKey = `onion:discover:${query}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const results: OnionSite[] = [];

  try {
    const ahmiaUrl = `https://ahmia.fi/search/? q=${encodeURIComponent(query)}`;
    
    const response = await fetchWithTimeout(
      ahmiaUrl,
      {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        },
      },
      TIMEOUTS. ONION_DISCOVERY
    );

    if (!response.ok) {
      console.error('Ahmia fetch failed:', response.statusText);
      return [];
    }

    const html = await response. text();

    const onions = unique((html.match(ONION_REGEX) || [])).slice(0, 25);
    const titleMatches = Array.from(html.matchAll(/<h4[^>]*><a[^>]*>([^<]+)<\/a><\/h4>/gi));
    const titles = titleMatches.map(m => stripHtml(m[1]));
    const descMatches = Array.from(html. matchAll(/<p class="result-[^"]*">([^<]+)<\/p>/gi));
    const descriptions = descMatches.map(m => stripHtml(m[1]));

    onions.forEach((onion, idx) => {
      const title = titles[idx] || 'Unknown Onion Service';
      const description = descriptions[idx] || 'No description available';
      const context = `${title} ${description}`.trim();

      results.push({
        url: onion,
        title,
        description,
        category: categorize(context),
        riskLevel: calculateRisk(context),
        lastSeen: nowISO(),
        status: 'unknown',
        tags: extractTags(context),
        discoveredFrom: 'ahmia',
      });
    });

    await cacheAPIResponse(cacheKey, results, 120);
    return results;
  } catch (error) {
    console.error('Onion discovery error:', error);
    return [];
  }
}

/* ============================================================================
   ONION UPTIME CHECK (Tor2Web Gateway) - OPTIMIZED
============================================================================ */

export async function checkOnionUptime(
  onion: string
): Promise<{
  status: 'online' | 'offline';
  responseTime?:  number;
  checkedAt:  string;
}> {
  try {
    const host = onion.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const proxy = TOR2WEB_PROXIES[0];
    const url = `https://${host}.${proxy}`;

    const start = Date.now();

    const response = await fetchWithTimeout(
      url,
      {
        method: 'HEAD',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        },
      },
      TIMEOUTS.UPTIME_CHECK
    );

    return {
      status: response.ok ? 'online' : 'offline',
      responseTime: Date.now() - start,
      checkedAt: nowISO(),
    };
  } catch (error) {
    return {
      status: 'offline',
      checkedAt: nowISO(),
    };
  }
}

/* ============================================================================
   PASTE & LEAK SIGNAL MONITORING - OPTIMIZED
============================================================================ */

async function scanPastebin(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `pastebin:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals:  LeakSignal[] = [];

  try {
    const response = await fetchWithTimeout(
      'https://pastebin.com/archive',
      {
        headers:  {
          'User-Agent':  'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        },
      },
      TIMEOUTS.PASTE_SCAN
    );

    if (!response.ok) return [];

    const html = await response. text();

    const pasteMatches = Array.from(
      html.matchAll(/<a href="\/([A-Za-z0-9]{8})"[^>]*>([^<]+)<\/a>/g)
    ).slice(0, 15);

    pasteMatches. forEach(([_, pasteId, title]) => {
      const cleanTitle = stripHtml(title);
      if (cleanTitle.toLowerCase().includes(indicator.toLowerCase())) {
        signals.push({
          id: `pb-${pasteId}`,
          title: cleanTitle,
          indicator,
          source: 'pastebin',
          timestamp:  nowISO(),
          url: `https://pastebin.com/${pasteId}`,
          context: 'Paste title match',
        });
      }
    });

    await cacheAPIResponse(cacheKey, signals, 60);
    return signals;
  } catch (error) {
    console.error('Pastebin scan error:', error);
    return [];
  }
}

async function scanPsbdmp(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `psbdmp:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals: LeakSignal[] = [];

  try {
    const response = await fetchWithTimeout(
      `https://psbdmp.ws/api/search/${encodeURIComponent(indicator)}`,
      {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        },
      },
      TIMEOUTS.PASTE_SCAN
    );

    if (!response.ok) return [];

    const data = await response.json();

    if (data.data && Array.isArray(data. data)) {
      data.data.slice(0, 10).forEach((paste: any) => {
        signals.push({
          id: `psbdmp-${paste.id}`,
          title: paste.text || 'Pastebin dump',
          indicator,
          source: 'psbdmp',
          timestamp: paste.time || nowISO(),
          url: `https://pastebin.com/${paste.id}`,
          context: 'Dump search match',
        });
      });
    }

    await cacheAPIResponse(cacheKey, signals, 60);
    return signals;
  } catch (error) {
    console.error('Psbdmp scan error:', error);
    return [];
  }
}

async function scanGitHubGists(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `gists:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals: LeakSignal[] = [];

  try {
    const response = await fetchWithTimeout(
      `https://api.github.com/search/code?q=${encodeURIComponent(indicator)}+in:file+language:text&per_page=10`,
      {
        headers: {
          'Accept': 'application/vnd. github.v3+json',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        },
      },
      TIMEOUTS.PASTE_SCAN
    );

    if (!response.ok) return [];

    const data = await response. json();

    if (data.items) {
      data.items.slice(0, 10).forEach((item: any) => {
        signals.push({
          id: `gist-${item.sha}`,
          title: item.name || 'GitHub code match',
          indicator,
          source: 'github_gist',
          timestamp: nowISO(),
          url: item.html_url,
          context: `Found in ${item.repository.full_name}`,
        });
      });
    }

    await cacheAPIResponse(cacheKey, signals, 60);
    return signals;
  } catch (error) {
    console.error('GitHub Gist scan error:', error);
    return [];
  }
}

async function scanRentry(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `rentry:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals: LeakSignal[] = [];

  try {
    const response = await fetchWithTimeout(
      `https://rentry.co/api/search? q=${encodeURIComponent(indicator)}`,
      {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        },
      },
      TIMEOUTS.PASTE_SCAN
    );

    if (!response.ok) return [];

    const data = await response.json();

    if (data.results && Array.isArray(data.results)) {
      data.results. slice(0, 10).forEach((result: any) => {
        signals.push({
          id: `rentry-${result.id}`,
          title: result.title || 'Rentry note',
          indicator,
          source:  'rentry',
          timestamp: result.created_at || nowISO(),
          url: `https://rentry.co/${result.id}`,
          context: 'Public note match',
        });
      });
    }

    await cacheAPIResponse(cacheKey, signals, 60);
    return signals;
  } catch (error) {
    console.error('Rentry scan error:', error);
    return [];
  }
}

async function scanGhostbin(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `ghostbin:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals: LeakSignal[] = [];

  try {
    const response = await fetchWithTimeout(
      'https://ghostbin.com/browse',
      {
        headers:  {
          'User-Agent':  'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        },
      },
      TIMEOUTS.PASTE_SCAN
    );

    if (!response. ok) return [];

    const html = await response.text();

    const pasteMatches = Array.from(
      html.matchAll(/<a href="\/paste\/([A-Za-z0-9]+)"[^>]*>([^<]+)<\/a>/g)
    ).slice(0, 10);

    pasteMatches. forEach(([_, pasteId, title]) => {
      const cleanTitle = stripHtml(title);
      if (cleanTitle.toLowerCase().includes(indicator.toLowerCase())) {
        signals.push({
          id: `gb-${pasteId}`,
          title: cleanTitle,
          indicator,
          source: 'ghostbin',
          timestamp: nowISO(),
          url: `https://ghostbin.com/paste/${pasteId}`,
          context: 'Ghostbin title match',
        });
      }
    });

    await cacheAPIResponse(cacheKey, signals, 60);
    return signals;
  } catch (error) {
    console.error('Ghostbin scan error:', error);
    return [];
  }
}

/* ============================================================================
   AGGREGATOR - COMBINE ALL SOURCES INCLUDING TELEGRAM
============================================================================ */

export async function searchDarkWebSignals(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `signals:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  // Use Promise.allSettled for parallel execution with Telegram included
  const results = (
    await Promise.allSettled([
      scanPastebin(indicator),
      scanPsbdmp(indicator),
      scanGitHubGists(indicator),
      scanRentry(indicator),
      scanGhostbin(indicator),
      scanTelegramMessages(indicator),
    ])
  )
    .filter((result): result is PromiseFulfilledResult<LeakSignal[]> => result.status === 'fulfilled')
    .flatMap(result => result.value);

  await cacheAPIResponse(cacheKey, results, 60);
  return results;
}

/* ============================================================================
   DARKNET MARKET STATUS CHECKER - OPTIMIZED
============================================================================ */

export async function checkDarknetMarketStatus(): Promise<Array<{
  name: string;
  url: string;
  status: 'online' | 'offline' | 'unknown';
  lastChecked: string;
}>> {
  try {
    const response = await fetchWithTimeout(
      'https://dark.fail/',
      {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        },
      },
      TIMEOUTS.ONION_DISCOVERY
    );

    if (!response.ok) return [];

    const html = await response.text();
    const markets:  Array<{ name: string; url: string; status: 'online' | 'offline' | 'unknown'; lastChecked: string }> = [];

    const marketMatches = Array.from(
      html.matchAll(/<div class="market"[^>]*>.*?<h3>([^<]+)<\/h3>.*?<code>([^<]+)<\/code>.*?<span class="status ([^"]+)">/gs)
    );

    marketMatches.forEach(([_, name, url, status]) => {
      markets.push({
        name: stripHtml(name),
        url: stripHtml(url),
        status:  status. includes('online') ? 'online' : 'offline',
        lastChecked: nowISO(),
      });
    });

    return markets;
  } catch (error) {
    console.error('Market status check error:', error);
    return [];
  }
}
