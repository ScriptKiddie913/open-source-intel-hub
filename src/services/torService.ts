// ============================================================================
// torService.ts
// REAL Dark Web Intelligence — Server-Safe, Vercel-Ready, Telegram-Integrated
// ============================================================================

import { cacheAPIResponse, getCachedData } from '@/lib/database';

/* ============================================================================
   TYPES
============================================================================ */

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low';

export interface OnionSite {
  url: string;
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
  context: string;
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
  mediaType?: string;
  link: string;
}

/* ============================================================================
   CONSTANTS
============================================================================ */

const TOR2WEB_PROXIES = [
  'onion.ws',
  'onion.pet',
  'onion.ly',
];

const ONION_REGEX = /([a-z2-7]{16,56}\.onion)/gi;

const TIMEOUTS = {
  ONION_DISCOVERY: 8000,
  PASTE_SCAN: 5000,
  UPTIME_CHECK: 10000,
  TELEGRAM_SCAN: 7000,
};

const MAX_RESULTS = {
  ONIONS: 25,
  TELEGRAM_CHANNELS: 15,
  TELEGRAM_MESSAGES: 20,
  PASTES: 15,
};

/* ============================================================================
   UTILITIES (SERVER SAFE)
============================================================================ */

/**
 * Strip HTML tags safely in Node.js
 */
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
    const res = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    return res;
  } finally {
    clearTimeout(id);
  }
}

/* ============================================================================
   RISK SCORING & TAGGING
============================================================================ */

function calculateRisk(text: string): RiskLevel {
  const t = text.toLowerCase();

  if (
    t.includes('malware') ||
    t.includes('exploit') ||
    t.includes('ransomware') ||
    t.includes('weapon') ||
    t.includes('drugs') ||
    t.includes('csam') ||
    t.includes('cp')
  ) {
    return 'critical';
  }

  if (
    t.includes('leak') ||
    t.includes('dump') ||
    t.includes('database') ||
    t.includes('breach') ||
    t.includes('credentials')
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
  if (t.includes('wiki')) return 'Wiki / Info';
  if (t.includes('channel') || t.includes('group')) return 'Communication';

  return 'Unknown';
}

/* ============================================================================
   TELEGRAM — PUBLIC SCRAPING ONLY (NO BOT API)
============================================================================ */

/**
 * Search public Telegram channels via Telemetr.io
 */
export async function searchTelegramChannels(
  query: string
): Promise<TelegramChannel[]> {
  const cacheKey = `telegram:channels:${query}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const channels: TelegramChannel[] = [];

  try {
    const url = `https://telemetr.io/en/channels/search?query=${encodeURIComponent(query)}`;

    const res = await fetchWithTimeout(
      url,
      { headers: { 'User-Agent': 'Mozilla/5.0' } },
      TIMEOUTS.TELEGRAM_SCAN
    );

    if (!res.ok) return [];

    const html = await res.text();

    const matches = Array.from(
      html.matchAll(
        /<a href="\/en\/channels\/([^"]+)"[\s\S]*?<h3[^>]*>([^<]+)<\/h3>[\s\S]*?<div class="subscribers">([^<]+)<\/div>[\s\S]*?<p[^>]*>([^<]+)<\/p>/g
      )
    );

    matches.slice(0, MAX_RESULTS.TELEGRAM_CHANNELS).forEach(match => {
      const username = match[1].replace('@', '');
      const title = stripHtml(match[2]);
      const subs = parseInt(match[3].replace(/[^0-9]/g, '')) || 0;
      const desc = stripHtml(match[4]);
      const ctx = `${title} ${desc}`;

      channels.push({
        id: `tg-${username}`,
        username,
        title,
        description: desc,
        subscribers: subs,
        category: categorize(ctx),
        riskLevel: calculateRisk(ctx),
        verified: false,
        tags: extractTags(ctx),
      });
    });

    await cacheAPIResponse(cacheKey, channels, 180);
    return channels;
  } catch {
    return [];
  }
}

/**
 * Scrape messages from public Telegram channel (web view)
 */
export async function scrapeTelegramChannel(
  channelUsername: string,
  limit = 20
): Promise<TelegramMessage[]> {
  const cacheKey = `telegram:messages:${channelUsername}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const messages: TelegramMessage[] = [];

  try {
    const url = `https://t.me/s/${channelUsername.replace('@', '')}`;

    const res = await fetchWithTimeout(
      url,
      { headers: { 'User-Agent': 'Mozilla/5.0' } },
      TIMEOUTS.TELEGRAM_SCAN
    );

    if (!res.ok) return [];

    const html = await res.text();

    const matches = Array.from(
      html.matchAll(
        /data-post="[^\/]+\/(\d+)"[\s\S]*?<div class="tgme_widget_message_text[^"]*">([\s\S]*?)<\/div>[\s\S]*?<time datetime="([^"]+)"[\s\S]*?(?:<span class="tgme_widget_message_views">([^<]*)<\/span>)?/g
      )
    );

    matches.slice(0, limit).forEach(m => {
      const id = parseInt(m[1]);
      const text = stripHtml(m[2]);
      const date = m[3];
      const views = parseInt((m[4] || '').replace(/[^0-9]/g, '')) || 0;

      messages.push({
        id: `tg-${channelUsername}-${id}`,
        channelUsername,
        messageId: id,
        text,
        date,
        views,
        forwards: 0,
        hasMedia: /tgme_widget_message_(photo|video)/.test(m[0]),
        link: `https://t.me/${channelUsername}/${id}`,
      });
    });

    await cacheAPIResponse(cacheKey, messages, 60);
    return messages;
  } catch {
    return [];
  }
}

/**
 * Scan Telegram messages for indicator
 */
async function scanTelegramMessages(
  indicator: string
): Promise<LeakSignal[]> {
  const cacheKey = `telegram:scan:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals: LeakSignal[] = [];

  const channels = await searchTelegramChannels(indicator);
  const top = channels.slice(0, 3);

  for (const ch of top) {
    const msgs = await scrapeTelegramChannel(ch.username, 10);

    msgs.forEach(msg => {
      if (msg.text.toLowerCase().includes(indicator.toLowerCase())) {
        signals.push({
          id: msg.id,
          title: msg.text.slice(0, 120),
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
          },
        });
      }
    });
  }

  await cacheAPIResponse(cacheKey, signals, 90);
  return signals;
}

/* ============================================================================
   ONION DISCOVERY — AHMIA
============================================================================ */

export async function discoverOnionSites(
  query: string
): Promise<OnionSite[]> {
  const cacheKey = `onion:discover:${query}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const sites: OnionSite[] = [];

  try {
    const url = `https://ahmia.fi/search/?q=${encodeURIComponent(query)}`;

    const res = await fetchWithTimeout(
      url,
      { headers: { 'User-Agent': 'Mozilla/5.0' } },
      TIMEOUTS.ONION_DISCOVERY
    );

    if (!res.ok) return [];

    const html = await res.text();

    const onions = unique(html.match(ONION_REGEX) || []).slice(0, MAX_RESULTS.ONIONS);

    onions.forEach(onion => {
      const ctx = onion;

      sites.push({
        url: onion,
        title: 'Unknown Onion Service',
        description: 'Discovered via Ahmia',
        category: categorize(ctx),
        riskLevel: calculateRisk(ctx),
        lastSeen: nowISO(),
        status: 'unknown',
        tags: extractTags(ctx),
        discoveredFrom: 'ahmia',
      });
    });

    await cacheAPIResponse(cacheKey, sites, 300);
    return sites;
  } catch {
    return [];
  }
}

/* ============================================================================
   ONION UPTIME CHECK
============================================================================ */

export async function checkOnionUptime(
  onion: string
): Promise<{
  status: 'online' | 'offline';
  responseTime?: number;
  checkedAt: string;
}> {
  try {
    const host = onion.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const proxy = TOR2WEB_PROXIES[0];
    const url = `https://${host}.${proxy}`;

    const start = Date.now();
    const res = await fetchWithTimeout(
      url,
      { method: 'HEAD', headers: { 'User-Agent': 'Mozilla/5.0' } },
      TIMEOUTS.UPTIME_CHECK
    );

    return {
      status: res.ok ? 'online' : 'offline',
      responseTime: Date.now() - start,
      checkedAt: nowISO(),
    };
  } catch {
    return { status: 'offline', checkedAt: nowISO() };
  }
}

/* ============================================================================
   PASTE & LEAK SOURCES
============================================================================ */

async function scanPastebin(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `pastebin:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals: LeakSignal[] = [];

  try {
    const res = await fetchWithTimeout(
      'https://pastebin.com/archive',
      { headers: { 'User-Agent': 'Mozilla/5.0' } },
      TIMEOUTS.PASTE_SCAN
    );

    if (!res.ok) return [];

    const html = await res.text();

    const matches = Array.from(
      html.matchAll(/href="\/([A-Za-z0-9]{8})">([^<]+)<\/a>/g)
    );

    matches.slice(0, MAX_RESULTS.PASTES).forEach(m => {
      if (m[2].toLowerCase().includes(indicator.toLowerCase())) {
        signals.push({
          id: `pb-${m[1]}`,
          title: stripHtml(m[2]),
          indicator,
          source: 'pastebin',
          timestamp: nowISO(),
          url: `https://pastebin.com/${m[1]}`,
          context: 'Pastebin archive match',
        });
      }
    });

    await cacheAPIResponse(cacheKey, signals, 90);
    return signals;
  } catch {
    return [];
  }
}

async function scanPsbdmp(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `psbdmp:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const res = await fetchWithTimeout(
      `https://psbdmp.ws/api/search/${encodeURIComponent(indicator)}`,
      { headers: { 'User-Agent': 'Mozilla/5.0' } },
      TIMEOUTS.PASTE_SCAN
    );

    if (!res.ok) return [];

    const data = await res.json();
    const signals: LeakSignal[] = [];

    (data?.data || []).slice(0, 10).forEach((p: any) => {
      signals.push({
        id: `psbdmp-${p.id}`,
        title: 'Paste dump',
        indicator,
        source: 'psbdmp',
        timestamp: p.time || nowISO(),
        url: `https://pastebin.com/${p.id}`,
        context: 'psbdmp search result',
      });
    });

    await cacheAPIResponse(cacheKey, signals, 90);
    return signals;
  } catch {
    return [];
  }
}

async function scanGitHubGists(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `gists:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const res = await fetchWithTimeout(
      `https://api.github.com/search/code?q=${encodeURIComponent(indicator)}+in:file&per_page=10`,
      {
        headers: {
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'Mozilla/5.0',
        },
      },
      TIMEOUTS.PASTE_SCAN
    );

    if (!res.ok) return [];

    const data = await res.json();
    const signals: LeakSignal[] = [];

    (data.items || []).forEach((i: any) => {
      signals.push({
        id: `gh-${i.sha}`,
        title: i.name,
        indicator,
        source: 'github_gist',
        timestamp: nowISO(),
        url: i.html_url,
        context: i.repository?.full_name,
      });
    });

    await cacheAPIResponse(cacheKey, signals, 120);
    return signals;
  } catch {
    return [];
  }
}

async function scanRentry(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `rentry:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const res = await fetchWithTimeout(
      `https://rentry.co/api/search?q=${encodeURIComponent(indicator)}`,
      { headers: { 'User-Agent': 'Mozilla/5.0' } },
      TIMEOUTS.PASTE_SCAN
    );

    if (!res.ok) return [];

    const data = await res.json();
    const signals: LeakSignal[] = [];

    (data.results || []).slice(0, 10).forEach((r: any) => {
      signals.push({
        id: `rentry-${r.id}`,
        title: r.title,
        indicator,
        source: 'rentry',
        timestamp: r.created_at || nowISO(),
        url: `https://rentry.co/${r.id}`,
        context: 'Public rentry note',
      });
    });

    await cacheAPIResponse(cacheKey, signals, 120);
    return signals;
  } catch {
    return [];
  }
}

async function scanGhostbin(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `ghostbin:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const res = await fetchWithTimeout(
      'https://ghostbin.com/browse',
      { headers: { 'User-Agent': 'Mozilla/5.0' } },
      TIMEOUTS.PASTE_SCAN
    );

    if (!res.ok) return [];

    const html = await res.text();
    const signals: LeakSignal[] = [];

    Array.from(
      html.matchAll(/href="\/paste\/([A-Za-z0-9]+)">([^<]+)<\/a>/g)
    ).forEach(m => {
      if (m[2].toLowerCase().includes(indicator.toLowerCase())) {
        signals.push({
          id: `gb-${m[1]}`,
          title: stripHtml(m[2]),
          indicator,
          source: 'ghostbin',
          timestamp: nowISO(),
          url: `https://ghostbin.com/paste/${m[1]}`,
          context: 'Ghostbin title match',
        });
      }
    });

    await cacheAPIResponse(cacheKey, signals, 120);
    return signals;
  } catch {
    return [];
  }
}

/* ============================================================================
   AGGREGATOR
============================================================================ */

export async function searchDarkWebSignals(
  indicator: string
): Promise<LeakSignal[]> {
  const cacheKey = `signals:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

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
    .filter((r): r is PromiseFulfilledResult<LeakSignal[]> => r.status === 'fulfilled')
    .flatMap(r => r.value);

  await cacheAPIResponse(cacheKey, results, 90);
  return results;
}

/* ============================================================================
   DARKNET MARKET STATUS (dark.fail)
============================================================================ */

export async function checkDarknetMarketStatus(): Promise<
  Array<{
    name: string;
    url: string;
    status: 'online' | 'offline' | 'unknown';
    lastChecked: string;
  }>
> {
  try {
    const res = await fetchWithTimeout(
      'https://dark.fail/',
      { headers: { 'User-Agent': 'Mozilla/5.0' } },
      TIMEOUTS.ONION_DISCOVERY
    );

    if (!res.ok) return [];

    const html = await res.text();
    const markets: any[] = [];

    Array.from(
      html.matchAll(
        /<h3>([^<]+)<\/h3>[\s\S]*?<code>([^<]+)<\/code>[\s\S]*?<span class="status ([^"]+)"/g
      )
    ).forEach(m => {
      markets.push({
        name: stripHtml(m[1]),
        url: stripHtml(m[2]),
        status: m[3].includes('online') ? 'online' : 'offline',
        lastChecked: nowISO(),
      });
    });

    return markets;
  } catch {
    return [];
  }
}
