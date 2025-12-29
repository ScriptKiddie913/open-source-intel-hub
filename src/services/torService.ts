// ============================================================================
// torService.ts
// REAL Dark Web Intelligence — Metadata Only (Legal & OSINT-Grade)
// ============================================================================
//
// ✔ Onion discovery via Ahmia & public directories
// ✔ Paste & leak signal monitoring (Pastebin, Ghostbin, Rentry, GitHub Gists)
// ✔ Tor2Web uptime checks (HEAD only)
// ✔ No Tor daemon required
// ✔ No content scraping
// ✔ No dump downloading
// ✔ No authentication bypass
// ✔ Vercel-safe (Edge-compatible fetch usage)
//
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
    | 'telegram_public';
  timestamp: string;
  url: string;
  context: string;
}

/* ============================================================================
   CONSTANTS
============================================================================ */

const TOR2WEB_PROXIES = [
  'https://onion.ws',
  'https://onion.ly',
  'https://tor2web.org',
];

const ONION_DIRECTORIES = [
  {
    name: 'ahmia',
    base: 'https://ahmia.fi/search/?q=',
  },
];

const EMAIL_REGEX =
  /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

const DOMAIN_REGEX =
  /\b[a-z0-9-]+\.[a-z]{2,}\b/gi;

const ONION_REGEX =
  /([a-z2-7]{16,56}\.onion)/gi;

/* ============================================================================
   UTILITIES
============================================================================ */

function stripHtml(input: string): string {
  return input.replace(/<[^>]*>/g, '').trim();
}

function nowISO(): string {
  return new Date().toISOString();
}

function unique<T>(arr: T[]): T[] {
  return Array.from(new Set(arr));
}

function clamp(val: number, min: number, max: number): number {
  return Math.min(Math.max(val, min), max);
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
    t.includes('drug')
  ) {
    return 'critical';
  }

  if (
    t.includes('leak') ||
    t.includes('dump') ||
    t.includes('database') ||
    t.includes('hack')
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
  ];

  const lower = text.toLowerCase();
  return keywords.filter(k => lower.includes(k)).slice(0, 6);
}

function categorize(text: string): string {
  const t = text.toLowerCase();

  if (t.includes('market')) return 'Marketplace';
  if (t.includes('forum')) return 'Forum';
  if (t.includes('leak') || t.includes('dump')) return 'Data Leak';
  if (t.includes('mail')) return 'Email Service';
  if (t.includes('hosting')) return 'Hosting';
  if (t.includes('directory')) return 'Directory';

  return 'Unknown';
}

/* ============================================================================
   LEVEL A — ONION DISCOVERY (AHMIA)
============================================================================ */

async function discoverOnionSites(
  query: string
): Promise<OnionSite[]> {
  const cacheKey = `onion:discover:${query}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const results: OnionSite[] = [];

  try {
    const url = `${ONION_DIRECTORIES[0].base}${encodeURIComponent(query)}`;

    const res = await fetch(
      `https://api.allorigins.win/get?url=${encodeURIComponent(url)}`
    );

    if (!res.ok) return [];

    const { contents } = await res.json();
    const html = contents as string;

    const onions = unique(
      (html.match(ONION_REGEX) || []).slice(0, 30)
    );

    const titles = Array.from(
      html.matchAll(/<h4[^>]*>(.*?)<\/h4>/gi)
    ).map(m => stripHtml(m[1]));

    const descs = Array.from(
      html.matchAll(/<p[^>]*>(.*?)<\/p>/gi)
    ).map(m => stripHtml(m[1]));

    onions.forEach((onion, idx) => {
      const context =
        `${titles[idx] || ''} ${descs[idx] || ''}`.trim();

      results.push({
        url: onion,
        title: titles[idx] || 'Unknown',
        description: descs[idx] || 'No description available',
        category: categorize(context),
        riskLevel: calculateRisk(context),
        lastSeen: nowISO(),
        status: 'unknown',
        tags: extractTags(context),
        discoveredFrom: 'ahmia',
      });
    });

    await cacheAPIResponse(cacheKey, results, 60);
    return results;
  } catch (err) {
    console.error('Onion discovery error:', err);
    return [];
  }
}

/* ============================================================================
   LEVEL A — ONION UPTIME CHECK (Tor2Web)
============================================================================ */

async function checkOnionUptime(
  onion: string
): Promise<{
  status: 'online' | 'offline';
  responseTime?: number;
  checkedAt: string;
}> {
  try {
    const proxy = TOR2WEB_PROXIES[0];
    const host = onion.replace(/^https?:\/\//, '');
    const url = `https://${host}.${proxy.replace('https://', '')}`;

    const start = Date.now();
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 10000);

    const res = await fetch(url, {
      method: 'HEAD',
      signal: controller.signal,
    });

    clearTimeout(t);

    return {
      status: res.ok ? 'online' : 'offline',
      responseTime: Date.now() - start,
      checkedAt: nowISO(),
    };
  } catch {
    return {
      status: 'offline',
      checkedAt: nowISO(),
    };
  }
}

/* ============================================================================
   LEVEL B — PASTE & LEAK SIGNALS (METADATA ONLY)
============================================================================ */

async function scanPastebin(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `pastebin:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals: LeakSignal[] = [];

  try {
    const res = await fetch(
      `https://api.allorigins.win/get?url=${encodeURIComponent(
        'https://pastebin.com/archive'
      )}`
    );

    if (!res.ok) return [];

    const { contents } = await res.json();
    const html = contents as string;

    const links = Array.from(
      html.matchAll(/<a href="\/([A-Za-z0-9]{8})"[^>]*>([^<]+)<\/a>/g)
    ).slice(0, 40);

    links.forEach(([_, id, title]) => {
      if (title.toLowerCase().includes(indicator.toLowerCase())) {
        signals.push({
          id: `pb-${id}`,
          title: stripHtml(title),
          indicator,
          source: 'pastebin',
          timestamp: nowISO(),
          url: `https://pastebin.com/${id}`,
          context: 'Paste title match',
        });
      }
    });

    await cacheAPIResponse(cacheKey, signals, 30);
    return signals;
  } catch (err) {
    console.error('Pastebin scan error:', err);
    return [];
  }
}

async function scanGhostbin(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `ghostbin:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals: LeakSignal[] = [];

  try {
    const res = await fetch(
      `https://api.allorigins.win/get?url=${encodeURIComponent(
        'https://ghostbin.com/browse'
      )}`
    );

    if (!res.ok) return [];

    const { contents } = await res.json();
    const html = contents as string;

    const links = Array.from(
      html.matchAll(/<a href="\/paste\/([A-Za-z0-9]+)"[^>]*>([^<]+)<\/a>/g)
    ).slice(0, 30);

    links.forEach(([_, id, title]) => {
      if (title.toLowerCase().includes(indicator.toLowerCase())) {
        signals.push({
          id: `gb-${id}`,
          title: stripHtml(title),
          indicator,
          source: 'ghostbin',
          timestamp: nowISO(),
          url: `https://ghostbin.com/paste/${id}`,
          context: 'Ghostbin title match',
        });
      }
    });

    await cacheAPIResponse(cacheKey, signals, 30);
    return signals;
  } catch (err) {
    console.error('Ghostbin scan error:', err);
    return [];
  }
}

async function scanRentry(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `rentry:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals: LeakSignal[] = [];

  try {
    const res = await fetch(
      `https://api.allorigins.win/get?url=${encodeURIComponent(
        `https://rentry.co/search?q=${indicator}`
      )}`
    );

    if (!res.ok) return [];

    const { contents } = await res.json();
    const html = contents as string;

    const links = Array.from(
      html.matchAll(/href="\/([a-zA-Z0-9_-]+)"/g)
    ).slice(0, 20);

    links.forEach(([_, id]) => {
      signals.push({
        id: `rentry-${id}`,
        title: 'Rentry public note',
        indicator,
        source: 'rentry',
        timestamp: nowISO(),
        url: `https://rentry.co/${id}`,
        context: 'Rentry public reference',
      });
    });

    await cacheAPIResponse(cacheKey, signals, 30);
    return signals;
  } catch (err) {
    console.error('Rentry scan error:', err);
    return [];
  }
}

async function scanGitHubGists(
  indicator: string
): Promise<LeakSignal[]> {
  const cacheKey = `gists:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals: LeakSignal[] = [];

  try {
    const res = await fetch(
      `https://api.allorigins.win/get?url=${encodeURIComponent(
        `https://github.com/search?q=${indicator}&type=gists`
      )}`
    );

    if (!res.ok) return [];

    const { contents } = await res.json();
    const html = contents as string;

    const links = Array.from(
      html.matchAll(/href="(\/[a-zA-Z0-9_-]+\/[a-zA-Z0-9]+)"/g)
    ).slice(0, 20);

    links.forEach(([_, path]) => {
      signals.push({
        id: `gist-${path}`,
        title: 'GitHub Gist reference',
        indicator,
        source: 'github_gist',
        timestamp: nowISO(),
        url: `https://github.com${path}`,
        context: 'Public gist search match',
      });
    });

    await cacheAPIResponse(cacheKey, signals, 30);
    return signals;
  } catch (err) {
    console.error('GitHub Gist scan error:', err);
    return [];
  }
}

/* ============================================================================
   AGGREGATOR
============================================================================ */

async function searchDarkWebSignals(
  indicator: string
): Promise<LeakSignal[]> {
  const cacheKey = `signals:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const results = (
    await Promise.all([
      scanPastebin(indicator),
      scanGhostbin(indicator),
      scanRentry(indicator),
      scanGitHubGists(indicator),
    ])
  ).flat();

  await cacheAPIResponse(cacheKey, results, 30);
  return results;
}

/* ============================================================================
   EXPORTS — SINGLE SOURCE OF TRUTH (FIXES YOUR BUILD)
============================================================================ */

export {
  discoverOnionSites,
  checkOnionUptime,
  searchDarkWebSignals,
};
