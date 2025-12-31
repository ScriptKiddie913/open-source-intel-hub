// ============================================================================
// torService.ts
// REAL Dark Web Intelligence Engine (FIXED)
// ✔ Onion discovery (Ahmia)
// ✔ Onion uptime (Tor2Web)
// ✔ Paste monitoring (Pastebin, Psbdmp, Ghostbin, Rentry)
// ✔ GitHub code leakage
// ✔ Library of Leaks RESOLVER (WORKING)
// ✔ Darknet market status
// ✔ Zero mock data
// ✔ OSINT-legal
// ✔ Vercel compatible
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
    | 'libraryofleaks'
    | 'archive'
    | 'intelx';
  timestamp: string;
  url: string;
  context: string;
}

/* ============================================================================
   CONSTANTS
============================================================================ */

const TOR2WEB_PROXIES = ['onion.ws', 'onion.pet', 'onion.ly'];
const ONION_REGEX = /([a-z2-7]{16,56}\.onion)/gi;

/* ============================================================================
   UTILS
============================================================================ */

const nowISO = () => new Date().toISOString();
const stripHtml = (s: string) => s.replace(/<[^>]*>/g, '').trim();
const unique = <T>(a: T[]) => Array.from(new Set(a));

/* ============================================================================
   RISK ENGINE
============================================================================ */

function calculateRisk(text: string): RiskLevel {
  const t = text.toLowerCase();
  if (/(child|weapon|exploit|malware|ransom)/.test(t)) return 'critical';
  if (/(leak|dump|breach|database)/.test(t)) return 'high';
  if (/(market|forum|selling)/.test(t)) return 'medium';
  return 'low';
}

function extractTags(text: string): string[] {
  const tags = [
    'leak','dump','breach','database','market','forum',
    'malware','exploit','credentials','phishing',
    'fraud','drugs','weapons','ransomware'
  ];
  const t = text.toLowerCase();
  return tags.filter(k => t.includes(k)).slice(0, 6);
}

function categorize(text: string): string {
  const t = text.toLowerCase();
  if (t.includes('market')) return 'Marketplace';
  if (t.includes('forum')) return 'Forum';
  if (t.includes('leak') || t.includes('dump')) return 'Data Leak';
  return 'Unknown';
}

/* ============================================================================
   ONION DISCOVERY — AHMIA
============================================================================ */

export async function discoverOnionSites(query: string): Promise<OnionSite[]> {
  const cacheKey = `onion:${query}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const res = await fetch(`https://ahmia.fi/search/?q=${encodeURIComponent(query)}`);
    if (!res.ok) return [];

    const html = await res.text();
    const onions = unique(html.match(ONION_REGEX) || []).slice(0, 50);

    const titles = [...html.matchAll(/<h4[^>]*><a[^>]*>([^<]+)</gi)].map(m => stripHtml(m[1]));
    const descs  = [...html.matchAll(/<p class="result[^"]*">([^<]+)/gi)].map(m => stripHtml(m[1]));

    const sites: OnionSite[] = onions.map((o, i) => {
      const ctx = `${titles[i] || ''} ${descs[i] || ''}`;
      return {
        url: o,
        title: titles[i] || 'Unknown Onion Service',
        description: descs[i] || '',
        category: categorize(ctx),
        riskLevel: calculateRisk(ctx),
        lastSeen: nowISO(),
        status: 'unknown' as const,
        tags: extractTags(ctx),
        discoveredFrom: 'ahmia',
      };
    });

    await cacheAPIResponse(cacheKey, sites, 60);
    return sites;
  } catch {
    return [];
  }
}

/* ============================================================================
   ONION UPTIME
============================================================================ */

export async function checkOnionUptime(onion: string) {
  try {
    const host = onion.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const res = await fetch(`https://${host}.${TOR2WEB_PROXIES[0]}`, { method: 'HEAD' });
    return { status: res.ok ? 'online' : 'offline', checkedAt: nowISO() };
  } catch {
    return { status: 'offline', checkedAt: nowISO() };
  }
}

/* ============================================================================
   PASTE / LEAK SOURCES
============================================================================ */

async function scanPastebin(indicator: string): Promise<LeakSignal[]> {
  const html = await (await fetch('https://pastebin.com/archive')).text();
  return [...html.matchAll(/\/([A-Za-z0-9]{8})">([^<]+)/g)]
    .filter(m => m[2].toLowerCase().includes(indicator.toLowerCase()))
    .map(m => ({
      id: `pb-${m[1]}`,
      title: stripHtml(m[2]),
      indicator,
      source: 'pastebin',
      timestamp: nowISO(),
      url: `https://pastebin.com/${m[1]}`,
      context: 'Paste title match',
    }));
}

async function scanPsbdmp(indicator: string): Promise<LeakSignal[]> {
  const res = await fetch(`https://psbdmp.ws/api/search/${encodeURIComponent(indicator)}`);
  if (!res.ok) return [];
  const data = await res.json();
  return (data.data || []).map((p: any) => ({
    id: `ps-${p.id}`,
    title: 'Pastebin Dump',
    indicator,
    source: 'psbdmp',
    timestamp: p.time || nowISO(),
    url: `https://pastebin.com/${p.id}`,
    context: 'Dump index match',
  }));
}

async function scanGhostbin(indicator: string): Promise<LeakSignal[]> {
  const html = await (await fetch('https://ghostbin.com/browse')).text();
  return [...html.matchAll(/\/paste\/([^"]+)">([^<]+)/g)]
    .filter(m => m[2].toLowerCase().includes(indicator.toLowerCase()))
    .map(m => ({
      id: `gb-${m[1]}`,
      title: stripHtml(m[2]),
      indicator,
      source: 'ghostbin',
      timestamp: nowISO(),
      url: `https://ghostbin.com/paste/${m[1]}`,
      context: 'Ghostbin title match',
    }));
}

async function scanRentry(indicator: string): Promise<LeakSignal[]> {
  const res = await fetch(`https://rentry.co/api/search?q=${encodeURIComponent(indicator)}`);
  if (!res.ok) return [];
  const data = await res.json();
  return (data.results || []).map((r: any) => ({
    id: `re-${r.id}`,
    title: r.title || 'Rentry Note',
    indicator,
    source: 'rentry',
    timestamp: r.created_at || nowISO(),
    url: `https://rentry.co/${r.id}`,
    context: 'Public note match',
  }));
}

async function scanGitHubGists(indicator: string): Promise<LeakSignal[]> {
  const res = await fetch(
    `https://api.github.com/search/code?q=${encodeURIComponent(indicator)}+in:file`
  );
  if (!res.ok) return [];
  const data = await res.json();
  return (data.items || []).map((i: any) => ({
    id: `gh-${i.sha}`,
    title: i.name,
    indicator,
    source: 'github_gist',
    timestamp: nowISO(),
    url: i.html_url,
    context: `Repo: ${i.repository.full_name}`,
  }));
}

/* ============================================================================
   LIBRARY OF LEAKS — REAL API INTEGRATION (ALEPH)
============================================================================ */

// Library of Leaks uses the Aleph API
// API Docs: https://search.libraryofleaks.org/api/2/entities
const LIBRARY_OF_LEAKS_BASE = 'https://search.libraryofleaks.org';

// Generate a session ID for API requests (UUID v4 format)
function generateSessionId(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

// Parse Library of Leaks API response - based on actual Aleph API structure
interface AlephEntity {
  id: string;
  schema: string;
  score?: number;
  created_at?: string;
  updated_at?: string;
  properties: {
    name?: string[];
    title?: string[];
    description?: string[];
    summary?: string[];
    fileName?: string[];
    mimeType?: string[];
    sourceUrl?: string[];
    publishedAt?: string[];
    modifiedAt?: string[];
    date?: string[];
    emails?: string[];
    emailMentioned?: string[];
    phones?: string[];
    addresses?: string[];
    country?: string[];
    companiesMentioned?: string[];
    peopleMentioned?: string[];
    detectedLanguage?: string[];
  };
  links?: {
    self?: string;
    ui?: string;
    file?: string;
    expand?: string;
  };
  highlight?: string[];
  collection?: {
    label?: string;
    category?: string;
    summary?: string;
    collection_id?: string;
    info_url?: string;
  };
}

interface AlephResponse {
  results: AlephEntity[];
  total: number;
  total_type?: string;
  limit: number;
  offset: number;
  page?: number;
  pages?: number;
  query_text?: string;
  facets?: Record<string, any>;
}

// Helper function to parse Aleph API results into LeakSignal format
function parseAlephResults(results: AlephEntity[], indicator: string, signals: LeakSignal[]): void {
  results.forEach((entity: AlephEntity) => {
    const props = entity.properties || {};
    
    // Get title from various possible fields
    const title = props.fileName?.[0] || 
                  props.name?.[0] || 
                  props.title?.[0] || 
                  `${entity.schema || 'Document'} - ${entity.id.substring(0, 8)}`;
    
    // Get timestamp
    const timestamp = entity.updated_at || entity.created_at || nowISO();
    
    // Clean up highlight text (remove HTML tags)
    const highlightRaw = entity.highlight?.join(' ') || '';
    const highlight = highlightRaw.replace(/<\/?em>/g, '**').replace(/<[^>]*>/g, '').substring(0, 150);
    
    // Build context from available data
    const contextParts: string[] = [];
    
    // Collection info
    if (entity.collection?.label) {
      contextParts.push(`📁 ${entity.collection.label}`);
    }
    
    // Document type
    if (entity.schema && entity.schema !== 'Thing') {
      contextParts.push(`Type: ${entity.schema}`);
    }
    
    // File type
    if (props.mimeType?.[0]) {
      const mime = props.mimeType[0];
      const fileType = mime.includes('pdf') ? 'PDF' : 
                       mime.includes('email') ? 'Email' : 
                       mime.includes('text') ? 'Text' :
                       mime.includes('image') ? 'Image' : mime.split('/')[1];
      contextParts.push(`Format: ${fileType}`);
    }
    
    // Mentioned entities
    if (props.companiesMentioned?.length) {
      contextParts.push(`Companies: ${props.companiesMentioned.slice(0, 2).join(', ')}`);
    }
    if (props.peopleMentioned?.length) {
      contextParts.push(`People: ${props.peopleMentioned.slice(0, 2).join(', ')}`);
    }
    if (props.emailMentioned?.length) {
      contextParts.push(`Email: ${props.emailMentioned[0]}`);
    }
    
    // Highlight/match context
    if (highlight) {
      contextParts.push(`"${highlight}..."`);
    }

    signals.push({
      id: `lol-${entity.id}`,
      title: title.substring(0, 100),
      indicator,
      source: 'libraryofleaks',
      timestamp,
      url: entity.links?.ui || `${LIBRARY_OF_LEAKS_BASE}/entities/${entity.id}`,
      context: contextParts.join(' • ') || 'Library of Leaks document',
    });
  });
}

async function scanLibraryOfLeaks(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `lol:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals: LeakSignal[] = [];
  let libraryOfLeaksSuccess = false;

  /* ------------------ METHOD 1: VERCEL PROXY (for production) ------------------ */
  try {
    const proxyUrl = `/api/library-of-leaks?q=${encodeURIComponent(indicator)}&limit=30`;
    console.log(`[Library of Leaks] Trying Vercel proxy: ${proxyUrl}`);
    
    const proxyRes = await fetch(proxyUrl, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });

    if (proxyRes.ok) {
      const data: AlephResponse = await proxyRes.json();
      if (data.results && data.results.length > 0) {
        libraryOfLeaksSuccess = true;
        parseAlephResults(data.results, indicator, signals);
        console.log(`[Library of Leaks] Proxy: Found ${data.total} total, returned ${signals.length} signals`);
      }
    } else {
      console.warn(`[Library of Leaks] Proxy failed: ${proxyRes.status}`);
    }
  } catch (err) {
    console.warn('[Library of Leaks] Proxy unavailable:', err);
  }

  /* ------------------ METHOD 2: DIRECT API (may have CORS issues) ------------------ */
  if (!libraryOfLeaksSuccess) {
    try {
      const sessionId = generateSessionId();
      const params = new URLSearchParams({
        'filter:schemata': 'Thing',
        'highlight': 'true',
        'limit': '30',
        'q': indicator,
      });

      const apiUrl = `${LIBRARY_OF_LEAKS_BASE}/api/2/entities?${params.toString()}`;
      console.log(`[Library of Leaks] Trying direct API: ${apiUrl}`);
      
      const res = await fetch(apiUrl, {
        method: 'GET',
        headers: {
          'Accept': 'application/json, text/plain, */*',
          'Accept-Language': 'en',
          'X-Aleph-Session': sessionId,
        },
      });

      if (res.ok) {
        const data: AlephResponse = await res.json();
        if (data.results && data.results.length > 0) {
          libraryOfLeaksSuccess = true;
          parseAlephResults(data.results, indicator, signals);
          console.log(`[Library of Leaks] Direct: Found ${data.total} total, returned ${signals.length} signals`);
        }
      } else {
        console.warn(`[Library of Leaks] Direct API failed: ${res.status}`);
      }
    } catch (err) {
      console.error('[Library of Leaks] Direct API error:', err);
    }
  }

  /* ------------------ METHOD 3: CORS PROXY FALLBACK ------------------ */
  if (!libraryOfLeaksSuccess) {
    try {
      const params = new URLSearchParams({
        'filter:schemata': 'Thing',
        'highlight': 'true',
        'limit': '30',
        'q': indicator,
      });
      
      // Use a public CORS proxy as last resort
      const targetUrl = `${LIBRARY_OF_LEAKS_BASE}/api/2/entities?${params.toString()}`;
      const corsProxyUrl = `https://api.allorigins.win/raw?url=${encodeURIComponent(targetUrl)}`;
      
      console.log(`[Library of Leaks] Trying CORS proxy fallback`);
      
      const res = await fetch(corsProxyUrl, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
      });

      if (res.ok) {
        const data: AlephResponse = await res.json();
        if (data.results && data.results.length > 0) {
          libraryOfLeaksSuccess = true;
          parseAlephResults(data.results, indicator, signals);
          console.log(`[Library of Leaks] CORS proxy: Found ${data.total} total, returned ${signals.length} signals`);
        }
      }
    } catch (err) {
      console.error('[Library of Leaks] CORS proxy error:', err);
    }
  }

  /* ------------------ ARCHIVE.ORG DATASETS (ADDITIONAL) ------------------ */
  try {
    const res = await fetch(
      `https://archive.org/advancedsearch.php?q=${encodeURIComponent(
        indicator
      )}+leak&fl[]=identifier&fl[]=title&fl[]=publicdate&output=json`
    );
    const data = await res.json();
    (data.response?.docs || []).forEach((d: any) => {
      signals.push({
        id: `ia-${d.identifier}`,
        title: d.title || 'Archived Leak Dataset',
        indicator,
        source: 'archive',
        timestamp: d.publicdate || nowISO(),
        url: `https://archive.org/details/${d.identifier}`,
        context: 'Archive.org dataset (downloadable)',
      });
    });
  } catch {}

  /* ------------------ GITHUB LEAK MIRRORS (FALLBACK) ------------------ */
  try {
    const res = await fetch(
      `https://api.github.com/search/repositories?q=${encodeURIComponent(
        indicator
      )}+leak+dump`
    );
    const data = await res.json();
    (data.items || []).slice(0, 10).forEach((r: any) => {
      signals.push({
        id: `lol-gh-${r.id}`,
        title: r.full_name,
        indicator,
        source: 'libraryofleaks',
        timestamp: r.updated_at,
        url: r.html_url,
        context: 'GitHub leak mirror',
      });
    });
  } catch {}

  await cacheAPIResponse(cacheKey, signals, 120);
  return signals;
}

/* ============================================================================
   AGGREGATOR
============================================================================ */

export async function searchDarkWebSignals(indicator: string): Promise<LeakSignal[]> {
  const results = (
    await Promise.allSettled([
      scanPastebin(indicator),
      scanPsbdmp(indicator),
      scanGhostbin(indicator),
      scanRentry(indicator),
      scanGitHubGists(indicator),
      scanLibraryOfLeaks(indicator),
    ])
  )
    .filter((r): r is PromiseFulfilledResult<LeakSignal[]> => r.status === 'fulfilled')
    .flatMap(r => r.value);

  return results;
}

/* ============================================================================
   DARKNET MARKET STATUS
============================================================================ */

export async function checkDarknetMarketStatus() {
  try {
    const html = await (await fetch('https://dark.fail/')).text();
    return [...html.matchAll(/<h3>([^<]+).*?<code>([^<]+).*?status ([^"]+)/gs)]
      .map(m => ({
        name: stripHtml(m[1]),
        url: stripHtml(m[2]),
        status: m[3].includes('online') ? 'online' : 'offline',
        lastChecked: nowISO(),
      }));
  } catch {
    return [];
  }
}
