// ============================================================================
// aptMapService.ts
// LIVE APT GROUP DATA SERVICE
// ============================================================================
// ✔ Fetches real-time APT data from APTmap (andreacristaldi.github.io)
// ✔ Parses MITRE ATT&CK group mappings
// ✔ Provides structured APT intelligence
// ✔ Caches results for performance
// ============================================================================

import { cacheAPIResponse, getCachedData } from '@/lib/database';

/* ============================================================================
   TYPES
============================================================================ */

export interface APTGroup {
  id: string;
  uuid: string;
  name: string;
  aliases: string[];
  description: string;
  country: string;
  countryCode: string;
  location: string;
  sponsor?: string;
  motivations: string[];
  firstSeen?: string;
  active: boolean;
  attributionConfidence: number;
  
  // Targeting
  targets: string[];
  targetCategories: string[];
  
  // TTPs
  ttps: APTTechnique[];
  tools: APTTool[];
  iocs: string[];
  operations: string[];
  
  // Links & Sources
  sources: APTSource[];
  externalLinks: APTExternalLink[];
  malwareSamples: APTMalwareSample[];
  
  // Geolocation
  coordinates?: {
    lat: number;
    lon: number;
  };
}

export interface APTTechnique {
  techniqueID: string;
  comment?: string;
  score?: number;
  showSubtechniques?: boolean;
}

export interface APTTool {
  name: string;
  description: string;
  category: string;
  references: string[];
  types: string[];
}

export interface APTSource {
  name: string;
  description: string;
  url: string;
  jsonUrl?: string;
  copyright?: string;
}

export interface APTExternalLink {
  description: string;
  url: string;
  type: 'web' | 'malwaresample';
}

export interface APTMalwareSample {
  description: string;
  url: string;
  hash?: string;
}

export interface APTMapResponse {
  type: string;
  features: APTFeature[];
}

export interface APTFeature {
  type: string;
  properties: {
    uuid: string;
    name: string;
    'other-names': string[];
    'associated-groups': string;
    related: any[];
    description: string;
    country: string;
    location: string;
    'image-url': string;
    'image-caption': string;
    sponsor: string;
    motivations: string[];
    'first-seen': string;
    sources: APTSource[];
    targets: string[];
    'target-category': string[];
    tools: any[];
    TTP: APTTechnique[];
    IOC: string[];
    operations: string[];
    'ext-links': any[];
    'attribution-confidence': string;
  };
  geometry?: {
    type: string;
    coordinates: [number, number];
  };
}

export interface APTSearchResult {
  groups: APTGroup[];
  totalCount: number;
  byCountry: Record<string, number>;
  byTargetSector: Record<string, number>;
  activeGroups: number;
  lastUpdated: Date;
}

export interface APTStats {
  totalGroups: number;
  byCountry: Record<string, number>;
  byMotivation: Record<string, number>;
  topTargetSectors: { sector: string; count: number }[];
  topTargetCountries: { country: string; count: number }[];
  ttpsCount: number;
  toolsCount: number;
  malwareSamplesCount: number;
}

/* ============================================================================
   CACHE KEYS
============================================================================ */

const CACHE_KEY = 'aptmap_data';
const CACHE_TTL = 3600000; // 1 hour

/* ============================================================================
   APT DATA FETCH & PARSING
============================================================================ */

// Fetch APT data from APTmap with multiple sources fallback
export async function fetchAPTMapData(): Promise<APTGroup[]> {
  // Check cache first
  const cached = await getCachedData(CACHE_KEY) as APTGroup[] | null;
  if (cached && Array.isArray(cached) && cached.length > 0) {
    console.log('[APTmap] Using cached data:', cached.length, 'groups');
    return cached;
  }
  
  // Multiple APT data sources for redundancy
  const aptSources = [
    'https://andreacristaldi.github.io/APTmap/apt.json',
    'https://raw.githubusercontent.com/andreacristaldi/APTmap/main/apt.json'
  ];
  
  for (const sourceUrl of aptSources) {
    try {
      console.log(`[APTmap] Fetching from ${sourceUrl}...`);
      const response = await fetch(sourceUrl, {
        headers: {
          'Accept': 'application/json',
        },
        cache: 'no-cache'
      });
      
      if (!response.ok) {
        console.warn(`[APTmap] Source ${sourceUrl} returned ${response.status}`);
        continue;
      }
      
      const data: APTMapResponse = await response.json();
      
      if (!data.features || !Array.isArray(data.features) || data.features.length === 0) {
        console.warn(`[APTmap] Invalid/empty data from ${sourceUrl}`);
        continue;
      }
      
      const groups = parseAPTFeatures(data.features);
      
      if (groups.length > 0) {
        // Cache the results
        await cacheAPIResponse(CACHE_KEY, groups, CACHE_TTL);
        console.log(`[APTmap] Loaded ${groups.length} APT groups from ${sourceUrl}`);
        return groups;
      }
    } catch (error) {
      console.warn(`[APTmap] Source ${sourceUrl} error:`, error);
      continue;
    }
  }
  
  // Fallback to MITRE ATT&CK groups API as backup
  try {
    console.log('[APTmap] Trying MITRE ATT&CK fallback...');
    const mitreResponse = await fetch('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/intrusion-set/intrusion-set.json');
    
    if (mitreResponse.ok) {
      const mitreData = await mitreResponse.json();
      const mitreGroups = parseMitreGroups(mitreData);
      
      if (mitreGroups.length > 0) {
        await cacheAPIResponse(CACHE_KEY, mitreGroups, CACHE_TTL);
        console.log(`[APTmap] Loaded ${mitreGroups.length} groups from MITRE ATT&CK`);
        return mitreGroups;
      }
    }
  } catch (error) {
    console.warn('[APTmap] MITRE fallback failed:', error);
  }
  
  console.error('[APTmap] All sources failed - returning empty array');
  return [];
}

// Parse MITRE ATT&CK intrusion sets as fallback
function parseMitreGroups(data: any): APTGroup[] {
  if (!data.objects || !Array.isArray(data.objects)) return [];
  
  return data.objects
    .filter((obj: any) => obj.type === 'intrusion-set')
    .map((group: any, idx: number) => {
      const aliases = group.aliases || [];
      const country = extractCountryFromDescription(group.description || '');
      
      return {
        id: `mitre-${idx}-${group.id?.slice(-8) || idx}`,
        uuid: group.id || `mitre-${idx}`,
        name: group.name || 'Unknown',
        aliases,
        description: group.description || `${group.name} is a threat group.`,
        country,
        countryCode: getCountryCode(country),
        location: country,
        motivations: extractMotivations(group.description || ''),
        firstSeen: group.first_seen,
        active: true,
        attributionConfidence: 70,
        targets: extractTargets(group.description || ''),
        targetCategories: extractTargetCategories(group.description || ''),
        ttps: [],
        tools: [],
        iocs: [],
        operations: [],
        sources: [{ name: 'MITRE ATT&CK', description: 'MITRE ATT&CK Framework', url: 'https://attack.mitre.org' }],
        externalLinks: group.external_references?.map((ref: any) => ({
          description: ref.description || ref.source_name,
          url: ref.url || '',
          type: 'web' as const
        })) || [],
        malwareSamples: [],
        coordinates: getCountryCoordinates(country)
      };
    });
}

// Extract country from description text
function extractCountryFromDescription(desc: string): string {
  const countryPatterns = [
    { pattern: /russia|russian|kremlin|moscow|gru|fsb|svr/i, country: 'Russia' },
    { pattern: /china|chinese|prc|beijing|pla|mss/i, country: 'China' },
    { pattern: /iran|iranian|tehran|irgc/i, country: 'Iran' },
    { pattern: /north korea|dprk|pyongyang|lazarus/i, country: 'North Korea' },
    { pattern: /israel|israeli|tel aviv|unit 8200/i, country: 'Israel' },
    { pattern: /vietnam|vietnamese|apt32/i, country: 'Vietnam' },
    { pattern: /india|indian/i, country: 'India' },
    { pattern: /pakistan|pakistani/i, country: 'Pakistan' },
    { pattern: /turkey|turkish/i, country: 'Turkey' },
  ];
  
  for (const { pattern, country } of countryPatterns) {
    if (pattern.test(desc)) return country;
  }
  return 'Unknown';
}

// Get country code from name
function getCountryCode(country: string): string {
  const codes: Record<string, string> = {
    'Russia': 'RU', 'China': 'CN', 'Iran': 'IR', 'North Korea': 'KP',
    'Israel': 'IL', 'Vietnam': 'VN', 'India': 'IN', 'Pakistan': 'PK',
    'Turkey': 'TR', 'United States': 'US'
  };
  return codes[country] || '';
}

// Get approximate coordinates for country
function getCountryCoordinates(country: string): { lat: number; lon: number } | undefined {
  const coords: Record<string, { lat: number; lon: number }> = {
    'Russia': { lat: 55.75, lon: 37.62 },
    'China': { lat: 39.90, lon: 116.40 },
    'Iran': { lat: 35.69, lon: 51.39 },
    'North Korea': { lat: 39.03, lon: 125.75 },
    'Israel': { lat: 31.77, lon: 35.22 },
    'Vietnam': { lat: 21.03, lon: 105.85 },
    'India': { lat: 28.61, lon: 77.21 },
    'Pakistan': { lat: 33.69, lon: 73.06 },
    'Turkey': { lat: 39.93, lon: 32.85 },
    'United States': { lat: 38.90, lon: -77.04 }
  };
  return coords[country];
}

// Extract motivations from description
function extractMotivations(desc: string): string[] {
  const motivations: string[] = [];
  if (/espionage|intelligence|spy/i.test(desc)) motivations.push('Espionage');
  if (/financial|money|bank/i.test(desc)) motivations.push('Financial');
  if (/sabotage|disrupt/i.test(desc)) motivations.push('Sabotage');
  if (/ransomware|extort/i.test(desc)) motivations.push('Financial');
  return motivations.length > 0 ? motivations : ['Unknown'];
}

// Extract targets from description
function extractTargets(desc: string): string[] {
  const targets: string[] = [];
  if (/government|military|defense/i.test(desc)) targets.push('Government');
  if (/financial|bank/i.test(desc)) targets.push('Financial');
  if (/energy|oil|gas/i.test(desc)) targets.push('Energy');
  if (/healthcare|medical/i.test(desc)) targets.push('Healthcare');
  if (/technology|tech/i.test(desc)) targets.push('Technology');
  return targets;
}

// Extract target categories
function extractTargetCategories(desc: string): string[] {
  return extractTargets(desc);
}

// Parse APT features into structured groups
function parseAPTFeatures(features: APTFeature[]): APTGroup[] {
  return features.map((feature, index) => {
    const props = feature.properties;
    
    // Parse tools
    const tools: APTTool[] = (props.tools || []).map((tool: any) => ({
      name: tool.value || tool.name || 'Unknown',
      description: tool.description || '',
      category: tool.category || 'Malware',
      references: tool.refs || [],
      types: tool.type || [],
    }));
    
    // Parse external links and malware samples
    const externalLinks: APTExternalLink[] = [];
    const malwareSamples: APTMalwareSample[] = [];
    
    (props['ext-links'] || []).forEach((link: any) => {
      if (link.type === 'malwaresample') {
        malwareSamples.push({
          description: link.description || '',
          url: link.url || '',
          hash: extractHashFromUrl(link.url),
        });
      } else {
        externalLinks.push({
          description: link.description || '',
          url: link.url || '',
          type: link.type || 'web',
        });
      }
    });
    
    // Determine if active based on recent activity
    const firstSeen = props['first-seen'];
    const currentYear = new Date().getFullYear();
    const active = !firstSeen || parseInt(firstSeen.split('-')[0]) > currentYear - 5;
    
    return {
      id: `apt-${index}-${props.uuid.slice(0, 8)}`,
      uuid: props.uuid,
      name: props.name,
      aliases: props['other-names'] || [],
      description: props.description || `${props.name} is an advanced persistent threat group.`,
      country: getCountryFromCode(props.country),
      countryCode: props.country || '',
      location: props.location || '',
      sponsor: props.sponsor || undefined,
      motivations: props.motivations || [],
      firstSeen: props['first-seen'] || undefined,
      active,
      attributionConfidence: parseInt(props['attribution-confidence'] || '50'),
      
      targets: props.targets || [],
      targetCategories: props['target-category'] || [],
      
      ttps: props.TTP || [],
      tools,
      iocs: props.IOC || [],
      operations: props.operations || [],
      
      sources: props.sources || [],
      externalLinks,
      malwareSamples,
      
      coordinates: feature.geometry?.coordinates ? {
        lon: feature.geometry.coordinates[0],
        lat: feature.geometry.coordinates[1],
      } : undefined,
    };
  });
}

// Extract hash from VX-Underground URL
function extractHashFromUrl(url: string): string | undefined {
  if (!url) return undefined;
  const match = url.match(/([a-fA-F0-9]{32,64})\.7z$/);
  return match ? match[1] : undefined;
}

// Convert country code to full name
function getCountryFromCode(code: string): string {
  const countries: Record<string, string> = {
    'CN': 'China',
    'RU': 'Russia',
    'IR': 'Iran',
    'KP': 'North Korea',
    'US': 'United States',
    'IL': 'Israel',
    'PK': 'Pakistan',
    'IN': 'India',
    'VN': 'Vietnam',
    'TR': 'Turkey',
    'UA': 'Ukraine',
    'SY': 'Syria',
    'LB': 'Lebanon',
    'PS': 'Palestine',
    'EG': 'Egypt',
    'SA': 'Saudi Arabia',
    'AE': 'UAE',
    'BY': 'Belarus',
    'KR': 'South Korea',
    'JP': 'Japan',
    'TW': 'Taiwan',
    'HK': 'Hong Kong',
    'SG': 'Singapore',
    'MY': 'Malaysia',
    'TH': 'Thailand',
    'PH': 'Philippines',
    'ID': 'Indonesia',
    'AU': 'Australia',
    'NZ': 'New Zealand',
    'GB': 'United Kingdom',
    'DE': 'Germany',
    'FR': 'France',
    'IT': 'Italy',
    'ES': 'Spain',
    'NL': 'Netherlands',
    'BE': 'Belgium',
    'PL': 'Poland',
    'CZ': 'Czech Republic',
    'RO': 'Romania',
    'HU': 'Hungary',
    'BG': 'Bulgaria',
    'SE': 'Sweden',
    'NO': 'Norway',
    'DK': 'Denmark',
    'FI': 'Finland',
    'CH': 'Switzerland',
    'AT': 'Austria',
    'BR': 'Brazil',
    'MX': 'Mexico',
    'AR': 'Argentina',
    'CL': 'Chile',
    'CO': 'Colombia',
    'VE': 'Venezuela',
    'CA': 'Canada',
    'ZA': 'South Africa',
    'NG': 'Nigeria',
    'KE': 'Kenya',
  };
  return countries[code] || code || 'Unknown';
}

/* ============================================================================
   SEARCH & FILTER
============================================================================ */

export async function searchAPTGroups(query: string): Promise<APTSearchResult> {
  const groups = await fetchAPTMapData();
  const lowerQuery = query.toLowerCase();
  
  const filtered = groups.filter(group => {
    // Search in name and aliases
    if (group.name.toLowerCase().includes(lowerQuery)) return true;
    if (group.aliases.some(alias => alias.toLowerCase().includes(lowerQuery))) return true;
    
    // Search in description
    if (group.description.toLowerCase().includes(lowerQuery)) return true;
    
    // Search in country
    if (group.country.toLowerCase().includes(lowerQuery)) return true;
    
    // Search in targets
    if (group.targets.some(t => t.toLowerCase().includes(lowerQuery))) return true;
    if (group.targetCategories.some(t => t.toLowerCase().includes(lowerQuery))) return true;
    
    // Search in tools
    if (group.tools.some(t => t.name.toLowerCase().includes(lowerQuery))) return true;
    
    return false;
  });
  
  // Compute statistics
  const byCountry: Record<string, number> = {};
  const byTargetSector: Record<string, number> = {};
  let activeCount = 0;
  
  filtered.forEach(group => {
    // Count by country
    const country = group.country || 'Unknown';
    byCountry[country] = (byCountry[country] || 0) + 1;
    
    // Count by target sector
    group.targetCategories.forEach(sector => {
      byTargetSector[sector] = (byTargetSector[sector] || 0) + 1;
    });
    
    // Count active
    if (group.active) activeCount++;
  });
  
  return {
    groups: filtered,
    totalCount: filtered.length,
    byCountry,
    byTargetSector,
    activeGroups: activeCount,
    lastUpdated: new Date(),
  };
}

export async function getAPTGroupByName(name: string): Promise<APTGroup | null> {
  const groups = await fetchAPTMapData();
  const lowerName = name.toLowerCase();
  
  return groups.find(group => 
    group.name.toLowerCase() === lowerName ||
    group.aliases.some(alias => alias.toLowerCase() === lowerName)
  ) || null;
}

export async function getAPTGroupsByCountry(countryCode: string): Promise<APTGroup[]> {
  const groups = await fetchAPTMapData();
  return groups.filter(group => 
    group.countryCode === countryCode || 
    group.country.toLowerCase() === countryCode.toLowerCase()
  );
}

export async function getAPTGroupsByTargetSector(sector: string): Promise<APTGroup[]> {
  const groups = await fetchAPTMapData();
  const lowerSector = sector.toLowerCase();
  
  return groups.filter(group =>
    group.targetCategories.some(cat => cat.toLowerCase().includes(lowerSector))
  );
}

/* ============================================================================
   STATISTICS
============================================================================ */

export async function getAPTStats(): Promise<APTStats> {
  const groups = await fetchAPTMapData();
  
  const byCountry: Record<string, number> = {};
  const byMotivation: Record<string, number> = {};
  const targetSectorCounts: Record<string, number> = {};
  const targetCountryCounts: Record<string, number> = {};
  
  let totalTTPs = 0;
  let totalTools = 0;
  let totalMalwareSamples = 0;
  
  groups.forEach(group => {
    // Count by origin country
    const country = group.country || 'Unknown';
    byCountry[country] = (byCountry[country] || 0) + 1;
    
    // Count by motivation
    group.motivations.forEach(motivation => {
      byMotivation[motivation] = (byMotivation[motivation] || 0) + 1;
    });
    
    // Count target sectors
    group.targetCategories.forEach(sector => {
      targetSectorCounts[sector] = (targetSectorCounts[sector] || 0) + 1;
    });
    
    // Count target countries
    group.targets.forEach(target => {
      targetCountryCounts[target] = (targetCountryCounts[target] || 0) + 1;
    });
    
    // Sum TTPs, tools, samples
    totalTTPs += group.ttps.length;
    totalTools += group.tools.length;
    totalMalwareSamples += group.malwareSamples.length;
  });
  
  // Sort and get top items
  const topTargetSectors = Object.entries(targetSectorCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([sector, count]) => ({ sector, count }));
  
  const topTargetCountries = Object.entries(targetCountryCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([country, count]) => ({ country, count }));
  
  return {
    totalGroups: groups.length,
    byCountry,
    byMotivation,
    topTargetSectors,
    topTargetCountries,
    ttpsCount: totalTTPs,
    toolsCount: totalTools,
    malwareSamplesCount: totalMalwareSamples,
  };
}

/* ============================================================================
   THREAT MAP DATA
============================================================================ */

export interface APTThreatPoint {
  id: string;
  name: string;
  country: string;
  lat: number;
  lon: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  type: 'apt' | 'cybercrime' | 'hacktivist';
  aliasCount: number;
  toolsCount: number;
  targetsCount: number;
  active: boolean;
  description: string;
  ttps: string[];
}

export async function getAPTThreatMapData(): Promise<APTThreatPoint[]> {
  const groups = await fetchAPTMapData();
  
  return groups
    .filter(group => group.coordinates) // Only groups with known locations
    .map(group => {
      // Determine severity based on activity and targeting
      let severity: 'critical' | 'high' | 'medium' | 'low' = 'medium';
      
      if (group.active && group.tools.length > 5 && group.targets.length > 5) {
        severity = 'critical';
      } else if (group.active && (group.tools.length > 3 || group.targets.length > 3)) {
        severity = 'high';
      } else if (!group.active) {
        severity = 'low';
      }
      
      return {
        id: group.id,
        name: group.name,
        country: group.country,
        lat: group.coordinates!.lat,
        lon: group.coordinates!.lon,
        severity,
        type: 'apt' as const,
        aliasCount: group.aliases.length,
        toolsCount: group.tools.length,
        targetsCount: group.targets.length,
        active: group.active,
        description: group.description.slice(0, 200) + (group.description.length > 200 ? '...' : ''),
        ttps: group.ttps.slice(0, 5).map(t => t.techniqueID),
      };
    });
}

/* ============================================================================
   EXPORTS
============================================================================ */

export default {
  fetchAPTMapData,
  searchAPTGroups,
  getAPTGroupByName,
  getAPTGroupsByCountry,
  getAPTGroupsByTargetSector,
  getAPTStats,
  getAPTThreatMapData,
};
