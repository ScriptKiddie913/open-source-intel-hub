// ============================================================================
// ADVANCED GEOLOCATION SERVICE
// ============================================================================
// Enhanced IP geolocation with multiple API providers and smart fallback
// Provides higher accuracy, reliability, and performance for alert location data
// ============================================================================

import { cacheAPIResponse, getCachedData } from '@/lib/database';

/* ============================================================================
   TYPES & INTERFACES
============================================================================ */

export interface GeoLocation {
  country: string;
  countryCode: string;
  city: string;
  region: string;
  regionCode?: string;
  lat: number;
  lon: number;
  timezone?: string;
  isp?: string;
  org?: string;
  asn?: string;
  postal?: string;
  mobile?: boolean;
  proxy?: boolean;
  hosting?: boolean;
  accuracy?: 'high' | 'medium' | 'low';
  source?: string;
}

export interface GeoLocationBatch {
  [ip: string]: GeoLocation | null;
}

/* ============================================================================
   CONFIGURATION
============================================================================ */

const CACHE_TTL = 86400; // 24 hours for geolocation data
const REQUEST_TIMEOUT = 5000; // 5 seconds timeout
const RATE_LIMIT_DELAY = 150; // 150ms between requests

// API Providers in order of preference
enum GeoProvider {
  IPAPI_CO = 'ipapi.co',           // Best accuracy, HTTPS, no key needed (1000/day)
  IP_API_COM = 'ip-api.com',       // Good data, batch support (45/min)
  IPAPI_COM = 'ipapi.com',         // Requires key but very accurate
  IPINFO_IO = 'ipinfo.io',         // Reliable, requires key for details
  GEOJS = 'get.geojs.io',          // Free, no key, basic data
}

/* ============================================================================
   ADVANCED GEOLOCATION SERVICE CLASS
============================================================================ */

class AdvancedGeoLocationService {
  private requestQueue: Map<string, Promise<GeoLocation | null>> = new Map();
  private lastRequestTime: number = 0;
  private failedProviders: Set<GeoProvider> = new Set();
  private providerSuccessRates: Map<GeoProvider, number> = new Map();

  /**
   * Get geolocation for a single IP with smart caching and fallback
   */
  async getLocation(ip: string): Promise<GeoLocation | null> {
    // Check cache first
    const cacheKey = `geo:advanced:${ip}`;
    const cached = await getCachedData(cacheKey);
    if (cached) return cached;

    // Check if request is already in progress
    if (this.requestQueue.has(ip)) {
      return this.requestQueue.get(ip)!;
    }

    // Create new request
    const promise = this.fetchLocation(ip);
    this.requestQueue.set(ip, promise);

    try {
      const result = await promise;
      if (result) {
        await cacheAPIResponse(cacheKey, result, CACHE_TTL);
      }
      return result;
    } finally {
      this.requestQueue.delete(ip);
    }
  }

  /**
   * Batch geolocation lookup with parallel processing
   */
  async getLocationBatch(ips: string[]): Promise<GeoLocationBatch> {
    const uniqueIps = [...new Set(ips)];
    const results: GeoLocationBatch = {};

    // Process in batches of 10 to avoid overwhelming APIs
    const batchSize = 10;
    for (let i = 0; i < uniqueIps.length; i += batchSize) {
      const batch = uniqueIps.slice(i, i + batchSize);
      const batchResults = await Promise.all(
        batch.map(async (ip) => ({
          ip,
          location: await this.getLocation(ip),
        }))
      );

      batchResults.forEach(({ ip, location }) => {
        results[ip] = location;
      });

      // Rate limiting between batches
      if (i + batchSize < uniqueIps.length) {
        await this.delay(RATE_LIMIT_DELAY);
      }
    }

    return results;
  }

  /**
   * Fetch location with automatic provider fallback
   */
  private async fetchLocation(ip: string): Promise<GeoLocation | null> {
    // Validate IP format
    if (!this.isValidIP(ip)) {
      console.warn(`[GeoLocation] Invalid IP: ${ip}`);
      return null;
    }

    // Try providers in order of reliability
    const providers = this.getProviderOrder();

    for (const provider of providers) {
      if (this.failedProviders.has(provider)) {
        continue; // Skip temporarily failed providers
      }

      try {
        await this.delay(RATE_LIMIT_DELAY);
        const location = await this.fetchFromProvider(ip, provider);
        
        if (location) {
          this.updateProviderSuccess(provider, true);
          return location;
        }
      } catch (error) {
        console.warn(`[GeoLocation] ${provider} failed for ${ip}:`, error);
        this.updateProviderSuccess(provider, false);
        continue; // Try next provider
      }
    }

    console.error(`[GeoLocation] All providers failed for ${ip}`);
    return null;
  }

  /**
   * Fetch from specific provider
   */
  private async fetchFromProvider(
    ip: string,
    provider: GeoProvider
  ): Promise<GeoLocation | null> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);

    try {
      let response: Response;
      let data: any;

      switch (provider) {
        case GeoProvider.IPAPI_CO:
          response = await fetch(`https://ipapi.co/${ip}/json/`, {
            signal: controller.signal,
          });
          data = await response.json();
          if (data.error) throw new Error(data.reason || 'API Error');
          return this.normalizeIpApiCo(data);

        case GeoProvider.IP_API_COM:
          response = await fetch(
            `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,mobile,proxy,hosting`,
            { signal: controller.signal }
          );
          data = await response.json();
          if (data.status !== 'success') throw new Error(data.message || 'API Error');
          return this.normalizeIpApiCom(data);

        case GeoProvider.GEOJS:
          response = await fetch(`https://get.geojs.io/v1/ip/geo/${ip}.json`, {
            signal: controller.signal,
          });
          data = await response.json();
          return this.normalizeGeoJs(data);

        case GeoProvider.IPINFO_IO:
          response = await fetch(`https://ipinfo.io/${ip}/json`, {
            signal: controller.signal,
          });
          data = await response.json();
          if (data.error) throw new Error(data.error.message || 'API Error');
          return this.normalizeIpInfo(data);

        default:
          throw new Error(`Unknown provider: ${provider}`);
      }
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Normalize responses from different providers
   */
  private normalizeIpApiCo(data: any): GeoLocation {
    return {
      country: data.country_name || data.country || 'Unknown',
      countryCode: data.country_code || data.country || 'XX',
      city: data.city || 'Unknown',
      region: data.region || data.region_code || '',
      regionCode: data.region_code,
      lat: parseFloat(data.latitude) || 0,
      lon: parseFloat(data.longitude) || 0,
      timezone: data.timezone,
      isp: data.org,
      org: data.org,
      asn: data.asn,
      postal: data.postal,
      accuracy: 'high',
      source: GeoProvider.IPAPI_CO,
    };
  }

  private normalizeIpApiCom(data: any): GeoLocation {
    return {
      country: data.country || 'Unknown',
      countryCode: data.countryCode || 'XX',
      city: data.city || 'Unknown',
      region: data.regionName || data.region || '',
      regionCode: data.region,
      lat: data.lat || 0,
      lon: data.lon || 0,
      timezone: data.timezone,
      isp: data.isp,
      org: data.org,
      asn: data.as,
      mobile: data.mobile,
      proxy: data.proxy,
      hosting: data.hosting,
      accuracy: 'high',
      source: GeoProvider.IP_API_COM,
    };
  }

  private normalizeGeoJs(data: any): GeoLocation {
    return {
      country: data.country || 'Unknown',
      countryCode: data.country_code || 'XX',
      city: data.city || 'Unknown',
      region: data.region || '',
      lat: parseFloat(data.latitude) || 0,
      lon: parseFloat(data.longitude) || 0,
      timezone: data.timezone,
      org: data.organization_name,
      accuracy: 'medium',
      source: GeoProvider.GEOJS,
    };
  }

  private normalizeIpInfo(data: any): GeoLocation {
    const [lat, lon] = (data.loc || '0,0').split(',').map(parseFloat);
    return {
      country: data.country || 'Unknown',
      countryCode: data.country || 'XX',
      city: data.city || 'Unknown',
      region: data.region || '',
      lat: lat || 0,
      lon: lon || 0,
      timezone: data.timezone,
      org: data.org,
      postal: data.postal,
      accuracy: 'medium',
      source: GeoProvider.IPINFO_IO,
    };
  }

  /**
   * Get provider order based on success rates
   */
  private getProviderOrder(): GeoProvider[] {
    const providers = [
      GeoProvider.IPAPI_CO,
      GeoProvider.IP_API_COM,
      GeoProvider.GEOJS,
      GeoProvider.IPINFO_IO,
    ];

    // Sort by success rate (if we have data)
    return providers.sort((a, b) => {
      const rateA = this.providerSuccessRates.get(a) || 1;
      const rateB = this.providerSuccessRates.get(b) || 1;
      return rateB - rateA;
    });
  }

  /**
   * Update provider success tracking
   */
  private updateProviderSuccess(provider: GeoProvider, success: boolean): void {
    const currentRate = this.providerSuccessRates.get(provider) || 1;
    const newRate = success
      ? Math.min(currentRate + 0.1, 1)
      : Math.max(currentRate - 0.2, 0);
    
    this.providerSuccessRates.set(provider, newRate);

    // Temporarily mark as failed if success rate drops too low
    if (newRate < 0.3) {
      this.failedProviders.add(provider);
      // Re-enable after 5 minutes
      setTimeout(() => {
        this.failedProviders.delete(provider);
        this.providerSuccessRates.set(provider, 0.5);
      }, 300000);
    }
  }

  /**
   * Validate IP address format
   */
  private isValidIP(ip: string): boolean {
    // IPv4
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(ip)) {
      const parts = ip.split('.').map(Number);
      return parts.every((part) => part >= 0 && part <= 255);
    }

    // IPv6 (basic check)
    const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
    return ipv6Regex.test(ip);
  }

  /**
   * Rate limiting helper
   */
  private async delay(ms: number): Promise<void> {
    const now = Date.now();
    const timeSinceLastRequest = now - this.lastRequestTime;
    
    if (timeSinceLastRequest < ms) {
      await new Promise((resolve) => setTimeout(resolve, ms - timeSinceLastRequest));
    }
    
    this.lastRequestTime = Date.now();
  }

  /**
   * Get service statistics
   */
  getStats(): {
    providers: Array<{ name: string; successRate: number; failed: boolean }>;
    cacheSize: number;
    queueSize: number;
  } {
    return {
      providers: Array.from(this.providerSuccessRates.entries()).map(
        ([name, rate]) => ({
          name,
          successRate: Math.round(rate * 100),
          failed: this.failedProviders.has(name),
        })
      ),
      cacheSize: 0, // Would need to query IndexedDB
      queueSize: this.requestQueue.size,
    };
  }

  /**
   * Reset provider failure tracking
   */
  resetProviderTracking(): void {
    this.failedProviders.clear();
    this.providerSuccessRates.clear();
  }
}

/* ============================================================================
   EXPORTS
============================================================================ */

// Singleton instance
const geoLocationService = new AdvancedGeoLocationService();

/**
 * Get geolocation for a single IP address
 */
export async function getAdvancedGeoLocation(ip: string): Promise<GeoLocation | null> {
  return geoLocationService.getLocation(ip);
}

/**
 * Get geolocation for multiple IP addresses in batch
 */
export async function getAdvancedGeoLocationBatch(ips: string[]): Promise<GeoLocationBatch> {
  return geoLocationService.getLocationBatch(ips);
}

/**
 * Get service statistics
 */
export function getGeoLocationStats() {
  return geoLocationService.getStats();
}

/**
 * Reset provider tracking (useful for debugging/testing)
 */
export function resetGeoLocationProviders() {
  geoLocationService.resetProviderTracking();
}

// Default export
export default geoLocationService;
