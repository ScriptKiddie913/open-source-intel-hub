import { supabase } from "@/integrations/supabase/client";

export interface ThreatIntelResult {
  success: boolean;
  type: string;
  target: string;
  raw: Record<string, any>;
  formatted: FormattedThreatData | null;
  errors?: string[];
  timestamp: string;
}

export interface FormattedThreatData {
  summary: string;
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'info';
  riskScore: number;
  indicators: ThreatIndicator[];
  detections: {
    malicious: number;
    suspicious: number;
    clean: number;
    undetected: number;
  };
  categories: string[];
  recommendations: string[];
  metadata: {
    asn: string | null;
    country: string | null;
    owner: string | null;
    lastAnalysis: string | null;
  };
}

export interface ThreatIndicator {
  type: string;
  value: string;
  source: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

export async function queryThreatIntel(
  type: 'ip' | 'domain' | 'url' | 'hash' | 'email',
  target: string,
  sources: string[] = ['virustotal', 'abuse', 'circl']
): Promise<ThreatIntelResult> {
  try {
    const { data, error } = await supabase.functions.invoke('threat-intel', {
      body: { type, target, sources },
    });

    if (error) {
      throw new Error(error.message);
    }

    return data as ThreatIntelResult;
  } catch (error) {
    console.error('Threat intel query error:', error);
    throw error;
  }
}

// Free OSINT feeds - no API key required
export async function queryFreeThreatFeeds(type: string, target: string): Promise<Record<string, any>> {
  const results: Record<string, any> = {};

  try {
    // OpenPhish for phishing URLs
    if (type === 'url' || type === 'domain') {
      const openPhishResponse = await fetch('https://openphish.com/feed.txt');
      if (openPhishResponse.ok) {
        const phishData = await openPhishResponse.text();
        const phishUrls = phishData.split('\n').filter(u => u.includes(target));
        results.openphish = {
          matched: phishUrls.length > 0,
          matchedUrls: phishUrls.slice(0, 10),
        };
      }
    }
  } catch (error) {
    console.error('OpenPhish query failed:', error);
  }

  return results;
}

export function getRiskColor(level: string): string {
  switch (level) {
    case 'critical': return 'text-red-500';
    case 'high': return 'text-orange-500';
    case 'medium': return 'text-yellow-500';
    case 'low': return 'text-blue-500';
    default: return 'text-muted-foreground';
  }
}

export function getRiskBgColor(level: string): string {
  switch (level) {
    case 'critical': return 'bg-red-500/20 border-red-500';
    case 'high': return 'bg-orange-500/20 border-orange-500';
    case 'medium': return 'bg-yellow-500/20 border-yellow-500';
    case 'low': return 'bg-blue-500/20 border-blue-500';
    default: return 'bg-muted border-border';
  }
}
