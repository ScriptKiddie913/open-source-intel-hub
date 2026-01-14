import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

interface ThreatIntelRequest {
  type: 'ip' | 'domain' | 'url' | 'hash' | 'email';
  target: string;
  sources?: string[];
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { type, target, sources = ['virustotal', 'abuse', 'circl'] } = await req.json() as ThreatIntelRequest;
    
    console.log(`Threat intel request: ${type} - ${target}`);
    
    const results: Record<string, any> = {};
    const errors: string[] = [];
    
    // VirusTotal API
    if (sources.includes('virustotal')) {
      const vtResult = await queryVirusTotal(type, target);
      if (vtResult.error) {
        errors.push(`VirusTotal: ${vtResult.error}`);
      } else {
        results.virustotal = vtResult;
      }
    }
    
    // Abuse.ch feeds
    if (sources.includes('abuse')) {
      const abuseResult = await queryAbuseCh(type, target);
      if (abuseResult.error) {
        errors.push(`Abuse.ch: ${abuseResult.error}`);
      } else {
        results.abuse = abuseResult;
      }
    }
    
    // CIRCL Hashlookup
    if (sources.includes('circl') && type === 'hash') {
      const circlResult = await queryCirclHashlookup(target);
      if (circlResult.error) {
        errors.push(`CIRCL: ${circlResult.error}`);
      } else {
        results.circl = circlResult;
      }
    }
    
    // URLhaus for URLs
    if (sources.includes('urlhaus') && type === 'url') {
      const urlhausResult = await queryUrlhaus(target);
      if (urlhausResult.error) {
        errors.push(`URLhaus: ${urlhausResult.error}`);
      } else {
        results.urlhaus = urlhausResult;
      }
    }
    
    // Use AI to format the data into a structured table format
    const formattedData = await formatWithAI(type, target, results);
    
    return new Response(JSON.stringify({
      success: true,
      type,
      target,
      raw: results,
      formatted: formattedData,
      errors: errors.length > 0 ? errors : undefined,
      timestamp: new Date().toISOString(),
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
    
  } catch (error) {
    console.error('Threat intel error:', error);
    return new Response(JSON.stringify({ 
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error' 
    }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});

async function queryVirusTotal(type: string, target: string): Promise<any> {
  const apiKey = Deno.env.get('VIRUSTOTAL_API_KEY');
  if (!apiKey) {
    return { error: 'VirusTotal API key not configured' };
  }
  
  let endpoint = '';
  switch (type) {
    case 'ip':
      endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${target}`;
      break;
    case 'domain':
      endpoint = `https://www.virustotal.com/api/v3/domains/${target}`;
      break;
    case 'url':
      const urlId = btoa(target).replace(/=/g, '');
      endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
      break;
    case 'hash':
      endpoint = `https://www.virustotal.com/api/v3/files/${target}`;
      break;
    default:
      return { error: `Unsupported type: ${type}` };
  }
  
  try {
    console.log(`Querying VirusTotal: ${endpoint}`);
    const response = await fetch(endpoint, {
      headers: {
        'x-apikey': apiKey,
        'Accept': 'application/json',
      },
    });
    
    if (!response.ok) {
      if (response.status === 404) {
        return { found: false, message: 'Not found in VirusTotal database' };
      }
      const errorText = await response.text();
      console.error(`VirusTotal error: ${response.status} - ${errorText}`);
      return { error: `API error: ${response.status}` };
    }
    
    const data = await response.json();
    return {
      found: true,
      data: data.data,
      attributes: data.data?.attributes,
    };
  } catch (error) {
    console.error('VirusTotal fetch error:', error);
    return { error: error instanceof Error ? error.message : 'Fetch failed' };
  }
}

async function queryAbuseCh(type: string, target: string): Promise<any> {
  try {
    const results: any = { matched: false, sources: [] };
    
    // Check Feodo Tracker for IPs
    if (type === 'ip') {
      const feodoResponse = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist.txt');
      if (feodoResponse.ok) {
        const feodoData = await feodoResponse.text();
        if (feodoData.includes(target)) {
          results.matched = true;
          results.sources.push({
            name: 'Feodo Tracker',
            type: 'Botnet C2',
            risk: 'high',
          });
        }
      }
    }
    
    // Check SSL Blacklist
    if (type === 'ip') {
      const sslResponse = await fetch('https://sslbl.abuse.ch/blacklist/sslipblacklist.txt');
      if (sslResponse.ok) {
        const sslData = await sslResponse.text();
        if (sslData.includes(target)) {
          results.matched = true;
          results.sources.push({
            name: 'SSL Blacklist',
            type: 'Malicious SSL',
            risk: 'high',
          });
        }
      }
    }
    
    // Check Spamhaus DROP
    if (type === 'ip') {
      const spamhausResponse = await fetch('https://www.spamhaus.org/drop/drop.txt');
      if (spamhausResponse.ok) {
        const spamhausData = await spamhausResponse.text();
        // Check if IP falls in any CIDR range (simplified - checks prefix)
        const ipPrefix = target.split('.').slice(0, 2).join('.');
        if (spamhausData.includes(ipPrefix)) {
          results.matched = true;
          results.sources.push({
            name: 'Spamhaus DROP',
            type: 'Known Bad IP Range',
            risk: 'critical',
          });
        }
      }
    }
    
    return results;
  } catch (error) {
    console.error('Abuse.ch query error:', error);
    return { error: error instanceof Error ? error.message : 'Query failed' };
  }
}

async function queryCirclHashlookup(hash: string): Promise<any> {
  try {
    // Determine hash type
    let hashType = 'sha256';
    if (hash.length === 32) hashType = 'md5';
    else if (hash.length === 40) hashType = 'sha1';
    
    const response = await fetch(`https://hashlookup.circl.lu/lookup/${hashType}/${hash}`);
    
    if (!response.ok) {
      if (response.status === 404) {
        return { found: false, message: 'Hash not found in CIRCL database' };
      }
      return { error: `API error: ${response.status}` };
    }
    
    const data = await response.json();
    return {
      found: true,
      filename: data.FileName,
      filesize: data.FileSize,
      knownSource: data.KnownMalicious ? 'malicious' : 'benign',
      md5: data.MD5,
      sha1: data.SHA1,
      sha256: data.SHA256,
    };
  } catch (error) {
    console.error('CIRCL query error:', error);
    return { error: error instanceof Error ? error.message : 'Query failed' };
  }
}

async function queryUrlhaus(url: string): Promise<any> {
  try {
    const response = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `url=${encodeURIComponent(url)}`,
    });
    
    if (!response.ok) {
      return { error: `API error: ${response.status}` };
    }
    
    const data = await response.json();
    return {
      found: data.query_status === 'ok',
      status: data.url_status,
      threat: data.threat,
      dateAdded: data.date_added,
      tags: data.tags,
    };
  } catch (error) {
    console.error('URLhaus query error:', error);
    return { error: error instanceof Error ? error.message : 'Query failed' };
  }
}

async function formatWithAI(type: string, target: string, results: Record<string, any>): Promise<any> {
  const lovableApiKey = Deno.env.get('LOVABLE_API_KEY');
  if (!lovableApiKey) {
    console.log('LOVABLE_API_KEY not configured, returning unformatted results');
    return null;
  }
  
  const prompt = `You are a cybersecurity analyst. Analyze the following threat intelligence data and format it into a structured JSON response.

Target: ${target}
Type: ${type}

Raw Data:
${JSON.stringify(results, null, 2)}

Return a JSON object with this exact structure:
{
  "summary": "One sentence threat summary",
  "riskLevel": "critical|high|medium|low|info",
  "riskScore": 0-100,
  "indicators": [
    {
      "type": "string (e.g., 'malicious_detection', 'reputation', 'association')",
      "value": "string",
      "source": "string",
      "severity": "critical|high|medium|low|info"
    }
  ],
  "detections": {
    "malicious": number,
    "suspicious": number,
    "clean": number,
    "undetected": number
  },
  "categories": ["array of threat categories"],
  "recommendations": ["array of security recommendations"],
  "metadata": {
    "asn": "string or null",
    "country": "string or null",
    "owner": "string or null",
    "lastAnalysis": "ISO date string or null"
  }
}

IMPORTANT: Return ONLY valid JSON, no markdown or explanation.`;

  try {
    const response = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${lovableApiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'google/gemini-2.5-flash',
        messages: [
          { role: 'system', content: 'You are a cybersecurity threat intelligence analyst. Always respond with valid JSON only.' },
          { role: 'user', content: prompt },
        ],
        temperature: 0.1,
      }),
    });
    
    if (!response.ok) {
      console.error('AI formatting failed:', response.status);
      return null;
    }
    
    const data = await response.json();
    const content = data.choices?.[0]?.message?.content;
    
    if (!content) {
      console.error('No AI response content');
      return null;
    }
    
    // Parse JSON from response (handle potential markdown code blocks)
    let jsonStr = content.trim();
    if (jsonStr.startsWith('```json')) {
      jsonStr = jsonStr.slice(7);
    }
    if (jsonStr.startsWith('```')) {
      jsonStr = jsonStr.slice(3);
    }
    if (jsonStr.endsWith('```')) {
      jsonStr = jsonStr.slice(0, -3);
    }
    
    return JSON.parse(jsonStr.trim());
  } catch (error) {
    console.error('AI formatting error:', error);
    return null;
  }
}
