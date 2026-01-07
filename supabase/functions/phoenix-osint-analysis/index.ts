// ============================================================================
// Phoenix OSINT Analysis Edge Function
// Powered by Lovable AI + Firecrawl for threat intelligence analysis
// ============================================================================

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface OSINTRequest {
  entityType: string;
  query: string;
  results: any;
  riskLevel: string;
  useWebSearch?: boolean;
  deepAnalysis?: boolean;
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { entityType, query, results, riskLevel, useWebSearch, deepAnalysis } = await req.json() as OSINTRequest;

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    const FIRECRAWL_API_KEY = Deno.env.get("FIRECRAWL_API_KEY");

    if (!LOVABLE_API_KEY) {
      throw new Error("LOVABLE_API_KEY is not configured");
    }

    // Prepare context for AI analysis
    let webContext = "";
    
    // Use Firecrawl for web search if available and requested
    if (useWebSearch && FIRECRAWL_API_KEY) {
      try {
        console.log("[Phoenix] Searching web for additional context...");
        
        const searchQuery = buildSearchQuery(entityType, query);
        const firecrawlResponse = await fetch("https://api.firecrawl.dev/v1/search", {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${FIRECRAWL_API_KEY}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            query: searchQuery,
            limit: 5,
            scrapeOptions: { formats: ["markdown"] },
          }),
        });

        if (firecrawlResponse.ok) {
          const searchData = await firecrawlResponse.json();
          if (searchData.data && searchData.data.length > 0) {
            webContext = "\n\nWeb Search Results:\n" + 
              searchData.data.map((r: any) => 
                `- ${r.title}: ${r.description || r.markdown?.substring(0, 200) || ''}`
              ).join("\n");
          }
        }
      } catch (e) {
        console.warn("[Phoenix] Web search failed:", e);
      }
    }

    // Build comprehensive prompt
    const systemPrompt = `You are Phoenix, an elite OSINT and threat intelligence analyst AI. You analyze security indicators and provide actionable intelligence.

Your analysis should be:
- Technical and precise
- Actionable with specific recommendations
- Structured with clear sections
- Risk-aware with appropriate severity levels

Entity types you handle:
- IP addresses: geolocation, reputation, associated threats
- Domains: DNS analysis, hosting info, certificate analysis
- File hashes: malware identification, threat attribution
- CVEs: vulnerability assessment, exploitation likelihood
- Emails: breach exposure, domain reputation
- Bitcoin addresses: transaction analysis, threat connections
- Usernames: platform presence, credential exposure

Always provide:
1. Summary of findings
2. Risk assessment
3. Specific recommendations
4. Related threats or indicators to investigate`;

    const userPrompt = buildAnalysisPrompt(entityType, query, results, riskLevel, webContext);

    console.log(`[Phoenix] Analyzing ${entityType}: ${query}`);

    // Call Lovable AI Gateway
    const aiResponse = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPrompt },
        ],
        temperature: 0.3,
        max_tokens: 2048,
      }),
    });

    if (!aiResponse.ok) {
      if (aiResponse.status === 429) {
        return new Response(
          JSON.stringify({ error: "Rate limit exceeded. Please try again in a moment." }),
          { status: 429, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }
      if (aiResponse.status === 402) {
        return new Response(
          JSON.stringify({ error: "AI credits exhausted. Please add credits to continue." }),
          { status: 402, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }
      
      const errorText = await aiResponse.text();
      console.error("[Phoenix] AI Gateway error:", aiResponse.status, errorText);
      throw new Error("AI analysis failed");
    }

    const aiData = await aiResponse.json();
    const analysis = aiData.choices?.[0]?.message?.content || "";

    console.log("[Phoenix] Analysis complete");

    return new Response(
      JSON.stringify({ 
        analysis,
        entityType,
        query,
        webSearchUsed: useWebSearch && !!FIRECRAWL_API_KEY,
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );

  } catch (error) {
    console.error("[Phoenix] Error:", error);
    const errorMessage = error instanceof Error ? error.message : "Unknown error";
    
    return new Response(
      JSON.stringify({ error: errorMessage }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function buildSearchQuery(entityType: string, query: string): string {
  const queryMap: Record<string, string> = {
    ip: `threat intelligence IP ${query} malware botnet`,
    domain: `${query} domain reputation security threats`,
    md5: `malware hash ${query} analysis`,
    sha1: `malware hash ${query} analysis`,
    sha256: `malware hash ${query} analysis threat`,
    sha512: `malware hash ${query} analysis`,
    cve: `${query} vulnerability exploit proof of concept`,
    email: `${query} breach data leak exposure`,
    bitcoin: `bitcoin address ${query} scam ransomware`,
    ethereum: `ethereum address ${query} scam fraud`,
    username: `${query} social media profiles`,
  };
  
  return queryMap[entityType] || `${query} cybersecurity threat intelligence`;
}

function buildAnalysisPrompt(
  entityType: string, 
  query: string, 
  results: any, 
  riskLevel: string,
  webContext: string
): string {
  let prompt = `Analyze this ${entityType} indicator: **${query}**

Risk Level Detected: ${riskLevel.toUpperCase()}

OSINT Results:
\`\`\`json
${JSON.stringify(results, null, 2)}
\`\`\``;

  if (webContext) {
    prompt += `\n${webContext}`;
  }

  prompt += `

Provide:
1. **Executive Summary** - 2-3 sentences on what this indicator represents
2. **Threat Assessment** - Technical analysis of the findings
3. **Risk Indicators** - Specific concerning elements found
4. **Recommended Actions** - Step-by-step mitigation or investigation steps
5. **Related Indicators** - Other IOCs to investigate

Format your response with markdown headers and bullet points for clarity.`;

  return prompt;
}
