// ============================================================================
// Phoenix Chat Edge Function
// Main chat endpoint for Phoenix AI assistant with OSINT integration
// ============================================================================

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface ChatMessage {
  role: "user" | "assistant" | "system";
  content: string;
}

interface ChatRequest {
  messages: ChatMessage[];
  osintContext?: {
    entityType: string;
    results: any;
    summary: string;
    riskLevel: string;
  };
  useWebSearch?: boolean;
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { messages, osintContext, useWebSearch } = await req.json() as ChatRequest;

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    const FIRECRAWL_API_KEY = Deno.env.get("FIRECRAWL_API_KEY");

    if (!LOVABLE_API_KEY) {
      throw new Error("LOVABLE_API_KEY is not configured");
    }

    // Build system prompt with OSINT context
    let systemPrompt = `You are Phoenix, an elite OSINT and cyber threat intelligence AI assistant integrated with multiple intelligence modules.

Your capabilities include:
- **IP Analysis**: Geolocation, reputation, open ports, vulnerabilities
- **Domain Intelligence**: DNS records, SSL certificates, subdomains, WHOIS
- **Hash Analysis**: Malware identification via MalwareBazaar, threat attribution
- **CVE Research**: Vulnerability details, exploit availability, CISA KEV status
- **Email Investigation**: Breach checking, domain analysis, dark web exposure
- **Bitcoin Tracing**: Transaction analysis, risk scoring, exchange identification
- **Username OSINT**: Platform enumeration, social media presence

When users provide indicators (IPs, domains, hashes, CVEs, emails, Bitcoin addresses, usernames), you can:
1. Automatically detect the entity type
2. Query relevant OSINT modules
3. Provide detailed threat intelligence analysis
4. Recommend next investigation steps

Response Guidelines:
- Be technical but accessible
- Use structured formatting (headers, bullets, code blocks)
- Provide confidence levels for assessments
- Always suggest related indicators to investigate
- Include specific remediation steps when threats are found`;

    // Add OSINT context if available
    if (osintContext) {
      systemPrompt += `

CURRENT INVESTIGATION CONTEXT:
Entity Type: ${osintContext.entityType}
Risk Level: ${osintContext.riskLevel.toUpperCase()}
Summary: ${osintContext.summary}

OSINT Results:
\`\`\`json
${JSON.stringify(osintContext.results, null, 2).substring(0, 3000)}
\`\`\`

Use this context to answer user questions about the investigation.`;
    }

    // Optional: Enhance with web search using Firecrawl
    let webEnhancement = "";
    if (useWebSearch && FIRECRAWL_API_KEY) {
      const lastUserMessage = messages.filter(m => m.role === "user").pop();
      if (lastUserMessage) {
        try {
          console.log("[Phoenix Chat] Performing web search...");
          const searchResponse = await fetch("https://api.firecrawl.dev/v1/search", {
            method: "POST",
            headers: {
              "Authorization": `Bearer ${FIRECRAWL_API_KEY}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({
              query: `${lastUserMessage.content} cybersecurity threat intelligence`,
              limit: 3,
            }),
          });

          if (searchResponse.ok) {
            const searchData = await searchResponse.json();
            if (searchData.data?.length > 0) {
              webEnhancement = "\n\nRecent Web Intelligence:\n" +
                searchData.data.map((r: any) => `- ${r.title}: ${r.description || ''}`).join("\n");
            }
          }
        } catch (e) {
          console.warn("[Phoenix Chat] Web search failed:", e);
        }
      }
    }

    if (webEnhancement) {
      systemPrompt += webEnhancement;
    }

    console.log("[Phoenix Chat] Processing message...");

    // Call Lovable AI (non-streaming for compatibility)
    const aiResponse = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-2.0-flash-exp",
        messages: [
          { role: "system", content: systemPrompt },
          ...messages,
        ],
        stream: false,
        temperature: 0.4,
        max_tokens: 4096,
      }),
    });

    if (!aiResponse.ok) {
      if (aiResponse.status === 429) {
        return new Response(
          JSON.stringify({ error: "Rate limit exceeded. Please wait a moment and try again." }),
          { status: 429, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }
      if (aiResponse.status === 402) {
        return new Response(
          JSON.stringify({ error: "AI credits exhausted. Please add credits to your workspace." }),
          { status: 402, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }
      if (aiResponse.status === 401) {
        return new Response(
          JSON.stringify({ error: "API key is invalid or expired. Please check your Lovable API configuration." }),
          { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      const errorText = await aiResponse.text();
      console.error("[Phoenix Chat] AI error:", aiResponse.status, errorText);
      throw new Error("AI service unavailable");
    }

    // Parse and return the response
    const result = await aiResponse.json();
    console.log("[Phoenix Chat] Response received", JSON.stringify(result).substring(0, 200));
    
    // Extract the actual content from the AI response
    let content = "";
    if (result.choices && Array.isArray(result.choices) && result.choices.length > 0) {
      content = result.choices[0]?.message?.content || result.choices[0]?.text || "";
    } else if (result.content) {
      content = result.content;
    } else if (result.message) {
      content = result.message;
    }
    
    if (!content) {
      console.error("[Phoenix Chat] No content found in response:", result);
      return new Response(
        JSON.stringify({ error: "No content in AI response" }),
        { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }
    
    // Return a simplified response with just the content
    return new Response(JSON.stringify({ content }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  } catch (error) {
    console.error("[Phoenix Chat] Error:", error);
    const errorMessage = error instanceof Error ? error.message : "Unknown error";

    return new Response(
      JSON.stringify({ error: errorMessage }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
