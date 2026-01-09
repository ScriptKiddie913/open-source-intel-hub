// src/pages/Dashboard.tsx
import { Routes, Route, Navigate } from "react-router-dom";
import { useEffect, useState, useRef, useCallback, MouseEvent } from "react";

import { OSINTSidebar } from "@/components/osint/OSINTSidebar";
import { Dashboard as DashboardHome } from "@/components/osint/Dashboard";
import { DataImporter } from "@/components/osint/DataImporter";
import { SettingsPage } from "@/components/osint/SettingsPage";
import { ThreatIntelSearch } from "@/components/osint/ThreatIntelSearch";
import { CVEExplorer } from "@/components/osint/CVEExplorer";
import { LiveThreatFeed } from "@/components/osint/LiveThreatFeed";
import { LiveThreatMap } from "@/components/osint/LiveThreatMap";

// NEW IMPORTS
import { UsernameEnumeration } from "@/components/osint/UsernameEnumeration";
import { DarkWebScanner } from "@/components/osint/DarkWebScanner";
import { GraphVisualization } from "@/components/osint/GraphVisualization";
import { NewsIntelligence } from "@/components/osint/NewsIntelligence";
import { TelegramIntelligence } from "@/components/osint/TelegramIntelligence";
import MalwarePipeline from "@/components/osint/MalwarePipeline";
import { StealthMoleScanner } from "@/components/osint/StealthMoleScanner";
import { MonitoringDashboard } from "@/components/osint/MonitoringDashboard";
import { SearchHistoryPage } from "@/components/osint/SearchHistoryPage";
import { PanicButton } from "@/components/osint/PanicButton";
import { ReportButton } from "@/components/osint/ReportButton";

import { useAuth } from "@/hooks/useAuth";
import { useIsMobile } from "@/hooks/use-mobile";
import { initDatabase } from "@/lib/database";
import { cn } from "@/lib/utils";
import { Loader2, Menu } from "lucide-react";
import { LanguageSelector } from "@/components/LanguageSelector";

// OSINT Integration
import { processOSINTQuery, OSINTResult } from "@/services/osintIntegrationService";
import { detectEntityType, getEntityLabel } from "@/services/entityDetectionService";

// Perplexity API Configuration
const PERPLEXITY_API_KEY = "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";
const PERPLEXITY_API_URL = "https://api.perplexity.ai/chat/completions";

import {
  Bot,
  Send,
  X,
  Maximize2,
  Minimize2,
  Sparkles,
  Shield,
  Zap,
  Terminal,
  Radio,
  Trash2,
  Copy,
  Check,
  Brain,
  Search,
  Globe,
  AlertTriangle,
  FileSearch,
  Skull,
  Bug,
  Network,
  MessageCircle,
  Server,
  Hash,
  Bitcoin,
  Mail,
  AtSign,
} from "lucide-react";

type ChatMessage = {
  role: "user" | "assistant";
  content: string;
  timestamp?: Date;
  osintResult?: OSINTResult;
  entityType?: string;
};

// Quick prompts for common OSINT queries
const QUICK_PROMPTS = [
  { icon: AlertTriangle, label: "Threat Intel", prompt: "What are the latest critical CVEs this week?" },
  { icon: Bug, label: "Malware", prompt: "Tell me about recent ransomware campaigns" },
  { icon: Globe, label: "APT Groups", prompt: "Which APT groups are most active currently?" },
  { icon: Skull, label: "Dark Web", prompt: "What are common dark web threat indicators?" },
  { icon: Network, label: "IOCs", prompt: "How do I analyze suspicious IP addresses?" },
  { icon: FileSearch, label: "OSINT Tips", prompt: "What are best practices for OSINT investigation?" },
];

function renderMessage(text: string) {
  // Enhanced message rendering with code blocks, links, and formatting
  const parts = text.split(/(\`\`\`[\s\S]*?\`\`\`|\`[^`]+\`|https?:\/\/[^\s]+|\*\*[^*]+\*\*|\n)/g);
  
  return parts.map((part, i) => {
    // Code blocks
    if (part.startsWith('```') && part.endsWith('```')) {
      const code = part.slice(3, -3).replace(/^\w+\n/, '');
      return (
        <pre key={i} className="bg-black/40 border border-primary/20 rounded-lg p-3 my-2 overflow-x-auto text-xs font-mono text-green-400">
          {code}
        </pre>
      );
    }
    // Inline code
    if (part.startsWith('`') && part.endsWith('`')) {
      return (
        <code key={i} className="bg-primary/20 text-primary px-1.5 py-0.5 rounded text-xs font-mono">
          {part.slice(1, -1)}
        </code>
      );
    }
    // Links
    if (part.match(/^https?:\/\//)) {
      return (
        <a
          key={i}
          href={part}
          target="_blank"
          rel="noopener noreferrer"
          className="text-cyan-400 hover:text-cyan-300 underline underline-offset-2 break-all transition-colors"
        >
          {part}
        </a>
      );
    }
    // Bold text
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={i} className="text-primary font-semibold">{part.slice(2, -2)}</strong>;
    }
    // Newlines
    if (part === '\n') {
      return <br key={i} />;
    }
    return <span key={i}>{part}</span>;
  });
}

function FloatingPerplexityChat() {
  const [open, setOpen] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [position, setPosition] = useState({ x: 24, y: 24 });
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);
  const [showQuickPrompts, setShowQuickPrompts] = useState(true);

  const dragging = useRef(false);
  const offset = useRef({ x: 0, y: 0 });
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Auto-scroll to bottom
  const scrollToBottom = useCallback(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages, scrollToBottom]);

  // Focus input when opening
  useEffect(() => {
    if (open) {
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  }, [open]);

  const onMouseDown = (e: MouseEvent) => {
    if (expanded) return;
    dragging.current = true;
    offset.current = {
      x: e.clientX - position.x,
      y: e.clientY - position.y,
    };
  };

  const onMouseMove = (e: globalThis.MouseEvent) => {
    if (!dragging.current || expanded) return;
    e.preventDefault();
    const nextX = e.clientX - offset.current.x;
    const nextY = e.clientY - offset.current.y;
    setPosition({
      x: Math.max(8, Math.min(nextX, window.innerWidth - 80)),
      y: Math.max(8, Math.min(nextY, window.innerHeight - 80)),
    });
  };

  const onMouseUp = () => {
    dragging.current = false;
  };

  useEffect(() => {
    window.addEventListener("mousemove", onMouseMove as EventListener);
    window.addEventListener("mouseup", onMouseUp);
    return () => {
      window.removeEventListener("mousemove", onMouseMove as EventListener);
      window.removeEventListener("mouseup", onMouseUp);
    };
  }, []);

  const copyToClipboard = async (text: string, index: number) => {
    await navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const clearChat = () => {
    setMessages([]);
    setShowQuickPrompts(true);
  };

  const sendMessage = async (customPrompt?: string) => {
    const messageText = customPrompt || input.trim();
    if (!messageText) return;

    const userMsg: ChatMessage = {
      role: "user",
      content: messageText,
      timestamp: new Date(),
    };

    setMessages((m) => [...m, userMsg]);
    setInput("");
    setLoading(true);
    setShowQuickPrompts(false);

    try {
      // Detect if input is a specific entity (IP, domain, hash, CVE, email, BTC, etc.)
      const entity = detectEntityType(messageText.trim());
      
      let reply = "";
      let osintResult: OSINTResult | undefined;
      
      if (entity.confidence >= 70 && entity.type !== 'unknown') {
        // Run OSINT query for specific entities
        console.log(`[Phoenix] Detected ${entity.type}: ${entity.normalized}`);
        
        osintResult = await processOSINTQuery({
          input: entity.normalized,
          includeAI: true,
          deepScan: entity.type === 'bitcoin' || entity.type === 'cve',
        });
        
        reply = `## ${getEntityLabel(entity.type)} Analysis\n\n`;
        reply += `**Query:** \`${entity.normalized}\`\n`;
        reply += `**Risk Level:** ${osintResult.riskLevel.toUpperCase()}\n\n`;
        reply += `### Summary\n${osintResult.summary}\n\n`;
        
        if (osintResult.recommendations.length > 0) {
          reply += `### Recommendations\n`;
          osintResult.recommendations.forEach((rec, i) => {
            reply += `${i + 1}. ${rec}\n`;
          });
        }
        
        if (osintResult.modulesUsed.length > 0) {
          reply += `\n*Modules: ${osintResult.modulesUsed.join(', ')}*`;
        }
      } else {
        // Use Phoenix AI chat via Perplexity API directly
        console.log('[Phoenix] Sending message to Perplexity API...');
        
        const systemPrompt = `You are Phoenix, an advanced OSINT (Open Source Intelligence) and cybersecurity assistant. You specialize in:
- Threat intelligence analysis
- CVE and vulnerability research
- Malware analysis and indicators of compromise (IOCs)
- Dark web monitoring insights
- APT group tracking and attribution
- Network security and IP/domain analysis
- Cyber attack patterns and TTPs (Tactics, Techniques, and Procedures)

Provide accurate, actionable intelligence. Use technical terminology appropriately. When discussing threats, include relevant IOCs, MITRE ATT&CK references, and mitigation recommendations where applicable. Always cite sources when possible.`;

        const response = await fetch(PERPLEXITY_API_URL, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${PERPLEXITY_API_KEY}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: 'sonar-pro',
            messages: [
              { role: 'system', content: systemPrompt },
              ...messages.map(m => ({ role: m.role, content: m.content })),
              { role: 'user', content: messageText },
            ],
            temperature: 0.2,
            top_p: 0.9,
            search_domain_filter: [],
            return_images: false,
            return_related_questions: false,
            search_recency_filter: "month",
            frequency_penalty: 1,
          }),
        });

        console.log('[Phoenix] Response status:', response.status);
        
        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          console.error('[Phoenix] API error:', response.status, errorData);
          
          if (response.status === 401) {
            throw new Error('API authentication failed. Invalid API key.');
          } else if (response.status === 429) {
            throw new Error('Rate limit exceeded. Please wait before trying again.');
          } else if (response.status === 402) {
            throw new Error('API credits exhausted. Please check your subscription.');
          } else {
            throw new Error(errorData.error?.message || `API request failed with status ${response.status}`);
          }
        }
        
        const data = await response.json();
        console.log('[Phoenix] Response data:', data);
        
        if (data.choices && data.choices[0]?.message?.content) {
          reply = data.choices[0].message.content;
        } else {
          throw new Error('Unexpected response format from Perplexity API');
        }
      }

      setMessages((m) => [
        ...m,
        { role: "assistant", content: reply, timestamp: new Date(), osintResult },
      ]);
    } catch (err) {
      console.error('[Phoenix] Error:', err);
      const errorMessage = err instanceof Error ? err.message : 'Unknown error occurred';
      
      let userFriendlyMessage = "⚠️ Connection to intelligence service failed.";
      
      // Provide specific error messages
      if (errorMessage.includes('Rate limit') || errorMessage.includes('429')) {
        userFriendlyMessage = '⚠️ Rate limit reached. Please wait a moment before trying again.';
      } else if (errorMessage.includes('credits') || errorMessage.includes('402')) {
        userFriendlyMessage = '⚠️ API credits exhausted. Please check your Perplexity subscription.';
      } else if (errorMessage.includes('API key') || errorMessage.includes('401') || errorMessage.includes('Unauthorized')) {
        userFriendlyMessage = '⚠️ API authentication failed. Please check your Perplexity API key.';
      } else if (errorMessage.includes('network') || errorMessage.includes('fetch') || errorMessage.includes('Failed to connect')) {
        userFriendlyMessage = '⚠️ Network error. Please check your connection and try again.';
      }
      
      setMessages((m) => [
        ...m,
        {
          role: "assistant",
          content: `${userFriendlyMessage}\n\n**Error details:** ${errorMessage}`,
          timestamp: new Date(),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  // Floating button when closed
  if (!open) {
    return (
      <button
        className="fixed bottom-4 right-4 sm:bottom-6 sm:right-6 z-50 group"
        onClick={() => setOpen(true)}
        title="Open Phoenix Intelligence Assistant"
      >
        <div className="relative">
          {/* Outer glow ring */}
          <div className="absolute inset-0 rounded-full bg-gradient-to-r from-cyan-500 via-primary to-purple-500 opacity-75 blur-lg group-hover:opacity-100 transition-opacity animate-pulse" />
          
          {/* Main button */}
          <div className="relative flex items-center gap-2 px-3 py-2 sm:px-4 sm:py-3 rounded-full bg-gradient-to-r from-slate-900 to-slate-800 border border-primary/50 shadow-2xl shadow-primary/25 hover:shadow-primary/50 transition-all duration-300 group-hover:scale-105">
            <div className="relative">
              <Brain className="h-4 w-4 sm:h-5 sm:w-5 text-cyan-400" />
              <div className="absolute -top-1 -right-1 w-2 h-2 bg-green-500 rounded-full animate-pulse" />
            </div>
            <span className="text-xs sm:text-sm font-semibold bg-gradient-to-r from-cyan-400 to-primary bg-clip-text text-transparent">
              PHOENIX
            </span>
            <Sparkles className="h-3 w-3 sm:h-4 sm:w-4 text-primary animate-pulse" />
          </div>
        </div>
      </button>
    );
  }

  return (
    <div
      className={cn(
        "fixed z-[9999] transition-all duration-300",
        expanded
          ? "inset-0 flex items-center justify-center bg-black/60 backdrop-blur-sm"
          : ""
      )}
    >
      <div
        className={cn(
          "flex flex-col overflow-hidden transition-all duration-300",
          "bg-gradient-to-b from-slate-900 via-slate-900 to-slate-950",
          "border border-primary/30 rounded-2xl",
          "shadow-2xl shadow-primary/20",
          expanded
            ? "w-full h-full sm:w-[800px] sm:h-[85vh] max-w-[95vw]"
            : "w-full h-[70vh] sm:w-[380px] sm:h-[520px] max-w-[95vw]"
        )}
        style={
          expanded
            ? undefined
            : { 
                left: typeof window !== 'undefined' && window.innerWidth < 640 ? 0 : position.x, 
                bottom: typeof window !== 'undefined' && window.innerWidth < 640 ? 0 : position.y, 
                position: "fixed"
              }
        }
      >
        {/* Header */}
        <div
          className={cn(
            "flex items-center justify-between px-4 py-3",
            "bg-gradient-to-r from-primary/10 via-transparent to-cyan-500/10",
            "border-b border-primary/20 cursor-move select-none"
          )}
          onMouseDown={onMouseDown}
        >
          <div className="flex items-center gap-3">
            <div className="relative">
              <div className="absolute inset-0 bg-primary/50 rounded-lg blur-md" />
              <div className="relative p-2 bg-gradient-to-br from-primary/20 to-cyan-500/20 rounded-lg border border-primary/30">
                <Brain className="h-5 w-5 text-cyan-400" />
              </div>
            </div>
            <div>
              <h3 className="text-sm font-bold flex items-center gap-2">
                <span className="bg-gradient-to-r from-cyan-400 via-primary to-purple-400 bg-clip-text text-transparent">
                  PHOENIX
                </span>
                <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-green-500/20 text-green-400 border border-green-500/30 font-normal">
                  ONLINE
                </span>
              </h3>
              <p className="text-[10px] text-muted-foreground flex items-center gap-1">
                <Radio className="h-3 w-3 animate-pulse text-cyan-500" />
                Perplexity Sonar Pro • Real-time Intelligence
              </p>
            </div>
          </div>
          
          <div className="flex items-center gap-1">
            <button
              onClick={clearChat}
              className="p-2 rounded-lg hover:bg-red-500/10 text-muted-foreground hover:text-red-400 transition-colors"
              title="Clear conversation"
            >
              <Trash2 className="h-4 w-4" />
            </button>
            <button 
              onClick={() => setExpanded((e) => !e)} 
              className="p-2 rounded-lg hover:bg-primary/10 text-muted-foreground hover:text-primary transition-colors"
              title={expanded ? "Minimize" : "Expand"}
            >
              {expanded ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
            </button>
            <button 
              onClick={() => setOpen(false)} 
              className="p-2 rounded-lg hover:bg-red-500/10 text-muted-foreground hover:text-red-400 transition-colors"
              title="Close"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Messages Area */}
        <div className="flex-1 overflow-y-auto p-3 sm:p-4 space-y-3 sm:space-y-4 scrollbar-thin scrollbar-thumb-primary/20 scrollbar-track-transparent">
          {messages.length === 0 && showQuickPrompts && (
            <div className="flex flex-col items-center justify-center h-full animate-fade-in">
              {/* Hero Section */}
              <div className="relative mb-6">
                <div className="absolute inset-0 bg-gradient-to-r from-cyan-500 via-primary to-purple-500 rounded-full blur-2xl opacity-30 animate-pulse" />
                <div className="relative p-6 bg-gradient-to-br from-primary/10 to-cyan-500/10 rounded-full border border-primary/20">
                  <Shield className="h-12 w-12 text-cyan-400" />
                </div>
              </div>
              
              <h2 className="text-lg font-bold bg-gradient-to-r from-cyan-400 via-primary to-purple-400 bg-clip-text text-transparent mb-2">
                PHOENIX Intelligence Assistant
              </h2>
              <p className="text-xs text-muted-foreground text-center max-w-[280px] mb-6">
                Powered by Perplexity Sonar Pro with real-time web search for threat intelligence
              </p>

              {/* Quick Prompts Grid */}
              <div className="w-full space-y-2">
                <p className="text-[10px] uppercase tracking-wider text-muted-foreground text-center mb-3">
                  Quick Intelligence Queries
                </p>
                <div className={cn(
                  "grid gap-2",
                  "grid-cols-1 sm:grid-cols-2",
                  expanded && "lg:grid-cols-3"
                )}>
                  {QUICK_PROMPTS.map((item, i) => (
                    <button
                      key={i}
                      onClick={() => sendMessage(item.prompt)}
                      className={cn(
                        "flex items-center gap-2 p-3 rounded-xl text-left",
                        "bg-gradient-to-br from-slate-800/80 to-slate-900/80",
                        "border border-slate-700/50 hover:border-primary/50",
                        "hover:bg-primary/5 transition-all duration-200",
                        "group"
                      )}
                    >
                      <div className="p-1.5 rounded-lg bg-primary/10 group-hover:bg-primary/20 transition-colors">
                        <item.icon className="h-3.5 w-3.5 text-primary" />
                      </div>
                      <span className="text-xs font-medium text-slate-300 group-hover:text-white">
                        {item.label}
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Chat Messages */}
          {messages.map((m, i) => (
            <div
              key={i}
              className={cn(
                "animate-fade-in group",
                m.role === "user" ? "flex justify-end" : "flex justify-start"
              )}
            >
              <div
                className={cn(
                  "relative max-w-[85%] rounded-2xl px-4 py-3",
                  m.role === "user"
                    ? "bg-gradient-to-br from-primary/20 to-primary/10 border border-primary/30 rounded-br-md"
                    : "bg-gradient-to-br from-slate-800/80 to-slate-900/80 border border-slate-700/50 rounded-bl-md"
                )}
              >
                {/* Message Header */}
                <div className="flex items-center gap-2 mb-2">
                  {m.role === "assistant" ? (
                    <div className="p-1 rounded bg-cyan-500/10">
                      <Zap className="h-3 w-3 text-cyan-400" />
                    </div>
                  ) : (
                    <div className="p-1 rounded bg-primary/10">
                      <Terminal className="h-3 w-3 text-primary" />
                    </div>
                  )}
                  <span className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider">
                    {m.role === "assistant" ? "PHOENIX" : "You"}
                  </span>
                  {m.timestamp && (
                    <span className="text-[10px] text-muted-foreground/50">
                      {m.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  )}
                </div>
                
                {/* Message Content */}
                <div className="text-sm leading-relaxed whitespace-pre-wrap break-words">
                  {renderMessage(m.content)}
                </div>

                {/* Copy Button (for assistant messages) */}
                {m.role === "assistant" && (
                  <button
                    onClick={() => copyToClipboard(m.content, i)}
                    className="absolute top-2 right-2 p-1.5 rounded-lg bg-slate-700/50 opacity-0 group-hover:opacity-100 hover:bg-slate-600/50 transition-all"
                    title="Copy response"
                  >
                    {copiedIndex === i ? (
                      <Check className="h-3 w-3 text-green-400" />
                    ) : (
                      <Copy className="h-3 w-3 text-muted-foreground" />
                    )}
                  </button>
                )}
              </div>
            </div>
          ))}

          {/* Loading State */}
          {loading && (
            <div className="flex justify-start animate-fade-in">
              <div className="bg-gradient-to-br from-slate-800/80 to-slate-900/80 border border-slate-700/50 rounded-2xl rounded-bl-md px-4 py-3">
                <div className="flex items-center gap-3">
                  <div className="flex gap-1">
                    <div className="w-2 h-2 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                    <div className="w-2 h-2 bg-primary rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                    <div className="w-2 h-2 bg-purple-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                  </div>
                  <span className="text-xs text-muted-foreground">Analyzing intelligence...</span>
                </div>
              </div>
            </div>
          )}
          
          <div ref={messagesEndRef} />
        </div>

        {/* Input Area */}
        <div className="p-4 border-t border-primary/20 bg-gradient-to-r from-slate-900/50 to-transparent">
          <div className="flex items-center gap-2">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <input
                ref={inputRef}
                className={cn(
                  "w-full pl-10 pr-4 py-3 rounded-xl",
                  "bg-slate-800/50 border border-slate-700/50",
                  "focus:border-primary/50 focus:ring-1 focus:ring-primary/20",
                  "text-sm placeholder:text-muted-foreground",
                  "outline-none transition-all"
                )}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && sendMessage()}
                placeholder="Ask about threats, CVEs, IOCs, APT groups..."
                disabled={loading}
              />
            </div>
            <button
              onClick={() => sendMessage()}
              disabled={loading || !input.trim()}
              className={cn(
                "p-3 rounded-xl transition-all duration-200",
                "bg-gradient-to-r from-primary to-cyan-500",
                "hover:from-primary/90 hover:to-cyan-500/90",
                "disabled:opacity-50 disabled:cursor-not-allowed",
                "shadow-lg shadow-primary/25 hover:shadow-primary/40",
                "group"
              )}
              title="Send message"
            >
              <Send className="h-4 w-4 text-white group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
            </button>
          </div>
          
          {/* Footer */}
          <div className="flex items-center justify-center gap-2 mt-3 text-[10px] text-muted-foreground/50">
            <MessageCircle className="h-3 w-3" />
            <span>Press Enter to send • Powered by Perplexity AI</span>
          </div>
        </div>
      </div>
    </div>
  );
}

const DashboardPage = () => {
  const { user, loading, signOut } = useAuth(true);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const isMobile = useIsMobile();

  useEffect(() => {
    initDatabase().catch(console.error);
  }, []);

  // Show loading while checking auth
  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center bg-background">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </div>
    );
  }

  // If not authenticated, useAuth will redirect to /auth
  if (!user) {
    return null;
  }

  return (
    <div className="flex h-screen bg-background overflow-hidden">
      <OSINTSidebar 
        onSignOut={signOut} 
        userEmail={user.email} 
        isOpen={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
      />
      
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Mobile Header */}
        {isMobile && (
          <header className="flex items-center justify-between h-14 px-4 border-b border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
            <button 
              onClick={() => setSidebarOpen(true)}
              className="p-2 -ml-2 rounded-lg hover:bg-secondary transition-colors"
            >
              <Menu className="h-5 w-5" />
            </button>
            
            <div className="flex items-center gap-2">
              <div className="flex items-center justify-center w-7 h-7 rounded-lg bg-gradient-cyber">
                <Terminal className="h-3.5 w-3.5 text-primary-foreground" />
              </div>
              <span className="font-bold text-foreground text-sm">SoTaNik OSINT</span>
            </div>
            
            <LanguageSelector variant="compact" />
          </header>
        )}
        
        <main className="flex-1 overflow-y-auto relative">
          <Routes>
            <Route path="/" element={<DashboardHome />} />
            <Route path="/threat-intel" element={<ThreatIntelSearch />} />
            <Route path="/cve" element={<CVEExplorer />} />
            <Route path="/live-threats" element={<LiveThreatFeed />} />
            <Route path="/import" element={<DataImporter />} />
            <Route path="/settings" element={<SettingsPage />} />
            
            {/* NEW ROUTES */}
            <Route path="/username" element={<UsernameEnumeration />} />
            <Route path="/darkweb" element={<DarkWebScanner />} />
            <Route path="/graph" element={<GraphVisualization />} />
            <Route path="/news" element={<NewsIntelligence />} />
            <Route path="/telegram" element={<TelegramIntelligence />} />
            <Route path="/malware-pipeline" element={<MalwarePipeline />} />
            <Route path="/stealthmole" element={<StealthMoleScanner />} />
            <Route path="/threat-map" element={<LiveThreatMap />} />
            <Route path="/monitoring" element={<MonitoringDashboard />} />
            <Route path="/history" element={<SearchHistoryPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
      
      <FloatingPerplexityChat />
      <ReportButton />
      <PanicButton />
    </div>
  );
};

export default DashboardPage;
