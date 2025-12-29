import { Routes, Route, Navigate } from "react-router-dom";
import { useEffect, useState, useRef } from "react";

import { OSINTSidebar } from "@/components/osint/OSINTSidebar";
import { Dashboard } from "@/components/osint/Dashboard";
import { DomainIntelligence } from "@/components/osint/DomainIntelligence";
import { IPAnalyzer } from "@/components/osint/IPAnalyzer";
import { CertificateInspector } from "@/components/osint/CertificateInspector";
import { BreachChecker } from "@/components/osint/BreachChecker";
import { DataImporter } from "@/components/osint/DataImporter";
import { SettingsPage } from "@/components/osint/SettingsPage";
import { ThreatIntelSearch } from "@/components/osint/ThreatIntelSearch";
import { CVEExplorer } from "@/components/osint/CVEExplorer";
import { LiveThreatFeed } from "@/components/osint/LiveThreatFeed";

// NEW ENHANCED IMPORTS
import { UsernameEnumeration } from "@/components/osint/UsernameEnumeration";
import { DarkWebScanner } from "@/components/osint/DarkWebScanner";
import { GraphVisualization } from "@/components/osint/GraphVisualization";
import { MalwareIntelligence } from "@/components/osint/MalwareIntelligence";
import { NewsIntelligenceScanner } from "@/components/osint/NewsIntelligenceScanner";
import { AIAssistant } from "@/components/osint/AIAssistant";

import { initDatabase } from "@/lib/database";
import { cn } from "@/lib/utils";

import {
  Bot,
  Send,
  X,
  Maximize2,
  Minimize2,
} from "lucide-react";

const PERPLEXITY_API_KEY = "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";

type ChatMessage = {
  role: "user" | "assistant";
  content: string;
};

function renderMessage(text: string) {
  const parts = text.split(/(https?:\/\/[^\s]+)/g);
  return parts.map((part, i) =>
    part.match(/^https?:\/\//) ? (
      <a
        key={i}
        href={part}
        target="_blank"
        rel="noopener noreferrer"
        className="text-primary underline break-all"
      >
        {part}
      </a>
    ) : (
      <span key={i}>{part}</span>
    )
  );
}

function FloatingPerplexityChat() {
  const [open, setOpen] = useState(true);
  const [expanded, setExpanded] = useState(false);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [position, setPosition] = useState({ x: 24, y: 24 });

  const dragging = useRef(false);
  const offset = useRef({ x: 0, y: 0 });

  const onMouseDown = (e: React.MouseEvent) => {
    if (expanded) return;
    dragging.current = true;
    offset.current = {
      x: e.clientX - position.x,
      y: e.clientY - position.y,
    };
  };

  const onMouseMove = (e: MouseEvent) => {
    if (!dragging.current || expanded) return;

    const nextX = e.clientX - offset.current.x;
    const nextY = e.clientY - offset.current.y;

    setPosition({
      x: Math.max(8, Math.min(nextX, window.innerWidth - 360)),
      y: Math.max(8, Math.min(nextY, window.innerHeight - 120)),
    });
  };

  const onMouseUp = () => {
    dragging.current = false;
  };

  useEffect(() => {
    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
    return () => {
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
    };
  }, []);

  const sendMessage = async () => {
    if (!input.trim()) return;

    const userMsg: ChatMessage = {
      role: "user",
      content: input,
    };

    setMessages((m) => [...m, userMsg]);
    setInput("");
    setLoading(true);

    try {
      const res = await fetch(
        "https://api.perplexity.ai/chat/completions",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${PERPLEXITY_API_KEY}`,
          },
          body: JSON.stringify({
            model: "sonar-pro",
            messages: [
              {
                role: "system",
                content:
                  "You are an OSINT and threat intelligence assistant. Respond with structured paragraphs, preserve links, lists, and indicators. Do not truncate.",
              },
              ...messages,
              userMsg,
            ],
            temperature: 0.2,
          }),
        }
      );

      const data = await res.json();
      const reply = data?.choices?.[0]?.message?.content || "";

      setMessages((m) => [
        ...m,
        { role: "assistant", content: reply },
      ]);
    } catch {
      setMessages((m) => [
        ...m,
        {
          role: "assistant",
          content: "Error contacting intelligence service.",
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  if (!open) {
    return (
      <button
        className="fixed bottom-4 right-4 z-50 px-4 py-2 rounded-full bg-primary text-primary-foreground shadow-lg hover:shadow-xl transition-all"
        onClick={() => setOpen(true)}
      >
        <Bot className="h-5 w-5" />
      </button>
    );
  }

  return (
    <div
      className={cn(
        "fixed z-50",
        expanded
          ? "inset-0 flex items-center justify-center bg-black/40"
          : ""
      )}
    >
      <div
        className={cn(
          "card-cyber border border-border shadow-xl flex flex-col",
          expanded
            ? "w-[720px] h-[85vh]"
            : "w-[340px] max-h-[60vh]"
        )}
        style={
          expanded
            ? undefined
            : { left: position.x, bottom: position.y, position: "fixed" }
        }
      >
        <div
          className="flex items-center justify-between p-2 border-b border-border cursor-move"
          onMouseDown={onMouseDown}
        >
          <div className="flex items-center gap-2 text-sm font-semibold">
            <Bot className="h-4 w-4 text-primary" />
            OSINT Assistant
          </div>
          <div className="flex gap-2">
            <button onClick={() => setExpanded((e) => !e)} className="hover:text-primary">
              {expanded ? (
                <Minimize2 className="h-4 w-4" />
              ) : (
                <Maximize2 className="h-4 w-4" />
              )}
            </button>
            <button onClick={() => setOpen(false)} className="hover:text-destructive">
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-3 space-y-3 text-sm leading-relaxed">
          {messages.length === 0 && (
            <div className="text-center text-muted-foreground py-8">
              <Bot className="h-12 w-12 mx-auto mb-3 opacity-30" />
              <p className="text-xs">Ask me about threats, CVEs, IPs, or any OSINT query</p>
            </div>
          )}
          {messages.map((m, i) => (
            <div
              key={i}
              className={cn(
                "p-3 rounded whitespace-pre-wrap break-words",
                m.role === "user"
                  ? "bg-primary/10 text-right ml-8"
                  : "bg-secondary/50 mr-8"
              )}
            >
              {renderMessage(m.content)}
            </div>
          ))}
          {loading && (
            <div className="text-xs text-muted-foreground flex items-center gap-2">
              <div className="w-2 h-2 bg-primary rounded-full animate-pulse" />
              Thinking…
            </div>
          )}
        </div>

        <div className="p-2 border-t border-border flex gap-2">
          <input
            className="flex-1 bg-transparent outline-none text-sm placeholder:text-muted-foreground"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && sendMessage()}
            placeholder="Ask about threats, CVEs, domains..."
          />
          <button 
            onClick={sendMessage} 
            disabled={loading || !input.trim()}
            className="text-primary hover:text-primary/80 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Send className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
}

const Index = () => {
  useEffect(() => {
    initDatabase().catch(console.error);
  }, []);

  return (
    <div className="flex h-screen bg-background overflow-hidden">
      <OSINTSidebar />
      <main className="flex-1 overflow-y-auto relative">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/threat-intel" element={<ThreatIntelSearch />} />
          <Route path="/malware" element={<MalwareIntelligence />} />
          <Route path="/news" element={<NewsIntelligenceScanner />} />
          <Route path="/ai-assistant" element={<AIAssistant />} />
          <Route path="/domain" element={<DomainIntelligence />} />
          <Route path="/ip" element={<IPAnalyzer />} />
          <Route path="/certs" element={<CertificateInspector />} />
          <Route path="/breach" element={<BreachChecker />} />
          <Route path="/cve" element={<CVEExplorer />} />
          <Route path="/live-threats" element={<LiveThreatFeed />} />
          <Route path="/import" element={<DataImporter />} />
          <Route path="/settings" element={<SettingsPage />} />
          
          {/* ENHANCED ROUTES */}
          <Route path="/username" element={<UsernameEnumeration />} />
          <Route path="/darkweb" element={<DarkWebScanner />} />
          <Route path="/graph" element={<GraphVisualization />} />
          
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
      <FloatingPerplexityChat />
    </div>
  );
};

export default Index;
