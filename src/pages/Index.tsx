import { Routes, Route, Navigate } from "react-router-dom";
import { useEffect, useState, useRef } from "react";

import { OSINTSidebar } from "@/components/osint/OSINTSidebar";
import { Dashboard } from "@/components/osint/Dashboard";
import { SearchInterface } from "@/components/osint/SearchInterface";
import { DomainIntelligence } from "@/components/osint/DomainIntelligence";
import { IPAnalyzer } from "@/components/osint/IPAnalyzer";
import { CertificateInspector } from "@/components/osint/CertificateInspector";
import { BreachChecker } from "@/components/osint/BreachChecker";
import { DataImporter } from "@/components/osint/DataImporter";
import { SettingsPage } from "@/components/osint/SettingsPage";
import { ThreatIntelSearch } from "@/components/osint/ThreatIntelSearch";

import { initDatabase } from "@/lib/database";
import { cn } from "@/lib/utils";

import {
  Bot,
  Send,
  X,
  Maximize2,
  Minimize2,
} from "lucide-react";

/* =====================================================
   🔑 PERPLEXITY API KEY (CLIENT-SIDE, EXPOSED)
===================================================== */

const PERPLEXITY_API_KEY = "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";

/* =====================================================
   FLOATING PERPLEXITY CHAT
===================================================== */

type ChatMessage = {
  role: "user" | "assistant";
  content: string;
};

function FloatingPerplexityChat() {
  const [open, setOpen] = useState(true);
  const [expanded, setExpanded] = useState(false);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [position, setPosition] = useState({ x: 24, y: 24 });

  const dragging = useRef(false);
  const offset = useRef({ x: 0, y: 0 });

  /* ---------------- DRAG LOGIC ---------------- */

  const onMouseDown = (e: React.MouseEvent) => {
    dragging.current = true;
    offset.current = {
      x: e.clientX - position.x,
      y: e.clientY - position.y,
    };
  };

  const onMouseMove = (e: MouseEvent) => {
    if (!dragging.current) return;
    setPosition({
      x: e.clientX - offset.current.x,
      y: e.clientY - offset.current.y,
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
  });

  /* ---------------- SEND MESSAGE ---------------- */

  const sendMessage = async () => {
    if (!input.trim()) return;

    if (!PERPLEXITY_API_KEY || PERPLEXITY_API_KEY.startsWith("pplx-REPLACE")) {
      setMessages((m) => [
        ...m,
        {
          role: "assistant",
          content: "Perplexity API key is not configured.",
        },
      ]);
      return;
    }

    const userMessage: ChatMessage = {
      role: "user",
      content: input,
    };

    setMessages((m) => [...m, userMessage]);
    setInput("");
    setLoading(true);

    try {
      const response = await fetch(
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
                  "You are an OSINT and threat intelligence research assistant. Be accurate, concise, and cite sources when possible.",
              },
              ...messages,
              userMessage,
            ],
            temperature: 0.2,
          }),
        }
      );

      const data = await response.json();
      const reply = data?.choices?.[0]?.message?.content;

      setMessages((m) => [
        ...m,
        {
          role: "assistant",
          content: reply || "No response received.",
        },
      ]);
    } catch {
      setMessages((m) => [
        ...m,
        {
          role: "assistant",
          content: "Error contacting Perplexity API.",
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  /* ---------------- UI ---------------- */

  return (
    <div
      className={cn(
        "fixed z-50",
        expanded ? "w-[420px] h-[520px]" : "w-[320px]"
      )}
      style={{ left: position.x, bottom: position.y }}
    >
      <div className="card-cyber border border-border shadow-xl flex flex-col h-full">
        {/* HEADER */}
        <div
          className="flex items-center justify-between p-2 border-b border-border cursor-move"
          onMouseDown={onMouseDown}
        >
          <div className="flex items-center gap-2 text-sm font-semibold">
            <Bot className="h-4 w-4" />
            Perplexity OSINT Chat
          </div>
          <div className="flex gap-2">
            <button onClick={() => setExpanded((e) => !e)}>
              {expanded ? (
                <Minimize2 className="h-4 w-4" />
              ) : (
                <Maximize2 className="h-4 w-4" />
              )}
            </button>
            <button onClick={() => setOpen(false)}>
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>

        {open ? (
          <>
            {/* MESSAGES */}
            <div className="flex-1 overflow-y-auto p-3 space-y-3 text-sm">
              {messages.map((m, i) => (
                <div
                  key={i}
                  className={cn(
                    "p-2 rounded",
                    m.role === "user"
                      ? "bg-primary/10 text-right"
                      : "bg-secondary/50"
                  )}
                >
                  {m.content}
                </div>
              ))}
              {loading && (
                <div className="text-xs text-muted-foreground">
                  Thinking…
                </div>
              )}
            </div>

            {/* INPUT */}
            <div className="p-2 border-t border-border flex gap-2">
              <input
                className="flex-1 bg-transparent outline-none text-sm"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && sendMessage()}
                placeholder="Ask OSINT / threat intel question…"
              />
              <button onClick={sendMessage} disabled={loading}>
                <Send className="h-4 w-4" />
              </button>
            </div>
          </>
        ) : (
          <button
            className="p-3 text-sm text-center"
            onClick={() => setOpen(true)}
          >
            Open Perplexity Chat
          </button>
        )}
      </div>
    </div>
  );
}

/* =====================================================
   MAIN INDEX
===================================================== */

const Index = () => {
  useEffect(() => {
    initDatabase().catch(console.error);
  }, []);

  return (
    <div className="flex h-screen bg-background overflow-hidden">
      <OSINTSidebar />

      <main className="flex-1 overflow-y-auto relative">
        <div className="min-h-full">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/search" element={<SearchInterface />} />
            <Route path="/threat-intel" element={<ThreatIntelPage />} />
            <Route path="/domain" element={<DomainIntelligence />} />
            <Route path="/ip" element={<IPAnalyzer />} />
            <Route path="/certs" element={<CertificateInspector />} />
            <Route path="/breach" element={<BreachChecker />} />
            <Route path="/import" element={<DataImporter />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </div>
      </main>

      {/* GLOBAL PERPLEXITY CHAT */}
      <FloatingPerplexityChat />
    </div>
  );
};

/* =====================================================
   EXTRA PAGE
===================================================== */

function ThreatIntelPage() {
  return (
    <div className="p-6 animate-fade-in">
      <h1 className="text-2xl font-bold mb-6">
        Threat Intelligence
      </h1>
      <ThreatIntelSearch />
    </div>
  );
}

export default Index;
