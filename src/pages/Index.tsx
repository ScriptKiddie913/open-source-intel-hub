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
   API KEY (CLIENT SIDE, AS REQUESTED)
===================================================== */

const PERPLEXITY_API_KEY =
  "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";

/* =====================================================
   TYPES
===================================================== */

type ChatMessage = {
  role: "user" | "assistant";
  content: string;
};

/* =====================================================
   MESSAGE RENDERER (LINK SAFE)
===================================================== */

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

/* =====================================================
   FLOATING CHAT
===================================================== */

function FloatingPerplexityChat() {
  const [open, setOpen] = useState(true);
  const [expanded, setExpanded] = useState(false);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [position, setPosition] = useState({ x: 24, y: 24 });

  const dragging = useRef(false);
  const offset = useRef({ x: 0, y: 0 });

  /* ---------------- DRAG ---------------- */

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

  /* ---------------- SEND ---------------- */

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
        className="fixed bottom-4 right-4 z-50 px-4 py-2 rounded-full bg-primary text-primary-foreground shadow-lg"
        onClick={() => setOpen(true)}
      >
        Open Chat
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
        {/* HEADER */}
        <div
          className="flex items-center justify-between p-2 border-b border-border cursor-move"
          onMouseDown={onMouseDown}
        >
          <div className="flex items-center gap-2 text-sm font-semibold">
            <Bot className="h-4 w-4" />
            OSINT Chat
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

        {/* MESSAGES */}
        <div className="flex-1 overflow-y-auto p-3 space-y-3 text-sm leading-relaxed">
          {messages.map((m, i) => (
            <div
              key={i}
              className={cn(
                "p-3 rounded whitespace-pre-wrap break-words",
                m.role === "user"
                  ? "bg-primary/10 text-right"
                  : "bg-secondary/50"
              )}
            >
              {renderMessage(m.content)}
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
        <Routes>
          <Route path="/" element={<Dashboard />} />
       
          <Route path="/threat-intel" element={<ThreatIntelPage />} />
          <Route path="/domain" element={<DomainIntelligence />} />
          <Route path="/ip" element={<IPAnalyzer />} />
          <Route path="/certs" element={<CertificateInspector />} />
          <Route path="/breach" element={<BreachChecker />} />
          <Route path="/import" element={<DataImporter />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
      <FloatingPerplexityChat />
    </div>
  );
};

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
