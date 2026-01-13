// src/pages/Dashboard.tsx
import { Routes, Route, Navigate } from "react-router-dom";
import { useEffect, useState, useRef, MouseEvent } from "react";

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

// External chatbot URL
const GARUD_CHATBOT_URL = "https://garud1.vercel.app/";

import {
  X,
  Maximize2,
  Minimize2,
  Sparkles,
  Terminal,
  Radio,
  Brain,
} from "lucide-react";

function FloatingGarudChat() {
  const [open, setOpen] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const [position, setPosition] = useState({ x: 24, y: 24 });
  const dragging = useRef(false);
  const offset = useRef({ x: 0, y: 0 });

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

  // Floating button when closed
  if (!open) {
    return (
      <button
        className="fixed bottom-4 right-4 sm:bottom-6 sm:right-6 z-50 group"
        onClick={() => setOpen(true)}
        title="Open GARUD Intelligence Assistant"
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
              GARUD
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
            ? "w-full h-full sm:w-[900px] sm:h-[90vh] max-w-[95vw]"
            : "w-full h-[75vh] sm:w-[420px] sm:h-[600px] max-w-[95vw]"
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
                  GARUD AI
                </span>
                <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-green-500/20 text-green-400 border border-green-500/30 font-normal">
                  ONLINE
                </span>
              </h3>
              <p className="text-[10px] text-muted-foreground flex items-center gap-1">
                <Radio className="h-3 w-3 animate-pulse text-cyan-500" />
                Advanced Threat Intelligence Assistant
              </p>
            </div>
          </div>
          
          <div className="flex items-center gap-1">
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

        {/* Iframe Content */}
        <div className="flex-1 relative">
          <iframe
            src={GARUD_CHATBOT_URL}
            className="w-full h-full border-0"
            title="GARUD AI Intelligence Assistant"
            allow="microphone; camera"
            sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-modals"
          />
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
      
      <FloatingGarudChat />
      <ReportButton />
      <PanicButton />
    </div>
  );
};

export default DashboardPage;
