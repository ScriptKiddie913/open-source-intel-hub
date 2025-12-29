// ============================================================================
// OSINTSidebar.tsx
// FULL PRODUCTION SIDEBAR – FIXED & VERCEL SAFE
// Lines ~260+
// ============================================================================

import { useState, useEffect } from "react";
import { Link, useLocation } from "react-router-dom";
import { cn } from "@/lib/utils";

import {
  LayoutDashboard,
  Radar,
  Zap,
  Bug,
  Newspaper,
  Globe,
  Activity,
  Lock,
  Shield,
  User,
  Eye,
  Network,
  Upload,
  Bell,
  FileText,
  Database,
  Settings,
  Terminal,
  Search,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

/* ============================================================================
   TYPES
============================================================================ */

interface NavItem {
  name: string;
  href: string;
  icon: typeof LayoutDashboard;
  description?: string;
  badge?: number;
  isNew?: boolean;
}

/* ============================================================================
   NAV CONFIG
============================================================================ */

// ── Threat / Intel
const threatNav: NavItem[] = [
  {
    name: "Dashboard",
    href: "/",
    icon: LayoutDashboard,
    description: "Overview & statistics",
  },
  {
    name: "Threat Intel",
    href: "/threat-intel",
    icon: Radar,
    description: "IOC & reputation analysis",
  },
  {
    name: "Live Threats",
    href: "/live-threats",
    icon: Zap,
    description: "Real-time attack feeds",
  },
  {
    name: "CVE Explorer",
    href: "/cve",
    icon: Bug,
    description: "Vulnerabilities & exploits",
  },
  {
    name: "News Intel",
    href: "/news",
    icon: Newspaper,
    description: "OSINT news monitoring",
  },
];

// ── Analysis Tools
const toolsNav: NavItem[] = [
  {
    name: "Domain Intel",
    href: "/domain",
    icon: Globe,
    description: "DNS & WHOIS analysis",
  },
  {
    name: "IP Analyzer",
    href: "/ip",
    icon: Activity,
    description: "IP reputation & geo",
  },
  {
    name: "Certificates",
    href: "/certs",
    icon: Lock,
    description: "SSL/TLS intelligence",
  },
  {
    name: "Breach Check",
    href: "/breach",
    icon: Shield,
    description: "Email breach lookup",
  },
  {
    name: "Username OSINT",
    href: "/username",
    icon: User,
    description: "Cross-platform search",
  },
  {
    name: "Dark Web",
    href: "/darkweb",
    icon: Eye,
    description: "Leaks & onion discovery",
  },
  {
    name: "Graph Map",
    href: "/graph",
    icon: Network,
    description: "Relationship visualization",
  },
];

// ── Data
const dataNav: NavItem[] = [
  {
    name: "Import Data",
    href: "/import",
    icon: Upload,
    description: "Upload datasets",
  },
  {
    name: "Monitors",
    href: "/monitors",
    icon: Bell,
    description: "Active monitoring",
  },
  {
    name: "Reports",
    href: "/reports",
    icon: FileText,
    description: "Generated reports",
  },
];

// ── System
const systemNav: NavItem[] = [
  {
    name: "Database",
    href: "/database",
    icon: Database,
    description: "Local OSINT store",
  },
  {
    name: "Settings",
    href: "/settings",
    icon: Settings,
    description: "Configuration",
  },
];

/* ============================================================================
   COMPONENT
============================================================================ */

export function OSINTSidebar() {
  const [collapsed, setCollapsed] = useState(false);
  const [time, setTime] = useState(new Date());
  const location = useLocation();

  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  /* ------------------------------------------------------------------------ */

  const NavLink = ({ item }: { item: NavItem }) => {
    const active = location.pathname === item.href;

    return (
      <Link
        to={item.href}
        className={cn(
          "group relative flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition-all",
          active
            ? "bg-primary/10 text-primary border-l-2 border-primary"
            : "text-muted-foreground hover:bg-secondary hover:text-foreground"
        )}
      >
        <item.icon
          className={cn(
            "h-4 w-4 shrink-0",
            active ? "text-primary" : "text-muted-foreground group-hover:text-foreground"
          )}
        />

        {!collapsed && (
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="truncate">{item.name}</span>
              {item.isNew && (
                <Badge variant="destructive" className="h-4 px-1 text-[9px]">
                  NEW
                </Badge>
              )}
            </div>
            {item.description && (
              <p className="mt-0.5 truncate text-xs text-muted-foreground/70">
                {item.description}
              </p>
            )}
          </div>
        )}

        {collapsed && (
          <div className="pointer-events-none absolute left-full z-50 ml-2 rounded-md border bg-popover px-2 py-1 text-xs opacity-0 shadow-lg transition-opacity group-hover:opacity-100">
            {item.name}
          </div>
        )}
      </Link>
    );
  };

  const Section = ({
    title,
    icon: Icon,
    items,
  }: {
    title: string;
    icon: typeof AlertTriangle;
    items: NavItem[];
  }) => (
    <div className="space-y-1">
      {!collapsed && (
        <div className="flex items-center gap-2 px-3 py-2">
          <Icon className="h-3 w-3 text-primary" />
          <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
            {title}
          </span>
        </div>
      )}
      {items.map(item => (
        <NavLink key={item.href} item={item} />
      ))}
    </div>
  );

  /* ------------------------------------------------------------------------ */

  return (
    <aside
      className={cn(
        "flex h-screen flex-col border-r bg-sidebar transition-all duration-300",
        collapsed ? "w-16" : "w-64"
      )}
    >
      {/* HEADER */}
      <div className="flex h-16 items-center gap-3 border-b px-4">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-primary">
          <Terminal className="h-4 w-4 text-primary-foreground" />
        </div>
        {!collapsed && (
          <div>
            <h1 className="text-sm font-bold">SoTaNik OSINT</h1>
            <p className="text-[10px] uppercase tracking-widest text-muted-foreground">
              Platform v2.6
            </p>
          </div>
        )}
      </div>

      {/* NAV */}
      <nav className="flex-1 space-y-6 overflow-y-auto p-3">
        <Section title="Threat Intelligence" icon={AlertTriangle} items={threatNav} />
        <Section title="Analysis Tools" icon={Search} items={toolsNav} />
        <Section title="Data Management" icon={Database} items={dataNav} />
        <Section title="System" icon={Settings} items={systemNav} />
      </nav>

      {/* STATUS */}
      {!collapsed && (
        <div className="border-t bg-secondary/20 p-3 text-xs">
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-2">
              <span className="h-2 w-2 animate-pulse rounded-full bg-green-500" />
              System Online
            </span>
            <span className="font-mono text-muted-foreground">
              {time.toLocaleTimeString()}
            </span>
          </div>
        </div>
      )}

      {/* TOGGLE */}
      <div className="border-t p-3">
        <Button
          variant="ghost"
          size="sm"
          className="w-full justify-center"
          onClick={() => setCollapsed(v => !v)}
        >
          {collapsed ? (
            <ChevronRight className="h-4 w-4" />
          ) : (
            <>
              <ChevronLeft className="mr-2 h-4 w-4" />
              Collapse
            </>
          )}
        </Button>
      </div>
    </aside>
  );
}
