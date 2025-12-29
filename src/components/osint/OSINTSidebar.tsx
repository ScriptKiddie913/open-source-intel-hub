// src/components/osint/OSINTSidebar.tsx - COMPLETE REWRITE v2.6
import { useState, useEffect } from "react";
import { Link, useLocation } from "react-router-dom";
import { cn } from "@/lib/utils";
import {
  LayoutDashboard,
  Search,
  Globe,
  Shield,
  Bell,
  Upload,
  Settings,
  Database,
  FileText,
  ChevronLeft,
  ChevronRight,
  Terminal,
  Lock,
  Activity,
  Radar,
  Bug,
  Zap,
  AlertTriangle,
  User,
  Network,
  Eye,
  Newspaper,
  FileWarning,
  Send,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

interface NavItem {
  name: string;
  href: string;
  icon: typeof LayoutDashboard;
  badge?: number;
  description?:  string;
  isNew?: boolean;
  status?: 'stable' | 'beta' | 'new';
}

// THREAT INTELLIGENCE SECTION
const mainNavItems: NavItem[] = [
  { 
    name: "Dashboard", 
    href: "/", 
    icon: LayoutDashboard, 
    description: "Overview & Statistics",
    status: 'stable'
  },
  { 
    name: "Threat Intel", 
    href: "/threat-intel", 
    icon:  Radar, 
    description: "VirusTotal & Threat Analysis",
    status: 'stable'
  },
  { 
    name: "Live Threats", 
    href: "/live-threats", 
    icon:  Zap, 
    description: "Real-time Threat Feeds",
    status: 'stable'
  },
  { 
    name: "CVE Explorer", 
    href: "/cve", 
    icon:  Bug, 
    description: "Vulnerabilities & Exploits",
    status: 'stable'
  },
  { 
    name: "News Intel", 
    href: "/news", 
    icon: Newspaper, 
    description: "Real-time News & OSINT",
    status: 'stable'
  },
  { 
    name: "Malware Intel", 
    href: "/malware", 
    icon:  FileWarning, 
    description: "Malware Analysis & Tracking",
    status: 'new',
    isNew: true
  },
];

// ANALYSIS TOOLS SECTION
const toolsNavItems: NavItem[] = [
  { 
    name: "Domain Intel", 
    href: "/domain", 
    icon: Globe, 
    description: "DNS & Domain Analysis",
    status:  'stable'
  },
  { 
    name: "IP Analyzer", 
    href: "/ip", 
    icon: Activity, 
    description:  "IP Intelligence",
    status:  'stable'
  },
  { 
    name: "Certificates", 
    href:  "/certs", 
    icon: Lock, 
    description:  "SSL/TLS Certificates",
    status: 'stable'
  },
  { 
    name: "Breach Check", 
    href: "/breach", 
    icon: Shield, 
    description: "Email Breach Lookup",
    status: 'stable'
  },
  { 
    name: "Telegram Scanner", 
    href:  "/telegram", 
    icon:  Send, 
    description: "Public Channel Leak Monitor",
    status: 'new',
    isNew: true
  },
  { 
    name: "Username OSINT", 
    href: "/username", 
    icon: User, 
    description: "100+ Platform Enumeration",
    status: 'stable'
  },
  { 
    name: "Dark Web", 
    href: "/darkweb", 
    icon: Eye, 
    description:  "Dark Web & Leak Monitor",
    status: 'stable'
  },
  { 
    name: "Graph Map", 
    href: "/graph", 
    icon: Network, 
    description: "Maltego-style Visualization",
    status:  'stable'
  },
];

// DATA MANAGEMENT SECTION
const dataNavItems: NavItem[] = [
  { 
    name: "Import Data", 
    href: "/import", 
    icon: Upload, 
    description: "Upload Datasets",
    status: 'stable'
  },
  { 
    name: "Monitors", 
    href: "/monitors", 
    icon: Bell, 
    description: "Active Monitoring",
    status: 'stable'
  },
  { 
    name: "Reports", 
    href: "/reports", 
    icon: FileText, 
    description: "Generated Reports",
    status: 'stable'
  },
];

// SYSTEM SECTION
const systemNavItems:  NavItem[] = [
  { 
    name: "Database", 
    href: "/database", 
    icon: Database, 
    description: "Local Data Store",
    status: 'stable'
  },
  { 
    name: "Settings", 
    href: "/settings", 
    icon: Settings, 
    description: "Configuration",
    status: 'stable'
  },
];

export function OSINTSidebar() {
  const [collapsed, setCollapsed] = useState(false);
  const [currentTime, setCurrentTime] = useState(new Date());
  const location = useLocation();

  // Update time every second
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const NavLink = ({ item }:  { item: NavItem }) => {
    const isActive = location. pathname === item.href;
    
    return (
      <Link
        to={item.href}
        className={cn(
          "flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200",
          "hover: bg-secondary group relative",
          isActive
            ? "bg-primary/10 text-primary border-l-2 border-primary"
            : "text-muted-foreground hover:text-foreground"
        )}
      >
        <item.icon className={cn(
          "h-4 w-4 shrink-0 transition-colors",
          isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground"
        )} />
        
        {! collapsed && (
          <>
            <div className="flex-1 truncate">
              <div className="flex items-center gap-2">
                <span className="truncate">{item.name}</span>
                {item.isNew && (
                  <Badge variant="destructive" className="text-[8px] px-1 py-0 h-4">
                    NEW
                  </Badge>
                )}
              </div>
              {item.description && (
                <div className="text-xs text-muted-foreground/60 truncate mt-0.5">
                  {item.description}
                </div>
              )}
            </div>
            {item.badge !== undefined && item. badge > 0 && (
              <span className="flex h-5 w-5 items-center justify-center rounded-full bg-destructive text-[10px] font-bold text-destructive-foreground">
                {item. badge > 99 ? "99+" : item.badge}
              </span>
            )}
          </>
        )}
        
        {isActive && (
          <div className="absolute inset-0 bg-primary/5 rounded-lg animate-pulse-ring" />
        )}

        {collapsed && (
          <div className="absolute left-full ml-2 px-2 py-1 bg-popover border border-border rounded-md text-xs whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50 shadow-lg">
            <div className="font-medium">{item.name}</div>
            {item.description && (
              <div className="text-[10px] text-muted-foreground mt-0.5">
                {item.description}
              </div>
            )}
            {item.isNew && (
              <Badge variant="destructive" className="text-[8px] px-1 py-0 h-4 mt-1">
                NEW
              </Badge>
            )}
          </div>
        )}
      </Link>
    );
  };

  const SectionHeader = ({ icon:  Icon, title }: { icon: typeof AlertTriangle, title: string }) => (
    ! collapsed && (
      <div className="flex items-center gap-2 px-3 mb-2 mt-1">
        <Icon className="h-3 w-3 text-primary" />
        <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-widest">
          {title}
        </p>
      </div>
    )
  );

  return (
    <aside
      className={cn(
        "flex flex-col h-screen bg-sidebar border-r border-sidebar-border transition-all duration-300",
        collapsed ? "w-16" : "w-64"
      )}
    >
      {/* Header */}
      <div className="flex items-center gap-3 px-4 h-16 border-b border-sidebar-border">
        <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-gradient-to-br from-primary to-primary/50 shadow-lg">
          <Terminal className="h-4 w-4 text-primary-foreground" />
        </div>
        {!collapsed && (
          <div>
            <h1 className="font-bold text-foreground tracking-tight">SoTaNik OSINT</h1>
            <p className="text-[10px] text-muted-foreground uppercase tracking-widest">Platform v2.6</p>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto p-3 space-y-6">
        {/* Threat Intelligence */}
        <div className="space-y-1">
          <SectionHeader icon={AlertTriangle} title="Threat Intelligence" />
          {mainNavItems.map((item) => (
            <NavLink key={item.href} item={item} />
          ))}
        </div>

        {/* Analysis Tools */}
        <div className="space-y-1">
          <SectionHeader icon={Search} title="Analysis Tools" />
          {toolsNavItems.map((item) => (
            <NavLink key={item.href} item={item} />
          ))}
        </div>

        {/* Data Management */}
        <div className="space-y-1">
          <SectionHeader icon={Database} title="Data Management" />
          {dataNavItems.map((item) => (
            <NavLink key={item. href} item={item} />
          ))}
        </div>

        {/* System */}
        <div className="space-y-1">
          <SectionHeader icon={Settings} title="System" />
          {systemNavItems.map((item) => (
            <NavLink key={item. href} item={item} />
          ))}
        </div>
      </nav>

      {/* Status Bar */}
      {!collapsed && (
        <div className="p-3 border-t border-sidebar-border bg-secondary/20">
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                <span className="text-muted-foreground">System Online</span>
              </div>
              <span className="font-mono text-muted-foreground">
                {currentTime.toLocaleTimeString()}
              </span>
            </div>
            <div className="flex items-center justify-between text-[10px] text-muted-foreground">
              <span>Modules Active</span>
              <span className="font-bold text-green-500">
                {mainNavItems.length + toolsNavItems.length}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Collapse Toggle */}
      <div className="p-3 border-t border-sidebar-border">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setCollapsed(!collapsed)}
          className="w-full justify-center hover:bg-secondary/50"
        >
          {collapsed ?  (
            <ChevronRight className="h-4 w-4" />
          ) : (
            <>
              <ChevronLeft className="h-4 w-4 mr-2" />
              Collapse
            </>
          )}
        </Button>
      </div>
    </aside>
  );
}
