import { useState } from "react";
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
} from "lucide-react";
import { Button } from "@/components/ui/button";

interface NavItem {
  name: string;
  href: string;
  icon: typeof LayoutDashboard;
  badge?: number;
}

const mainNavItems: NavItem[] = [
  { name: "Dashboard", href: "/", icon: LayoutDashboard },
  { name: "Search", href: "/search", icon: Search },
  { name: "Domain Intel", href: "/domain", icon: Globe },
  { name: "IP Analyzer", href: "/ip", icon: Activity },
  { name: "Certificates", href: "/certs", icon: Lock },
  { name: "Breach Check", href: "/breach", icon: Shield },
];

const toolsNavItems: NavItem[] = [
  { name: "Import Data", href: "/import", icon: Upload },
  { name: "Monitors", href: "/monitors", icon: Bell },
  { name: "Reports", href: "/reports", icon: FileText },
];

const systemNavItems: NavItem[] = [
  { name: "Database", href: "/database", icon: Database },
  { name: "Settings", href: "/settings", icon: Settings },
];

export function OSINTSidebar() {
  const [collapsed, setCollapsed] = useState(false);
  const location = useLocation();

  const NavLink = ({ item }: { item: NavItem }) => {
    const isActive = location.pathname === item.href;
    
    return (
      <Link
        to={item.href}
        className={cn(
          "flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-200",
          "hover:bg-secondary group relative",
          isActive
            ? "bg-primary/10 text-primary border-l-2 border-primary"
            : "text-muted-foreground hover:text-foreground"
        )}
      >
        <item.icon className={cn(
          "h-4 w-4 shrink-0 transition-colors",
          isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground"
        )} />
        {!collapsed && (
          <>
            <span className="truncate">{item.name}</span>
            {item.badge !== undefined && item.badge > 0 && (
              <span className="ml-auto flex h-5 w-5 items-center justify-center rounded-full bg-destructive text-[10px] font-bold text-destructive-foreground">
                {item.badge > 99 ? "99+" : item.badge}
              </span>
            )}
          </>
        )}
        
        {/* Active indicator glow */}
        {isActive && (
          <div className="absolute inset-0 bg-primary/5 rounded-lg animate-pulse-ring" />
        )}
      </Link>
    );
  };

  return (
    <aside
      className={cn(
        "flex flex-col h-screen bg-sidebar border-r border-sidebar-border transition-all duration-300",
        collapsed ? "w-16" : "w-64"
      )}
    >
      {/* Header */}
      <div className="flex items-center gap-3 px-4 h-16 border-b border-sidebar-border">
        <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-gradient-cyber">
          <Terminal className="h-4 w-4 text-primary-foreground" />
        </div>
        {!collapsed && (
          <div>
            <h1 className="font-bold text-foreground tracking-tight">OSINT</h1>
            <p className="text-[10px] text-muted-foreground uppercase tracking-widest">Platform</p>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto p-3 space-y-6">
        {/* Main */}
        <div className="space-y-1">
          {!collapsed && (
            <p className="px-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-widest mb-2">
              Intelligence
            </p>
          )}
          {mainNavItems.map((item) => (
            <NavLink key={item.href} item={item} />
          ))}
        </div>

        {/* Tools */}
        <div className="space-y-1">
          {!collapsed && (
            <p className="px-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-widest mb-2">
              Tools
            </p>
          )}
          {toolsNavItems.map((item) => (
            <NavLink key={item.href} item={item} />
          ))}
        </div>

        {/* System */}
        <div className="space-y-1">
          {!collapsed && (
            <p className="px-3 text-[10px] font-semibold text-muted-foreground uppercase tracking-widest mb-2">
              System
            </p>
          )}
          {systemNavItems.map((item) => (
            <NavLink key={item.href} item={item} />
          ))}
        </div>
      </nav>

      {/* Collapse Toggle */}
      <div className="p-3 border-t border-sidebar-border">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setCollapsed(!collapsed)}
          className="w-full justify-center"
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
        </Button>
      </div>
    </aside>
  );
}
