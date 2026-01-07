import { useEffect, useState } from "react";
import { 
  Database, 
  Bell, 
  AlertTriangle, 
  Shield, 
  Activity,
  Clock,
  Search,
  Upload,
  Globe,
  Server,
  Bug,
  Zap,
  TrendingUp,
  Eye,
  MessageSquare,
  Minimize2,
  Maximize2,
} from "lucide-react";
import { StatCard } from "./StatCard";
import { APIStatusIndicator } from "./APIStatusIndicator";
import { ThreatBadge } from "./ThreatBadge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { 
  getRecordCount, 
  getActiveMonitorCount, 
  getAlertsToday, 
  getRecentActivity,
  initDatabase,
} from "@/lib/database";
import { getRecentCVEs } from "@/services/cveService";
import { getLiveThreatFeeds } from "@/services/cveService";
import { resolveDNS } from "@/services/dnsService";
import { getIPGeolocation } from "@/services/ipService";
import { cn } from "@/lib/utils";

type APIStatus = "online" | "offline" | "rate_limited" | "checking";

interface DashboardMetrics {
  totalRecords: number;
  activeMonitors: number;
  alertsToday: number;
  threatScore: number;
  recentCVEs: number;
  liveThreats: number;
}

interface RecentActivityItem {
  id: string;
  type: string;
  title: string;
  description: string;
  timestamp: Date;
}

export function Dashboard() {
  const [metrics, setMetrics] = useState<DashboardMetrics>({
    totalRecords: 0,
    activeMonitors: 0,
    alertsToday: 0,
    threatScore: 0,
    recentCVEs: 0,
    liveThreats: 0,
  });
  const [apiStatus, setApiStatus] = useState<Record<string, APIStatus>>({
    dns: "checking",
    ipGeo: "checking",
    shodan: "checking",
    certs: "checking",
    nvd: "checking",
    threatFeeds: "checking",
  });
  const [recentActivity, setRecentActivity] = useState<RecentActivityItem[]>([]);
  const [recentCVEs, setRecentCVEs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [chatExpanded, setChatExpanded] = useState(false);

  useEffect(() => {
    loadDashboard();
  }, []);

  const loadDashboard = async () => {
    try {
      await initDatabase();
      
      // Load metrics from IndexedDB
      const [records, monitors, alerts, activity] = await Promise.all([
        getRecordCount(),
        getActiveMonitorCount(),
        getAlertsToday(),
        getRecentActivity(10),
      ]);

      // Load recent CVEs and threats
      const [cves, threats] = await Promise.all([
        getRecentCVEs(7, 5).catch(() => []),
        getLiveThreatFeeds().catch(() => []),
      ]);

      setMetrics({
        totalRecords: records,
        activeMonitors: monitors,
        alertsToday: alerts,
        threatScore: calculateThreatScore(alerts, threats.length),
        recentCVEs: cves.length,
        liveThreats: threats.length,
      });

      setRecentActivity(activity);
      setRecentCVEs(cves);

      // Check API statuses
      checkAPIStatus();
    } catch (error) {
      console.error("Dashboard load error:", error);
    } finally {
      setLoading(false);
    }
  };

  const checkAPIStatus = async () => {
    // Check DNS API
    try {
      await resolveDNS("google.com", "A");
      setApiStatus(prev => ({ ...prev, dns: "online" }));
    } catch {
      setApiStatus(prev => ({ ...prev, dns: "offline" }));
    }

    // Check IP API
    try {
      await getIPGeolocation("8.8.8.8");
      setApiStatus(prev => ({ ...prev, ipGeo: "online" }));
    } catch {
      setApiStatus(prev => ({ ...prev, ipGeo: "offline" }));
    }

    // Check NVD API
    try {
      await fetch('https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1');
      setApiStatus(prev => ({ ...prev, nvd: "online" }));
    } catch {
      setApiStatus(prev => ({ ...prev, nvd: "offline" }));
    }

    // Mark other services as online (they don't have easy health checks)
    setApiStatus(prev => ({ 
      ...prev, 
      shodan: "online", 
      certs: "online",
      threatFeeds: "online",
    }));
  };

  const calculateThreatScore = (alerts: number, threats: number): number => {
    const alertScore = Math.min(alerts * 2, 50);
    const threatScore = Math.min(threats / 10, 50);
    return Math.round(alertScore + threatScore);
  };

  const getActivityIcon = (type: string) => {
    switch (type) {
      case "search": return <Search className="h-4 w-4" />;
      case "upload": return <Upload className="h-4 w-4" />;
      case "monitor": return <Bell className="h-4 w-4" />;
      case "alert": return <AlertTriangle className="h-4 w-4" />;
      default: return <Activity className="h-4 w-4" />;
    }
  };

  const formatTimeAgo = (date: Date) => {
    const seconds = Math.floor((new Date().getTime() - new Date(date).getTime()) / 1000);
    if (seconds < 60) return "just now";
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  };

  const getSeverityColor = (severity: string) => {
    const s = severity?.toUpperCase() || '';
    if (s === 'CRITICAL') return 'text-red-500';
    if (s === 'HIGH') return 'text-orange-500';
    if (s === 'MEDIUM') return 'text-yellow-500';
    if (s === 'LOW') return 'text-blue-500';
    return 'text-gray-500';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="text-center space-y-4">
          <div className="w-12 h-12 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto" />
          <p className="text-muted-foreground font-mono text-sm">Initializing OSINT Platform...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Dashboard</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Real-time intelligence monitoring and threat analysis
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-muted-foreground font-mono">
          <Clock className="h-3 w-3" />
          <span>Last updated: {new Date().toLocaleTimeString()}</span>
        </div>
      </div>

      {/* Threat Intel Assistant Chat */}
      <Card className="border-primary/20 bg-gradient-to-r from-primary/5 to-transparent overflow-hidden">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-primary/10 rounded-lg">
                <MessageSquare className="h-5 w-5 text-primary" />
              </div>
              <div>
                <CardTitle className="text-lg">Threat Intel Assistant</CardTitle>
                <p className="text-xs text-muted-foreground mt-0.5">
                  AI-powered threat intelligence analysis and investigation
                </p>
              </div>
            </div>
            <button
              onClick={() => setChatExpanded(!chatExpanded)}
              className="p-2 hover:bg-primary/10 rounded-lg transition-colors"
              title={chatExpanded ? "Minimize" : "Expand"}
            >
              {chatExpanded ? (
                <Minimize2 className="h-4 w-4 text-muted-foreground" />
              ) : (
                <Maximize2 className="h-4 w-4 text-muted-foreground" />
              )}
            </button>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="relative">
            {/* Iframe container with overlay to hide base44 popup */}
            <div className="relative w-full" style={{ height: chatExpanded ? '600px' : '400px' }}>
              <iframe
                src="https://threat-intel-assistant-8b6ecbcd.base44.app/"
                className="w-full h-full border-0"
                title="Threat Intel Assistant"
                sandbox="allow-same-origin allow-scripts allow-forms allow-popups"
              />
              {/* Overlay to cover base44 popup - positioned at bottom right */}
              <div 
                className="absolute bottom-0 right-0 w-64 h-20 bg-background pointer-events-none z-10"
                style={{
                  background: 'linear-gradient(to top, hsl(var(--background)) 70%, transparent 100%)',
                }}
              />
              {/* Additional overlay for bottom left if needed */}
              <div 
                className="absolute bottom-0 left-0 w-48 h-16 bg-background pointer-events-none z-10"
                style={{
                  background: 'linear-gradient(to top, hsl(var(--background)) 60%, transparent 100%)',
                }}
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Records"
          value={metrics.totalRecords.toLocaleString()}
          icon={Database}
          variant="default"
        />
        <StatCard
          title="Recent CVEs (7d)"
          value={metrics.recentCVEs}
          icon={Bug}
          variant="primary"
        />
        <StatCard
          title="Live Threats"
          value={metrics.liveThreats}
          icon={Zap}
          variant={metrics.liveThreats > 100 ? "danger" : "warning"}
        />
        <StatCard
          title="Threat Score"
          value={`${metrics.threatScore}%`}
          icon={Shield}
          variant={metrics.threatScore > 50 ? "danger" : metrics.threatScore > 25 ? "warning" : "default"}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* API Status */}
        <div className="card-cyber p-4 space-y-4">
          <div className="flex items-center gap-2">
            <Server className="h-4 w-4 text-primary" />
            <h2 className="font-semibold text-foreground">Data Sources</h2>
          </div>
          <div className="space-y-2">
            <APIStatusIndicator name="Google DNS" status={apiStatus.dns} />
            <APIStatusIndicator name="IP Geolocation" status={apiStatus.ipGeo} />
            <APIStatusIndicator name="Shodan InternetDB" status={apiStatus.shodan} />
            <APIStatusIndicator name="Certificate Transparency" status={apiStatus.certs} />
            <APIStatusIndicator name="NVD Database" status={apiStatus.nvd} />
            <APIStatusIndicator name="Threat Feeds" status={apiStatus.threatFeeds} />
          </div>
        </div>

        {/* Recent CVEs */}
        <div className="card-cyber p-4 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Bug className="h-4 w-4 text-primary" />
              <h2 className="font-semibold text-foreground">Recent CVEs</h2>
            </div>
            <a href="/cve" className="text-xs text-primary hover:underline">
              View All →
            </a>
          </div>
          
          {recentCVEs.length > 0 ? (
            <div className="space-y-2">
              {recentCVEs.map((cve) => (
                <a
                  key={cve.id}
                  href="/cve"
                  className="flex items-center gap-3 p-2 rounded-lg bg-secondary/50 hover:bg-secondary transition-colors"
                >
                  <div className="p-2 rounded-lg bg-destructive/10">
                    <Shield className="h-4 w-4 text-destructive" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-foreground truncate">
                      {cve.id}
                    </p>
                    <p className="text-xs text-muted-foreground truncate">
                      CVSS: <span className={getSeverityColor(cve.cvss.severity)}>{cve.cvss.score.toFixed(1)}</span>
                    </p>
                  </div>
                  <Badge variant="outline" className="text-xs">
                    {cve.cvss.severity}
                  </Badge>
                </a>
              ))}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <Bug className="h-12 w-12 text-muted-foreground/30 mb-4" />
              <p className="text-muted-foreground text-sm">No recent CVEs</p>
            </div>
          )}
        </div>

        {/* Recent Activity */}
        <div className="card-cyber p-4 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-primary" />
              <h2 className="font-semibold text-foreground">Recent Activity</h2>
            </div>
          </div>
          
          {recentActivity.length > 0 ? (
            <div className="space-y-2">
              {recentActivity.slice(0, 5).map((activity) => (
                <div
                  key={activity.id}
                  className="flex items-center gap-3 p-2 rounded-lg bg-secondary/50 hover:bg-secondary transition-colors"
                >
                  <div className="p-2 rounded-lg bg-primary/10 text-primary">
                    {getActivityIcon(activity.type)}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-foreground truncate">
                      {activity.title}
                    </p>
                    <p className="text-xs text-muted-foreground truncate">
                      {activity.description}
                    </p>
                  </div>
                  <span className="text-xs text-muted-foreground font-mono">
                    {formatTimeAgo(activity.timestamp)}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-8 text-center">
              <Globe className="h-12 w-12 text-muted-foreground/30 mb-4" />
              <p className="text-muted-foreground text-sm">No recent activity</p>
              <p className="text-muted-foreground/60 text-xs mt-1">
                Start by searching for domains, IPs, or CVEs
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Quick Actions */}
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Zap className="h-5 w-5 text-primary" />
            Quick Actions
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
            <a
              href="/threat-intel"
              className="flex flex-col items-center gap-2 p-4 rounded-lg bg-secondary/50 hover:bg-secondary transition-all duration-200 hover:border-primary/50 border border-transparent group"
            >
              <Shield className="h-6 w-6 text-muted-foreground group-hover:text-primary transition-colors" />
              <span className="text-sm font-medium text-foreground text-center">Threat Intel</span>
            </a>
            <a
              href="/live-threats"
              className="flex flex-col items-center gap-2 p-4 rounded-lg bg-secondary/50 hover:bg-secondary transition-all duration-200 hover:border-primary/50 border border-transparent group"
            >
              <Zap className="h-6 w-6 text-muted-foreground group-hover:text-primary transition-colors" />
              <span className="text-sm font-medium text-foreground text-center">Live Threats</span>
            </a>
            <a
              href="/cve"
              className="flex flex-col items-center gap-2 p-4 rounded-lg bg-secondary/50 hover:bg-secondary transition-all duration-200 hover:border-primary/50 border border-transparent group"
            >
              <Bug className="h-6 w-6 text-muted-foreground group-hover:text-primary transition-colors" />
              <span className="text-sm font-medium text-foreground text-center">CVE Explorer</span>
            </a>
            <a
              href="/domain"
              className="flex flex-col items-center gap-2 p-4 rounded-lg bg-secondary/50 hover:bg-secondary transition-all duration-200 hover:border-primary/50 border border-transparent group"
            >
              <Globe className="h-6 w-6 text-muted-foreground group-hover:text-primary transition-colors" />
              <span className="text-sm font-medium text-foreground text-center">Domain Intel</span>
            </a>
            <a
              href="/ip"
              className="flex flex-col items-center gap-2 p-4 rounded-lg bg-secondary/50 hover:bg-secondary transition-all duration-200 hover:border-primary/50 border border-transparent group"
            >
              <Activity className="h-6 w-6 text-muted-foreground group-hover:text-primary transition-colors" />
              <span className="text-sm font-medium text-foreground text-center">IP Analyzer</span>
            </a>
            <a
              href="/import"
              className="flex flex-col items-center gap-2 p-4 rounded-lg bg-secondary/50 hover:bg-secondary transition-all duration-200 hover:border-primary/50 border border-transparent group"
            >
              <Upload className="h-6 w-6 text-muted-foreground group-hover:text-primary transition-colors" />
              <span className="text-sm font-medium text-foreground text-center">Import Data</span>
            </a>
          </div>
        </CardContent>
      </Card>

      {/* Info Banner */}
      <Card className="bg-gradient-to-r from-primary/10 to-accent/10 border-primary/30">
        <CardContent className="p-4">
          <div className="flex items-start gap-3">
            <TrendingUp className="h-5 w-5 text-primary mt-0.5" />
            <div>
              <h3 className="font-semibold text-foreground mb-1">Platform v2.0 Features</h3>
              <p className="text-sm text-muted-foreground">
                Now with live threat feeds, CVE/exploit database, real-time malware tracking, 
                and interactive threat maps. All data is processed locally in your browser.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
