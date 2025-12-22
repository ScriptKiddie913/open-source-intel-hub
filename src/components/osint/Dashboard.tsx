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
} from "lucide-react";
import { StatCard } from "./StatCard";
import { APIStatusIndicator } from "./APIStatusIndicator";
import { ThreatBadge } from "./ThreatBadge";
import { 
  getRecordCount, 
  getActiveMonitorCount, 
  getAlertsToday, 
  getRecentActivity,
  initDatabase,
} from "@/lib/database";
import { resolveDNS } from "@/services/dnsService";
import { getIPGeolocation } from "@/services/ipService";
import { cn } from "@/lib/utils";

type APIStatus = "online" | "offline" | "rate_limited" | "checking";

interface DashboardMetrics {
  totalRecords: number;
  activeMonitors: number;
  alertsToday: number;
  threatScore: number;
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
  });
  const [apiStatus, setApiStatus] = useState<Record<string, APIStatus>>({
    dns: "checking",
    ipGeo: "checking",
    shodan: "checking",
    certs: "checking",
  });
  const [recentActivity, setRecentActivity] = useState<RecentActivityItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
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

        setMetrics({
          totalRecords: records,
          activeMonitors: monitors,
          alertsToday: alerts,
          threatScore: calculateThreatScore(alerts),
        });

        setRecentActivity(activity);

        // Check API statuses
        checkAPIStatus();
      } catch (error) {
        console.error("Dashboard load error:", error);
      } finally {
        setLoading(false);
      }
    };

    loadDashboard();
  }, []);

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

    // For Shodan and certs, we'll mark as online (they don't have easy health checks)
    setApiStatus(prev => ({ ...prev, shodan: "online", certs: "online" }));
  };

  const calculateThreatScore = (alerts: number): number => {
    // Simple threat score calculation based on alerts
    if (alerts === 0) return 0;
    if (alerts < 5) return 25;
    if (alerts < 10) return 50;
    if (alerts < 20) return 75;
    return 100;
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
          <h1 className="text-2xl font-bold text-foreground">Dashboard</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Real-time intelligence monitoring and analysis
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-muted-foreground font-mono">
          <Clock className="h-3 w-3" />
          <span>Last updated: {new Date().toLocaleTimeString()}</span>
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Records"
          value={metrics.totalRecords.toLocaleString()}
          icon={Database}
          variant="default"
        />
        <StatCard
          title="Active Monitors"
          value={metrics.activeMonitors}
          icon={Activity}
          variant="primary"
        />
        <StatCard
          title="Alerts Today"
          value={metrics.alertsToday}
          icon={Bell}
          variant={metrics.alertsToday > 10 ? "danger" : "default"}
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
          </div>
        </div>

        {/* Recent Activity */}
        <div className="lg:col-span-2 card-cyber p-4 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-primary" />
              <h2 className="font-semibold text-foreground">Recent Activity</h2>
            </div>
          </div>
          
          {recentActivity.length > 0 ? (
            <div className="space-y-2">
              {recentActivity.map((activity) => (
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
                Start by searching for domains, IPs, or importing data
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Quick Actions */}
      <div className="card-cyber p-4">
        <h2 className="font-semibold text-foreground mb-4">Quick Actions</h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <a
            href="/search"
            className="flex flex-col items-center gap-2 p-4 rounded-lg bg-secondary/50 hover:bg-secondary transition-all duration-200 hover:border-primary/50 border border-transparent group"
          >
            <Search className="h-6 w-6 text-muted-foreground group-hover:text-primary transition-colors" />
            <span className="text-sm font-medium text-foreground">Search</span>
          </a>
          <a
            href="/domain"
            className="flex flex-col items-center gap-2 p-4 rounded-lg bg-secondary/50 hover:bg-secondary transition-all duration-200 hover:border-primary/50 border border-transparent group"
          >
            <Globe className="h-6 w-6 text-muted-foreground group-hover:text-primary transition-colors" />
            <span className="text-sm font-medium text-foreground">Domain Intel</span>
          </a>
          <a
            href="/import"
            className="flex flex-col items-center gap-2 p-4 rounded-lg bg-secondary/50 hover:bg-secondary transition-all duration-200 hover:border-primary/50 border border-transparent group"
          >
            <Upload className="h-6 w-6 text-muted-foreground group-hover:text-primary transition-colors" />
            <span className="text-sm font-medium text-foreground">Import Data</span>
          </a>
          <a
            href="/monitors"
            className="flex flex-col items-center gap-2 p-4 rounded-lg bg-secondary/50 hover:bg-secondary transition-all duration-200 hover:border-primary/50 border border-transparent group"
          >
            <Bell className="h-6 w-6 text-muted-foreground group-hover:text-primary transition-colors" />
            <span className="text-sm font-medium text-foreground">Monitors</span>
          </a>
        </div>
      </div>
    </div>
  );
}
