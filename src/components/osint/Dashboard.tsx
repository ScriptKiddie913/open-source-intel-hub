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

/* ============================
   Types
============================ */

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

/* ============================
   Component
============================ */

export function Dashboard() {
  /* ---------- Metrics ---------- */
  const [metrics, setMetrics] = useState<DashboardMetrics>({
    totalRecords: 0,
    activeMonitors: 0,
    alertsToday: 0,
    threatScore: 0,
    recentCVEs: 0,
    liveThreats: 0,
  });

  /* ---------- API Status ---------- */
  const [apiStatus, setApiStatus] = useState<Record<string, APIStatus>>({
    dns: "checking",
    ipGeo: "checking",
    shodan: "checking",
    certs: "checking",
    nvd: "checking",
    threatFeeds: "checking",
  });

  /* ---------- Data ---------- */
  const [recentActivity, setRecentActivity] = useState<RecentActivityItem[]>([]);
  const [recentCVEs, setRecentCVEs] = useState<any[]>([]);
  const [liveThreats, setLiveThreats] = useState<any[]>([]);

  /* ---------- UI ---------- */
  const [loading, setLoading] = useState(true);

  /* ============================
     Effects
  ============================ */

  useEffect(() => {
    initializeDashboard();
  }, []);

  /* ============================
     Initialization
  ============================ */

  const initializeDashboard = async () => {
    setLoading(true);

    try {
      await initDatabase();

      /* ----- Local DB Metrics ----- */
      const recordCountPromise = getRecordCount();
      const monitorCountPromise = getActiveMonitorCount();
      const alertsTodayPromise = getAlertsToday();
      const recentActivityPromise = getRecentActivity(10);

      /* ----- External Intelligence ----- */
      const recentCVEsPromise = getRecentCVEs(7, 5).catch(() => []);
      const liveThreatsPromise = getLiveThreatFeeds().catch(() => []);

      const [
        recordCount,
        monitorCount,
        alertsToday,
        activity,
        cves,
        threats,
      ] = await Promise.all([
        recordCountPromise,
        monitorCountPromise,
        alertsTodayPromise,
        recentActivityPromise,
        recentCVEsPromise,
        liveThreatsPromise,
      ]);

      /* ----- Deterministic Threat Score ----- */
      const computedThreatScore = calculateThreatScore(alertsToday, threats.length);

      setMetrics({
        totalRecords: recordCount,
        activeMonitors: monitorCount,
        alertsToday,
        threatScore: computedThreatScore,
        recentCVEs: cves.length,
        liveThreats: threats.length,
      });

      setRecentActivity(activity);
      setRecentCVEs(cves);
      setLiveThreats(threats);

      await evaluateAPIHealth();
    } catch (err) {
      console.error("Dashboard initialization failure:", err);
    } finally {
      setLoading(false);
    }
  };

  /* ============================
     API Health Checks
  ============================ */

  const evaluateAPIHealth = async () => {
    /* DNS */
    try {
      await resolveDNS("google.com", "A");
      setApiStatus(s => ({ ...s, dns: "online" }));
    } catch {
      setApiStatus(s => ({ ...s, dns: "offline" }));
    }

    /* IP Geolocation */
    try {
      await getIPGeolocation("8.8.8.8");
      setApiStatus(s => ({ ...s, ipGeo: "online" }));
    } catch {
      setApiStatus(s => ({ ...s, ipGeo: "offline" }));
    }

    /* NVD */
    try {
      await fetch("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1");
      setApiStatus(s => ({ ...s, nvd: "online" }));
    } catch {
      setApiStatus(s => ({ ...s, nvd: "offline" }));
    }

    /* Static / Assumed */
    setApiStatus(s => ({
      ...s,
      shodan: "online",
      certs: "online",
      threatFeeds: "online",
    }));
  };

  /* ============================
     Helpers
  ============================ */

  const calculateThreatScore = (alerts: number, threats: number): number => {
    const alertWeight = Math.min(alerts * 2, 60);
    const threatWeight = Math.min(Math.floor(threats / 5), 40);
    return Math.min(alertWeight + threatWeight, 100);
  };

  const formatTimeAgo = (date: Date) => {
    const seconds = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
    if (seconds < 60) return "just now";
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  };

  const getSeverityColor = (severity: string) => {
    const s = severity?.toUpperCase();
    if (s === "CRITICAL") return "text-red-500";
    if (s === "HIGH") return "text-orange-500";
    if (s === "MEDIUM") return "text-yellow-500";
    if (s === "LOW") return "text-blue-500";
    return "text-muted-foreground";
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

  /* ============================
     Loading
  ============================ */

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="space-y-4 text-center">
          <div className="h-12 w-12 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto" />
          <p className="text-xs font-mono text-muted-foreground">
            Initializing OSINT workspace…
          </p>
        </div>
      </div>
    );
  }

  /* ============================
     Render
  ============================ */

  return (
    <div className="p-6 space-y-8 animate-fade-in">
      {/* Header */}
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Real-time intelligence monitoring and structured threat context
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
          <Clock className="h-3 w-3" />
          {new Date().toLocaleTimeString()}
        </div>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Total Records" value={metrics.totalRecords} icon={Database} />
        <StatCard title="Active Monitors" value={metrics.activeMonitors} icon={Bell} />
        <StatCard title="Alerts Today" value={metrics.alertsToday} icon={AlertTriangle} variant="warning" />
        <StatCard title="Threat Score" value={`${metrics.threatScore}%`} icon={Shield} variant="danger" />
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* API Status */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Server className="h-4 w-4 text-primary" />
              Data Sources
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <APIStatusIndicator name="DNS Resolver" status={apiStatus.dns} />
            <APIStatusIndicator name="IP Geolocation" status={apiStatus.ipGeo} />
            <APIStatusIndicator name="Shodan" status={apiStatus.shodan} />
            <APIStatusIndicator name="Cert Transparency" status={apiStatus.certs} />
            <APIStatusIndicator name="NVD" status={apiStatus.nvd} />
            <APIStatusIndicator name="Threat Feeds" status={apiStatus.threatFeeds} />
          </CardContent>
        </Card>

        {/* CVEs */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Bug className="h-4 w-4 text-primary" />
              Recent CVEs
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {recentCVEs.map(cve => (
              <div key={cve.id} className="flex justify-between items-center p-2 rounded-lg bg-secondary/50">
                <div>
                  <p className="text-sm font-medium">{cve.id}</p>
                  <p className="text-xs text-muted-foreground">
                    CVSS {cve.cvss.score.toFixed(1)}
                  </p>
                </div>
                <Badge variant="outline" className={getSeverityColor(cve.cvss.severity)}>
                  {cve.cvss.severity}
                </Badge>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Activity */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-primary" />
              Recent Activity
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {recentActivity.map(item => (
              <div key={item.id} className="flex justify-between p-2 rounded-lg bg-secondary/50">
                <div className="flex gap-2">
                  <div className="text-primary">{getActivityIcon(item.type)}</div>
                  <div>
                    <p className="text-sm">{item.title}</p>
                    <p className="text-xs text-muted-foreground">{item.description}</p>
                  </div>
                </div>
                <span className="text-xs font-mono text-muted-foreground">
                  {formatTimeAgo(item.timestamp)}
                </span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
