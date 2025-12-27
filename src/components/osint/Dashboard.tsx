import { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Bug,
  Clock,
  Database,
  Globe,
  Search,
  Server,
  Shield,
  TrendingUp,
  Upload,
  Zap,
} from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { StatCard } from "./StatCard";
import { APIStatusIndicator } from "./APIStatusIndicator";

import {
  initDatabase,
  getRecordCount,
  getActiveMonitorCount,
  getAlertsToday,
  getRecentActivity,
} from "@/lib/database";

import { getRecentCVEs } from "@/services/cveService";
import { resolveDNS } from "@/services/dnsService";
import { getIPGeolocation } from "@/services/ipService";

type APIStatus = "online" | "offline" | "checking";

interface Metrics {
  records: number;
  monitors: number;
  alertsToday: number;
  cves7d: number;
}

interface ActivityItem {
  id: string;
  type: string;
  title: string;
  description: string;
  timestamp: Date;
}

export function Dashboard() {
  const [metrics, setMetrics] = useState<Metrics>({
    records: 0,
    monitors: 0,
    alertsToday: 0,
    cves7d: 0,
  });

  const [recentCVEs, setRecentCVEs] = useState<any[]>([]);
  const [activity, setActivity] = useState<ActivityItem[]>([]);
  const [apiStatus, setApiStatus] = useState<Record<string, APIStatus>>({
    dns: "checking",
    ipGeo: "checking",
    nvd: "checking",
  });

  const [loading, setLoading] = useState(true);

  useEffect(() => {
    bootstrap();
  }, []);

  async function bootstrap() {
    setLoading(true);

    try {
      await initDatabase();

      const [
        records,
        monitors,
        alerts,
        activityLog,
        cves,
      ] = await Promise.all([
        getRecordCount(),
        getActiveMonitorCount(),
        getAlertsToday(),
        getRecentActivity(8),
        getRecentCVEs(7, 6).catch(() => []),
      ]);

      setMetrics({
        records,
        monitors,
        alertsToday: alerts,
        cves7d: cves.length,
      });

      setActivity(activityLog);
      setRecentCVEs(cves);

      await checkAPIs();
    } catch (err) {
      console.error("Dashboard bootstrap failure:", err);
    } finally {
      setLoading(false);
    }
  }

  async function checkAPIs() {
    try {
      await resolveDNS("google.com", "A");
      setApiStatus(s => ({ ...s, dns: "online" }));
    } catch {
      setApiStatus(s => ({ ...s, dns: "offline" }));
    }

    try {
      await getIPGeolocation("8.8.8.8");
      setApiStatus(s => ({ ...s, ipGeo: "online" }));
    } catch {
      setApiStatus(s => ({ ...s, ipGeo: "offline" }));
    }

    try {
      await fetch("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1");
      setApiStatus(s => ({ ...s, nvd: "online" }));
    } catch {
      setApiStatus(s => ({ ...s, nvd: "offline" }));
    }
  }

  function timeAgo(date: Date) {
    const delta = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
    if (delta < 60) return "just now";
    if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
    if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
    return `${Math.floor(delta / 86400)}d ago`;
  }

  function severityColor(sev: string) {
    switch (sev) {
      case "CRITICAL": return "text-red-500";
      case "HIGH": return "text-orange-500";
      case "MEDIUM": return "text-yellow-500";
      case "LOW": return "text-blue-500";
      default: return "text-muted-foreground";
    }
  }

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="space-y-4 text-center">
          <div className="h-12 w-12 animate-spin rounded-full border-2 border-primary border-t-transparent mx-auto" />
          <p className="text-sm font-mono text-muted-foreground">
            Initializing intelligence workspace…
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-8 animate-fade-in">
      {/* Header */}
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Security Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Consolidated OSINT, CVE intelligence, and monitoring state
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
          <Clock className="h-3 w-3" />
          {new Date().toLocaleTimeString()}
        </div>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Stored Records" value={metrics.records} icon={Database} />
        <StatCard title="Active Monitors" value={metrics.monitors} icon={Activity} />
        <StatCard title="Alerts Today" value={metrics.alertsToday} icon={AlertTriangle} variant="warning" />
        <StatCard title="CVEs (7 days)" value={metrics.cves7d} icon={Bug} variant="primary" />
      </div>

      {/* Middle Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* API Health */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Server className="h-4 w-4 text-primary" />
              Data Source Health
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <APIStatusIndicator name="DNS Resolver" status={apiStatus.dns} />
            <APIStatusIndicator name="IP Geolocation" status={apiStatus.ipGeo} />
            <APIStatusIndicator name="NVD CVE API" status={apiStatus.nvd} />
          </CardContent>
        </Card>

        {/* Recent CVEs */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Bug className="h-4 w-4 text-primary" />
              Recent Vulnerabilities
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {recentCVEs.map(cve => (
              <div
                key={cve.id}
                className="flex items-center justify-between rounded-lg bg-secondary/50 p-2"
              >
                <div>
                  <p className="text-sm font-medium">{cve.id}</p>
                  <p className="text-xs text-muted-foreground">
                    CVSS {cve.cvss.score.toFixed(1)}
                  </p>
                </div>
                <Badge variant="outline" className={severityColor(cve.cvss.severity)}>
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
            {activity.map(item => (
              <div
                key={item.id}
                className="flex justify-between items-center rounded-lg bg-secondary/50 p-2"
              >
                <div>
                  <p className="text-sm">{item.title}</p>
                  <p className="text-xs text-muted-foreground">{item.description}</p>
                </div>
                <span className="text-xs font-mono text-muted-foreground">
                  {timeAgo(item.timestamp)}
                </span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Quick Actions */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Zap className="h-5 w-5 text-primary" />
            Quick Actions
          </CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          {[
            ["/threat-intel", Shield, "Threat Intel"],
            ["/live-threats", Zap, "Live Map"],
            ["/cve", Bug, "CVE Explorer"],
            ["/domain", Globe, "Domain Intel"],
            ["/ip", Activity, "IP Analysis"],
            ["/import", Upload, "Import Data"],
          ].map(([href, Icon, label]) => (
            <a
              key={href as string}
              href={href as string}
              className="flex flex-col items-center gap-2 rounded-lg border bg-secondary/50 p-4 hover:border-primary transition"
            >
              <Icon className="h-6 w-6 text-muted-foreground" />
              <span className="text-sm">{label}</span>
            </a>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
