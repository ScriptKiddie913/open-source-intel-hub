import { useState, useEffect } from "react";
import { Settings, Database, Trash2, Download, RefreshCw, HardDrive } from "lucide-react";
import { Button } from "@/components/ui/button";
import { getRecordCount, getBreachCount, getDatasets, clearAllData, getMonitors } from "@/lib/database";
import { useToast } from "@/hooks/use-toast";

export function SettingsPage() {
  const [stats, setStats] = useState({
    records: 0,
    breaches: 0,
    datasets: 0,
    monitors: 0,
  });
  const [loading, setLoading] = useState(true);
  const [clearing, setClearing] = useState(false);
  const { toast } = useToast();

  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    setLoading(true);
    try {
      const [records, breaches, datasets, monitors] = await Promise.all([
        getRecordCount(),
        getBreachCount(),
        getDatasets(),
        getMonitors(),
      ]);

      setStats({
        records,
        breaches,
        datasets: datasets.length,
        monitors: monitors.length,
      });
    } catch (error) {
      console.error("Failed to load stats:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleClearData = async () => {
    if (!confirm("Are you sure you want to clear all data? This cannot be undone.")) {
      return;
    }

    setClearing(true);
    try {
      await clearAllData();
      await loadStats();
      toast({ title: "Data cleared", description: "All data has been deleted" });
    } catch (error) {
      toast({ title: "Error", description: "Failed to clear data", variant: "destructive" });
    } finally {
      setClearing(false);
    }
  };

  const handleExportAll = async () => {
    toast({ title: "Export", description: "Export functionality coming soon" });
  };

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground">Settings</h1>
        <p className="text-muted-foreground text-sm mt-1">
          Manage your OSINT platform configuration and data
        </p>
      </div>

      {/* Database Stats */}
      <div className="card-cyber p-4">
        <div className="flex items-center gap-2 mb-4">
          <Database className="h-4 w-4 text-primary" />
          <h2 className="font-semibold text-foreground">Database Statistics</h2>
          <Button
            variant="ghost"
            size="icon"
            onClick={loadStats}
            disabled={loading}
            className="h-6 w-6 ml-auto"
          >
            <RefreshCw className={`h-3 w-3 ${loading ? "animate-spin" : ""}`} />
          </Button>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-3 rounded-lg bg-secondary/50">
            <p className="text-2xl font-mono font-bold text-primary">{stats.records.toLocaleString()}</p>
            <p className="text-xs text-muted-foreground">Intelligence Records</p>
          </div>
          <div className="p-3 rounded-lg bg-secondary/50">
            <p className="text-2xl font-mono font-bold text-primary">{stats.breaches.toLocaleString()}</p>
            <p className="text-xs text-muted-foreground">Breach Records</p>
          </div>
          <div className="p-3 rounded-lg bg-secondary/50">
            <p className="text-2xl font-mono font-bold text-primary">{stats.datasets}</p>
            <p className="text-xs text-muted-foreground">Imported Datasets</p>
          </div>
          <div className="p-3 rounded-lg bg-secondary/50">
            <p className="text-2xl font-mono font-bold text-primary">{stats.monitors}</p>
            <p className="text-xs text-muted-foreground">Active Monitors</p>
          </div>
        </div>
      </div>

      {/* Data Management */}
      <div className="card-cyber p-4">
        <div className="flex items-center gap-2 mb-4">
          <HardDrive className="h-4 w-4 text-primary" />
          <h2 className="font-semibold text-foreground">Data Management</h2>
        </div>

        <div className="space-y-3">
          <div className="flex items-center justify-between p-3 rounded-lg bg-secondary/50">
            <div>
              <p className="font-medium text-foreground">Export All Data</p>
              <p className="text-xs text-muted-foreground">Download all records as JSON</p>
            </div>
            <Button variant="outline" size="sm" onClick={handleExportAll}>
              <Download className="h-4 w-4 mr-2" />
              Export
            </Button>
          </div>

          <div className="flex items-center justify-between p-3 rounded-lg bg-destructive/5 border border-destructive/30">
            <div>
              <p className="font-medium text-destructive">Clear All Data</p>
              <p className="text-xs text-muted-foreground">Permanently delete all stored data</p>
            </div>
            <Button variant="danger" size="sm" onClick={handleClearData} disabled={clearing}>
              <Trash2 className="h-4 w-4 mr-2" />
              {clearing ? "Clearing..." : "Clear"}
            </Button>
          </div>
        </div>
      </div>

      {/* API Configuration */}
      <div className="card-cyber p-4">
        <div className="flex items-center gap-2 mb-4">
          <Settings className="h-4 w-4 text-primary" />
          <h2 className="font-semibold text-foreground">API Configuration</h2>
        </div>

        <div className="space-y-3">
          <div className="p-3 rounded-lg bg-secondary/50">
            <div className="flex items-center justify-between mb-2">
              <p className="font-medium text-foreground">Google Public DNS</p>
              <span className="text-xs text-success">Active</span>
            </div>
            <p className="text-xs text-muted-foreground font-mono">https://dns.google/resolve</p>
          </div>

          <div className="p-3 rounded-lg bg-secondary/50">
            <div className="flex items-center justify-between mb-2">
              <p className="font-medium text-foreground">IP Geolocation (ip-api.com)</p>
              <span className="text-xs text-success">Active</span>
            </div>
            <p className="text-xs text-muted-foreground font-mono">http://ip-api.com/json</p>
          </div>

          <div className="p-3 rounded-lg bg-secondary/50">
            <div className="flex items-center justify-between mb-2">
              <p className="font-medium text-foreground">Shodan InternetDB</p>
              <span className="text-xs text-success">Active</span>
            </div>
            <p className="text-xs text-muted-foreground font-mono">https://internetdb.shodan.io</p>
          </div>

          <div className="p-3 rounded-lg bg-secondary/50">
            <div className="flex items-center justify-between mb-2">
              <p className="font-medium text-foreground">Certificate Transparency (crt.sh)</p>
              <span className="text-xs text-success">Active</span>
            </div>
            <p className="text-xs text-muted-foreground font-mono">https://crt.sh</p>
          </div>
        </div>
      </div>

      {/* About */}
      <div className="card-cyber p-4">
        <h2 className="font-semibold text-foreground mb-3">About OSINT Platform</h2>
        <p className="text-sm text-muted-foreground">
          This platform uses publicly available OSINT (Open Source Intelligence) APIs and data sources.
          All data is stored locally in your browser using IndexedDB. No data is sent to external servers
          except for the public APIs used for lookups.
        </p>
        <div className="mt-4 pt-4 border-t border-border">
          <div className="flex items-center gap-4 text-xs text-muted-foreground">
            <span>Version 1.0.0</span>
            <span>•</span>
            <span>Built with React + TypeScript</span>
          </div>
        </div>
      </div>
    </div>
  );
}
