import { useEffect, useState } from "react";
import {
  AlertTriangle,
  Shield,
  Clock,
  ExternalLink,
  RefreshCcw,
} from "lucide-react";
import { cn } from "@/lib/utils";

/* =====================================================
   TYPES
===================================================== */

type Severity = "low" | "medium" | "high" | "critical";

interface FeedItem {
  timestamp: string;
  value: string;
  type: "ip" | "domain" | "url" | "hash";
  source: string;
  severity: Severity;
  tags: string[];
  reference: string;
}

interface FeedStatus {
  name: string;
  status: "online" | "offline";
}

/* =====================================================
   CORS-SAFE PUBLIC MIRRORS
===================================================== */

const FEEDS = [
  {
    name: "ThreatFox",
    url: "https://cors.isomorphic-git.org/https://threatfox.abuse.ch/export/txt/recent/",
    severity: "critical" as Severity,
    tags: ["malware", "c2", "ransomware"],
    ref: "https://threatfox.abuse.ch",
  },
  {
    name: "URLHaus",
    url: "https://cors.isomorphic-git.org/https://urlhaus.abuse.ch/downloads/text/",
    severity: "high" as Severity,
    tags: ["malware", "payload"],
    ref: "https://urlhaus.abuse.ch",
  },
  {
    name: "OpenPhish",
    url: "https://cors.isomorphic-git.org/https://openphish.com/feed.txt",
    severity: "high" as Severity,
    tags: ["phishing"],
    ref: "https://openphish.com",
  },
];

/* =====================================================
   COMPONENT
===================================================== */

export function IPAnalyzer() {
  const [items, setItems] = useState<FeedItem[]>([]);
  const [feedStatus, setFeedStatus] = useState<FeedStatus[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadFeeds();
  }, []);

  const loadFeeds = async () => {
    setLoading(true);
    const collected: FeedItem[] = [];
    const statuses: FeedStatus[] = [];

    for (const feed of FEEDS) {
      try {
        const res = await fetch(feed.url);
        const text = await res.text();

        const lines = text
          .split("\n")
          .filter(
            (l) =>
              l &&
              !l.startsWith("#") &&
              !l.startsWith("//") &&
              l.length > 4
          )
          .slice(0, 10);

        for (const line of lines) {
          collected.push({
            timestamp: new Date().toISOString(),
            value: line.trim(),
            type: inferType(line),
            source: feed.name,
            severity: feed.severity,
            tags: feed.tags,
            reference: feed.ref,
          });
        }

        statuses.push({ name: feed.name, status: "online" });
      } catch {
        statuses.push({ name: feed.name, status: "offline" });
      }
    }

    setItems(collected);
    setFeedStatus(statuses);
    setLoading(false);
  };

  const inferType = (v: string): FeedItem["type"] => {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return "ip";
    if (v.startsWith("http")) return "url";
    if (v.length === 64) return "hash";
    return "domain";
  };

  const severityClass = (s: Severity) => {
    switch (s) {
      case "critical":
        return "bg-destructive/20 text-destructive";
      case "high":
        return "bg-orange-500/20 text-orange-500";
      case "medium":
        return "bg-yellow-500/20 text-yellow-500";
      default:
        return "bg-primary/10 text-primary";
    }
  };

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* HEADER */}
      <div>
        <h1 className="text-2xl font-bold">
          🔥 Latest Threat Intelligence (Live, No API)
        </h1>
        <p className="text-muted-foreground text-sm">
          Public threat feeds updated in near real-time
        </p>
      </div>

      {/* FEED STATUS */}
      <div className="card-cyber p-4 space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-primary" />
            <span className="font-semibold">Active Threat Feeds</span>
          </div>
          <button
            onClick={loadFeeds}
            className="text-xs flex items-center gap-1 text-muted-foreground hover:text-primary"
          >
            <RefreshCcw className="h-3 w-3" />
            Refresh
          </button>
        </div>

        <div className="flex flex-wrap gap-3 text-xs">
          {feedStatus.map((f) => (
            <span
              key={f.name}
              className={cn(
                "px-2 py-1 rounded font-mono",
                f.status === "online"
                  ? "bg-success/20 text-success"
                  : "bg-destructive/20 text-destructive"
              )}
            >
              {f.name}: {f.status}
            </span>
          ))}
        </div>
      </div>

      {/* FEED ITEMS */}
      {loading ? (
        <div className="text-center text-muted-foreground py-10">
          Loading live threat intelligence…
        </div>
      ) : items.length === 0 ? (
        <div className="text-center text-muted-foreground py-10">
          No threat data available (feeds blocked or offline)
        </div>
      ) : (
        <div className="space-y-3">
          {items.map((i, idx) => (
            <div key={idx} className="card-cyber p-4 flex gap-4">
              <AlertTriangle className="h-5 w-5 text-destructive mt-1" />

              <div className="flex-1 space-y-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span
                    className={cn(
                      "px-2 py-0.5 rounded text-xs font-mono",
                      severityClass(i.severity)
                    )}
                  >
                    {i.severity.toUpperCase()}
                  </span>
                  <span className="text-xs font-mono text-muted-foreground">
                    {i.source}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    [{i.type}]
                  </span>
                </div>

                <p className="font-mono text-sm break-all">{i.value}</p>

                <div className="flex items-center gap-3 text-xs text-muted-foreground">
                  <span className="flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    {new Date(i.timestamp).toUTCString()}
                  </span>

                  <a
                    href={i.reference}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-1 hover:underline"
                  >
                    Source
                    <ExternalLink className="h-3 w-3" />
                  </a>
                </div>

                <div className="flex flex-wrap gap-2 pt-1">
                  {i.tags.map((t) => (
                    <span
                      key={t}
                      className="px-2 py-0.5 rounded bg-secondary text-xs font-mono"
                    >
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* FOOTER */}
      <div className="card-cyber p-4 text-xs text-muted-foreground">
        Sources include ThreatFox, URLHaus, and OpenPhish via public mirrors.
        No API keys required.
      </div>
    </div>
  );
}
