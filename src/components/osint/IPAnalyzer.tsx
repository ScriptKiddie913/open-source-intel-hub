import { useEffect, useState } from "react";
import {
  AlertTriangle,
  Globe,
  Shield,
  Clock,
  ExternalLink,
} from "lucide-react";
import { cn } from "@/lib/utils";

/* =====================================================
   TYPES
===================================================== */

type ThreatSeverity = "low" | "medium" | "high" | "critical";

interface ThreatItem {
  timestamp: string;
  type: "ip" | "domain" | "url" | "hash";
  value: string;
  source: string;
  severity: ThreatSeverity;
  tags: string[];
  reference?: string;
}

/* =====================================================
   STATIC FEED DEFINITIONS (NO API)
===================================================== */

const FEEDS = [
  {
    name: "ThreatFox",
    endpoint: "https://threatfox.abuse.ch/export/json/recent/",
    severity: "critical" as ThreatSeverity,
    tags: ["malware", "c2", "ransomware"],
  },
  {
    name: "URLHaus",
    endpoint: "https://urlhaus.abuse.ch/downloads/text/",
    severity: "high" as ThreatSeverity,
    tags: ["malware", "payload"],
  },
  {
    name: "OpenPhish",
    endpoint: "https://openphish.com/feed.txt",
    severity: "high" as ThreatSeverity,
    tags: ["phishing", "credential-harvest"],
  },
  {
    name: "Feodo Tracker",
    endpoint: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    severity: "medium" as ThreatSeverity,
    tags: ["botnet", "c2"],
  },
  {
    name: "SSL Blacklist",
    endpoint: "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
    severity: "medium" as ThreatSeverity,
    tags: ["tls", "encrypted-c2"],
  },
  {
    name: "Spamhaus DROP",
    endpoint: "https://www.spamhaus.org/drop/drop.txt",
    severity: "medium" as ThreatSeverity,
    tags: ["infrastructure", "abuse"],
  },
  {
    name: "CERT.PL",
    endpoint: "https://hole.cert.pl/domains/domains.txt",
    severity: "low" as ThreatSeverity,
    tags: ["malicious-domain"],
  },
];

/* =====================================================
   COMPONENT
===================================================== */

export function IPAnalyzer() {
  const [items, setItems] = useState<ThreatItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadThreatFeeds();
  }, []);

  /* =====================================================
     LOAD FEEDS
  ===================================================== */

  const loadThreatFeeds = async () => {
    setLoading(true);
    const collected: ThreatItem[] = [];

    for (const feed of FEEDS) {
      try {
        const res = await fetch(feed.endpoint);
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
          .slice(0, 5); // limit per feed for UI sanity

        for (const line of lines) {
          collected.push({
            timestamp: new Date().toISOString(),
            type: inferType(line),
            value: line.trim(),
            source: feed.name,
            severity: feed.severity,
            tags: feed.tags,
            reference: feed.endpoint,
          });
        }
      } catch {
        // silently skip unavailable feeds
      }
    }

    // newest first
    setItems(
      collected.sort(
        (a, b) =>
          new Date(b.timestamp).getTime() -
          new Date(a.timestamp).getTime()
      )
    );

    setLoading(false);
  };

  /* =====================================================
     HELPERS
  ===================================================== */

  const inferType = (value: string): ThreatItem["type"] => {
    if (value.match(/^\d{1,3}(\.\d{1,3}){3}/)) return "ip";
    if (value.startsWith("http")) return "url";
    if (value.length === 64) return "hash";
    return "domain";
  };

  const severityColor = (s: ThreatSeverity) => {
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

  /* =====================================================
     UI
  ===================================================== */

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground">
          🔥 Latest Threat Intelligence (Live, No API)
        </h1>
        <p className="text-muted-foreground text-sm mt-1">
          Public threat feeds updated in near real-time
        </p>
      </div>

      {/* Feed Status */}
      <div className="card-cyber p-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-primary" />
          <span className="font-semibold text-foreground">
            Active Threat Feeds
          </span>
        </div>
        <span className="text-xs text-muted-foreground font-mono">
          Updated: {new Date().toUTCString()}
        </span>
      </div>

      {/* Feed List */}
      {loading ? (
        <div className="text-center py-12 text-muted-foreground">
          Loading live threat intelligence…
        </div>
      ) : (
        <div className="space-y-3">
          {items.map((item, idx) => (
            <div
              key={idx}
              className="card-cyber p-4 flex items-start gap-4"
            >
              <div className="pt-1">
                <AlertTriangle className="h-5 w-5 text-destructive" />
              </div>

              <div className="flex-1 space-y-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span
                    className={cn(
                      "px-2 py-0.5 rounded text-xs font-mono",
                      severityColor(item.severity)
                    )}
                  >
                    {item.severity.toUpperCase()}
                  </span>
                  <span className="text-xs text-muted-foreground font-mono">
                    {item.source}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    [{item.type}]
                  </span>
                </div>

                <p className="font-mono text-sm break-all">
                  {item.value}
                </p>

                <div className="flex items-center gap-3 text-xs text-muted-foreground">
                  <span className="flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    {new Date(item.timestamp).toUTCString()}
                  </span>

                  {item.reference && (
                    <a
                      href={item.reference}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-1 hover:underline"
                    >
                      Source
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  )}
                </div>

                <div className="flex flex-wrap gap-2 pt-1">
                  {item.tags.map((tag) => (
                    <span
                      key={tag}
                      className="px-2 py-0.5 rounded bg-secondary text-xs font-mono"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Footer */}
      <div className="card-cyber p-4 text-xs text-muted-foreground">
        Sources include ThreatFox, URLHaus, OpenPhish, Feodo Tracker, SSLBL,
        Spamhaus DROP, and CERT.PL. No API keys required.
      </div>
    </div>
  );
}
