import { useEffect, useState } from "react";
import {
  AlertTriangle,
  Shield,
  Clock,
  ExternalLink,
  RefreshCcw,
  User,
  Search,
  Loader2,
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

interface WMNPlatform {
  name: string;
  uri_check: string;
}

interface UsernameResult {
  platform: string;
  url: string;
}

/* =====================================================
   CONSTANTS
===================================================== */

const WMN_RULES_URL =
  "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json";

/* =====================================================
   CORS-SAFE PUBLIC MIRRORS (THREAT FEEDS)
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
   COMPONENT (DO NOT RENAME)
===================================================== */

export function IPAnalyzer() {
  /* ---------- Threat Feed State ---------- */
  const [items, setItems] = useState<FeedItem[]>([]);
  const [feedStatus, setFeedStatus] = useState<FeedStatus[]>([]);
  const [loadingFeeds, setLoadingFeeds] = useState(false);

  /* ---------- Username Search State ---------- */
  const [username, setUsername] = useState("");
  const [wmnPlatforms, setWmnPlatforms] = useState<WMNPlatform[]>([]);
  const [usernameResults, setUsernameResults] = useState<UsernameResult[]>([]);
  const [loadingRules, setLoadingRules] = useState(true);
  const [loadingUserSearch, setLoadingUserSearch] = useState(false);

  /* =====================================================
     INITIAL LOAD
  ===================================================== */

  useEffect(() => {
    loadFeeds();
    loadWMNRules();
  }, []);

  /* =====================================================
     LOAD THREAT FEEDS
  ===================================================== */

  const loadFeeds = async () => {
    setLoadingFeeds(true);

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
    setLoadingFeeds(false);
  };

  /* =====================================================
     LOAD WHATS MY NAME RULES
  ===================================================== */

  const loadWMNRules = async () => {
    try {
      const res = await fetch(WMN_RULES_URL);
      const data = await res.json();
      setWmnPlatforms(data?.sites || []);
    } catch (err) {
      console.error("Failed to load WhatsMyName rules", err);
    } finally {
      setLoadingRules(false);
    }
  };

  /* =====================================================
     USERNAME SEARCH (SAFE MODE)
  ===================================================== */

  const runUsernameSearch = () => {
    const clean = username.trim();
    if (!clean || wmnPlatforms.length === 0) return;

    setLoadingUserSearch(true);

    const generated: UsernameResult[] = wmnPlatforms
      .filter((p) => p.uri_check)
      .slice(0, 150)
      .map((platform) => ({
        platform: platform.name,
        url: platform.uri_check.replace(
          "{account}",
          encodeURIComponent(clean)
        ),
      }));

    setUsernameResults(generated);
    setLoadingUserSearch(false);
  };

  /* =====================================================
     HELPERS
  ===================================================== */

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

  /* =====================================================
     RENDER
  ===================================================== */

  return (
    <div className="p-6 space-y-10 animate-fade-in">
      {/* ================= THREAT INTEL ================= */}

      <div>
        <h1 className="text-2xl font-bold">
          🔥 Latest Threat Intelligence (Live, No API)
        </h1>
        <p className="text-muted-foreground text-sm">
          Public threat feeds updated in near real-time
        </p>
      </div>

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

      {loadingFeeds ? (
        <div className="text-center text-muted-foreground">
          Loading live threat intelligence…
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

      {/* ================= USERNAME SEARCH ================= */}

      <div>
        <h2 className="text-xl font-bold">👤 Username Intelligence</h2>
        <p className="text-muted-foreground text-sm">
          Multi-platform username enumeration using WhatsMyName rules
        </p>
      </div>

      <div className="card-cyber p-4 flex gap-3">
        <div className="relative flex-1">
          <User className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input
            className="w-full bg-transparent border border-border rounded pl-10 pr-3 py-2 text-sm outline-none"
            placeholder="Enter username (e.g. john_doe)"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && runUsernameSearch()}
            disabled={loadingRules}
          />
        </div>

        <button
          onClick={runUsernameSearch}
          disabled={loadingRules || loadingUserSearch}
          className="px-4 py-2 rounded bg-primary text-primary-foreground text-sm flex items-center gap-2"
        >
          {loadingUserSearch ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Search className="h-4 w-4" />
          )}
          Search
        </button>
      </div>

      {usernameResults.length > 0 && (
        <div className="card-cyber p-4 space-y-3">
          <h3 className="font-semibold">
            Verification Links ({usernameResults.length})
          </h3>

          <div className="space-y-2 max-h-[520px] overflow-y-auto">
            {usernameResults.map((r, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between p-3 rounded bg-secondary/50"
              >
                <div className="flex flex-col min-w-0">
                  <span className="font-medium text-sm">
                    {r.platform}
                  </span>
                  <span className="text-xs font-mono text-muted-foreground truncate">
                    {r.url}
                  </span>
                </div>

                <a
                  href={r.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 text-primary hover:underline"
                >
                  Open
                  <ExternalLink className="h-4 w-4" />
                </a>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="card-cyber p-4 text-xs text-muted-foreground">
        Threat feeds + username enumeration powered by public OSINT sources.  
        No API keys. No login. Browser-safe mode.
      </div>
    </div>
  );
}
