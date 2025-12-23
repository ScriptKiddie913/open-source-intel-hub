import { useEffect, useState } from "react";
import {
  Search,
  Loader2,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ExternalLink,
  User,
} from "lucide-react";
import { cn } from "@/lib/utils";

/* =====================================================
   TYPES
===================================================== */

type PlatformResultStatus = "found" | "not_found" | "unknown" | "error";

interface WMNPlatform {
  name: string;
  uri_check: string;
  e_code?: number;
  m_code?: number;
  e_string?: string;
  m_string?: string;
}

interface UsernameResult {
  platform: string;
  url: string;
  status: PlatformResultStatus;
  httpStatus?: number;
}

/* =====================================================
   CONSTANTS
===================================================== */

const WMN_RULES_URL =
  "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json";

/* =====================================================
   COMPONENT
===================================================== */

export function UsernameIntel() {
  const [username, setUsername] = useState("");
  const [platforms, setPlatforms] = useState<WMNPlatform[]>([]);
  const [results, setResults] = useState<UsernameResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadingRules, setLoadingRules] = useState(true);

  /* =====================================================
     LOAD WHATS MY NAME RULES
  ===================================================== */

  useEffect(() => {
    const loadRules = async () => {
      try {
        const res = await fetch(WMN_RULES_URL);
        const data = await res.json();

        // WhatsMyName JSON structure: { sites: [...] }
        setPlatforms(data.sites || []);
      } catch (err) {
        console.error("Failed to load WMN rules", err);
      } finally {
        setLoadingRules(false);
      }
    };

    loadRules();
  }, []);

  /* =====================================================
     USERNAME CHECK LOGIC
  ===================================================== */

  const checkUsername = async () => {
    const cleanUsername = username.trim();

    if (!cleanUsername || platforms.length === 0) return;

    setLoading(true);
    setResults([]);

    const collected: UsernameResult[] = [];

    for (const platform of platforms) {
      if (!platform.uri_check) continue;

      const url = platform.uri_check.replace(
        "{account}",
        encodeURIComponent(cleanUsername)
      );

      try {
        const res = await fetch(url, {
          method: "GET",
          redirect: "manual",
        });

        let status: PlatformResultStatus = "unknown";

        if (platform.m_code && res.status === platform.m_code) {
          status = "found";
        } else if (platform.e_code && res.status === platform.e_code) {
          status = "not_found";
        } else if (res.status === 403 || res.status === 429) {
          status = "unknown";
        }

        collected.push({
          platform: platform.name,
          url,
          status,
          httpStatus: res.status,
        });
      } catch {
        collected.push({
          platform: platform.name,
          url,
          status: "error",
        });
      }
    }

    setResults(collected);
    setLoading(false);
  };

  /* =====================================================
     UI HELPERS
  ===================================================== */

  const statusBadge = (status: PlatformResultStatus) => {
    switch (status) {
      case "found":
        return (
          <span className="flex items-center gap-1 text-success">
            <CheckCircle2 className="h-4 w-4" />
            FOUND
          </span>
        );
      case "not_found":
        return (
          <span className="flex items-center gap-1 text-muted-foreground">
            <XCircle className="h-4 w-4" />
            NOT FOUND
          </span>
        );
      case "error":
        return (
          <span className="flex items-center gap-1 text-destructive">
            <AlertTriangle className="h-4 w-4" />
            ERROR
          </span>
        );
      default:
        return (
          <span className="flex items-center gap-1 text-yellow-500">
            <AlertTriangle className="h-4 w-4" />
            UNKNOWN
          </span>
        );
    }
  };

  /* =====================================================
     RENDER
  ===================================================== */

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* HEADER */}
      <div>
        <h1 className="text-2xl font-bold">Username Intelligence</h1>
        <p className="text-muted-foreground text-sm mt-1">
          Multi-platform username enumeration using WhatsMyName rules
        </p>
      </div>

      {/* SEARCH */}
      <div className="card-cyber p-4 flex gap-3">
        <div className="relative flex-1">
          <User className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input
            className="w-full bg-transparent border border-border rounded pl-10 pr-3 py-2 text-sm outline-none"
            placeholder="Enter username (e.g. john_doe)"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && checkUsername()}
            disabled={loadingRules}
          />
        </div>
        <button
          onClick={checkUsername}
          disabled={loading || loadingRules}
          className="px-4 py-2 rounded bg-primary text-primary-foreground text-sm flex items-center gap-2"
        >
          {loading ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Search className="h-4 w-4" />
          )}
          Search
        </button>
      </div>

      {/* RULE LOAD STATUS */}
      {loadingRules && (
        <div className="text-sm text-muted-foreground">
          Loading WhatsMyName platform rules…
        </div>
      )}

      {/* RESULTS */}
      {results.length > 0 && (
        <div className="card-cyber p-4 space-y-3">
          <h2 className="font-semibold text-foreground">
            Results ({results.length} platforms checked)
          </h2>

          <div className="space-y-2 max-h-[520px] overflow-y-auto">
            {results.map((r, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between p-3 rounded bg-secondary/50"
              >
                <div className="flex flex-col min-w-0">
                  <span className="font-medium text-sm">
                    {r.platform}
                  </span>
                  <a
                    href={r.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs font-mono text-muted-foreground truncate hover:underline"
                  >
                    {r.url}
                  </a>
                </div>

                <div className="flex items-center gap-3">
                  {statusBadge(r.status)}
                  <a
                    href={r.url}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <ExternalLink className="h-4 w-4 text-muted-foreground hover:text-primary" />
                  </a>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* EMPTY STATE */}
      {!loading && results.length === 0 && !loadingRules && (
        <div className="card-cyber p-12 text-center text-muted-foreground">
          Enter a username to enumerate across hundreds of platforms
        </div>
      )}

      {/* FOOTER */}
      <div className="card-cyber p-4 text-xs text-muted-foreground">
        Powered by WhatsMyName open-source rule database.  
        No API keys. No login. Direct platform verification.
      </div>
    </div>
  );
}
