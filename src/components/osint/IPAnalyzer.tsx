import { useEffect, useState } from "react";
import {
  Search,
  Loader2,
  ExternalLink,
  User,
  ShieldCheck,
} from "lucide-react";
import { cn } from "@/lib/utils";

/* =====================================================
   TYPES
===================================================== */

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
   COMPONENT
===================================================== */

export function UsernameIntel() {
  const [username, setUsername] = useState("");
  const [platforms, setPlatforms] = useState<WMNPlatform[]>([]);
  const [results, setResults] = useState<UsernameResult[]>([]);
  const [loadingRules, setLoadingRules] = useState(true);
  const [loading, setLoading] = useState(false);

  /* =====================================================
     LOAD WHATS MY NAME RULES
  ===================================================== */

  useEffect(() => {
    const loadRules = async () => {
      try {
        const res = await fetch(WMN_RULES_URL);
        const data = await res.json();

        if (!data?.sites) {
          throw new Error("Invalid WMN data format");
        }

        setPlatforms(data.sites);
      } catch (err) {
        console.error("Failed to load WhatsMyName rules:", err);
      } finally {
        setLoadingRules(false);
      }
    };

    loadRules();
  }, []);

  /* =====================================================
     BUILD USERNAME LINKS (SAFE MODE)
  ===================================================== */

  const generateResults = () => {
    const clean = username.trim();
    if (!clean) return;

    setLoading(true);

    const generated: UsernameResult[] = platforms
      .filter((p) => p.uri_check)
      .slice(0, 150) // hard cap to keep UI responsive
      .map((platform) => ({
        platform: platform.name,
        url: platform.uri_check.replace(
          "{account}",
          encodeURIComponent(clean)
        ),
      }));

    setResults(generated);
    setLoading(false);
  };

  /* =====================================================
     UI
  ===================================================== */

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* HEADER */}
      <div>
        <h1 className="text-2xl font-bold">Username Intelligence</h1>
        <p className="text-muted-foreground text-sm mt-1">
          Platform enumeration using WhatsMyName open-source rules
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
            onKeyDown={(e) => e.key === "Enter" && generateResults()}
            disabled={loadingRules}
          />
        </div>

        <button
          onClick={generateResults}
          disabled={loading || loadingRules}
          className="px-4 py-2 rounded bg-primary text-primary-foreground text-sm flex items-center gap-2"
        >
          {loading ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Search className="h-4 w-4" />
          )}
          Generate
        </button>
      </div>

      {/* STATUS */}
      <div className="card-cyber p-4 flex items-center gap-2 text-sm">
        <ShieldCheck className="h-4 w-4 text-primary" />
        <span>
          {loadingRules
            ? "Loading platform rules…"
            : `Loaded ${platforms.length} platforms`}
        </span>
      </div>

      {/* RESULTS */}
      {results.length > 0 && (
        <div className="card-cyber p-4 space-y-3">
          <h2 className="font-semibold">
            Verification Links ({results.length})
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

      {/* EMPTY */}
      {!loading && results.length === 0 && !loadingRules && (
        <div className="card-cyber p-12 text-center text-muted-foreground">
          Enter a username to generate verification links
        </div>
      )}

      {/* FOOTER */}
      <div className="card-cyber p-4 text-xs text-muted-foreground">
        Uses WhatsMyName rule database.  
        Browser-safe mode. Manual verification recommended.
      </div>
    </div>
  );
}
