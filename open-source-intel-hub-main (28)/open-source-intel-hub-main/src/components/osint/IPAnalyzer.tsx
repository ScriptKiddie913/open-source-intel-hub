import { useState } from "react";
import {
  Server,
  Search,
  Loader2,
  Copy,
  MapPin,
  Shield,
  AlertTriangle,
  ExternalLink,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { saveSearchHistory } from "@/services/userDataService";

/* =====================================================
   SHODAN CONFIG (CLIENT-SIDE – EXPOSED AS REQUESTED)
===================================================== */

const SHODAN_API_KEY = "hhK0hGKpmCm198eK7OdWYzPqQ3Q14w9S";
const SHODAN_HOST_API = "https://api.shodan.io/shodan/host";

/* =====================================================
   TYPES
===================================================== */

type ThreatLevel = "info" | "medium" | "high" | "critical";

interface ShodanResponse {
  ip_str: string;
  country_name?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  org?: string;
  isp?: string;
  asn?: string;
  ports?: number[];
  hostnames?: string[];
  tags?: string[];
  vulns?: Record<string, unknown>;
}

/* =====================================================
   COMPONENT
===================================================== */

export function IPAnalyzer() {
  const [ip, setIP] = useState("");
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<ShodanResponse | null>(null);
  const [threat, setThreat] = useState<ThreatLevel>("info");

  /* =====================================================
     HELPERS
  ===================================================== */

  const isValidIP = (value: string) =>
    /^(\d{1,3}\.){3}\d{1,3}$/.test(value);

  const calculateThreat = (ports: number[] = [], vulns?: object): ThreatLevel => {
    let score = 0;

    if (ports.includes(22)) score += 1;
    if (ports.includes(23)) score += 2;
    if (ports.includes(3389)) score += 3;
    if (ports.includes(5900)) score += 2;
    if (ports.includes(445)) score += 3;

    if (vulns && Object.keys(vulns).length > 0) score += 5;

    if (score >= 8) return "critical";
    if (score >= 5) return "high";
    if (score >= 2) return "medium";
    return "info";
  };

  const threatClass = (t: ThreatLevel) => {
    switch (t) {
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
     FETCH SHODAN DATA
  ===================================================== */

  const analyzeIP = async () => {
    const clean = ip.trim();
    if (!isValidIP(clean)) return;

    setLoading(true);
    setData(null);

    try {
      const res = await fetch(
        `${SHODAN_HOST_API}/${clean}?key=${SHODAN_API_KEY}`
      );

      const json: ShodanResponse = await res.json();
      setData(json);
      const threatLevel = calculateThreat(json.ports, json.vulns);
      setThreat(threatLevel);

      // Save to Supabase search history (for logged-in users)
      await saveSearchHistory(clean, 'ip', json.ports?.length || 0, {
        location: `${json.city || 'Unknown'}, ${json.country_name || 'Unknown'}`,
        org: json.org,
        isp: json.isp,
        portsCount: json.ports?.length || 0,
        threatLevel,
      });
    } catch (err) {
      console.error("Shodan fetch failed", err);
    } finally {
      setLoading(false);
    }
  };

  const copy = (v: string) => navigator.clipboard.writeText(v);

  /* =====================================================
     RENDER
  ===================================================== */

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* HEADER */}
      <div>
        <h1 className="text-2xl font-bold text-foreground">
          IP Analyzer (Shodan Live)
        </h1>
        <p className="text-muted-foreground text-sm">
          Real-time host intelligence from Shodan
        </p>
      </div>

      {/* INPUT */}
      <div className="card-cyber p-4 flex gap-3">
        <div className="relative flex-1">
          <Server className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input
            className="w-full bg-transparent border border-border rounded pl-10 pr-3 py-2 text-sm outline-none"
            placeholder="Enter IP address (e.g. 8.8.8.8)"
            value={ip}
            onChange={(e) => setIP(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && analyzeIP()}
          />
        </div>

        <button
          onClick={analyzeIP}
          disabled={loading}
          className="px-4 py-2 rounded bg-primary text-primary-foreground flex items-center gap-2"
        >
          {loading ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Search className="h-4 w-4" />
          )}
          Analyze
        </button>
      </div>

      {/* RESULTS */}
      {data && (
        <div className="space-y-4">
          {/* SUMMARY */}
          <div className="card-cyber p-4 flex justify-between items-center">
            <div>
              <div className="flex items-center gap-2">
                <h2 className="font-mono text-xl font-bold">{data.ip_str}</h2>
                <button onClick={() => copy(data.ip_str)}>
                  <Copy className="h-4 w-4" />
                </button>
              </div>
              <p className="text-sm text-muted-foreground">
                {data.city}, {data.country_name}
              </p>
            </div>

            <span
              className={cn(
                "px-3 py-1 rounded text-sm font-mono",
                threatClass(threat)
              )}
            >
              {threat.toUpperCase()}
            </span>
          </div>

          {/* GEO */}
          <div className="card-cyber p-4">
            <h3 className="font-semibold flex items-center gap-2">
              <MapPin className="h-4 w-4" />
              Geolocation
            </h3>
            <p className="text-sm font-mono">
              {data.city}, {data.country_name}
            </p>
            <p className="text-xs text-muted-foreground">
              Lat: {data.latitude} | Lon: {data.longitude}
            </p>
          </div>

          {/* PORTS */}
          <div className="card-cyber p-4">
            <h3 className="font-semibold flex items-center gap-2">
              <Shield className="h-4 w-4" />
              Open Ports
            </h3>
            <div className="flex flex-wrap gap-2 mt-2">
              {data.ports?.map((p) => (
                <span
                  key={p}
                  className="px-2 py-1 bg-secondary text-xs font-mono rounded"
                >
                  {p}
                </span>
              ))}
            </div>
          </div>

          {/* VULNS */}
          {data.vulns && (
            <div className="card-cyber p-4 border-destructive/30 bg-destructive/5">
              <h3 className="font-semibold flex items-center gap-2 text-destructive">
                <AlertTriangle className="h-4 w-4" />
                Vulnerabilities
              </h3>

              <div className="flex flex-wrap gap-2 mt-2">
                {Object.keys(data.vulns).map((v) => (
                  <a
                    key={v}
                    href={`https://nvd.nist.gov/vuln/detail/${v}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-3 py-1 rounded bg-destructive/20 text-destructive text-xs font-mono hover:underline flex items-center gap-1"
                  >
                    {v}
                    <ExternalLink className="h-3 w-3" />
                  </a>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
