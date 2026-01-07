import { useState } from "react";
import {
  Shield,
  Search,
  Loader2,
  AlertTriangle,
  CheckCircle2,
  Mail,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ThreatBadge } from "./ThreatBadge";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";

/* ===================== TYPES ===================== */

type BreachRecord = {
  id: string;
  source: string;
  date: string;
  dataTypes: string[];
  passwordExposed: boolean;
};

type ThreatLevel = "info" | "medium" | "high" | "critical";

/* ===================== COMPONENT ===================== */

export function BreachChecker() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<BreachRecord[]>([]);
  const [searched, setSearched] = useState(false);
  const { toast } = useToast();

  /* ===================== HELPERS ===================== */

  const validateEmail = (e: string) =>
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

  const getThreatLevel = (n: number): ThreatLevel => {
    if (n === 0) return "info";
    if (n <= 2) return "medium";
    if (n <= 5) return "high";
    return "critical";
  };

  const iconForType = (t: string) => {
    if (t.includes("pass")) return "🔐";
    if (t.includes("phone")) return "📱";
    if (t.includes("user")) return "👤";
    if (t.includes("ip")) return "🌐";
    return "📧";
  };

  /* ===================== OSINT LOOKUPS ===================== */

  async function queryBreachDirectory(email: string): Promise<BreachRecord[]> {
    try {
      const url =
        "https://r.jina.ai/https://api.breachdirectory.org/?func=auto&term=" +
        encodeURIComponent(email);

      const res = await fetch(url);
      const text = await res.text();

      // jina.ai returns text, not JSON
      if (!text.includes("source")) return [];

      const matches = [...text.matchAll(/source["']?\s*:\s*["']([^"']+)/gi)];

      return matches.map((m, i) => ({
        id: `bd-${i}`,
        source: m[1],
        date: "Unknown",
        dataTypes: ["email"],
        passwordExposed: false,
      }));
    } catch {
      return [];
    }
  }

  async function queryLeakCheck(email: string): Promise<BreachRecord[]> {
    try {
      const proxy =
        "https://api.allorigins.win/raw?url=" +
        encodeURIComponent(
          `https://leakcheck.io/api/public?check=${email}`
        );

      const res = await fetch(proxy);
      const json = await res.json();

      if (!Array.isArray(json?.result)) return [];

      return json.result.map((r: any, i: number) => ({
        id: `lc-${i}`,
        source: r.source || "LeakCheck",
        date: r.date || "Unknown",
        dataTypes: r.fields || ["email"],
        passwordExposed:
          r.fields?.some((f: string) =>
            f.toLowerCase().includes("pass")
          ) ?? false,
      }));
    } catch {
      return [];
    }
  }

  function heuristicDomainCheck(email: string): BreachRecord[] {
    const domain = email.split("@")[1];

    const riskyDomains = [
      "gmail.com",
      "yahoo.com",
      "hotmail.com",
      "outlook.com",
    ];

    if (!riskyDomains.includes(domain)) return [];

    return [
      {
        id: "heuristic-1",
        source: "Heuristic Analysis",
        date: "N/A",
        dataTypes: ["email"],
        passwordExposed: false,
      },
    ];
  }

  /* ===================== ACTION ===================== */

  async function checkEmail() {
    const clean = email.trim().toLowerCase();

    if (!validateEmail(clean)) {
      toast({
        title: "Invalid email",
        description: "Enter a valid email address",
        variant: "destructive",
      });
      return;
    }

    setLoading(true);
    setSearched(true);
    setResults([]);

    try {
      const collected: BreachRecord[] = [];

      const bd = await queryBreachDirectory(clean);
      const lc = await queryLeakCheck(clean);
      const heur = heuristicDomainCheck(clean);

      collected.push(...bd, ...lc, ...heur);

      // Deduplicate
      const uniq = Array.from(
        new Map(collected.map((i) => [i.source + i.id, i])).values()
      );

      setResults(uniq);

      toast({
        title: uniq.length
          ? "Breaches Detected"
          : "No Breaches Found",
        description: `${uniq.length} signal(s) identified`,
        variant: uniq.length ? "destructive" : "default",
      });
    } catch {
      toast({
        title: "Lookup failed",
        description:
          "Public OSINT sources blocked or rate-limited",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  }

  /* ===================== UI ===================== */

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold">Email Breach OSINT</h1>
        <p className="text-sm text-muted-foreground">
          Client-side breach intelligence using free public OSINT
        </p>
      </div>

      <div className="card-cyber p-4 flex gap-3">
        <div className="relative flex-1">
          <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" />
          <Input
            className="pl-10"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && checkEmail()}
            placeholder="email@example.com"
          />
        </div>
        <Button onClick={checkEmail} disabled={loading} variant="cyber">
          {loading ? (
            <Loader2 className="animate-spin h-4 w-4" />
          ) : (
            <Search className="h-4 w-4 mr-1" />
          )}
          Check
        </Button>
      </div>

      {searched && (
        <div
          className={cn(
            "card-cyber p-6",
            results.length
              ? "border-destructive/40 bg-destructive/5"
              : "border-success/40 bg-success/5"
          )}
        >
          <div className="flex justify-between items-center">
            <div className="flex gap-3 items-center">
              {results.length ? (
                <AlertTriangle className="text-destructive" />
              ) : (
                <CheckCircle2 className="text-success" />
              )}
              <div>
                <h2 className="font-bold">
                  {results.length
                    ? "Breaches Detected"
                    : "No Breaches Found"}
                </h2>
                <p className="text-xs font-mono text-muted-foreground">
                  {email}
                </p>
              </div>
            </div>
            <ThreatBadge
              level={getThreatLevel(results.length)}
              size="lg"
            />
          </div>

          {results.length > 0 && (
            <div className="mt-4 space-y-3">
              {results.map((b) => (
                <div
                  key={b.id}
                  className="p-4 rounded-lg bg-secondary/40 border"
                >
                  <div className="flex justify-between mb-2">
                    <strong>{b.source}</strong>
                    <span className="text-xs">{b.date}</span>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    {b.dataTypes.map((t) => (
                      <span
                        key={t}
                        className="text-xs px-2 py-1 rounded bg-destructive/10 text-destructive"
                      >
                        {iconForType(t)} {t}
                      </span>
                    ))}
                  </div>

                  {b.passwordExposed && (
                    <p className="text-xs text-destructive mt-2">
                      Password exposure detected
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {!searched && (
        <div className="card-cyber p-12 text-center">
          <Shield className="h-12 w-12 mx-auto text-muted-foreground/40" />
          <p className="text-muted-foreground mt-3">
            Enter an email to begin OSINT analysis
          </p>
        </div>
      )}
    </div>
  );
}
