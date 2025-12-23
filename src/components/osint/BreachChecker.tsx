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

/* ---------------- TYPES ---------------- */

export type BreachRecord = {
  id: string;
  source: string;
  date: string;
  dataTypes: string[];
  passwordExposed: boolean;
};

export type ThreatLevel = "info" | "medium" | "high" | "critical";

/* ---------------- COMPONENT ---------------- */

export function BreachChecker() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<BreachRecord[] | null>(null);
  const [searched, setSearched] = useState(false);
  const { toast } = useToast();

  /* ---------------- HELPERS ---------------- */

  const validateEmail = (value: string) =>
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);

  const getThreatLevel = (count: number): ThreatLevel => {
    if (count === 0) return "info";
    if (count <= 2) return "medium";
    if (count <= 5) return "high";
    return "critical";
  };

  const getDataTypeIcon = (type: string) => {
    switch (type) {
      case "password":
      case "hash":
        return "🔐";
      case "username":
        return "👤";
      case "ip":
        return "🌐";
      case "phone":
        return "📱";
      case "name":
        return "📛";
      default:
        return "📧";
    }
  };

  /* ---------------- OSINT LOOKUP ---------------- */

  const fetchBreaches = async (email: string): Promise<BreachRecord[]> => {
    const endpoint = `https://api.breachdirectory.org/?func=auto&term=${encodeURIComponent(
      email
    )}`;

    const res = await fetch(endpoint, {
      headers: {
        Accept: "application/json",
      },
    });

    if (!res.ok) {
      throw new Error("OSINT source unreachable");
    }

    const json = await res.json();

    if (!json || !Array.isArray(json.result)) {
      return [];
    }

    return json.result.map((entry: any, idx: number) => {
      const dataClasses: string[] =
        entry.data_classes ||
        entry.dataTypes ||
        entry.fields ||
        ["email"];

      return {
        id: `${entry.source || "unknown"}-${idx}`,
        source: entry.source || entry.breach || "Unknown Breach",
        date: entry.breach_date || entry.date || "Unknown",
        dataTypes: dataClasses,
        passwordExposed: dataClasses.some((d) =>
          ["password", "hash"].includes(d.toLowerCase())
        ),
      };
    });
  };

  /* ---------------- ACTION ---------------- */

  const checkEmail = async () => {
    const cleanEmail = email.trim().toLowerCase();

    if (!cleanEmail) {
      toast({
        title: "Input required",
        description: "Please enter an email address",
        variant: "destructive",
      });
      return;
    }

    if (!validateEmail(cleanEmail)) {
      toast({
        title: "Invalid email",
        description: "Please enter a valid email format",
        variant: "destructive",
      });
      return;
    }

    setLoading(true);
    setSearched(true);

    try {
      const breaches = await fetchBreaches(cleanEmail);
      setResults(breaches);

      toast({
        title: breaches.length
          ? "Breaches detected"
          : "No breaches found",
        description: `${breaches.length} breach record(s)`,
        variant: breaches.length ? "destructive" : "default",
      });
    } catch (err) {
      console.error(err);
      toast({
        title: "Lookup failed",
        description:
          "Public OSINT breach sources are currently unavailable",
        variant: "destructive",
      });
      setResults([]);
    } finally {
      setLoading(false);
    }
  };

  /* ---------------- UI ---------------- */

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold">Email Breach OSINT</h1>
        <p className="text-sm text-muted-foreground">
          Live breach intelligence using free public OSINT sources
        </p>
      </div>

      {/* Search */}
      <div className="card-cyber p-4">
        <div className="flex gap-3">
          <div className="relative flex-1">
            <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && checkEmail()}
              placeholder="email@example.com"
              className="pl-10"
            />
          </div>
          <Button onClick={checkEmail} disabled={loading} variant="cyber">
            {loading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Search className="h-4 w-4 mr-2" />
            )}
            Check
          </Button>
        </div>
      </div>

      {/* Results */}
      {searched && results && (
        <div className="space-y-4">
          {/* Summary */}
          <div
            className={cn(
              "card-cyber p-6",
              results.length
                ? "border-destructive/40 bg-destructive/5"
                : "border-success/40 bg-success/5"
            )}
          >
            <div className="flex justify-between items-center">
              <div className="flex items-center gap-4">
                <div
                  className={cn(
                    "p-3 rounded-full",
                    results.length
                      ? "bg-destructive/20"
                      : "bg-success/20"
                  )}
                >
                  {results.length ? (
                    <AlertTriangle className="text-destructive h-6 w-6" />
                  ) : (
                    <CheckCircle2 className="text-success h-6 w-6" />
                  )}
                </div>
                <div>
                  <h2 className="text-xl font-bold">
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
          </div>

          {/* Breach list */}
          {results.length > 0 && (
            <div className="card-cyber p-4">
              <h3 className="font-semibold mb-3">Breach Details</h3>
              <div className="space-y-3">
                {results.map((b) => (
                  <div
                    key={b.id}
                    className="p-4 rounded-lg bg-secondary/40 border hover:border-destructive/50"
                  >
                    <div className="flex justify-between mb-2">
                      <h4 className="font-semibold">{b.source}</h4>
                      <span className="text-xs font-mono text-muted-foreground">
                        {b.date}
                      </span>
                    </div>

                    <div className="flex flex-wrap gap-2">
                      {b.dataTypes.map((t) => (
                        <span
                          key={t}
                          className="text-xs px-2 py-1 rounded bg-destructive/10 text-destructive"
                        >
                          {getDataTypeIcon(t)} {t}
                        </span>
                      ))}
                    </div>

                    {b.passwordExposed && (
                      <div className="mt-3 p-2 rounded bg-destructive/10 border border-destructive/30">
                        <p className="text-xs font-semibold text-destructive">
                          Password data exposed
                        </p>
                        <p className="text-xs text-muted-foreground">
                          Immediate password change recommended
                        </p>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Empty */}
      {!searched && (
        <div className="card-cyber p-12 text-center">
          <Shield className="h-12 w-12 mx-auto text-muted-foreground/40 mb-4" />
          <p className="text-muted-foreground">
            Enter an email to begin OSINT breach analysis
          </p>
        </div>
      )}
    </div>
  );
}
