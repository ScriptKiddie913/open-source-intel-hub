import { useState } from "react";
import { Shield, Search, Loader2, AlertTriangle, CheckCircle2, Mail } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ThreatBadge } from "./ThreatBadge";
import { searchBreaches, logActivity } from "@/lib/database";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import { BreachRecord, ThreatLevel } from "@/types/osint";

export function BreachChecker() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<BreachRecord[] | null>(null);
  const [searched, setSearched] = useState(false);
  const { toast } = useToast();

  const checkEmail = async () => {
    const cleanEmail = email.trim().toLowerCase();
    
    if (!cleanEmail) {
      toast({ title: "Error", description: "Please enter an email address", variant: "destructive" });
      return;
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      toast({ title: "Error", description: "Invalid email format", variant: "destructive" });
      return;
    }

    setLoading(true);
    setSearched(true);

    try {
      const breaches = await searchBreaches(cleanEmail);
      setResults(breaches);

      await logActivity({
        type: "search",
        title: `Breach check: ${cleanEmail}`,
        description: `Found ${breaches.length} breach records`,
      });

      toast({ 
        title: breaches.length > 0 ? "Breaches found" : "No breaches found",
        description: `${breaches.length} records in database`,
        variant: breaches.length > 0 ? "destructive" : "default",
      });
    } catch (error) {
      console.error("Breach check error:", error);
      toast({ title: "Check failed", description: "An error occurred", variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  const getThreatLevel = (count: number): ThreatLevel => {
    if (count === 0) return "info";
    if (count < 3) return "medium";
    if (count < 5) return "high";
    return "critical";
  };

  const getDataTypeIcon = (type: string) => {
    switch (type) {
      case "password": return "🔐";
      case "username": return "👤";
      case "ip": return "🌐";
      case "name": return "📛";
      case "phone": return "📱";
      default: return "📧";
    }
  };

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground">Breach Checker</h1>
        <p className="text-muted-foreground text-sm mt-1">
          Check if an email appears in imported breach databases
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
              placeholder="Enter email address"
              className="pl-10"
            />
          </div>
          <Button onClick={checkEmail} disabled={loading} variant="cyber">
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4 mr-2" />}
            Check
          </Button>
        </div>
      </div>

      {/* Results */}
      {searched && results !== null && (
        <div className="space-y-4">
          {/* Summary */}
          <div className={cn(
            "card-cyber p-6",
            results.length > 0 ? "border-destructive/30 bg-destructive/5" : "border-success/30 bg-success/5"
          )}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className={cn(
                  "p-3 rounded-full",
                  results.length > 0 ? "bg-destructive/20" : "bg-success/20"
                )}>
                  {results.length > 0 ? (
                    <AlertTriangle className="h-6 w-6 text-destructive" />
                  ) : (
                    <CheckCircle2 className="h-6 w-6 text-success" />
                  )}
                </div>
                <div>
                  <h2 className="text-xl font-bold text-foreground">
                    {results.length > 0 ? "Breaches Detected" : "No Breaches Found"}
                  </h2>
                  <p className="text-sm text-muted-foreground font-mono">{email}</p>
                </div>
              </div>
              <ThreatBadge level={getThreatLevel(results.length)} size="lg" />
            </div>

            {results.length > 0 && (
              <div className="mt-4 pt-4 border-t border-border">
                <p className="text-sm text-muted-foreground">
                  This email was found in <span className="font-bold text-destructive">{results.length}</span> breach{results.length !== 1 && "es"}. 
                  You should consider changing passwords for any accounts associated with this email.
                </p>
              </div>
            )}
          </div>

          {/* Breach List */}
          {results.length > 0 && (
            <div className="card-cyber p-4">
              <h3 className="font-semibold text-foreground mb-4">Breach Details</h3>
              <div className="space-y-3">
                {results.map((breach) => (
                  <div
                    key={breach.id}
                    className="p-4 rounded-lg bg-secondary/50 border border-border hover:border-destructive/50 transition-colors"
                  >
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="font-semibold text-foreground">{breach.source}</h4>
                      <span className="text-xs text-muted-foreground font-mono">{breach.date}</span>
                    </div>
                    
                    <div className="flex flex-wrap gap-2">
                      {breach.dataTypes.map((type) => (
                        <span
                          key={type}
                          className="inline-flex items-center gap-1 px-2 py-1 rounded bg-destructive/10 text-destructive text-xs"
                        >
                          <span>{getDataTypeIcon(type)}</span>
                          {type}
                        </span>
                      ))}
                    </div>

                    {breach.password && (
                      <div className="mt-3 p-2 rounded bg-destructive/10 border border-destructive/30">
                        <p className="text-xs text-destructive font-medium">Password exposed</p>
                        <p className="text-xs text-muted-foreground mt-1">
                          A password hash was found in this breach. Change this password immediately.
                        </p>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recommendations */}
          {results.length > 0 && (
            <div className="card-cyber p-4">
              <h3 className="font-semibold text-foreground mb-3">Recommendations</h3>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li className="flex items-start gap-2">
                  <span className="text-primary">•</span>
                  Change passwords for all accounts using this email
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-primary">•</span>
                  Enable two-factor authentication where possible
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-primary">•</span>
                  Use a password manager to generate unique passwords
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-primary">•</span>
                  Monitor your accounts for suspicious activity
                </li>
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Empty State */}
      {!searched && (
        <div className="card-cyber p-12 text-center">
          <Shield className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
          <p className="text-muted-foreground">Enter an email to check for breaches</p>
          <p className="text-xs text-muted-foreground/60 mt-2">
            Searches against imported breach databases
          </p>
        </div>
      )}

      {/* Info Card */}
      <div className="card-cyber p-4 border-accent/30 bg-accent/5">
        <div className="flex items-start gap-3">
          <Shield className="h-5 w-5 text-accent mt-0.5" />
          <div>
            <p className="font-medium text-foreground">About Breach Checking</p>
            <p className="text-sm text-muted-foreground mt-1">
              This tool checks emails against breach databases you've imported. Import breach data 
              using the Data Import feature to enable comprehensive breach checking.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
