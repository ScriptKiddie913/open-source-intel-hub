import { useState } from "react";
import { Server, Search, Loader2, Copy, MapPin, Shield, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ThreatBadge } from "./ThreatBadge";
import { getFullIPAnalysis, isValidIP } from "@/services/ipService";
import { reverseDNS } from "@/services/dnsService";
import { saveRecord, logActivity } from "@/lib/database";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import { GeoLocation, PortInfo, ThreatLevel } from "@/types/osint";

interface IPResults {
  ip: string;
  geo: GeoLocation | null;
  ports: PortInfo | null;
  reverseDns: string | null;
  threatLevel: ThreatLevel;
}

export function IPAnalyzer() {
  const [ip, setIP] = useState("");
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<IPResults | null>(null);
  const { toast } = useToast();

  const analyzeIP = async () => {
    const cleanIP = ip.trim();
    
    if (!cleanIP) {
      toast({ title: "Error", description: "Please enter an IP address", variant: "destructive" });
      return;
    }

    if (!isValidIP(cleanIP)) {
      toast({ title: "Error", description: "Invalid IP address format", variant: "destructive" });
      return;
    }

    setLoading(true);

    try {
      const [analysis, rdns] = await Promise.all([
        getFullIPAnalysis(cleanIP),
        reverseDNS(cleanIP).catch(() => null),
      ]);

      setResults({
        ip: cleanIP,
        geo: analysis.geo,
        ports: analysis.ports,
        reverseDns: rdns,
        threatLevel: analysis.threatLevel,
      });

      // Save to database
      await saveRecord({
        id: crypto.randomUUID(),
        target: cleanIP,
        type: "ip",
        data: { geo: analysis.geo, ports: analysis.ports, reverseDns: rdns },
        threatLevel: analysis.threatLevel,
        timestamp: new Date(),
        source: "ip-analyzer",
      });

      await logActivity({
        type: "search",
        title: `IP analysis: ${cleanIP}`,
        description: `Location: ${analysis.geo?.city || "Unknown"}, ${analysis.geo?.country || "Unknown"}`,
      });

      toast({ title: "Analysis complete" });
    } catch (error) {
      console.error("IP analysis error:", error);
      toast({ title: "Analysis failed", description: "Could not analyze IP", variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({ title: "Copied", description: "Copied to clipboard" });
  };

  const getPortService = (port: number): string => {
    const services: Record<number, string> = {
      21: "FTP",
      22: "SSH",
      23: "Telnet",
      25: "SMTP",
      53: "DNS",
      80: "HTTP",
      110: "POP3",
      143: "IMAP",
      443: "HTTPS",
      445: "SMB",
      993: "IMAPS",
      995: "POP3S",
      3306: "MySQL",
      3389: "RDP",
      5432: "PostgreSQL",
      5900: "VNC",
      6379: "Redis",
      8080: "HTTP-Alt",
      8443: "HTTPS-Alt",
      27017: "MongoDB",
    };
    return services[port] || "Unknown";
  };

  const isHighRiskPort = (port: number): boolean => {
    const highRisk = [22, 23, 3389, 5900, 445, 139, 21];
    return highRisk.includes(port);
  };

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground">IP Analyzer</h1>
        <p className="text-muted-foreground text-sm mt-1">
          Geolocation, open ports, and threat intelligence for IP addresses
        </p>
      </div>

      {/* Search */}
      <div className="card-cyber p-4">
        <div className="flex gap-3">
          <div className="relative flex-1">
            <Server className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              value={ip}
              onChange={(e) => setIP(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && analyzeIP()}
              placeholder="Enter IP address (e.g., 8.8.8.8)"
              className="pl-10"
            />
          </div>
          <Button onClick={analyzeIP} disabled={loading} variant="cyber">
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4 mr-2" />}
            Analyze
          </Button>
        </div>
      </div>

      {/* Results */}
      {results && (
        <div className="space-y-4">
          {/* Summary */}
          <div className="card-cyber p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="p-3 rounded-lg bg-primary/10">
                  <Server className="h-6 w-6 text-primary" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-xl font-mono font-bold text-foreground">{results.ip}</h2>
                    <Button variant="ghost" size="icon" onClick={() => copyToClipboard(results.ip)} className="h-6 w-6">
                      <Copy className="h-3 w-3" />
                    </Button>
                  </div>
                  {results.reverseDns && (
                    <p className="text-sm text-muted-foreground font-mono">{results.reverseDns}</p>
                  )}
                </div>
              </div>
              <ThreatBadge level={results.threatLevel} size="lg" />
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Geolocation */}
            {results.geo && (
              <div className="card-cyber p-4 space-y-4">
                <div className="flex items-center gap-2">
                  <MapPin className="h-4 w-4 text-primary" />
                  <h3 className="font-semibold text-foreground">Geolocation</h3>
                </div>
                
                <div className="grid grid-cols-2 gap-3">
                  {[
                    { label: "Country", value: `${results.geo.country} (${results.geo.countryCode})` },
                    { label: "City", value: results.geo.city },
                    { label: "Region", value: results.geo.region },
                    { label: "Timezone", value: results.geo.timezone },
                    { label: "ISP", value: results.geo.isp },
                    { label: "Organization", value: results.geo.org },
                    { label: "ASN", value: results.geo.as },
                    { label: "Coordinates", value: `${results.geo.lat}, ${results.geo.lon}` },
                  ].map((item) => (
                    <div key={item.label} className="p-2 rounded bg-secondary/50">
                      <p className="text-[10px] text-muted-foreground uppercase">{item.label}</p>
                      <p className="font-mono text-xs text-foreground truncate">{item.value || "N/A"}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Ports & Services */}
            <div className="card-cyber p-4 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Shield className="h-4 w-4 text-primary" />
                  <h3 className="font-semibold text-foreground">Ports & Services</h3>
                </div>
                {results.ports && (
                  <span className="text-xs text-muted-foreground font-mono">
                    {results.ports.ports.length} open
                  </span>
                )}
              </div>

              {results.ports && results.ports.ports.length > 0 ? (
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {results.ports.ports.map((port) => (
                    <div
                      key={port}
                      className={cn(
                        "flex items-center justify-between p-2 rounded",
                        isHighRiskPort(port) ? "bg-destructive/10 border border-destructive/30" : "bg-secondary/50"
                      )}
                    >
                      <div className="flex items-center gap-2">
                        {isHighRiskPort(port) && <AlertTriangle className="h-3 w-3 text-destructive" />}
                        <span className="font-mono text-sm font-bold text-foreground">{port}</span>
                        <span className="text-xs text-muted-foreground">{getPortService(port)}</span>
                      </div>
                      {isHighRiskPort(port) && (
                        <span className="text-xs text-destructive">High Risk</span>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-muted-foreground text-center py-4">
                  No open ports detected
                </p>
              )}
            </div>
          </div>

          {/* Vulnerabilities */}
          {results.ports?.vulns && results.ports.vulns.length > 0 && (
            <div className="card-cyber p-4 border-destructive/30 bg-destructive/5">
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle className="h-5 w-5 text-destructive" />
                <h3 className="font-semibold text-destructive">Known Vulnerabilities</h3>
              </div>
              <div className="flex flex-wrap gap-2">
                {results.ports.vulns.map((vuln) => (
                  <a
                    key={vuln}
                    href={`https://nvd.nist.gov/vuln/detail/${vuln}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-3 py-1.5 rounded bg-destructive/20 text-destructive text-sm font-mono hover:bg-destructive/30 transition-colors"
                  >
                    {vuln}
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* Tags & Hostnames */}
          {results.ports && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {results.ports.hostnames.length > 0 && (
                <div className="card-cyber p-4">
                  <h3 className="font-semibold text-foreground mb-3">Hostnames</h3>
                  <div className="flex flex-wrap gap-2">
                    {results.ports.hostnames.map((hostname) => (
                      <span
                        key={hostname}
                        className="px-2 py-1 rounded bg-secondary text-foreground text-xs font-mono"
                      >
                        {hostname}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {results.ports.tags.length > 0 && (
                <div className="card-cyber p-4">
                  <h3 className="font-semibold text-foreground mb-3">Tags</h3>
                  <div className="flex flex-wrap gap-2">
                    {results.ports.tags.map((tag) => (
                      <span
                        key={tag}
                        className={cn(
                          "px-2 py-1 rounded text-xs font-mono",
                          ["malware", "botnet", "c2", "compromised", "scanner"].includes(tag.toLowerCase())
                            ? "bg-destructive/20 text-destructive"
                            : "bg-primary/10 text-primary"
                        )}
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Empty State */}
      {!loading && !results && (
        <div className="card-cyber p-12 text-center">
          <Server className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
          <p className="text-muted-foreground">Enter an IP address to analyze</p>
          <p className="text-xs text-muted-foreground/60 mt-2">
            Get geolocation, open ports, and vulnerability data from Shodan InternetDB
          </p>
        </div>
      )}
    </div>
  );
}
