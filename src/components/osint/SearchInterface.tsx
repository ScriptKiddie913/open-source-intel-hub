import { useState, useCallback } from "react";
import { Search, Globe, Server, Mail, Link, Loader2, AlertCircle, Copy, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ThreatBadge } from "./ThreatBadge";
import { getAllRecords, getSubdomains } from "@/services/dnsService";
import { getFullIPAnalysis, isValidIP } from "@/services/ipService";
import { searchCertificates, getSubdomainsFromCerts, analyzeCertificates } from "@/services/certService";
import { searchBreaches } from "@/lib/database";
import { saveRecord, logActivity } from "@/lib/database";
import { saveSearchHistory } from "@/services/userDataService";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import { ThreatLevel, DNSResults, GeoLocation, PortInfo, Certificate, BreachRecord } from "@/types/osint";

type SearchType = "domain" | "ip" | "email" | "url";

interface SearchResults {
  dns?: DNSResults;
  geo?: GeoLocation | null;
  ports?: PortInfo | null;
  certificates?: Certificate[];
  subdomains?: string[];
  breaches?: BreachRecord[];
  threatLevel?: ThreatLevel;
  loading: boolean;
  error?: string;
}

export function SearchInterface() {
  const [query, setQuery] = useState("");
  const [searchType, setSearchType] = useState<SearchType>("domain");
  const [results, setResults] = useState<SearchResults>({ loading: false });
  const { toast } = useToast();

  const detectSearchType = (input: string): SearchType => {
    const trimmed = input.trim().toLowerCase();
    
    // Check if it's an email
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) {
      return "email";
    }
    
    // Check if it's an IP
    if (isValidIP(trimmed)) {
      return "ip";
    }
    
    // Check if it's a URL
    if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
      return "url";
    }
    
    // Default to domain
    return "domain";
  };

  const handleSearch = useCallback(async () => {
    if (!query.trim()) {
      toast({ title: "Error", description: "Please enter a search query", variant: "destructive" });
      return;
    }

    setResults({ loading: true });
    const detectedType = detectSearchType(query);
    setSearchType(detectedType);

    try {
      switch (detectedType) {
        case "domain": {
          const [dns, certs, subdomains] = await Promise.all([
            getAllRecords(query),
            searchCertificates(query).catch(() => []),
            getSubdomainsFromCerts(query).catch(() => []),
          ]);

          // Get IP from A record and analyze it
          const aRecord = dns.records.find(r => r.type === "A");
          let geo = null;
          let ports = null;
          let threatLevel: ThreatLevel = "info";

          if (aRecord) {
            const ipAnalysis = await getFullIPAnalysis(aRecord.data);
            geo = ipAnalysis.geo;
            ports = ipAnalysis.ports;
            threatLevel = ipAnalysis.threatLevel;
          }

          setResults({
            dns,
            geo,
            ports,
            certificates: certs,
            subdomains,
            threatLevel,
            loading: false,
          });

          // Save to database
          await saveRecord({
            id: crypto.randomUUID(),
            target: query,
            type: "dns",
            data: { dns, geo, ports, certificates: certs.slice(0, 10), subdomains: subdomains.slice(0, 20) },
            threatLevel,
            timestamp: new Date(),
            source: "search",
          });
          
          await logActivity({
            type: "search",
            title: `Domain search: ${query}`,
            description: `Found ${dns.records.length} DNS records, ${subdomains.length} subdomains`,
          });

          // Save to Supabase search history (for logged-in users)
          await saveSearchHistory(query, 'domain', dns.records.length + subdomains.length, {
            recordsCount: dns.records.length,
            subdomainsCount: subdomains.length,
            threatLevel,
          });
          break;
        }

        case "ip": {
          const { geo, ports, threatLevel } = await getFullIPAnalysis(query);
          
          setResults({
            geo,
            ports,
            threatLevel,
            loading: false,
          });

          await saveRecord({
            id: crypto.randomUUID(),
            target: query,
            type: "ip",
            data: { geo, ports },
            threatLevel,
            timestamp: new Date(),
            source: "search",
          });

          await logActivity({
            type: "search",
            title: `IP search: ${query}`,
            description: `Location: ${geo?.city || "Unknown"}, ${geo?.country || "Unknown"}`,
          });

          // Save to Supabase search history (for logged-in users)
          await saveSearchHistory(query, 'ip', 1, {
            location: `${geo?.city || "Unknown"}, ${geo?.country || "Unknown"}`,
            threatLevel,
          });
          break;
        }

        case "email": {
          const breaches = await searchBreaches(query);
          const threatLevel: ThreatLevel = breaches.length > 5 ? "critical" : breaches.length > 0 ? "high" : "info";

          setResults({
            breaches,
            threatLevel,
            loading: false,
          });

          await logActivity({
            type: "search",
            title: `Email search: ${query}`,
            description: `Found ${breaches.length} breach records`,
          });

          // Save to Supabase search history (for logged-in users)
          await saveSearchHistory(query, 'breach', breaches.length, {
            breachCount: breaches.length,
            threatLevel,
          });
          break;
        }

        case "url": {
          // Extract domain from URL and search
          const url = new URL(query);
          setQuery(url.hostname);
          const dns = await getAllRecords(url.hostname);
          
          setResults({
            dns,
            threatLevel: "info",
            loading: false,
          });
          break;
        }
      }

      toast({ title: "Search complete", description: "Results loaded successfully" });
    } catch (error) {
      console.error("Search error:", error);
      setResults({
        loading: false,
        error: error instanceof Error ? error.message : "Search failed",
      });
      toast({ title: "Search failed", description: "An error occurred", variant: "destructive" });
    }
  }, [query, toast]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({ title: "Copied", description: "Copied to clipboard" });
  };

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground">Intelligence Search</h1>
        <p className="text-muted-foreground text-sm mt-1">
          Search domains, IPs, emails, and URLs across multiple data sources
        </p>
      </div>

      {/* Search Input */}
      <div className="card-cyber p-4">
        <div className="flex gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSearch()}
              placeholder="Enter domain, IP address, email, or URL..."
              className="pl-10"
            />
          </div>
          <Button onClick={handleSearch} disabled={results.loading} variant="cyber">
            {results.loading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              "Search"
            )}
          </Button>
        </div>
        
        <div className="flex items-center gap-4 mt-3">
          <span className="text-xs text-muted-foreground">Search type:</span>
          <div className="flex gap-2">
            {(["domain", "ip", "email"] as SearchType[]).map((type) => (
              <button
                key={type}
                onClick={() => setSearchType(type)}
                className={cn(
                  "px-3 py-1 rounded-full text-xs font-medium transition-all",
                  searchType === type
                    ? "bg-primary text-primary-foreground"
                    : "bg-secondary text-muted-foreground hover:text-foreground"
                )}
              >
                {type.charAt(0).toUpperCase() + type.slice(1)}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Error State */}
      {results.error && (
        <div className="card-cyber p-4 border-destructive/50 bg-destructive/5">
          <div className="flex items-center gap-3">
            <AlertCircle className="h-5 w-5 text-destructive" />
            <div>
              <p className="font-medium text-destructive">Search Failed</p>
              <p className="text-sm text-muted-foreground">{results.error}</p>
            </div>
          </div>
        </div>
      )}

      {/* Results */}
      {!results.loading && !results.error && (results.dns || results.geo || results.breaches) && (
        <div className="space-y-4">
          {/* Threat Level Summary */}
          <div className="card-cyber p-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Globe className="h-5 w-5 text-primary" />
              <div>
                <p className="font-mono text-lg font-bold text-foreground">{query}</p>
                <p className="text-xs text-muted-foreground">
                  {searchType === "domain" && results.dns && `${results.dns.records.length} DNS records found`}
                  {searchType === "ip" && results.geo && `${results.geo.city}, ${results.geo.country}`}
                  {searchType === "email" && `${results.breaches?.length || 0} breach records`}
                </p>
              </div>
            </div>
            {results.threatLevel && <ThreatBadge level={results.threatLevel} size="lg" />}
          </div>

          {/* Tabs for different result types */}
          <Tabs defaultValue="overview" className="w-full">
            <TabsList className="bg-secondary/50 border border-border">
              <TabsTrigger value="overview">Overview</TabsTrigger>
              {results.dns && <TabsTrigger value="dns">DNS</TabsTrigger>}
              {results.geo && <TabsTrigger value="geo">Geolocation</TabsTrigger>}
              {results.ports && <TabsTrigger value="ports">Ports</TabsTrigger>}
              {results.certificates && results.certificates.length > 0 && (
                <TabsTrigger value="certs">Certificates</TabsTrigger>
              )}
              {results.subdomains && results.subdomains.length > 0 && (
                <TabsTrigger value="subdomains">Subdomains</TabsTrigger>
              )}
              {results.breaches && <TabsTrigger value="breaches">Breaches</TabsTrigger>}
            </TabsList>

            <TabsContent value="overview" className="mt-4 space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {results.dns && (
                  <div className="card-cyber p-4">
                    <h3 className="font-semibold text-foreground mb-2">DNS Records</h3>
                    <p className="text-2xl font-mono font-bold text-primary">{results.dns.records.length}</p>
                    <p className="text-xs text-muted-foreground mt-1">Total records found</p>
                  </div>
                )}
                {results.subdomains && (
                  <div className="card-cyber p-4">
                    <h3 className="font-semibold text-foreground mb-2">Subdomains</h3>
                    <p className="text-2xl font-mono font-bold text-primary">{results.subdomains.length}</p>
                    <p className="text-xs text-muted-foreground mt-1">Discovered via certs</p>
                  </div>
                )}
                {results.ports && (
                  <div className="card-cyber p-4">
                    <h3 className="font-semibold text-foreground mb-2">Open Ports</h3>
                    <p className="text-2xl font-mono font-bold text-primary">{results.ports.ports.length}</p>
                    <p className="text-xs text-muted-foreground mt-1">From Shodan InternetDB</p>
                  </div>
                )}
              </div>
            </TabsContent>

            <TabsContent value="dns" className="mt-4">
              <div className="card-cyber p-4">
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-border">
                        <th className="text-left py-2 text-xs font-semibold text-muted-foreground uppercase">Type</th>
                        <th className="text-left py-2 text-xs font-semibold text-muted-foreground uppercase">Name</th>
                        <th className="text-left py-2 text-xs font-semibold text-muted-foreground uppercase">Value</th>
                        <th className="text-left py-2 text-xs font-semibold text-muted-foreground uppercase">TTL</th>
                        <th className="text-right py-2 text-xs font-semibold text-muted-foreground uppercase">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {results.dns?.records.map((record, i) => (
                        <tr key={i} className="border-b border-border/50 hover:bg-secondary/30">
                          <td className="py-2">
                            <span className="px-2 py-0.5 rounded bg-primary/10 text-primary text-xs font-mono">
                              {record.type}
                            </span>
                          </td>
                          <td className="py-2 font-mono text-sm text-foreground">{record.name}</td>
                          <td className="py-2 font-mono text-sm text-foreground max-w-xs truncate">{record.data}</td>
                          <td className="py-2 font-mono text-sm text-muted-foreground">{record.ttl}s</td>
                          <td className="py-2 text-right">
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => copyToClipboard(record.data)}
                              className="h-7 w-7"
                            >
                              <Copy className="h-3 w-3" />
                            </Button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="geo" className="mt-4">
              {results.geo && (
                <div className="card-cyber p-4">
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                    {[
                      { label: "IP Address", value: results.geo.ip },
                      { label: "Country", value: `${results.geo.country} (${results.geo.countryCode})` },
                      { label: "City", value: results.geo.city },
                      { label: "Region", value: results.geo.region },
                      { label: "ISP", value: results.geo.isp },
                      { label: "Organization", value: results.geo.org },
                      { label: "ASN", value: results.geo.as },
                      { label: "Timezone", value: results.geo.timezone },
                      { label: "Coordinates", value: `${results.geo.lat}, ${results.geo.lon}` },
                    ].map((item) => (
                      <div key={item.label} className="space-y-1">
                        <p className="text-xs text-muted-foreground uppercase">{item.label}</p>
                        <p className="font-mono text-sm text-foreground">{item.value || "N/A"}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </TabsContent>

            <TabsContent value="ports" className="mt-4">
              {results.ports && (
                <div className="card-cyber p-4 space-y-4">
                  {results.ports.vulns.length > 0 && (
                    <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/30">
                      <p className="text-sm font-semibold text-destructive mb-2">Vulnerabilities Detected</p>
                      <div className="flex flex-wrap gap-2">
                        {results.ports.vulns.map((vuln) => (
                          <span key={vuln} className="px-2 py-1 rounded bg-destructive/20 text-destructive text-xs font-mono">
                            {vuln}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  <div>
                    <p className="text-sm font-semibold text-foreground mb-2">Open Ports</p>
                    <div className="flex flex-wrap gap-2">
                      {results.ports.ports.length > 0 ? (
                        results.ports.ports.map((port) => (
                          <span key={port} className="px-2 py-1 rounded bg-primary/10 text-primary text-xs font-mono">
                            {port}
                          </span>
                        ))
                      ) : (
                        <span className="text-muted-foreground text-sm">No open ports detected</span>
                      )}
                    </div>
                  </div>

                  {results.ports.hostnames.length > 0 && (
                    <div>
                      <p className="text-sm font-semibold text-foreground mb-2">Hostnames</p>
                      <div className="flex flex-wrap gap-2">
                        {results.ports.hostnames.map((hostname) => (
                          <span key={hostname} className="px-2 py-1 rounded bg-secondary text-foreground text-xs font-mono">
                            {hostname}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {results.ports.tags.length > 0 && (
                    <div>
                      <p className="text-sm font-semibold text-foreground mb-2">Tags</p>
                      <div className="flex flex-wrap gap-2">
                        {results.ports.tags.map((tag) => (
                          <span
                            key={tag}
                            className={cn(
                              "px-2 py-1 rounded text-xs font-mono",
                              ["malware", "botnet", "c2", "compromised"].includes(tag.toLowerCase())
                                ? "bg-destructive/20 text-destructive"
                                : "bg-secondary text-foreground"
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
            </TabsContent>

            <TabsContent value="certs" className="mt-4">
              <div className="card-cyber p-4">
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-border">
                        <th className="text-left py-2 text-xs font-semibold text-muted-foreground uppercase">Common Name</th>
                        <th className="text-left py-2 text-xs font-semibold text-muted-foreground uppercase">Issuer</th>
                        <th className="text-left py-2 text-xs font-semibold text-muted-foreground uppercase">Valid From</th>
                        <th className="text-left py-2 text-xs font-semibold text-muted-foreground uppercase">Valid To</th>
                      </tr>
                    </thead>
                    <tbody>
                      {results.certificates?.slice(0, 20).map((cert) => (
                        <tr key={cert.id} className="border-b border-border/50 hover:bg-secondary/30">
                          <td className="py-2 font-mono text-sm text-foreground max-w-xs truncate">{cert.commonName}</td>
                          <td className="py-2 font-mono text-xs text-muted-foreground max-w-xs truncate">
                            {cert.issuerName.split(",")[0]}
                          </td>
                          <td className="py-2 font-mono text-xs text-muted-foreground">
                            {new Date(cert.notBefore).toLocaleDateString()}
                          </td>
                          <td className="py-2 font-mono text-xs text-muted-foreground">
                            {new Date(cert.notAfter).toLocaleDateString()}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="subdomains" className="mt-4">
              <div className="card-cyber p-4">
                <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
                  {results.subdomains?.map((subdomain) => (
                    <div
                      key={subdomain}
                      className="flex items-center justify-between p-2 rounded bg-secondary/50 hover:bg-secondary group"
                    >
                      <span className="font-mono text-xs text-foreground truncate">{subdomain}</span>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => copyToClipboard(subdomain)}
                        className="h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity"
                      >
                        <Copy className="h-3 w-3" />
                      </Button>
                    </div>
                  ))}
                </div>
              </div>
            </TabsContent>

            <TabsContent value="breaches" className="mt-4">
              <div className="card-cyber p-4">
                {results.breaches && results.breaches.length > 0 ? (
                  <div className="space-y-3">
                    {results.breaches.map((breach) => (
                      <div key={breach.id} className="p-3 rounded-lg bg-destructive/5 border border-destructive/30">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-foreground">{breach.source}</span>
                          <span className="text-xs text-muted-foreground font-mono">{breach.date}</span>
                        </div>
                        <div className="flex flex-wrap gap-2 mt-2">
                          {breach.dataTypes.map((type) => (
                            <span key={type} className="px-2 py-0.5 rounded bg-destructive/20 text-destructive text-xs">
                              {type}
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <p className="text-muted-foreground">No breach records found</p>
                    <p className="text-xs text-muted-foreground/60 mt-1">
                      Import breach databases to check against
                    </p>
                  </div>
                )}
              </div>
            </TabsContent>
          </Tabs>
        </div>
      )}

      {/* Empty State */}
      {!results.loading && !results.error && !results.dns && !results.geo && !results.breaches && (
        <div className="card-cyber p-12 text-center">
          <Search className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
          <p className="text-muted-foreground">Enter a domain, IP, or email to search</p>
          <p className="text-xs text-muted-foreground/60 mt-2">
            Real-time data from DNS, Shodan, and Certificate Transparency logs
          </p>
        </div>
      )}
    </div>
  );
}
