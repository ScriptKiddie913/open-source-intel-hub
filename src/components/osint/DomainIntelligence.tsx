import { useState } from "react";
import { Globe, Search, Loader2, Copy, ChevronDown, ChevronUp, Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ThreatBadge } from "./ThreatBadge";
import { getAllRecords, getSubdomains } from "@/services/dnsService";
import { getFullIPAnalysis } from "@/services/ipService";
import { searchCertificates, getSubdomainsFromCerts, analyzeCertificates } from "@/services/certService";
import { saveRecord, logActivity } from "@/lib/database";
import { saveSearchHistory } from "@/services/userDataService";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import { DNSResults, GeoLocation, PortInfo, Certificate, ThreatLevel } from "@/types/osint";

interface DomainResults {
  domain: string;
  dns: DNSResults | null;
  geo: GeoLocation | null;
  ports: PortInfo | null;
  certificates: Certificate[];
  subdomains: string[];
  threatLevel: ThreatLevel;
  analysisTime: number;
}

export function DomainIntelligence() {
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<DomainResults | null>(null);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    dns: true,
    ip: true,
    certs: false,
    subdomains: false,
  });
  const { toast } = useToast();

  const toggleSection = (section: string) => {
    setExpandedSections(prev => ({ ...prev, [section]: !prev[section] }));
  };

  const analyzeDomain = async () => {
    if (!domain.trim()) {
      toast({ title: "Error", description: "Please enter a domain", variant: "destructive" });
      return;
    }

    // Clean domain input
    let cleanDomain = domain.trim().toLowerCase();
    cleanDomain = cleanDomain.replace(/^https?:\/\//, "").split("/")[0];

    setLoading(true);
    const startTime = Date.now();

    try {
      // Fetch all data in parallel
      const [dns, certs, subdomainsFromCerts] = await Promise.all([
        getAllRecords(cleanDomain),
        searchCertificates(cleanDomain).catch(() => []),
        getSubdomainsFromCerts(cleanDomain).catch(() => []),
      ]);

      // Get IP analysis from A record
      let geo: GeoLocation | null = null;
      let ports: PortInfo | null = null;
      let threatLevel: ThreatLevel = "info";

      const aRecord = dns.records.find(r => r.type === "A");
      if (aRecord) {
        const ipAnalysis = await getFullIPAnalysis(aRecord.data);
        geo = ipAnalysis.geo;
        ports = ipAnalysis.ports;
        threatLevel = ipAnalysis.threatLevel;
      }

      const analysisTime = (Date.now() - startTime) / 1000;

      setResults({
        domain: cleanDomain,
        dns,
        geo,
        ports,
        certificates: certs,
        subdomains: subdomainsFromCerts,
        threatLevel,
        analysisTime,
      });

      // Save to database
      await saveRecord({
        id: crypto.randomUUID(),
        target: cleanDomain,
        type: "dns",
        data: { dns, geo, ports },
        threatLevel,
        timestamp: new Date(),
        source: "domain-intel",
      });

      await logActivity({
        type: "search",
        title: `Domain analysis: ${cleanDomain}`,
        description: `Completed in ${analysisTime.toFixed(2)}s`,
      });

      // Save to Supabase search history (for logged-in users)
      await saveSearchHistory(cleanDomain, 'domain', dns.records.length + subdomainsFromCerts.length, {
        recordsCount: dns.records.length,
        subdomainsCount: subdomainsFromCerts.length,
        certificatesCount: certs.length,
        threatLevel,
        analysisTime,
      });

      toast({ title: "Analysis complete", description: `Found ${dns.records.length} records` });
    } catch (error) {
      console.error("Domain analysis error:", error);
      toast({ title: "Analysis failed", description: "Could not analyze domain", variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({ title: "Copied", description: "Copied to clipboard" });
  };

  const exportResults = () => {
    if (!results) return;
    const blob = new Blob([JSON.stringify(results, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${results.domain}-intel.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground">Domain Intelligence</h1>
        <p className="text-muted-foreground text-sm mt-1">
          Comprehensive domain analysis with DNS, certificates, and threat detection
        </p>
      </div>

      {/* Search */}
      <div className="card-cyber p-4">
        <div className="flex gap-3">
          <div className="relative flex-1">
            <Globe className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && analyzeDomain()}
              placeholder="Enter domain name (e.g., example.com)"
              className="pl-10"
            />
          </div>
          <Button onClick={analyzeDomain} disabled={loading} variant="cyber">
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4 mr-2" />}
            Analyze
          </Button>
        </div>
      </div>

      {/* Results */}
      {results && (
        <div className="space-y-4">
          {/* Summary Card */}
          <div className="card-cyber p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="p-3 rounded-lg bg-primary/10">
                  <Globe className="h-6 w-6 text-primary" />
                </div>
                <div>
                  <h2 className="text-xl font-mono font-bold text-foreground">{results.domain}</h2>
                  <p className="text-sm text-muted-foreground">
                    Analyzed in {results.analysisTime.toFixed(2)}s
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <ThreatBadge level={results.threatLevel} size="lg" />
                <Button variant="outline" size="sm" onClick={exportResults}>
                  Export JSON
                </Button>
              </div>
            </div>

            {/* Quick Stats */}
            <div className="grid grid-cols-4 gap-4 mt-4 pt-4 border-t border-border">
              <div className="text-center">
                <p className="text-2xl font-mono font-bold text-primary">{results.dns?.records.length || 0}</p>
                <p className="text-xs text-muted-foreground">DNS Records</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-mono font-bold text-primary">{results.subdomains.length}</p>
                <p className="text-xs text-muted-foreground">Subdomains</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-mono font-bold text-primary">{results.ports?.ports.length || 0}</p>
                <p className="text-xs text-muted-foreground">Open Ports</p>
              </div>
              <div className="text-center">
                <p className="text-2xl font-mono font-bold text-primary">{results.certificates.length}</p>
                <p className="text-xs text-muted-foreground">Certificates</p>
              </div>
            </div>
          </div>

          {/* DNS Section */}
          <div className="card-cyber overflow-hidden">
            <button
              onClick={() => toggleSection("dns")}
              className="w-full flex items-center justify-between p-4 hover:bg-secondary/30 transition-colors"
            >
              <h3 className="font-semibold text-foreground">DNS Records</h3>
              {expandedSections.dns ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </button>
            {expandedSections.dns && results.dns && (
              <div className="p-4 pt-0">
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-border">
                        <th className="text-left py-2 text-xs font-semibold text-muted-foreground uppercase">Type</th>
                        <th className="text-left py-2 text-xs font-semibold text-muted-foreground uppercase">Name</th>
                        <th className="text-left py-2 text-xs font-semibold text-muted-foreground uppercase">Value</th>
                        <th className="text-right py-2 text-xs font-semibold text-muted-foreground uppercase">TTL</th>
                      </tr>
                    </thead>
                    <tbody>
                      {results.dns.records.map((record, i) => (
                        <tr key={i} className="border-b border-border/50 hover:bg-secondary/30 group">
                          <td className="py-2">
                            <span className="px-2 py-0.5 rounded bg-primary/10 text-primary text-xs font-mono">
                              {record.type}
                            </span>
                          </td>
                          <td className="py-2 font-mono text-sm text-foreground">{record.name}</td>
                          <td className="py-2 font-mono text-sm text-foreground flex items-center gap-2">
                            <span className="truncate max-w-md">{record.data}</span>
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => copyToClipboard(record.data)}
                              className="h-6 w-6 opacity-0 group-hover:opacity-100"
                            >
                              <Copy className="h-3 w-3" />
                            </Button>
                          </td>
                          <td className="py-2 font-mono text-sm text-muted-foreground text-right">{record.ttl}s</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>

          {/* IP/Geo Section */}
          {results.geo && (
            <div className="card-cyber overflow-hidden">
              <button
                onClick={() => toggleSection("ip")}
                className="w-full flex items-center justify-between p-4 hover:bg-secondary/30 transition-colors"
              >
                <h3 className="font-semibold text-foreground">IP Intelligence</h3>
                {expandedSections.ip ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </button>
              {expandedSections.ip && (
                <div className="p-4 pt-0 space-y-4">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {[
                      { label: "IP Address", value: results.geo.ip },
                      { label: "Location", value: `${results.geo.city}, ${results.geo.country}` },
                      { label: "ISP", value: results.geo.isp },
                      { label: "ASN", value: results.geo.as },
                    ].map((item) => (
                      <div key={item.label} className="p-3 rounded-lg bg-secondary/50">
                        <p className="text-xs text-muted-foreground uppercase">{item.label}</p>
                        <p className="font-mono text-sm text-foreground mt-1 truncate">{item.value}</p>
                      </div>
                    ))}
                  </div>

                  {results.ports && results.ports.ports.length > 0 && (
                    <div>
                      <p className="text-sm font-semibold text-foreground mb-2">Open Ports</p>
                      <div className="flex flex-wrap gap-2">
                        {results.ports.ports.map((port) => (
                          <span key={port} className="px-2 py-1 rounded bg-primary/10 text-primary text-xs font-mono">
                            {port}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {results.ports?.vulns && results.ports.vulns.length > 0 && (
                    <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/30">
                      <div className="flex items-center gap-2 mb-2">
                        <Shield className="h-4 w-4 text-destructive" />
                        <p className="text-sm font-semibold text-destructive">Vulnerabilities</p>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {results.ports.vulns.map((vuln) => (
                          <span key={vuln} className="px-2 py-1 rounded bg-destructive/20 text-destructive text-xs font-mono">
                            {vuln}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Subdomains Section */}
          {results.subdomains.length > 0 && (
            <div className="card-cyber overflow-hidden">
              <button
                onClick={() => toggleSection("subdomains")}
                className="w-full flex items-center justify-between p-4 hover:bg-secondary/30 transition-colors"
              >
                <h3 className="font-semibold text-foreground">
                  Subdomains ({results.subdomains.length})
                </h3>
                {expandedSections.subdomains ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </button>
              {expandedSections.subdomains && (
                <div className="p-4 pt-0">
                  <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2 max-h-64 overflow-y-auto">
                    {results.subdomains.map((subdomain) => (
                      <div
                        key={subdomain}
                        className="flex items-center justify-between p-2 rounded bg-secondary/50 hover:bg-secondary group"
                      >
                        <span className="font-mono text-xs text-foreground truncate">{subdomain}</span>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => copyToClipboard(subdomain)}
                          className="h-6 w-6 opacity-0 group-hover:opacity-100"
                        >
                          <Copy className="h-3 w-3" />
                        </Button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Certificates Section */}
          {results.certificates.length > 0 && (
            <div className="card-cyber overflow-hidden">
              <button
                onClick={() => toggleSection("certs")}
                className="w-full flex items-center justify-between p-4 hover:bg-secondary/30 transition-colors"
              >
                <h3 className="font-semibold text-foreground">
                  SSL Certificates ({results.certificates.length})
                </h3>
                {expandedSections.certs ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
              </button>
              {expandedSections.certs && (
                <div className="p-4 pt-0">
                  <div className="overflow-x-auto max-h-64 overflow-y-auto">
                    <table className="w-full">
                      <thead className="sticky top-0 bg-card">
                        <tr className="border-b border-border">
                          <th className="text-left py-2 text-xs font-semibold text-muted-foreground uppercase">Common Name</th>
                          <th className="text-left py-2 text-xs font-semibold text-muted-foreground uppercase">Issuer</th>
                          <th className="text-left py-2 text-xs font-semibold text-muted-foreground uppercase">Not Before</th>
                          <th className="text-left py-2 text-xs font-semibold text-muted-foreground uppercase">Not After</th>
                        </tr>
                      </thead>
                      <tbody>
                        {results.certificates.slice(0, 50).map((cert) => (
                          <tr key={cert.id} className="border-b border-border/50 hover:bg-secondary/30">
                            <td className="py-2 font-mono text-xs text-foreground max-w-xs truncate">{cert.commonName}</td>
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
              )}
            </div>
          )}
        </div>
      )}

      {/* Empty State */}
      {!loading && !results && (
        <div className="card-cyber p-12 text-center">
          <Globe className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
          <p className="text-muted-foreground">Enter a domain to analyze</p>
          <p className="text-xs text-muted-foreground/60 mt-2">
            Get DNS records, IP intelligence, SSL certificates, and subdomain discovery
          </p>
        </div>
      )}
    </div>
  );
}
