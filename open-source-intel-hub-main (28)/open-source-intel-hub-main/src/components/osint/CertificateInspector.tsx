import { useState } from "react";
import { Lock, Search, Loader2, AlertTriangle, CheckCircle2, Clock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { searchCertificates, getSubdomainsFromCerts, analyzeCertificates, getCertificateStatus } from "@/services/certService";
import { logActivity } from "@/lib/database";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import { Certificate } from "@/types/osint";

interface CertResults {
  domain: string;
  certificates: Certificate[];
  subdomains: string[];
  analysis: ReturnType<typeof analyzeCertificates>;
}

export function CertificateInspector() {
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<CertResults | null>(null);
  const { toast } = useToast();

  const searchDomain = async () => {
    const cleanDomain = domain.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0];
    
    if (!cleanDomain) {
      toast({ title: "Error", description: "Please enter a domain", variant: "destructive" });
      return;
    }

    setLoading(true);

    try {
      const [certs, subdomains] = await Promise.all([
        searchCertificates(cleanDomain),
        getSubdomainsFromCerts(cleanDomain),
      ]);

      const analysis = analyzeCertificates(certs);

      setResults({
        domain: cleanDomain,
        certificates: certs,
        subdomains,
        analysis,
      });

      await logActivity({
        type: "search",
        title: `Certificate search: ${cleanDomain}`,
        description: `Found ${certs.length} certificates, ${subdomains.length} subdomains`,
      });

      toast({ title: "Search complete", description: `Found ${certs.length} certificates` });
    } catch (error) {
      console.error("Certificate search error:", error);
      toast({ title: "Search failed", description: "Could not search certificates", variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  const getStatusBadge = (notAfter: string) => {
    const { status, daysRemaining } = getCertificateStatus(notAfter);
    
    if (status === "expired") {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-destructive/20 text-destructive text-xs">
          <AlertTriangle className="h-3 w-3" />
          Expired
        </span>
      );
    }
    
    if (status === "expiring") {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-warning/20 text-warning text-xs">
          <Clock className="h-3 w-3" />
          {daysRemaining}d left
        </span>
      );
    }
    
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-success/20 text-success text-xs">
        <CheckCircle2 className="h-3 w-3" />
        Valid
      </span>
    );
  };

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground">Certificate Inspector</h1>
        <p className="text-muted-foreground text-sm mt-1">
          Search certificate transparency logs for SSL/TLS certificates
        </p>
      </div>

      {/* Search */}
      <div className="card-cyber p-4">
        <div className="flex gap-3">
          <div className="relative flex-1">
            <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && searchDomain()}
              placeholder="Enter domain (e.g., example.com)"
              className="pl-10"
            />
          </div>
          <Button onClick={searchDomain} disabled={loading} variant="cyber">
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4 mr-2" />}
            Search
          </Button>
        </div>
      </div>

      {/* Results */}
      {results && (
        <div className="space-y-4">
          {/* Summary */}
          <div className="card-cyber p-4">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <Lock className="h-5 w-5 text-primary" />
                <div>
                  <h2 className="text-lg font-mono font-bold text-foreground">{results.domain}</h2>
                  <p className="text-sm text-muted-foreground">Certificate Transparency Logs</p>
                </div>
              </div>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="p-3 rounded-lg bg-secondary/50 text-center">
                <p className="text-2xl font-mono font-bold text-primary">{results.analysis.totalCerts}</p>
                <p className="text-xs text-muted-foreground">Total Certs</p>
              </div>
              <div className="p-3 rounded-lg bg-secondary/50 text-center">
                <p className="text-2xl font-mono font-bold text-primary">{results.analysis.uniqueSubdomains}</p>
                <p className="text-xs text-muted-foreground">Subdomains</p>
              </div>
              <div className="p-3 rounded-lg bg-warning/10 border border-warning/30 text-center">
                <p className="text-2xl font-mono font-bold text-warning">{results.analysis.expiringCerts}</p>
                <p className="text-xs text-muted-foreground">Expiring</p>
              </div>
              <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/30 text-center">
                <p className="text-2xl font-mono font-bold text-destructive">{results.analysis.expiredCerts}</p>
                <p className="text-xs text-muted-foreground">Expired</p>
              </div>
            </div>
          </div>

          {/* Issuers */}
          {results.analysis.issuers.length > 0 && (
            <div className="card-cyber p-4">
              <h3 className="font-semibold text-foreground mb-3">Certificate Issuers</h3>
              <div className="flex flex-wrap gap-2">
                {results.analysis.issuers.map((issuer) => (
                  <span
                    key={issuer.name}
                    className="px-3 py-1.5 rounded-lg bg-secondary text-foreground text-sm"
                  >
                    {issuer.name} <span className="text-muted-foreground">({issuer.count})</span>
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Subdomains */}
          {results.subdomains.length > 0 && (
            <div className="card-cyber p-4">
              <h3 className="font-semibold text-foreground mb-3">
                Discovered Subdomains ({results.subdomains.length})
              </h3>
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2 max-h-48 overflow-y-auto">
                {results.subdomains.map((subdomain) => (
                  <span
                    key={subdomain}
                    className="px-2 py-1 rounded bg-primary/10 text-primary text-xs font-mono truncate"
                  >
                    {subdomain}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Certificate List */}
          <div className="card-cyber p-4">
            <h3 className="font-semibold text-foreground mb-3">
              Certificates ({results.certificates.length})
            </h3>
            <div className="overflow-x-auto max-h-96 overflow-y-auto">
              <table className="w-full">
                <thead className="sticky top-0 bg-card">
                  <tr className="border-b border-border">
                    <th className="text-left py-2 text-xs font-semibold text-muted-foreground uppercase">Common Name</th>
                    <th className="text-left py-2 text-xs font-semibold text-muted-foreground uppercase">Issuer</th>
                    <th className="text-left py-2 text-xs font-semibold text-muted-foreground uppercase">Valid From</th>
                    <th className="text-left py-2 text-xs font-semibold text-muted-foreground uppercase">Valid To</th>
                    <th className="text-left py-2 text-xs font-semibold text-muted-foreground uppercase">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {results.certificates.slice(0, 100).map((cert) => (
                    <tr key={cert.id} className="border-b border-border/50 hover:bg-secondary/30">
                      <td className="py-2 font-mono text-xs text-foreground max-w-xs truncate">
                        {cert.commonName}
                      </td>
                      <td className="py-2 font-mono text-xs text-muted-foreground max-w-xs truncate">
                        {cert.issuerName.split(",")[0]}
                      </td>
                      <td className="py-2 font-mono text-xs text-muted-foreground">
                        {new Date(cert.notBefore).toLocaleDateString()}
                      </td>
                      <td className="py-2 font-mono text-xs text-muted-foreground">
                        {new Date(cert.notAfter).toLocaleDateString()}
                      </td>
                      <td className="py-2">
                        {getStatusBadge(cert.notAfter)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Empty State */}
      {!loading && !results && (
        <div className="card-cyber p-12 text-center">
          <Lock className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
          <p className="text-muted-foreground">Enter a domain to search certificates</p>
          <p className="text-xs text-muted-foreground/60 mt-2">
            Data from Certificate Transparency logs via crt.sh
          </p>
        </div>
      )}
    </div>
  );
}
