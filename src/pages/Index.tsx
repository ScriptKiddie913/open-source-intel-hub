import { Routes, Route, Navigate } from "react-router-dom";
import { OSINTSidebar } from "@/components/osint/OSINTSidebar";
import { Dashboard } from "@/components/osint/Dashboard";
import { SearchInterface } from "@/components/osint/SearchInterface";
import { DomainIntelligence } from "@/components/osint/DomainIntelligence";
import { IPAnalyzer } from "@/components/osint/IPAnalyzer";
import { CertificateInspector } from "@/components/osint/CertificateInspector";
import { BreachChecker } from "@/components/osint/BreachChecker";
import { DataImporter } from "@/components/osint/DataImporter";
import { SettingsPage } from "@/components/osint/SettingsPage";
import { useEffect } from "react";
import { initDatabase } from "@/lib/database";

const Index = () => {
  useEffect(() => {
    // Initialize IndexedDB on mount
    initDatabase().catch(console.error);
  }, []);

  return (
    <div className="flex h-screen bg-background overflow-hidden">
      <OSINTSidebar />
      <main className="flex-1 overflow-y-auto">
        <div className="min-h-full">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/search" element={<SearchInterface />} />
            <Route path="/domain" element={<DomainIntelligence />} />
            <Route path="/ip" element={<IPAnalyzer />} />
            <Route path="/certs" element={<CertificateInspector />} />
            <Route path="/breach" element={<BreachChecker />} />
            <Route path="/import" element={<DataImporter />} />
            <Route path="/monitors" element={<ComingSoon title="Monitoring" />} />
            <Route path="/reports" element={<ComingSoon title="Reports" />} />
            <Route path="/database" element={<ComingSoon title="Database Explorer" />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </div>
      </main>
    </div>
  );
};

function ComingSoon({ title }: { title: string }) {
  return (
    <div className="p-6 animate-fade-in">
      <h1 className="text-2xl font-bold text-foreground">{title}</h1>
      <div className="card-cyber p-12 text-center mt-6">
        <p className="text-muted-foreground">This feature is coming soon</p>
      </div>
    </div>
  );
}

export default Index;
