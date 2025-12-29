import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Shield, 
  AlertTriangle, 
  TrendingUp, 
  Search,
  RefreshCw,
  Globe,
  Database,
  Activity
} from 'lucide-react';
import { 
  getCVEData, 
  getThreatIntelligence, 
  searchCVE,
  type CVEData,
  type ThreatIntel
} from '@/services/cveService';

const Dashboard = () => {
  const [cveData, setCveData] = useState<CVEData[]>([]);
  const [threatIntel, setThreatIntel] = useState<ThreatIntel[]>([]);
  const [loading, setLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    fetchData();
    // Removed getLiveThreatFeeds call - function doesn't exist in cveService
  }, []);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [cves, threats] = await Promise.all([
        getCVEData(),
        getThreatIntelligence()
      ]);
      setCveData(cves);
      setThreatIntel(threats);
    } catch (error) {
      console.error('Error fetching data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = async () => {
    if (!searchQuery.trim()) return;
    
    setLoading(true);
    try {
      const results = await searchCVE(searchQuery);
      setCveData(results);
    } catch (error) {
      console.error('Error searching CVEs:', error);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'destructive';
      case 'high':
        return 'destructive';
      case 'medium':
        return 'default';
      case 'low':
        return 'secondary';
      default:
        return 'outline';
    }
  };

  const stats = {
    totalCVEs: cveData.length,
    criticalThreats: cveData.filter(c => c.severity === 'CRITICAL').length,
    activeThreats: threatIntel.filter(t => t.status === 'active').length,
    avgScore: cveData.length > 0 
      ? (cveData.reduce((acc, c) => acc + c.cvssScore, 0) / cveData.length).toFixed(1)
      : '0.0'
  };

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
              <Shield className="h-8 w-8 text-blue-600" />
              Open Source Intelligence Hub
            </h1>
            <p className="text-gray-500 dark:text-gray-400 mt-1">
              Real-time threat intelligence and vulnerability monitoring
            </p>
          </div>
          <Button onClick={fetchData} disabled={loading}>
            <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            Refresh Data
          </Button>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium">Total CVEs</CardTitle>
              <Database className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.totalCVEs}</div>
              <p className="text-xs text-muted-foreground">Tracked vulnerabilities</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium">Critical Threats</CardTitle>
              <AlertTriangle className="h-4 w-4 text-red-600" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-600">{stats.criticalThreats}</div>
              <p className="text-xs text-muted-foreground">Require immediate attention</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium">Active Threats</CardTitle>
              <Activity className="h-4 w-4 text-orange-600" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-orange-600">{stats.activeThreats}</div>
              <p className="text-xs text-muted-foreground">Currently monitored</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-sm font-medium">Avg CVSS Score</CardTitle>
              <TrendingUp className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.avgScore}</div>
              <p className="text-xs text-muted-foreground">Severity rating</p>
            </CardContent>
          </Card>
        </div>

        {/* Search Bar */}
        <Card>
          <CardContent className="pt-6">
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search CVEs, threats, or vulnerabilities..."
                  className="pl-10"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
                />
              </div>
              <Button onClick={handleSearch} disabled={loading}>
                Search
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Main Content Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="cves">CVE Database</TabsTrigger>
            <TabsTrigger value="threats">Threat Intelligence</TabsTrigger>
            <TabsTrigger value="feeds">Live Feeds</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* Recent CVEs */}
              <Card>
                <CardHeader>
                  <CardTitle>Recent CVEs</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {cveData.slice(0, 5).map((cve) => (
                      <div key={cve.id} className="flex items-start justify-between border-b pb-3 last:border-0">
                        <div className="flex-1">
                          <div className="font-medium">{cve.id}</div>
                          <p className="text-sm text-muted-foreground line-clamp-2">
                            {cve.description}
                          </p>
                          <div className="flex items-center gap-2 mt-2">
                            <Badge variant={getSeverityColor(cve.severity)}>
                              {cve.severity}
                            </Badge>
                            <span className="text-xs text-muted-foreground">
                              CVSS: {cve.cvssScore}
                            </span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Active Threats */}
              <Card>
                <CardHeader>
                  <CardTitle>Active Threats</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {threatIntel.slice(0, 5).map((threat) => (
                      <div key={threat.id} className="flex items-start justify-between border-b pb-3 last:border-0">
                        <div className="flex-1">
                          <div className="font-medium flex items-center gap-2">
                            <Globe className="h-4 w-4" />
                            {threat.name}
                          </div>
                          <p className="text-sm text-muted-foreground line-clamp-2">
                            {threat.description}
                          </p>
                          <div className="flex items-center gap-2 mt-2">
                            <Badge variant={threat.status === 'active' ? 'destructive' : 'secondary'}>
                              {threat.status}
                            </Badge>
                            <span className="text-xs text-muted-foreground">
                              {threat.source}
                            </span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="cves" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>CVE Database</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {cveData.map((cve) => (
                    <div key={cve.id} className="border rounded-lg p-4">
                      <div className="flex items-start justify-between mb-2">
                        <div>
                          <h3 className="font-semibold text-lg">{cve.id}</h3>
                          <p className="text-sm text-muted-foreground mt-1">
                            Published: {new Date(cve.publishedDate).toLocaleDateString()}
                          </p>
                        </div>
                        <div className="flex flex-col items-end gap-2">
                          <Badge variant={getSeverityColor(cve.severity)}>
                            {cve.severity}
                          </Badge>
                          <span className="text-sm font-medium">CVSS: {cve.cvssScore}</span>
                        </div>
                      </div>
                      <p className="text-sm">{cve.description}</p>
                      {cve.affectedSystems && cve.affectedSystems.length > 0 && (
                        <div className="mt-3">
                          <p className="text-xs font-medium mb-1">Affected Systems:</p>
                          <div className="flex flex-wrap gap-1">
                            {cve.affectedSystems.map((system, idx) => (
                              <Badge key={idx} variant="outline" className="text-xs">
                                {system}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="threats" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Threat Intelligence</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {threatIntel.map((threat) => (
                    <div key={threat.id} className="border rounded-lg p-4">
                      <div className="flex items-start justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <Globe className="h-5 w-5" />
                          <h3 className="font-semibold text-lg">{threat.name}</h3>
                        </div>
                        <Badge variant={threat.status === 'active' ? 'destructive' : 'secondary'}>
                          {threat.status}
                        </Badge>
                      </div>
                      <p className="text-sm mb-3">{threat.description}</p>
                      <div className="flex items-center gap-4 text-sm text-muted-foreground">
                        <span>Source: {threat.source}</span>
                        <span>•</span>
                        <span>Updated: {new Date(threat.lastUpdated).toLocaleDateString()}</span>
                      </div>
                      {threat.indicators && threat.indicators.length > 0 && (
                        <div className="mt-3">
                          <p className="text-xs font-medium mb-1">Indicators:</p>
                          <div className="flex flex-wrap gap-1">
                            {threat.indicators.map((indicator, idx) => (
                              <Badge key={idx} variant="outline" className="text-xs font-mono">
                                {indicator}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="feeds" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle>Live Threat Feeds</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground">
                  Live threat feed integration coming soon...
                </p>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default Dashboard;