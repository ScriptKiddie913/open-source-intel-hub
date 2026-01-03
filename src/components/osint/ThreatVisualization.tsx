// Real-time threat intelligence visualization component
// Generates live graphs and charts based on database-stored threat data

import React, { useEffect, useState, useRef, useCallback } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { AlertTriangle, TrendingUp, Shield, Activity, Globe, Target, RefreshCw } from 'lucide-react';
import { threatIntelligenceDB, type ThreatIntelligenceRecord } from '@/services/threatIntelligenceDatabase';
import { realTimeThreatFeedService, type RealTimeThreatStats, type ThreatTrendData, type LiveFeedEntry } from '@/services/realTimeThreatFeedService';
import { toast } from 'sonner';

// Recharts imports for real-time visualization
import {
  LineChart,
  Line,
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar
} from 'recharts';

interface ThreatVisualizationProps {
  refreshInterval?: number; // Refresh interval in milliseconds (default: 30 seconds)
  showRealTimeUpdates?: boolean;
  // Additional props for data injection from MalwarePipeline
  campaigns?: any[];
  correlations?: any[];
  aptGroups?: any[];
  indicators?: any[];
  ransomwareVictims?: any[];
}

export const ThreatVisualization: React.FC<ThreatVisualizationProps> = ({
  refreshInterval = 30000,
  showRealTimeUpdates = true,
  campaigns = [],
  correlations = [],
  aptGroups = [],
  indicators = [],
  ransomwareVictims = []
}) => {
  const [threatData, setThreatData] = useState<ThreatIntelligenceRecord[]>([]);
  const [statistics, setStatistics] = useState<any>(null);
  const [timeSeriesData, setTimeSeriesData] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());
  const [realTimeStats, setRealTimeStats] = useState<RealTimeThreatStats | null>(null);
  const [realTimeTrends, setRealTimeTrends] = useState<ThreatTrendData | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const subscriptionRef = useRef<(() => void) | null>(null);

  // Subscribe to real-time feed service for live updates
  useEffect(() => {
    // Initialize and subscribe to real-time updates
    const initRealTime = async () => {
      try {
        await realTimeThreatFeedService.initialize();
        
        // Subscribe to updates
        subscriptionRef.current = realTimeThreatFeedService.subscribe((data) => {
          setRealTimeStats(data.stats);
          setRealTimeTrends(data.trendData);
          setLastUpdate(new Date());
          console.log('[ThreatViz] Real-time update received:', data.stats?.totalThreats);
        });
      } catch (error) {
        console.error('[ThreatViz] Failed to initialize real-time feed:', error);
      }
    };
    
    initRealTime();
    
    return () => {
      if (subscriptionRef.current) {
        subscriptionRef.current();
      }
    };
  }, []);

  // Real-time data loading from database
  useEffect(() => {
    loadThreatVisualizationData();

    if (showRealTimeUpdates) {
      intervalRef.current = setInterval(() => {
        loadThreatVisualizationData();
      }, refreshInterval);
    }

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [refreshInterval, showRealTimeUpdates]);

  // Manual refresh handler
  const handleRefresh = useCallback(async () => {
    setLoading(true);
    try {
      await realTimeThreatFeedService.refresh();
      await loadThreatVisualizationData();
      toast.success('Threat data refreshed');
    } catch (error) {
      toast.error('Refresh failed');
    }
    setLoading(false);
  }, []);

  const loadThreatVisualizationData = async () => {
    try {
      setLoading(true);

      // Load comprehensive threat data for visualization
      const [recentThreats, stats, timeSeriesThreats] = await Promise.all([
        threatIntelligenceDB.queryThreatIntelligence({
          timeRange: {
            from: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(), // Last 7 days
            to: new Date().toISOString()
          }
        }),
        threatIntelligenceDB.getThreatStatistics(),
        threatIntelligenceDB.queryThreatIntelligence({
          timeRange: {
            from: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString(), // Last 30 days
            to: new Date().toISOString()
          }
        })
      ]);

      setThreatData(recentThreats);
      setStatistics(stats);

      // Process time series data for trend visualization
      const timeSeries = processTimeSeriesData(timeSeriesThreats);
      setTimeSeriesData(timeSeries);

      setLastUpdate(new Date());

      if (showRealTimeUpdates) {
        console.log('[ThreatViz] Real-time update:', {
          threats: recentThreats.length,
          totalInDB: stats.totalThreats,
          sources: Object.keys(stats.bySource).length
        });
      }

    } catch (error) {
      console.error('[ThreatViz] Failed to load visualization data:', error);
      toast.error('Failed to load threat visualization data');
    } finally {
      setLoading(false);
    }
  };

  // Process threat data into time series for trend analysis
  const processTimeSeriesData = (threats: ThreatIntelligenceRecord[]) => {
    const grouped = threats.reduce((acc, threat) => {
      const date = new Date(threat.created_at).toISOString().split('T')[0];
      if (!acc[date]) {
        acc[date] = {
          date,
          total: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          byType: {}
        };
      }

      acc[date].total++;
      acc[date][threat.severity_level]++;

      if (!acc[date].byType[threat.threat_type]) {
        acc[date].byType[threat.threat_type] = 0;
      }
      acc[date].byType[threat.threat_type]++;

      return acc;
    }, {} as any);

    return Object.values(grouped).sort((a: any, b: any) => a.date.localeCompare(b.date));
  };

  // Chart data processing for Recharts
  const threatTrendData = timeSeriesData.length > 0 ? timeSeriesData.map(d => ({
    date: new Date(d.date).toLocaleDateString(),
    total: d.total,
    critical: d.critical,
    high: d.high,
    medium: d.medium,
    low: d.low
  })) : (realTimeTrends?.trends || []).map(d => ({
    date: new Date(d.timestamp).toLocaleDateString(),
    total: d.total,
    critical: d.critical,
    high: d.high,
    medium: d.medium,
    low: d.low
  }));

  // Calculate combined statistics from both database, real-time feed, and injected props
  const combinedStats = {
    totalThreats: (realTimeStats?.totalThreats || statistics?.totalThreats || 0) + indicators.length + campaigns.length,
    critical: (realTimeStats?.criticalThreats || statistics?.bySeverity?.critical || 0) + indicators.filter((i: any) => i.severity === 'critical').length,
    high: (realTimeStats?.highThreats || statistics?.bySeverity?.high || 0) + indicators.filter((i: any) => i.severity === 'high').length,
    medium: realTimeStats?.mediumThreats || statistics?.bySeverity?.medium || 0,
    low: realTimeStats?.lowThreats || statistics?.bySeverity?.low || 0,
    aptGroups: aptGroups.length,
    ransomwareVictims: ransomwareVictims.length,
    campaigns: campaigns.length,
    activeC2: realTimeStats?.activeC2Servers || 0,
    maliciousUrls: realTimeStats?.maliciousUrls || 0,
    malwareSamples: realTimeStats?.malwareSamples || 0
  };

  const severityData = [
    { name: 'Critical', value: combinedStats.critical, color: '#dc2626' },
    { name: 'High', value: combinedStats.high, color: '#ea580c' },
    { name: 'Medium', value: combinedStats.medium, color: '#ca8a04' },
    { name: 'Low', value: combinedStats.low, color: '#16a34a' }
  ].filter(d => d.value > 0);

  // Include injected data and real-time feed data in threat type breakdown
  const threatTypeData = [
    ...Object.entries(statistics?.byType || {}).map(([type, count]) => ({
      name: type.charAt(0).toUpperCase() + type.slice(1),
      value: count as number
    })),
    { name: 'C2 Servers', value: combinedStats.activeC2 },
    { name: 'Malicious URLs', value: combinedStats.maliciousUrls },
    { name: 'Malware Samples', value: combinedStats.malwareSamples },
    { name: 'APT Groups', value: aptGroups.length },
    { name: 'Ransomware', value: ransomwareVictims.length },
    { name: 'Campaigns', value: campaigns.length }
  ].filter((d: { name: string; value: number }) => d.value > 0);

  // Use real-time source distribution if available
  const sourceData = realTimeTrends?.sourceDistribution?.length 
    ? realTimeTrends.sourceDistribution
    : Object.entries(statistics?.bySource || {}).map(([source, count]) => ({
        name: source,
        value: count,
        color: `hsl(${Math.random() * 360}, 70%, 50%)`
      }));

  if (loading && !statistics) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
        <span className="ml-2 text-sm text-gray-600">Loading threat visualization...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Real-time Status Header */}
      <Card className="bg-gray-900/50 border-gray-800">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2 text-white">
                <Activity className="h-5 w-5 text-blue-400" />
                Real-time Threat Intelligence Dashboard
              </CardTitle>
              <CardDescription className="text-gray-400">
                Live visualization based on database-stored threat intelligence
              </CardDescription>
            </div>
            <div className="flex items-center gap-4">
              <div className="text-right">
                <div className="text-sm text-gray-400">
                  Last Updated: {lastUpdate.toLocaleTimeString()}
                </div>
                <div className="flex items-center gap-2 mt-1">
                  <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                  <span className="text-xs text-green-400">Live • Auto-updating</span>
                </div>
              </div>
              <Button 
                variant="outline" 
                size="sm" 
                onClick={handleRefresh}
                disabled={loading}
                className="border-gray-700"
              >
                <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
              </Button>
            </div>
          </div>
        </CardHeader>
      </Card>

      {/* Key Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="bg-gradient-to-br from-blue-500/10 to-blue-600/5 border-blue-500/30">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <Shield className="h-8 w-8 text-blue-400" />
              <div>
                <p className="text-2xl font-bold text-blue-400">{combinedStats.totalThreats.toLocaleString()}</p>
                <p className="text-sm text-gray-400">Total Threats</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-red-500/10 to-red-600/5 border-red-500/30">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <AlertTriangle className="h-8 w-8 text-red-400" />
              <div>
                <p className="text-2xl font-bold text-red-400">{combinedStats.critical}</p>
                <p className="text-sm text-gray-400">Critical Threats</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-orange-500/10 to-orange-600/5 border-orange-500/30">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <Target className="h-8 w-8 text-orange-400" />
              <div>
                <p className="text-2xl font-bold text-orange-400">{combinedStats.aptGroups}</p>
                <p className="text-sm text-gray-400">APT Groups</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-purple-500/10 to-purple-600/5 border-purple-500/30">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <Globe className="h-8 w-8 text-purple-400" />
              <div>
                <p className="text-2xl font-bold text-purple-400">{combinedStats.ransomwareVictims}</p>
                <p className="text-sm text-gray-400">Ransomware Victims</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Visualization Charts */}
      <Tabs defaultValue="trends" className="w-full">
        <TabsList className="grid w-full grid-cols-4 bg-gray-900/50 border border-gray-800">
          <TabsTrigger value="trends" className="data-[state=active]:bg-gray-800 data-[state=active]:text-white">Threat Trends</TabsTrigger>
          <TabsTrigger value="severity" className="data-[state=active]:bg-gray-800 data-[state=active]:text-white">Severity Analysis</TabsTrigger>
          <TabsTrigger value="types" className="data-[state=active]:bg-gray-800 data-[state=active]:text-white">Threat Types</TabsTrigger>
          <TabsTrigger value="sources" className="data-[state=active]:bg-gray-800 data-[state=active]:text-white">Source Distribution</TabsTrigger>
        </TabsList>

        <TabsContent value="trends" className="mt-6">
          <Card className="bg-gray-900/50 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white">Threat Intelligence Trends (30 Days)</CardTitle>
              <CardDescription className="text-gray-400">Real-time trend analysis from database records</CardDescription>
            </CardHeader>
            <CardContent>
              <div style={{ height: '400px' }}>
                {threatTrendData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={threatTrendData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                      <XAxis dataKey="date" stroke="#9ca3af" tick={{ fill: '#9ca3af' }} />
                      <YAxis stroke="#9ca3af" tick={{ fill: '#9ca3af' }} />
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#1f2937', 
                          border: '1px solid #374151',
                          borderRadius: '8px',
                          color: '#fff'
                        }}
                      />
                      <Legend />
                      <Area 
                        type="monotone" 
                        dataKey="total" 
                        stackId="1" 
                        stroke="#3b82f6" 
                        fill="#3b82f640" 
                        name="Total Threats"
                      />
                      <Area 
                        type="monotone" 
                        dataKey="critical" 
                        stackId="2" 
                        stroke="#dc2626" 
                        fill="#dc262640" 
                        name="Critical"
                      />
                      <Area 
                        type="monotone" 
                        dataKey="high" 
                        stackId="3" 
                        stroke="#ea580c" 
                        fill="#ea580c40" 
                        name="High"
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex items-center justify-center h-full text-gray-500">
                    <div className="text-center">
                      <TrendingUp className="h-12 w-12 mx-auto mb-2 opacity-50" />
                      <p>Loading trend data...</p>
                      <p className="text-xs mt-1">Data will appear after first sync</p>
                    </div>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="severity" className="mt-6">
          <Card className="bg-gray-900/50 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white">Threat Severity Distribution</CardTitle>
              <CardDescription className="text-gray-400">Current threat severity breakdown</CardDescription>
            </CardHeader>
            <CardContent>
              <div style={{ height: '400px' }}>
                {severityData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={severityData}
                        cx="50%"
                        cy="50%"
                        outerRadius={120}
                        innerRadius={60}
                        fill="#8884d8"
                        dataKey="value"
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                        labelLine={{ stroke: '#9ca3af' }}
                      >
                        {severityData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#1f2937', 
                          border: '1px solid #374151',
                          borderRadius: '8px'
                        }}
                      />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex items-center justify-center h-full text-gray-500">
                    <p>No severity data available</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="types" className="mt-6">
          <Card className="bg-gray-900/50 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white">Threat Type Analysis</CardTitle>
              <CardDescription className="text-gray-400">Distribution of threats by classification</CardDescription>
            </CardHeader>
            <CardContent>
              <div style={{ height: '400px' }}>
                {threatTypeData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={threatTypeData}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                      <XAxis dataKey="name" stroke="#9ca3af" tick={{ fill: '#9ca3af', fontSize: 12 }} />
                      <YAxis stroke="#9ca3af" tick={{ fill: '#9ca3af' }} />
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#1f2937', 
                          border: '1px solid #374151',
                          borderRadius: '8px'
                        }}
                      />
                      <Legend />
                      <Bar dataKey="value" fill="#3b82f6" name="Threat Count" />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex items-center justify-center h-full text-gray-500">
                    <p>No threat type data available</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="sources" className="mt-6">
          <Card className="bg-gray-900/50 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white">Intelligence Source Distribution</CardTitle>
              <CardDescription className="text-gray-400">Threats by intelligence source</CardDescription>
            </CardHeader>
            <CardContent>
              <div style={{ height: '400px' }}>
                {sourceData.length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={sourceData}
                        cx="50%"
                        cy="50%"
                        outerRadius={120}
                        fill="#8884d8"
                        dataKey="value"
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                        labelLine={{ stroke: '#9ca3af' }}
                      >
                        {sourceData.map((entry: any, index: number) => (
                          <Cell 
                            key={`cell-${index}`} 
                            fill={entry.color || `hsl(${index * 45}, 70%, 50%)`} 
                          />
                        ))}
                      </Pie>
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#1f2937', 
                          border: '1px solid #374151',
                          borderRadius: '8px'
                        }}
                      />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex items-center justify-center h-full text-gray-500">
                    <p>No source data available</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Recent Threats Table */}
      <Card className="bg-gray-900/50 border-gray-800">
        <CardHeader>
          <CardTitle className="text-white">Recent Threat Intelligence (Last 7 Days)</CardTitle>
          <CardDescription className="text-gray-400">Live database records with no mock data</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {threatData.map(threat => (
              <div key={threat.id} className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg border border-gray-700">
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <h4 className="font-medium text-sm text-white">{threat.title}</h4>
                    <Badge variant={
                      threat.severity_level === 'critical' ? 'destructive' :
                      threat.severity_level === 'high' ? 'secondary' :
                      threat.severity_level === 'medium' ? 'outline' : 'default'
                    }>
                      {threat.severity_level}
                    </Badge>
                    <Badge variant="outline" className="bg-gray-800 border-gray-700">{threat.threat_type}</Badge>
                  </div>
                  <p className="text-xs text-gray-500 mt-1">
                    Source: {threat.source_name} | Confidence: {threat.confidence_level}%
                  </p>
                </div>
                <div className="text-xs text-gray-500">
                  {new Date(threat.created_at).toLocaleDateString()}
                </div>
              </div>
            ))}
            {threatData.length === 0 && (
              <div className="text-center py-8 text-gray-500">
                <Target className="h-12 w-12 mx-auto mb-2 opacity-50" />
                <p>No threat intelligence data found</p>
                <p className="text-xs">Check network connectivity and API access</p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default ThreatVisualization;
