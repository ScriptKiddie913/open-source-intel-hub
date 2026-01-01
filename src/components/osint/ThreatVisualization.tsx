// Real-time threat intelligence visualization component
// Generates live graphs and charts based on database-stored threat data

import React, { useEffect, useState, useRef } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { AlertTriangle, TrendingUp, Shield, Activity, Globe, Target } from 'lucide-react';
import { threatIntelligenceDB, type ThreatIntelligenceRecord } from '@/services/threatIntelligenceDatabase';
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
}

export const ThreatVisualization: React.FC<ThreatVisualizationProps> = ({
  refreshInterval = 30000,
  showRealTimeUpdates = true
}) => {
  const [threatData, setThreatData] = useState<ThreatIntelligenceRecord[]>([]);
  const [statistics, setStatistics] = useState<any>(null);
  const [timeSeriesData, setTimeSeriesData] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());
  const intervalRef = useRef<NodeJS.Timeout | null>(null);

  // Real-time data loading
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

  const loadThreatVisualizationData = async () => {
    try {
      setLoading(true);

      // Load comprehensive threat data for visualization
      const [recentThreats, stats, timeSeriesThreats] = await Promise.all([
        threatIntelligenceDB.queryThreatIntelligence({
          limit: 500,
          timeRange: {
            from: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(), // Last 7 days
            to: new Date().toISOString()
          }
        }),
        threatIntelligenceDB.getThreatStatistics(),
        threatIntelligenceDB.queryThreatIntelligence({
          limit: 1000,
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
  const threatTrendData = timeSeriesData.map(d => ({
    date: new Date(d.date).toLocaleDateString(),
    total: d.total,
    critical: d.critical,
    high: d.high,
    medium: d.medium,
    low: d.low
  }));

  const severityData = [
    { name: 'Critical', value: statistics?.bySeverity?.critical || 0, color: '#dc2626' },
    { name: 'High', value: statistics?.bySeverity?.high || 0, color: '#ea580c' },
    { name: 'Medium', value: statistics?.bySeverity?.medium || 0, color: '#ca8a04' },
    { name: 'Low', value: statistics?.bySeverity?.low || 0, color: '#16a34a' }
  ];

  const threatTypeData = Object.entries(statistics?.byType || {}).map(([type, count]) => ({
    name: type.charAt(0).toUpperCase() + type.slice(1),
    value: count
  }));

  const sourceData = Object.entries(statistics?.bySource || {}).map(([source, count]) => ({
    name: source,
    value: count
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
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Activity className="h-5 w-5 text-blue-600" />
                Real-time Threat Intelligence Dashboard
              </CardTitle>
              <CardDescription>
                Live visualization based on database-stored threat intelligence
              </CardDescription>
            </div>
            <div className="text-right">
              <div className="text-sm text-gray-500">
                Last Updated: {lastUpdate.toLocaleTimeString()}
              </div>
              <div className="flex items-center gap-2 mt-1">
                <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                <span className="text-xs text-green-600">Live</span>
              </div>
            </div>
          </div>
        </CardHeader>
      </Card>

      {/* Key Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <Shield className="h-8 w-8 text-blue-600" />
              <div>
                <p className="text-2xl font-bold">{statistics?.totalThreats?.toLocaleString() || 0}</p>
                <p className="text-sm text-gray-600">Total Threats</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <AlertTriangle className="h-8 w-8 text-red-600" />
              <div>
                <p className="text-2xl font-bold">{statistics?.bySeverity?.critical || 0}</p>
                <p className="text-sm text-gray-600">Critical Threats</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <TrendingUp className="h-8 w-8 text-orange-600" />
              <div>
                <p className="text-2xl font-bold">{statistics?.recentCount || 0}</p>
                <p className="text-sm text-gray-600">Recent (24h)</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <Globe className="h-8 w-8 text-green-600" />
              <div>
                <p className="text-2xl font-bold">{Object.keys(statistics?.bySource || {}).length}</p>
                <p className="text-sm text-gray-600">Intel Sources</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Visualization Charts */}
      <Tabs defaultValue="trends" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="trends">Threat Trends</TabsTrigger>
          <TabsTrigger value="severity">Severity Analysis</TabsTrigger>
          <TabsTrigger value="types">Threat Types</TabsTrigger>
          <TabsTrigger value="sources">Source Distribution</TabsTrigger>
        </TabsList>

        <TabsContent value="trends" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle>Threat Intelligence Trends (30 Days)</CardTitle>
              <CardDescription>Real-time trend analysis from database records</CardDescription>
            </CardHeader>
            <CardContent>
              <div style={{ height: '400px' }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={threatTrendData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="date" />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <Area 
                      type="monotone" 
                      dataKey="total" 
                      stackId="1" 
                      stroke="#ef4444" 
                      fill="#ef444440" 
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
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="severity" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle>Threat Severity Distribution</CardTitle>
              <CardDescription>Current threat severity breakdown</CardDescription>
            </CardHeader>
            <CardContent>
              <div style={{ height: '400px' }}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityData}
                      cx="50%"
                      cy="50%"
                      outerRadius={120}
                      fill="#8884d8"
                      dataKey="value"
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    >
                      {severityData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="types" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle>Threat Type Analysis</CardTitle>
              <CardDescription>Distribution of threats by classification</CardDescription>
            </CardHeader>
            <CardContent>
              <div style={{ height: '400px' }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={threatTypeData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <Bar dataKey="value" fill="#3b82f6" name="Threat Count" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="sources" className="mt-6">
          <Card>
            <CardHeader>
              <CardTitle>Intelligence Source Distribution</CardTitle>
              <CardDescription>Threats by intelligence source</CardDescription>
            </CardHeader>
            <CardContent>
              <div style={{ height: '400px' }}>
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
                    >
                      {sourceData.map((entry, index) => (
                        <Cell 
                          key={`cell-${index}`} 
                          fill={`hsl(${index * 45}, 70%, 50%)`} 
                        />
                      ))}
                    </Pie>
                    <Tooltip />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Recent Threats Table */}
      <Card>
        <CardHeader>
          <CardTitle>Recent Threat Intelligence (Last 7 Days)</CardTitle>
          <CardDescription>Live database records with no mock data</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {threatData.slice(0, 20).map(threat => (
              <div key={threat.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <h4 className="font-medium text-sm">{threat.title}</h4>
                    <Badge variant={
                      threat.severity_level === 'critical' ? 'destructive' :
                      threat.severity_level === 'high' ? 'secondary' :
                      threat.severity_level === 'medium' ? 'outline' : 'default'
                    }>
                      {threat.severity_level}
                    </Badge>
                    <Badge variant="outline">{threat.threat_type}</Badge>
                  </div>
                  <p className="text-xs text-gray-600 mt-1">
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
