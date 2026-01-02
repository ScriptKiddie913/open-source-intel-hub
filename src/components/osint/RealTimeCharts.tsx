// ============================================================================
// RealTimeCharts.tsx  
// REAL-TIME THREAT INTELLIGENCE CHARTS COMPONENT
// ============================================================================
// ✔ Auto-updating charts with live data
// ✔ Multiple chart types (line, bar, pie, area)
// ✔ Background data synchronization
// ✔ Animated transitions
// ============================================================================

import React, { useEffect, useState, useCallback, useRef } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { 
  Activity, 
  AlertTriangle, 
  Globe, 
  RefreshCw, 
  Shield, 
  Target, 
  TrendingUp,
  Server,
  Bug,
  Link2,
  Zap,
  Lock,
  Fish
} from 'lucide-react';
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
  RadialBarChart,
  RadialBar,
  ComposedChart
} from 'recharts';
import { 
  realTimeThreatFeedService, 
  type RealTimeThreatStats, 
  type ThreatTrendData,
  type LiveFeedEntry 
} from '@/services/realTimeThreatFeedService';
import { toast } from 'sonner';

interface RealTimeChartsProps {
  refreshInterval?: number;
  showLiveFeed?: boolean;
}

const COLORS = {
  critical: '#dc2626',
  high: '#ea580c', 
  medium: '#ca8a04',
  low: '#16a34a',
  primary: '#3b82f6',
  secondary: '#8b5cf6',
  tertiary: '#ec4899',
  quaternary: '#14b8a6'
};

const RealTimeCharts: React.FC<RealTimeChartsProps> = ({ 
  refreshInterval = 30000,
  showLiveFeed = true 
}) => {
  const [stats, setStats] = useState<RealTimeThreatStats | null>(null);
  const [trendData, setTrendData] = useState<ThreatTrendData | null>(null);
  const [liveFeed, setLiveFeed] = useState<LiveFeedEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());
  const [updateCount, setUpdateCount] = useState(0);
  const subscriptionRef = useRef<(() => void) | null>(null);

  // Initialize service and subscribe to updates
  useEffect(() => {
    const initService = async () => {
      try {
        setIsLoading(true);
        await realTimeThreatFeedService.initialize();
        
        // Subscribe to real-time updates
        subscriptionRef.current = realTimeThreatFeedService.subscribe((data) => {
          setStats(data.stats);
          setTrendData(data.trendData);
          setLiveFeed(data.liveFeed || []);
          setLastUpdate(new Date());
          setUpdateCount(prev => prev + 1);
          setIsLoading(false);
        });

      } catch (error) {
        console.error('[RealTimeCharts] Initialization failed:', error);
        toast.error('Failed to initialize threat feed');
        setIsLoading(false);
      }
    };

    initService();

    return () => {
      if (subscriptionRef.current) {
        subscriptionRef.current();
      }
    };
  }, []);

  // Manual refresh handler
  const handleRefresh = useCallback(async () => {
    setIsLoading(true);
    try {
      await realTimeThreatFeedService.refresh();
      toast.success('Threat data refreshed');
    } catch (error) {
      toast.error('Refresh failed');
    }
    setIsLoading(false);
  }, []);

  // Get severity badge style
  const getSeverityStyle = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 text-red-400 border-red-500/50';
      case 'high': return 'bg-orange-500/20 text-orange-400 border-orange-500/50';
      case 'medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50';
      case 'low': return 'bg-green-500/20 text-green-400 border-green-500/50';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/50';
    }
  };

  // Format number for display
  const formatNumber = (num: number) => {
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
    return num.toString();
  };

  if (isLoading && !stats) {
    return (
      <div className="flex items-center justify-center h-64 bg-gray-900/50 rounded-lg">
        <div className="text-center">
          <RefreshCw className="h-8 w-8 animate-spin text-cyan-400 mx-auto mb-2" />
          <p className="text-gray-400">Loading real-time threat data...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header with Live Status */}
      <Card className="bg-gray-900/50 border-gray-800">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2 text-white">
                <Activity className="h-5 w-5 text-cyan-400" />
                Real-Time Threat Intelligence
              </CardTitle>
              <CardDescription className="text-gray-400">
                Live data from multiple threat intelligence feeds
              </CardDescription>
            </div>
            <div className="flex items-center gap-4">
              <div className="text-right">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                  <span className="text-xs text-green-400">Live</span>
                </div>
                <p className="text-xs text-gray-500">
                  Updated: {lastUpdate.toLocaleTimeString()}
                </p>
                <p className="text-xs text-gray-600">
                  Syncs: {updateCount}
                </p>
              </div>
              <Button 
                variant="outline" 
                size="sm" 
                onClick={handleRefresh}
                disabled={isLoading}
                className="border-gray-700"
              >
                <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
              </Button>
            </div>
          </div>
        </CardHeader>
      </Card>

      {/* Key Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <Card className="bg-gradient-to-br from-red-500/10 to-red-600/5 border-red-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">Total Threats</p>
                <p className="text-3xl font-bold text-red-400">
                  {formatNumber(stats?.totalThreats || 0)}
                </p>
              </div>
              <Shield className="h-10 w-10 text-red-400/50" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-orange-500/10 to-orange-600/5 border-orange-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">C2 Servers</p>
                <p className="text-3xl font-bold text-orange-400">
                  {formatNumber(stats?.activeC2Servers || 0)}
                </p>
              </div>
              <Server className="h-10 w-10 text-orange-400/50" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-yellow-500/10 to-yellow-600/5 border-yellow-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">Malicious URLs</p>
                <p className="text-3xl font-bold text-yellow-400">
                  {formatNumber(stats?.maliciousUrls || 0)}
                </p>
              </div>
              <Link2 className="h-10 w-10 text-yellow-400/50" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-cyan-500/10 to-cyan-600/5 border-cyan-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">Malware Samples</p>
                <p className="text-3xl font-bold text-cyan-400">
                  {formatNumber(stats?.malwareSamples || 0)}
                </p>
              </div>
              <Bug className="h-10 w-10 text-cyan-400/50" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-purple-500/10 to-purple-600/5 border-purple-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">Phishing URLs</p>
                <p className="text-3xl font-bold text-purple-400">
                  {formatNumber(stats?.phishingUrls || 0)}
                </p>
              </div>
              <Fish className="h-10 w-10 text-purple-400/50" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-green-500/10 to-green-600/5 border-green-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">SSL Blacklist</p>
                <p className="text-3xl font-bold text-green-400">
                  {formatNumber(stats?.sslCertificates || 0)}
                </p>
              </div>
              <Lock className="h-10 w-10 text-green-400/50" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Charts Tabs */}
      <Tabs defaultValue="trends" className="w-full">
        <TabsList className="bg-gray-900/50 border border-gray-800">
          <TabsTrigger value="trends" className="data-[state=active]:bg-gray-800">
            <TrendingUp className="h-4 w-4 mr-2" />
            Threat Trends
          </TabsTrigger>
          <TabsTrigger value="types" className="data-[state=active]:bg-gray-800">
            <Target className="h-4 w-4 mr-2" />
            Threat Types
          </TabsTrigger>
          <TabsTrigger value="sources" className="data-[state=active]:bg-gray-800">
            <Globe className="h-4 w-4 mr-2" />
            Sources
          </TabsTrigger>
          <TabsTrigger value="severity" className="data-[state=active]:bg-gray-800">
            <AlertTriangle className="h-4 w-4 mr-2" />
            Severity
          </TabsTrigger>
        </TabsList>

        {/* Threat Trends Chart */}
        <TabsContent value="trends" className="mt-6">
          <Card className="bg-gray-900/50 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white">Threat Intelligence Trends</CardTitle>
              <CardDescription className="text-gray-400">
                Real-time threat activity over time
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div style={{ height: '400px' }}>
                <ResponsiveContainer width="100%" height="100%">
                  <ComposedChart data={trendData?.trends || []}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis 
                      dataKey="date" 
                      stroke="#9ca3af"
                      tick={{ fill: '#9ca3af', fontSize: 12 }}
                    />
                    <YAxis 
                      stroke="#9ca3af"
                      tick={{ fill: '#9ca3af', fontSize: 12 }}
                    />
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: '#1f2937', 
                        border: '1px solid #374151',
                        borderRadius: '8px'
                      }}
                      labelStyle={{ color: '#fff' }}
                    />
                    <Legend />
                    <Area 
                      type="monotone" 
                      dataKey="total" 
                      fill="#3b82f620" 
                      stroke="#3b82f6"
                      name="Total Threats"
                    />
                    <Line 
                      type="monotone" 
                      dataKey="critical" 
                      stroke={COLORS.critical}
                      strokeWidth={2}
                      dot={{ fill: COLORS.critical }}
                      name="Critical"
                    />
                    <Line 
                      type="monotone" 
                      dataKey="high" 
                      stroke={COLORS.high}
                      strokeWidth={2}
                      dot={{ fill: COLORS.high }}
                      name="High"
                    />
                  </ComposedChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Threat Types Chart */}
        <TabsContent value="types" className="mt-6">
          <Card className="bg-gray-900/50 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white">Threat Type Distribution</CardTitle>
              <CardDescription className="text-gray-400">
                Breakdown by threat classification
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div style={{ height: '350px' }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={trendData?.typeDistribution || []}
                        cx="50%"
                        cy="50%"
                        outerRadius={120}
                        innerRadius={60}
                        fill="#8884d8"
                        dataKey="value"
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                        labelLine={{ stroke: '#9ca3af' }}
                      >
                        {(trendData?.typeDistribution || []).map((entry, index) => (
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
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div style={{ height: '350px' }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart 
                      data={trendData?.typeDistribution || []}
                      layout="vertical"
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                      <XAxis type="number" stroke="#9ca3af" />
                      <YAxis 
                        type="category" 
                        dataKey="name" 
                        stroke="#9ca3af" 
                        width={100}
                        tick={{ fill: '#9ca3af', fontSize: 12 }}
                      />
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#1f2937', 
                          border: '1px solid #374151',
                          borderRadius: '8px'
                        }}
                      />
                      <Bar dataKey="value" name="Count">
                        {(trendData?.typeDistribution || []).map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Sources Chart */}
        <TabsContent value="sources" className="mt-6">
          <Card className="bg-gray-900/50 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white">Intelligence Source Distribution</CardTitle>
              <CardDescription className="text-gray-400">
                Threats by data source
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div style={{ height: '350px' }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={trendData?.sourceDistribution || []}
                        cx="50%"
                        cy="50%"
                        outerRadius={120}
                        fill="#8884d8"
                        dataKey="value"
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                        labelLine={{ stroke: '#9ca3af' }}
                      >
                        {(trendData?.sourceDistribution || []).map((entry, index) => (
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
                </div>
                <div className="space-y-3">
                  {(trendData?.sourceDistribution || []).map((source, index) => (
                    <div 
                      key={source.name}
                      className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg border border-gray-700"
                    >
                      <div className="flex items-center gap-3">
                        <div 
                          className="w-4 h-4 rounded-full"
                          style={{ backgroundColor: source.color }}
                        />
                        <span className="text-white font-medium">{source.name}</span>
                      </div>
                      <div className="text-right">
                        <span className="text-2xl font-bold text-cyan-400">
                          {formatNumber(source.value)}
                        </span>
                        <p className="text-xs text-gray-500">indicators</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Severity Chart */}
        <TabsContent value="severity" className="mt-6">
          <Card className="bg-gray-900/50 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white">Threat Severity Analysis</CardTitle>
              <CardDescription className="text-gray-400">
                Current threat severity breakdown
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div style={{ height: '350px' }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <RadialBarChart 
                      cx="50%" 
                      cy="50%" 
                      innerRadius="20%" 
                      outerRadius="90%" 
                      data={trendData?.severityDistribution || []}
                      startAngle={180}
                      endAngle={0}
                    >
                      <RadialBar
                        minAngle={15}
                        background
                        clockWise
                        dataKey="value"
                        label={{ position: 'insideStart', fill: '#fff', fontSize: 12 }}
                      >
                        {(trendData?.severityDistribution || []).map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </RadialBar>
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: '#1f2937', 
                          border: '1px solid #374151',
                          borderRadius: '8px'
                        }}
                      />
                      <Legend 
                        iconSize={10}
                        layout="horizontal"
                        verticalAlign="bottom"
                      />
                    </RadialBarChart>
                  </ResponsiveContainer>
                </div>
                <div className="space-y-4">
                  {(trendData?.severityDistribution || []).map((severity) => (
                    <div 
                      key={severity.name}
                      className="p-4 rounded-lg border"
                      style={{ 
                        borderColor: `${severity.color}50`,
                        backgroundColor: `${severity.color}10`
                      }}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-semibold" style={{ color: severity.color }}>
                          {severity.name}
                        </span>
                        <span className="text-2xl font-bold" style={{ color: severity.color }}>
                          {formatNumber(severity.value)}
                        </span>
                      </div>
                      <div className="w-full bg-gray-700 rounded-full h-2">
                        <div 
                          className="h-2 rounded-full transition-all duration-500"
                          style={{ 
                            backgroundColor: severity.color,
                            width: `${Math.min((severity.value / (stats?.totalThreats || 1)) * 100, 100)}%`
                          }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Live Feed */}
      {showLiveFeed && (
        <Card className="bg-gray-900/50 border-gray-800">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-white">
              <Zap className="h-5 w-5 text-yellow-400" />
              Live Threat Feed
            </CardTitle>
            <CardDescription className="text-gray-400">
              Real-time threat indicators as they arrive
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[400px]">
              <div className="space-y-2">
                {liveFeed.slice(0, 50).map((entry, index) => (
                  <div 
                    key={`${entry.id}-${index}`}
                    className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg border border-gray-700 hover:border-gray-600 transition-colors"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <Badge 
                          variant="outline" 
                          className={`${getSeverityStyle(entry.severity)} text-xs`}
                        >
                          {entry.type.toUpperCase()}
                        </Badge>
                        <Badge variant="outline" className="text-xs bg-gray-800 border-gray-700">
                          {entry.source}
                        </Badge>
                        {entry.malwareFamily && (
                          <Badge variant="outline" className="text-xs bg-purple-500/20 text-purple-400 border-purple-500/50">
                            {entry.malwareFamily}
                          </Badge>
                        )}
                      </div>
                      <code className="text-sm text-cyan-400 font-mono block truncate">
                        {entry.value}
                      </code>
                    </div>
                    <div className="text-right ml-4">
                      <Badge 
                        variant="outline" 
                        className={getSeverityStyle(entry.severity)}
                      >
                        {entry.severity}
                      </Badge>
                      <p className="text-xs text-gray-500 mt-1">
                        {new Date(entry.timestamp).toLocaleTimeString()}
                      </p>
                    </div>
                  </div>
                ))}
                {liveFeed.length === 0 && (
                  <div className="text-center py-8 text-gray-500">
                    <Activity className="h-12 w-12 mx-auto mb-2 opacity-50" />
                    <p>Waiting for threat data...</p>
                  </div>
                )}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      )}

      {/* Malware Families */}
      {trendData?.malwareFamilies && trendData.malwareFamilies.length > 0 && (
        <Card className="bg-gray-900/50 border-gray-800">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-white">
              <Bug className="h-5 w-5 text-purple-400" />
              Top Active Malware Families
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
              {trendData.malwareFamilies.slice(0, 15).map((family) => (
                <div 
                  key={family.name}
                  className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg border border-gray-700"
                >
                  <span className="text-sm font-medium text-gray-200 truncate">
                    {family.name}
                  </span>
                  <div className="flex items-center gap-1">
                    <Badge variant="outline" className="text-xs">
                      {family.count}
                    </Badge>
                    {family.trend === 'up' && (
                      <TrendingUp className="h-3 w-3 text-red-400" />
                    )}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
};

export default RealTimeCharts;
