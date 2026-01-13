// ============================================================================
// RealTimeCharts.tsx - Real-Time Threat Intelligence Charts
// ============================================================================
// Displays live threat data from abuse.ch feeds with auto-updating charts
// ============================================================================

import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { 
  Activity, AlertTriangle, Globe, RefreshCw, Shield, Target, 
  TrendingUp, Server, Bug, Link2, Zap, Clock, Info, ExternalLink,
  Copy, ChevronDown, ChevronUp, Eye, Hash, MapPin, Calendar, Tag
} from 'lucide-react';
import {
  LineChart, Line, AreaChart, Area, BarChart, Bar, PieChart, Pie,
  Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar,
  ComposedChart, Scatter
} from 'recharts';
import { 
  realTimeThreatFeedService, 
  type RealTimeThreatStats, 
  type ThreatTrendData,
  type LiveFeedEntry 
} from '@/services/realTimeThreatFeedService';
import { toast } from 'sonner';

// ============================================================================
// CUSTOM TOOLTIP COMPONENTS
// ============================================================================

interface CustomTooltipProps {
  active?: boolean;
  payload?: any[];
  label?: string;
}

// Enhanced Tooltip for Area/Line Charts
const TrendTooltip: React.FC<CustomTooltipProps> = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  
  const total = payload.reduce((sum, entry) => sum + (entry.value || 0), 0);
  
  return (
    <div className="bg-gray-900 border border-gray-700 rounded-lg p-4 shadow-xl min-w-[220px]">
      <div className="flex items-center gap-2 mb-3 pb-2 border-b border-gray-700">
        <Clock className="h-4 w-4 text-cyan-400" />
        <span className="text-white font-semibold">{label}</span>
      </div>
      <div className="space-y-2">
        {payload.map((entry, idx) => (
          <div key={idx} className="flex items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full" style={{ backgroundColor: entry.color }} />
              <span className="text-gray-300 text-sm">{entry.name}</span>
            </div>
            <span className="font-bold text-white">{entry.value?.toLocaleString()}</span>
          </div>
        ))}
      </div>
      <div className="mt-3 pt-2 border-t border-gray-700 flex justify-between">
        <span className="text-gray-400 text-sm">Total</span>
        <span className="font-bold text-cyan-400">{total.toLocaleString()}</span>
      </div>
    </div>
  );
};

// Enhanced Tooltip for Pie Charts
const PieTooltip: React.FC<CustomTooltipProps> = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  
  const data = payload[0];
  const percentage = data.payload?.percent ? (data.payload.percent * 100).toFixed(1) : '0';
  
  return (
    <div className="bg-gray-900 border border-gray-700 rounded-lg p-4 shadow-xl min-w-[200px]">
      <div className="flex items-center gap-2 mb-2">
        <div className="w-4 h-4 rounded-full" style={{ backgroundColor: data.payload?.color || data.color }} />
        <span className="text-white font-semibold">{data.name}</span>
      </div>
      <div className="space-y-1">
        <div className="flex justify-between">
          <span className="text-gray-400">Count</span>
          <span className="font-bold text-cyan-400">{data.value?.toLocaleString()}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-gray-400">Percentage</span>
          <span className="font-bold text-purple-400">{percentage}%</span>
        </div>
      </div>
    </div>
  );
};

// Enhanced Tooltip for Bar Charts
const BarTooltip: React.FC<CustomTooltipProps> = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  
  const data = payload[0];
  
  return (
    <div className="bg-gray-900 border border-gray-700 rounded-lg p-4 shadow-xl min-w-[180px]">
      <div className="flex items-center gap-2 mb-2">
        <div className="w-4 h-4 rounded-full" style={{ backgroundColor: data.payload?.color || data.color }} />
        <span className="text-white font-semibold">{label || data.payload?.name}</span>
      </div>
      <div className="flex justify-between items-center">
        <span className="text-gray-400">Threats</span>
        <span className="font-bold text-xl text-cyan-400">{data.value?.toLocaleString()}</span>
      </div>
    </div>
  );
};

// ============================================================================
// MALWARE DETAIL INTERFACES
// ============================================================================

interface MalwareDetail {
  name: string;
  count: number;
  trend: 'up' | 'down' | 'stable';
  samples: LiveFeedEntry[];
  firstSeen?: string;
  lastSeen?: string;
  types: string[];
  sources: string[];
  countries: string[];
  severity: { critical: number; high: number; medium: number; low: number };
}

// OpenCTI-inspired dark theme colors
const COLORS = {
  critical: '#ff1744',
  high: '#ff9100', 
  medium: '#ffea00',
  low: '#00e676',
  primary: '#00bcd4',
  secondary: '#7c4dff',
  tertiary: '#f50057',
  quaternary: '#00e5ff',
  accent: '#00b8d4',
  background: '#0d1117',
  surface: '#161b22',
  border: '#30363d',
  text: '#c9d1d9'
};

// OpenCTI-style gradient definitions for charts
const GRADIENTS = {
  critical: 'url(#gradientCritical)',
  high: 'url(#gradientHigh)',
  medium: 'url(#gradientMedium)',
  low: 'url(#gradientLow)',
  primary: 'url(#gradientPrimary)'
};

interface RealTimeChartsProps {
  refreshInterval?: number;
  showLiveFeed?: boolean;
}

const RealTimeCharts: React.FC<RealTimeChartsProps> = ({ 
  refreshInterval = 30000, 
  showLiveFeed = true 
}) => {
  const [stats, setStats] = useState<RealTimeThreatStats | null>(null);
  const [trendData, setTrendData] = useState<ThreatTrendData | null>(null);
  const [liveFeed, setLiveFeed] = useState<LiveFeedEntry[]>([]);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());
  const [selectedMalware, setSelectedMalware] = useState<MalwareDetail | null>(null);
  const [selectedThreat, setSelectedThreat] = useState<LiveFeedEntry | null>(null);
  const [expandedFamilies, setExpandedFamilies] = useState<Set<string>>(new Set());

  // Compute detailed malware information
  const malwareDetails = useMemo((): MalwareDetail[] => {
    if (!liveFeed.length) return [];
    
    const malwareMap = new Map<string, MalwareDetail>();
    
    liveFeed.forEach(entry => {
      const family = entry.malwareFamily || 'Unknown';
      
      if (!malwareMap.has(family)) {
        malwareMap.set(family, {
          name: family,
          count: 0,
          trend: 'stable',
          samples: [],
          types: [],
          sources: [],
          countries: [],
          severity: { critical: 0, high: 0, medium: 0, low: 0 }
        });
      }
      
      const detail = malwareMap.get(family)!;
      detail.count++;
      detail.samples.push(entry);
      
      // Track types
      if (!detail.types.includes(entry.type)) detail.types.push(entry.type);
      // Track sources
      if (!detail.sources.includes(entry.source)) detail.sources.push(entry.source);
      // Track countries
      if (entry.country && !detail.countries.includes(entry.country)) {
        detail.countries.push(entry.country);
      }
      // Track severity
      detail.severity[entry.severity]++;
      
      // Track timestamps
      const ts = entry.timestamp;
      if (ts) {
        if (!detail.firstSeen || ts < detail.firstSeen) detail.firstSeen = ts;
        if (!detail.lastSeen || ts > detail.lastSeen) detail.lastSeen = ts;
      }
    });
    
    return Array.from(malwareMap.values())
      .sort((a, b) => b.count - a.count)
      .map(d => ({
        ...d,
        trend: d.count > 20 ? 'up' : d.count > 5 ? 'stable' : 'down'
      }));
  }, [liveFeed]);

  // Initialize and subscribe to updates
  useEffect(() => {
    let unsubscribe: (() => void) | null = null;

    const init = async () => {
      try {
        await realTimeThreatFeedService.initialize();
        
        unsubscribe = realTimeThreatFeedService.subscribe((data) => {
          setStats(data.stats);
          setTrendData(data.trendData);
          setLiveFeed(data.liveFeed || []);
          setLastUpdate(new Date());
        });
      } catch (error) {
        console.error('[RealTimeCharts] Init error:', error);
        toast.error('Failed to initialize threat feed');
      }
    };

    init();

    return () => {
      if (unsubscribe) unsubscribe();
    };
  }, []);

  const handleRefresh = useCallback(async () => {
    try {
      await realTimeThreatFeedService.refresh();
      toast.success('Threat data refreshed');
    } catch (error) {
      toast.error('Refresh failed');
    }
  }, []);

  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      critical: 'bg-red-500/20 text-red-400 border-red-500/50',
      high: 'bg-orange-500/20 text-orange-400 border-orange-500/50',
      medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
      low: 'bg-green-500/20 text-green-400 border-green-500/50'
    };
    return colors[severity] || colors.medium;
  };

  const formatNumber = (num: number) => {
    if (num >= 1000000) return `${(num / 1000000).toFixed(1)}M`;
    if (num >= 1000) return `${(num / 1000).toFixed(1)}K`;
    return num.toString();
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard');
  };

  const toggleFamilyExpand = (name: string) => {
    setExpandedFamilies(prev => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  // Handle chart point click
  const handleChartClick = (data: any, _index: number) => {
    if (data?.activePayload?.[0]?.payload) {
      const payload = data.activePayload[0].payload;
      toast.info(`${payload.time || payload.name}: ${payload.total || payload.value} threats`);
    }
  };

  // Handle pie segment click
  const handlePieClick = (data: any) => {
    if (data?.name) {
      toast.info(`${data.name}: ${data.value?.toLocaleString()} threats (${((data.percent || 0) * 100).toFixed(1)}%)`);
    }
  };

  if (!stats) {
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
      {/* Header */}
      <Card className="bg-gray-900/50 border-gray-800">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2 text-white">
                <Activity className="h-5 w-5 text-cyan-400" />
                Real-Time Threat Intelligence
              </CardTitle>
              <CardDescription className="text-gray-400">
                Live data from abuse.ch threat feeds
              </CardDescription>
            </div>
            <div className="flex items-center gap-4">
              <div className="text-right">
                <div className="flex items-center gap-2">
                  <div className={`w-2 h-2 rounded-full ${stats.isLoading ? 'bg-yellow-500 animate-pulse' : 'bg-green-500'}`} />
                  <span className="text-xs text-green-400">{stats.isLoading ? 'Syncing...' : 'Live'}</span>
                </div>
                <p className="text-xs text-gray-500 flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  {lastUpdate.toLocaleTimeString()}
                </p>
                <p className="text-xs text-gray-600">Updates: {stats.updateCount}</p>
              </div>
              <Button 
                variant="outline" 
                size="sm" 
                onClick={handleRefresh}
                disabled={stats.isLoading}
                className="border-gray-700"
              >
                <RefreshCw className={`h-4 w-4 ${stats.isLoading ? 'animate-spin' : ''}`} />
              </Button>
            </div>
          </div>
          {stats.errors.length > 0 && (
            <div className="mt-2 text-xs text-red-400">
              Errors: {stats.errors.join(', ')}
            </div>
          )}
        </CardHeader>
      </Card>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="bg-gradient-to-br from-red-500/10 to-red-600/5 border-red-500/30">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">Total Threats</p>
                <p className="text-3xl font-bold text-red-400">{formatNumber(stats.totalThreats)}</p>
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
                <p className="text-3xl font-bold text-orange-400">{formatNumber(stats.activeC2Servers)}</p>
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
                <p className="text-3xl font-bold text-yellow-400">{formatNumber(stats.maliciousUrls)}</p>
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
                <p className="text-3xl font-bold text-cyan-400">{formatNumber(stats.malwareSamples)}</p>
              </div>
              <Bug className="h-10 w-10 text-cyan-400/50" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Charts Tabs - OpenCTI Style */}
      <Tabs defaultValue="trends" className="w-full">
        <TabsList className="bg-[#0d1117] border border-[#30363d] p-1 rounded-lg">
          <TabsTrigger value="trends" className="data-[state=active]:bg-[#21262d] data-[state=active]:text-cyan-400 rounded-md transition-all">
            <TrendingUp className="h-4 w-4 mr-2" />
            Trends
          </TabsTrigger>
          <TabsTrigger value="radar" className="data-[state=active]:bg-[#21262d] data-[state=active]:text-cyan-400 rounded-md transition-all">
            <Shield className="h-4 w-4 mr-2" />
            Threat Radar
          </TabsTrigger>
          <TabsTrigger value="types" className="data-[state=active]:bg-[#21262d] data-[state=active]:text-cyan-400 rounded-md transition-all">
            <Target className="h-4 w-4 mr-2" />
            Types
          </TabsTrigger>
          <TabsTrigger value="sources" className="data-[state=active]:bg-[#21262d] data-[state=active]:text-cyan-400 rounded-md transition-all">
            <Globe className="h-4 w-4 mr-2" />
            Sources
          </TabsTrigger>
          <TabsTrigger value="severity" className="data-[state=active]:bg-[#21262d] data-[state=active]:text-cyan-400 rounded-md transition-all">
            <AlertTriangle className="h-4 w-4 mr-2" />
            Severity
          </TabsTrigger>
        </TabsList>

        {/* Trends Chart */}
        <TabsContent value="trends" className="mt-6">
          <Card className="bg-gray-900/50 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white">Threat Activity Over Time</CardTitle>
              <CardDescription className="text-gray-400">
                Real-time threat detection trends • Click on data points for details
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div style={{ height: '400px' }}>
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trendData?.trends || []} onClick={handleChartClick}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                    <XAxis dataKey="time" stroke="#9ca3af" tick={{ fill: '#9ca3af', fontSize: 12 }} />
                    <YAxis stroke="#9ca3af" tick={{ fill: '#9ca3af', fontSize: 12 }} />
                    <Tooltip content={<TrendTooltip />} />
                    <Legend />
                    <Area type="monotone" dataKey="critical" stackId="1" stroke={COLORS.critical} fill={COLORS.critical} fillOpacity={0.6} name="Critical" activeDot={{ r: 8, strokeWidth: 2 }} />
                    <Area type="monotone" dataKey="high" stackId="1" stroke={COLORS.high} fill={COLORS.high} fillOpacity={0.6} name="High" activeDot={{ r: 8, strokeWidth: 2 }} />
                    <Area type="monotone" dataKey="medium" stackId="1" stroke={COLORS.medium} fill={COLORS.medium} fillOpacity={0.6} name="Medium" activeDot={{ r: 8, strokeWidth: 2 }} />
                    <Area type="monotone" dataKey="low" stackId="1" stroke={COLORS.low} fill={COLORS.low} fillOpacity={0.6} name="Low" activeDot={{ r: 8, strokeWidth: 2 }} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* OpenCTI-Style Radar Chart */}
        <TabsContent value="radar" className="mt-6">
          <Card className="bg-[#0d1117] border-[#30363d]">
            <CardHeader>
              <CardTitle className="text-[#c9d1d9]">Threat Intelligence Radar</CardTitle>
              <CardDescription className="text-[#8b949e]">
                Multi-dimensional threat analysis in OpenCTI style
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div style={{ height: '400px' }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <RadarChart data={[
                      { subject: 'C2 Servers', A: stats?.activeC2Servers || 0, fullMark: Math.max(stats?.activeC2Servers || 100, 100) },
                      { subject: 'Malicious URLs', A: stats?.maliciousUrls || 0, fullMark: Math.max(stats?.maliciousUrls || 100, 100) },
                      { subject: 'Malware Samples', A: stats?.malwareSamples || 0, fullMark: Math.max(stats?.malwareSamples || 100, 100) },
                      { subject: 'Critical Threats', A: stats?.criticalThreats || 0, fullMark: Math.max(stats?.criticalThreats || 50, 50) },
                      { subject: 'High Threats', A: stats?.highThreats || 0, fullMark: Math.max(stats?.highThreats || 100, 100) },
                      { subject: 'IOCs', A: stats?.threatfoxIOCs || 0, fullMark: Math.max(stats?.threatfoxIOCs || 100, 100) },
                    ]}>
                      <PolarGrid stroke="#30363d" />
                      <PolarAngleAxis dataKey="subject" tick={{ fill: '#8b949e', fontSize: 11 }} />
                      <PolarRadiusAxis angle={30} domain={[0, 'auto']} tick={{ fill: '#8b949e', fontSize: 10 }} />
                      <Radar name="Threats" dataKey="A" stroke="#00bcd4" fill="#00bcd4" fillOpacity={0.4} />
                    </RadarChart>
                  </ResponsiveContainer>
                </div>
                <div className="space-y-4">
                  <div className="p-4 bg-[#161b22] border border-[#30363d] rounded-lg">
                    <h4 className="text-sm font-medium text-[#c9d1d9] mb-3 flex items-center gap-2">
                      <Shield className="h-4 w-4 text-cyan-400" />
                      Threat Landscape Summary
                    </h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between"><span className="text-[#8b949e]">Total Indicators</span><span className="text-cyan-400 font-bold">{formatNumber(stats?.totalThreats || 0)}</span></div>
                      <div className="flex justify-between"><span className="text-[#8b949e]">Active C2 Infrastructure</span><span className="text-red-400 font-bold">{formatNumber(stats?.activeC2Servers || 0)}</span></div>
                      <div className="flex justify-between"><span className="text-[#8b949e]">Malware Families</span><span className="text-purple-400 font-bold">{malwareDetails.length}</span></div>
                      <div className="flex justify-between"><span className="text-[#8b949e]">Data Sources</span><span className="text-green-400 font-bold">4</span></div>
                    </div>
                  </div>
                  <div className="p-4 bg-[#161b22] border border-[#30363d] rounded-lg">
                    <h4 className="text-sm font-medium text-[#c9d1d9] mb-3">Top Active Threats</h4>
                    <div className="space-y-2">
                      {malwareDetails.slice(0, 5).map((m, i) => (
                        <div key={m.name} className="flex items-center justify-between text-sm">
                          <span className="text-[#8b949e] flex items-center gap-2">
                            <span className="text-xs text-cyan-400">#{i + 1}</span>
                            {m.name}
                          </span>
                          <Badge variant="outline" className="text-xs">{m.count}</Badge>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Types Chart */}
        <TabsContent value="types" className="mt-6">
          <Card className="bg-gray-900/50 border-gray-800">
            <CardHeader>
              <CardTitle className="text-white">Threat Type Distribution</CardTitle>
              <CardDescription className="text-gray-400">Click on segments for detailed breakdown</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div style={{ height: '350px' }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={trendData?.typeDistribution || []}
                        cx="50%" cy="50%"
                        outerRadius={120} innerRadius={60}
                        dataKey="value"
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                        labelLine={{ stroke: '#9ca3af' }}
                        onClick={handlePieClick}
                      >
                        {(trendData?.typeDistribution || []).map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} cursor="pointer" />
                        ))}
                      </Pie>
                      <Tooltip content={<PieTooltip />} />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div style={{ height: '350px' }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={trendData?.typeDistribution || []} layout="vertical" onClick={handleChartClick}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                      <XAxis type="number" stroke="#9ca3af" />
                      <YAxis type="category" dataKey="name" stroke="#9ca3af" width={120} tick={{ fill: '#9ca3af', fontSize: 12 }} />
                      <Tooltip content={<BarTooltip />} />
                      <Bar dataKey="value" name="Count" cursor="pointer">
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
              <CardDescription className="text-gray-400">Click on segments for source details</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div style={{ height: '350px' }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={trendData?.sourceDistribution || []}
                        cx="50%" cy="50%"
                        outerRadius={120}
                        dataKey="value"
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                        labelLine={{ stroke: '#9ca3af' }}
                        onClick={handlePieClick}
                      >
                        {(trendData?.sourceDistribution || []).map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} cursor="pointer" />
                        ))}
                      </Pie>
                      <Tooltip content={<PieTooltip />} />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
                <div className="space-y-3">
                  {(trendData?.sourceDistribution || []).map((source) => (
                    <div key={source.name} className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg border border-gray-700 hover:border-gray-600 transition-colors cursor-pointer" onClick={() => toast.info(`${source.name}: ${source.value.toLocaleString()} indicators`)}>
                      <div className="flex items-center gap-3">
                        <div className="w-4 h-4 rounded-full" style={{ backgroundColor: source.color }} />
                        <span className="text-white font-medium">{source.name}</span>
                      </div>
                      <div className="text-right">
                        <span className="text-2xl font-bold text-cyan-400">{formatNumber(source.value)}</span>
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
              <CardDescription className="text-gray-400">Click on bars for severity breakdown</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div style={{ height: '350px' }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={trendData?.severityDistribution || []} onClick={handleChartClick}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                      <XAxis dataKey="name" stroke="#9ca3af" />
                      <YAxis stroke="#9ca3af" />
                      <Tooltip content={<BarTooltip />} />
                      <Bar dataKey="value" name="Count" cursor="pointer">
                        {(trendData?.severityDistribution || []).map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
                <div className="space-y-4">
                  {(trendData?.severityDistribution || []).map((severity) => (
                    <div key={severity.name} className="p-4 rounded-lg border cursor-pointer hover:scale-[1.02] transition-transform" style={{ borderColor: `${severity.color}50`, backgroundColor: `${severity.color}10` }} onClick={() => toast.info(`${severity.name}: ${severity.value.toLocaleString()} threats (${((severity.value / (stats?.totalThreats || 1)) * 100).toFixed(1)}%)`)}>
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-semibold" style={{ color: severity.color }}>{severity.name}</span>
                        <span className="text-2xl font-bold" style={{ color: severity.color }}>{formatNumber(severity.value)}</span>
                      </div>
                      <div className="w-full bg-gray-700 rounded-full h-2">
                        <div 
                          className="h-2 rounded-full transition-all duration-500"
                          style={{ backgroundColor: severity.color, width: `${Math.min((severity.value / (stats?.totalThreats || 1)) * 100, 100)}%` }}
                        />
                      </div>
                      <p className="text-xs text-gray-500 mt-1">{((severity.value / (stats?.totalThreats || 1)) * 100).toFixed(1)}% of total threats</p>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Live Feed */}
      <Card className="bg-gray-900/50 border-gray-800">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-white">
            <Zap className="h-5 w-5 text-yellow-400" />
            Live Threat Feed
          </CardTitle>
          <CardDescription className="text-gray-400">
            Real-time threat indicators from abuse.ch • Click entries for details
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[400px]">
            <div className="space-y-2">
              {liveFeed.map((entry, index) => (
                <div 
                  key={`${entry.id}-${index}`} 
                  className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg border border-gray-700 hover:border-cyan-500/50 hover:bg-gray-800 transition-all cursor-pointer"
                  onClick={() => setSelectedThreat(entry)}
                >
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <Badge variant="outline" className={`${getSeverityColor(entry.severity)} text-xs`}>
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
                  <div className="text-right ml-4 flex items-center gap-2">
                    <Badge variant="outline" className={getSeverityColor(entry.severity)}>
                      {entry.severity}
                    </Badge>
                    {entry.country && (
                      <span className="text-xs text-gray-500">{entry.country}</span>
                    )}
                    <Eye className="h-4 w-4 text-gray-500" />
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

      {/* Detailed Malware Analysis Section */}
      <Card className="bg-gray-900/50 border-gray-800">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-white">
            <Bug className="h-5 w-5 text-purple-400" />
            Malware Family Analysis
          </CardTitle>
          <CardDescription className="text-gray-400">
            Detailed breakdown of {malwareDetails.length} detected malware families • Click to expand
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[500px]">
            <div className="space-y-3">
              {malwareDetails.map((malware) => {
                const isExpanded = expandedFamilies.has(malware.name);
                return (
                  <div key={malware.name} className="border border-gray-700 rounded-lg overflow-hidden">
                    {/* Header - Always Visible */}
                    <div 
                      className="flex items-center justify-between p-4 bg-gray-800/50 hover:bg-gray-800 cursor-pointer transition-colors"
                      onClick={() => toggleFamilyExpand(malware.name)}
                    >
                      <div className="flex items-center gap-3">
                        <Bug className="h-5 w-5 text-purple-400" />
                        <div>
                          <h4 className="font-semibold text-white">{malware.name}</h4>
                          <div className="flex items-center gap-2 mt-1">
                            {malware.types.map(t => (
                              <Badge key={t} variant="outline" className="text-xs">{t}</Badge>
                            ))}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        <div className="text-right">
                          <span className="text-2xl font-bold text-cyan-400">{malware.count}</span>
                          <p className="text-xs text-gray-500">samples</p>
                        </div>
                        <div className="flex items-center gap-2">
                          {malware.trend === 'up' && <TrendingUp className="h-4 w-4 text-red-400" />}
                          {malware.trend === 'down' && <ChevronDown className="h-4 w-4 text-green-400" />}
                          {isExpanded ? <ChevronUp className="h-5 w-5 text-gray-400" /> : <ChevronDown className="h-5 w-5 text-gray-400" />}
                        </div>
                      </div>
                    </div>
                    
                    {/* Expanded Details */}
                    {isExpanded && (
                      <div className="p-4 bg-gray-900/50 border-t border-gray-700 space-y-4">
                        {/* Severity Breakdown */}
                        <div className="grid grid-cols-4 gap-2">
                          <div className="p-2 rounded bg-red-500/10 border border-red-500/30 text-center">
                            <p className="text-xs text-red-400">Critical</p>
                            <p className="text-lg font-bold text-red-400">{malware.severity.critical}</p>
                          </div>
                          <div className="p-2 rounded bg-orange-500/10 border border-orange-500/30 text-center">
                            <p className="text-xs text-orange-400">High</p>
                            <p className="text-lg font-bold text-orange-400">{malware.severity.high}</p>
                          </div>
                          <div className="p-2 rounded bg-yellow-500/10 border border-yellow-500/30 text-center">
                            <p className="text-xs text-yellow-400">Medium</p>
                            <p className="text-lg font-bold text-yellow-400">{malware.severity.medium}</p>
                          </div>
                          <div className="p-2 rounded bg-green-500/10 border border-green-500/30 text-center">
                            <p className="text-xs text-green-400">Low</p>
                            <p className="text-lg font-bold text-green-400">{malware.severity.low}</p>
                          </div>
                        </div>

                        {/* Info Grid */}
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <p className="text-xs text-gray-500 mb-1 flex items-center gap-1">
                              <Globe className="h-3 w-3" /> Sources
                            </p>
                            <div className="flex flex-wrap gap-1">
                              {malware.sources.map(s => (
                                <Badge key={s} variant="outline" className="text-xs bg-blue-500/10 text-blue-400 border-blue-500/30">{s}</Badge>
                              ))}
                            </div>
                          </div>
                          <div>
                            <p className="text-xs text-gray-500 mb-1 flex items-center gap-1">
                              <MapPin className="h-3 w-3" /> Countries
                            </p>
                            <div className="flex flex-wrap gap-1">
                              {malware.countries.slice(0, 10).map(c => (
                                <Badge key={c} variant="outline" className="text-xs">{c}</Badge>
                              ))}
                              {malware.countries.length > 10 && (
                                <Badge variant="outline" className="text-xs">+{malware.countries.length - 10}</Badge>
                              )}
                            </div>
                          </div>
                        </div>

                        {malware.firstSeen && (
                          <div className="flex items-center gap-4 text-xs text-gray-500">
                            <span className="flex items-center gap-1">
                              <Calendar className="h-3 w-3" /> First: {new Date(malware.firstSeen).toLocaleDateString()}
                            </span>
                            {malware.lastSeen && (
                              <span className="flex items-center gap-1">
                                <Calendar className="h-3 w-3" /> Last: {new Date(malware.lastSeen).toLocaleDateString()}
                              </span>
                            )}
                          </div>
                        )}

                        {/* Sample IOCs */}
                        <div>
                          <p className="text-xs text-gray-500 mb-2">Sample IOCs ({Math.min(5, malware.samples.length)} of {malware.samples.length})</p>
                          <div className="space-y-1">
                            {malware.samples.slice(0, 5).map((sample, idx) => (
                              <div key={idx} className="flex items-center justify-between p-2 bg-gray-800/50 rounded text-sm font-mono">
                                <code className="text-cyan-400 truncate flex-1">{sample.value}</code>
                                <Button 
                                  variant="ghost" 
                                  size="sm" 
                                  className="h-6 w-6 p-0 ml-2"
                                  onClick={(e) => { e.stopPropagation(); copyToClipboard(sample.value); }}
                                >
                                  <Copy className="h-3 w-3" />
                                </Button>
                              </div>
                            ))}
                          </div>
                        </div>

                        <Button 
                          variant="outline" 
                          size="sm" 
                          className="w-full"
                          onClick={(e) => { e.stopPropagation(); setSelectedMalware(malware); }}
                        >
                          <Eye className="h-4 w-4 mr-2" /> View All {malware.count} Samples
                        </Button>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>

      {/* Threat Detail Dialog */}
      <Dialog open={!!selectedThreat} onOpenChange={() => setSelectedThreat(null)}>
        <DialogContent className="bg-gray-900 border-gray-700 max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-white">
              <AlertTriangle className="h-5 w-5 text-yellow-400" />
              Threat Details
            </DialogTitle>
            <DialogDescription className="text-gray-400">
              Complete information about this threat indicator
            </DialogDescription>
          </DialogHeader>
          {selectedThreat && (
            <div className="space-y-4">
              {/* Value with Copy */}
              <div className="p-3 bg-gray-800 rounded-lg">
                <p className="text-xs text-gray-500 mb-1">Indicator Value</p>
                <div className="flex items-center justify-between">
                  <code className="text-cyan-400 font-mono text-sm break-all">{selectedThreat.value}</code>
                  <Button variant="ghost" size="sm" onClick={() => copyToClipboard(selectedThreat.value)}>
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
              </div>

              {/* Info Grid */}
              <div className="grid grid-cols-2 gap-4">
                <div className="p-3 bg-gray-800/50 rounded-lg">
                  <p className="text-xs text-gray-500 flex items-center gap-1"><Target className="h-3 w-3" /> Type</p>
                  <p className="text-white font-semibold">{selectedThreat.type.toUpperCase()}</p>
                </div>
                <div className="p-3 bg-gray-800/50 rounded-lg">
                  <p className="text-xs text-gray-500 flex items-center gap-1"><Globe className="h-3 w-3" /> Source</p>
                  <p className="text-white font-semibold">{selectedThreat.source}</p>
                </div>
                <div className="p-3 bg-gray-800/50 rounded-lg">
                  <p className="text-xs text-gray-500 flex items-center gap-1"><AlertTriangle className="h-3 w-3" /> Severity</p>
                  <Badge className={getSeverityColor(selectedThreat.severity)}>{selectedThreat.severity}</Badge>
                </div>
                {selectedThreat.malwareFamily && (
                  <div className="p-3 bg-gray-800/50 rounded-lg">
                    <p className="text-xs text-gray-500 flex items-center gap-1"><Bug className="h-3 w-3" /> Malware Family</p>
                    <p className="text-purple-400 font-semibold">{selectedThreat.malwareFamily}</p>
                  </div>
                )}
                {selectedThreat.country && (
                  <div className="p-3 bg-gray-800/50 rounded-lg">
                    <p className="text-xs text-gray-500 flex items-center gap-1"><MapPin className="h-3 w-3" /> Country</p>
                    <p className="text-white font-semibold">{selectedThreat.country}</p>
                  </div>
                )}
                {selectedThreat.port && (
                  <div className="p-3 bg-gray-800/50 rounded-lg">
                    <p className="text-xs text-gray-500 flex items-center gap-1"><Server className="h-3 w-3" /> Port</p>
                    <p className="text-white font-semibold">{selectedThreat.port}</p>
                  </div>
                )}
                {selectedThreat.timestamp && (
                  <div className="p-3 bg-gray-800/50 rounded-lg">
                    <p className="text-xs text-gray-500 flex items-center gap-1"><Calendar className="h-3 w-3" /> Timestamp</p>
                    <p className="text-white font-semibold">{new Date(selectedThreat.timestamp).toLocaleString()}</p>
                  </div>
                )}
                {selectedThreat.status && (
                  <div className="p-3 bg-gray-800/50 rounded-lg">
                    <p className="text-xs text-gray-500 flex items-center gap-1"><Activity className="h-3 w-3" /> Status</p>
                    <Badge className={selectedThreat.status === 'online' ? 'bg-red-500/20 text-red-400' : 'bg-gray-500/20 text-gray-400'}>
                      {selectedThreat.status}
                    </Badge>
                  </div>
                )}
              </div>

              {/* Tags */}
              {selectedThreat.tags?.length > 0 && (
                <div className="p-3 bg-gray-800/50 rounded-lg">
                  <p className="text-xs text-gray-500 mb-2 flex items-center gap-1"><Tag className="h-3 w-3" /> Tags</p>
                  <div className="flex flex-wrap gap-2">
                    {selectedThreat.tags.map((tag, idx) => (
                      <Badge key={idx} variant="outline" className="text-xs">{tag}</Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* Malware Detail Dialog */}
      <Dialog open={!!selectedMalware} onOpenChange={() => setSelectedMalware(null)}>
        <DialogContent className="bg-gray-900 border-gray-700 max-w-4xl max-h-[80vh]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-white">
              <Bug className="h-5 w-5 text-purple-400" />
              {selectedMalware?.name} - All Samples
            </DialogTitle>
            <DialogDescription className="text-gray-400">
              {selectedMalware?.count} total indicators detected
            </DialogDescription>
          </DialogHeader>
          {selectedMalware && (
            <ScrollArea className="h-[500px]">
              <div className="space-y-2">
                {selectedMalware.samples.map((sample, idx) => (
                  <div key={idx} className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg border border-gray-700">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <Badge variant="outline" className={`${getSeverityColor(sample.severity)} text-xs`}>
                          {sample.type.toUpperCase()}
                        </Badge>
                        <Badge variant="outline" className="text-xs bg-gray-800 border-gray-700">
                          {sample.source}
                        </Badge>
                        {sample.country && <span className="text-xs text-gray-500">{sample.country}</span>}
                      </div>
                      <code className="text-sm text-cyan-400 font-mono break-all">{sample.value}</code>
                    </div>
                    <Button variant="ghost" size="sm" onClick={() => copyToClipboard(sample.value)}>
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                ))}
              </div>
            </ScrollArea>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default RealTimeCharts;
