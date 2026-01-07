import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Input } from '@/components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { toast } from 'sonner';
import {
  History,
  Search,
  Trash2,
  Clock,
  Globe,
  Shield,
  Mail,
  Hash,
  AlertTriangle,
  RefreshCw,
  Loader2,
  ExternalLink,
  Filter,
  Workflow,
  Network,
  Eye,
  Bug,
  BarChart3,
  MessageSquare,
  Bitcoin,
} from 'lucide-react';
import {
  getSearchHistory,
  deleteSearchHistory,
  clearAllSearchHistory,
  type SearchHistoryItem,
} from '@/services/userDataService';
import {
  getEnhancedSearchHistory,
  getHistoryByCategory,
  type EnhancedSearchHistory,
  type SearchCategory,
} from '@/services/searchHistoryService';
import { cn } from '@/lib/utils';
import { useNavigate } from 'react-router-dom';

const SEARCH_TYPE_CONFIG: Record<string, { icon: any; label: string; route: string }> = {
  domain: { icon: Globe, label: 'Domain', route: '/dashboard/domain' },
  ip: { icon: Shield, label: 'IP', route: '/dashboard/ip' },
  breach: { icon: Mail, label: 'Breach', route: '/dashboard/breach' },
  cve: { icon: AlertTriangle, label: 'CVE', route: '/dashboard/cve' },
  darkweb: { icon: Hash, label: 'Dark Web', route: '/dashboard/darkweb' },
  username: { icon: Hash, label: 'Username', route: '/dashboard/username' },
  threat_intel: { icon: Shield, label: 'Threat Intel', route: '/dashboard/threat-intel' },
  malware_pipeline: { icon: Workflow, label: 'Pipeline', route: '/dashboard/pipeline' },
  stealthmole: { icon: Eye, label: 'StealthMole', route: '/dashboard/stealthmole' },
  'crypto-abuse': { icon: Bitcoin, label: 'Crypto Abuse', route: '/dashboard/crypto-abuse' },
  graph: { icon: Network, label: 'Graph', route: '/dashboard/graph' },
  malware: { icon: Bug, label: 'Malware', route: '/dashboard/malware' },
};

const CATEGORY_CONFIG: Record<SearchCategory, { icon: any; label: string; color: string }> = {
  pipeline: { icon: Workflow, label: 'Pipeline', color: 'bg-orange-500/20 text-orange-400 border-orange-500/50' },
  graph: { icon: Network, label: 'Graph', color: 'bg-purple-500/20 text-purple-400 border-purple-500/50' },
  stealthmole: { icon: Eye, label: 'StealthMole', color: 'bg-blue-500/20 text-blue-400 border-blue-500/50' },
  'crypto-abuse': { icon: Bitcoin, label: 'Crypto Abuse', color: 'bg-orange-600/20 text-orange-500 border-orange-600/50' },
  darkweb: { icon: Hash, label: 'Dark Web', color: 'bg-red-500/20 text-red-400 border-red-500/50' },
  malware: { icon: Bug, label: 'Malware', color: 'bg-green-500/20 text-green-400 border-green-500/50' },
  threat_intel: { icon: Shield, label: 'Threat Intel', color: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/50' },
  ransomware: { icon: AlertTriangle, label: 'Ransomware', color: 'bg-red-600/20 text-red-500 border-red-600/50' },
  ip: { icon: Globe, label: 'IP', color: 'bg-indigo-500/20 text-indigo-400 border-indigo-500/50' },
  domain: { icon: Globe, label: 'Domain', color: 'bg-teal-500/20 text-teal-400 border-teal-500/50' },
  breach: { icon: Mail, label: 'Breach', color: 'bg-pink-500/20 text-pink-400 border-pink-500/50' },
  cve: { icon: AlertTriangle, label: 'CVE', color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50' },
  telegram: { icon: Hash, label: 'Telegram', color: 'bg-sky-500/20 text-sky-400 border-sky-500/50' },
  general: { icon: Search, label: 'General', color: 'bg-gray-500/20 text-gray-400 border-gray-500/50' },
};

export function SearchHistoryPage() {
  const navigate = useNavigate();
  const [history, setHistory] = useState<SearchHistoryItem[]>([]);
  const [enhancedHistory, setEnhancedHistory] = useState<EnhancedSearchHistory[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchFilter, setSearchFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState<string | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<SearchCategory | 'all'>('all');
  const [activeTab, setActiveTab] = useState<'all' | 'pipeline' | 'graph' | 'stealthmole' | 'crypto-abuse' | 'other'>('all');

  useEffect(() => {
    loadHistory();
  }, []);

  useEffect(() => {
    loadEnhancedHistory();
  }, [categoryFilter]);

  const loadHistory = async () => {
    setLoading(true);
    try {
      const data = await getSearchHistory(100);
      setHistory(data);
    } catch (error) {
      console.error('Error loading history:', error);
      toast.error('Failed to load search history');
    } finally {
      setLoading(false);
    }
  };

  const loadEnhancedHistory = async () => {
    try {
      if (categoryFilter === 'all') {
        const data = await getEnhancedSearchHistory({ limit: 100 });
        setEnhancedHistory(data);
      } else {
        const byCategory = await getHistoryByCategory();
        setEnhancedHistory(byCategory[categoryFilter] || []);
      }
    } catch (error) {
      console.error('Error loading enhanced history:', error);
    }
  };

  const handleDelete = async (id: string) => {
    const success = await deleteSearchHistory(id);
    if (success) {
      setHistory(prev => prev.filter(h => h.id !== id));
      toast.success('Search removed from history');
    } else {
      toast.error('Failed to delete');
    }
  };

  const handleClearAll = async () => {
    if (!confirm('Are you sure you want to clear all search history?')) return;
    
    const success = await clearAllSearchHistory();
    if (success) {
      setHistory([]);
      toast.success('History cleared');
    } else {
      toast.error('Failed to clear history');
    }
  };

  const handleRerun = (item: SearchHistoryItem | EnhancedSearchHistory) => {
    const searchType = 'search_type' in item ? item.search_type : (item as any).searchType;
    const config = SEARCH_TYPE_CONFIG[searchType];
    if (config) {
      // Navigate to the search page with query
      navigate(`${config.route}?q=${encodeURIComponent(item.query)}`);
    }
  };

  const filteredHistory = history.filter(item => {
    const matchesSearch = !searchFilter || 
      item.query.toLowerCase().includes(searchFilter.toLowerCase());
    const matchesType = !typeFilter || item.search_type === typeFilter;
    return matchesSearch && matchesType;
  });

  const filteredEnhancedHistory = enhancedHistory.filter(item => {
    const matchesSearch = !searchFilter || 
      item.query.toLowerCase().includes(searchFilter.toLowerCase());
    return matchesSearch;
  });

  const groupedByDate = filteredHistory.reduce((acc, item) => {
    const date = new Date(item.created_at).toLocaleDateString();
    if (!acc[date]) acc[date] = [];
    acc[date].push(item);
    return acc;
  }, {} as Record<string, SearchHistoryItem[]>);

  const groupedEnhancedByDate = filteredEnhancedHistory.reduce((acc, item) => {
    const date = new Date(item.created_at).toLocaleDateString();
    if (!acc[date]) acc[date] = [];
    acc[date].push(item);
    return acc;
  }, {} as Record<string, EnhancedSearchHistory[]>);

  const uniqueTypes = [...new Set(history.map(h => h.search_type))];

  // Count by category for stats
  const categoryCounts = enhancedHistory.reduce((acc, item) => {
    acc[item.category] = (acc[item.category] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <History className="h-6 w-6 text-primary" />
            Search History
          </h1>
          <p className="text-muted-foreground">Your previous OSINT searches organized by category</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => { loadHistory(); loadEnhancedHistory(); }}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
          {history.length > 0 && (
            <Button variant="destructive" size="sm" onClick={handleClearAll}>
              <Trash2 className="h-4 w-4 mr-2" />
              Clear All
            </Button>
          )}
        </div>
      </div>

      {/* Category Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
        {Object.entries(CATEGORY_CONFIG).map(([category, config]) => {
          const Icon = config.icon;
          const count = categoryCounts[category] || 0;
          return (
            <Card 
              key={category}
              className={cn(
                "bg-slate-900/50 border-slate-800 cursor-pointer transition-all hover:border-primary/50",
                categoryFilter === category && "border-primary ring-1 ring-primary"
              )}
              onClick={() => setCategoryFilter(categoryFilter === category ? 'all' : category as SearchCategory)}
            >
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Icon className="h-4 w-4 text-primary" />
                    <span className="text-sm font-medium">{config.label}</span>
                  </div>
                  <Badge variant="outline" className={config.color}>
                    {count}
                  </Badge>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Filters */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardContent className="p-4">
          <div className="flex flex-wrap items-center gap-4">
            <div className="flex-1 min-w-[200px]">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Filter searches..."
                  value={searchFilter}
                  onChange={(e) => setSearchFilter(e.target.value)}
                  className="pl-10 bg-slate-800 border-slate-700"
                />
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm text-muted-foreground">
                {categoryFilter === 'all' ? 'All Categories' : CATEGORY_CONFIG[categoryFilter]?.label}
              </span>
              {categoryFilter !== 'all' && (
                <Button variant="ghost" size="sm" onClick={() => setCategoryFilter('all')}>
                  Clear
                </Button>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Tabbed History View */}
      <Tabs defaultValue="enhanced" className="w-full">
        <TabsList className="bg-slate-900/50 border border-slate-800">
          <TabsTrigger value="enhanced" className="data-[state=active]:bg-primary">
            <BarChart3 className="h-4 w-4 mr-2" />
            Categorized ({filteredEnhancedHistory.length})
          </TabsTrigger>
          <TabsTrigger value="legacy" className="data-[state=active]:bg-primary">
            <History className="h-4 w-4 mr-2" />
            All History ({filteredHistory.length})
          </TabsTrigger>
        </TabsList>

        {/* Enhanced Categorized History */}
        <TabsContent value="enhanced">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <MessageSquare className="h-5 w-5 text-primary" />
                Categorized Search Sessions
              </CardTitle>
              <CardDescription>
                Searches organized by category with full session context
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                {filteredEnhancedHistory.length === 0 ? (
                  <div className="text-center py-12 text-muted-foreground">
                    <History className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No categorized searches yet</p>
                    <p className="text-sm">Run pipeline or graph searches to see them here</p>
                  </div>
                ) : (
                  <div className="space-y-6">
                    {Object.entries(groupedEnhancedByDate).map(([date, items]) => (
                      <div key={date}>
                        <h3 className="text-sm font-medium text-muted-foreground mb-3 sticky top-0 bg-slate-900/50 py-2">
                          {date}
                        </h3>
                        <div className="space-y-2">
                          {items.map(item => {
                            const catConfig = CATEGORY_CONFIG[item.category];
                            const CatIcon = catConfig?.icon || Search;
                            return (
                              <div
                                key={item.id}
                                className="flex items-center justify-between p-4 rounded-lg bg-slate-800/50 border border-slate-700 hover:border-primary/30 transition-all group"
                              >
                                <div className="flex items-center gap-3 flex-1">
                                  <div className="p-2 rounded-lg bg-primary/10">
                                    <CatIcon className="h-5 w-5 text-primary" />
                                  </div>
                                  <div className="flex-1">
                                    <p className="font-medium font-mono">{item.query}</p>
                                    <div className="flex items-center gap-2 mt-1 flex-wrap">
                                      <Badge variant="outline" className={catConfig?.color || ''}>
                                        {catConfig?.label || item.category}
                                      </Badge>
                                      <Badge variant="outline" className="text-xs">
                                        {item.search_type}
                                      </Badge>
                                      {item.results_count > 0 && (
                                        <span className="text-xs text-muted-foreground">
                                          {item.results_count} results
                                        </span>
                                      )}
                                      <span className="text-xs text-muted-foreground flex items-center gap-1">
                                        <Clock className="h-3 w-3" />
                                        {new Date(item.created_at).toLocaleTimeString()}
                                      </span>
                                      {item.session_id && (
                                        <Badge variant="outline" className="text-xs bg-green-500/20 text-green-400 border-green-500/50">
                                          <MessageSquare className="h-3 w-3 mr-1" />
                                          Has Chat
                                        </Badge>
                                      )}
                                    </div>
                                    {item.metadata && (
                                      <div className="flex items-center gap-2 mt-2 text-xs text-muted-foreground">
                                        {item.metadata.aptGroupsFound !== undefined && (
                                          <span>APT Groups: {item.metadata.aptGroupsFound}</span>
                                        )}
                                        {item.metadata.indicatorsFound !== undefined && (
                                          <span>Indicators: {item.metadata.indicatorsFound}</span>
                                        )}
                                        {item.metadata.campaignsFound !== undefined && (
                                          <span>Campaigns: {item.metadata.campaignsFound}</span>
                                        )}
                                      </div>
                                    )}
                                  </div>
                                </div>
                                <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => handleRerun(item)}
                                  >
                                    <ExternalLink className="h-4 w-4" />
                                  </Button>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Legacy History */}
        <TabsContent value="legacy">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle>All Searches</CardTitle>
              <CardDescription>
                {filteredHistory.length} search{filteredHistory.length !== 1 ? 'es' : ''} found
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                {filteredHistory.length === 0 ? (
                  <div className="text-center py-12 text-muted-foreground">
                    <History className="h-12 w-12 mx-auto mb-4 opacity-50" />
                <p>No search history yet</p>
                <p className="text-sm">Your searches will appear here</p>
              </div>
            ) : (
              <div className="space-y-6">
                {Object.entries(groupedByDate).map(([date, items]) => (
                  <div key={date}>
                    <h3 className="text-sm font-medium text-muted-foreground mb-3 sticky top-0 bg-slate-900/50 py-2">
                      {date}
                    </h3>
                    <div className="space-y-2">
                      {items.map(item => {
                        const config = SEARCH_TYPE_CONFIG[item.search_type] || { 
                          icon: Search, 
                          label: item.search_type 
                        };
                        const Icon = config.icon;
                        return (
                          <div
                            key={item.id}
                            className="flex items-center justify-between p-3 rounded-lg bg-slate-800/50 border border-slate-700 hover:border-primary/30 transition-all group"
                          >
                            <div className="flex items-center gap-3">
                              <div className="p-2 rounded-lg bg-primary/10">
                                <Icon className="h-4 w-4 text-primary" />
                              </div>
                              <div>
                                <p className="font-medium font-mono">{item.query}</p>
                                <div className="flex items-center gap-2 mt-1">
                                  <Badge variant="outline" className="text-xs">
                                    {config.label}
                                  </Badge>
                                  {item.results_count > 0 && (
                                    <span className="text-xs text-muted-foreground">
                                      {item.results_count} results
                                    </span>
                                  )}
                                  <span className="text-xs text-muted-foreground flex items-center gap-1">
                                    <Clock className="h-3 w-3" />
                                    {new Date(item.created_at).toLocaleTimeString()}
                                  </span>
                                </div>
                              </div>
                            </div>
                            <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => handleRerun(item)}
                              >
                                <ExternalLink className="h-4 w-4" />
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => handleDelete(item.id)}
                                className="text-red-400 hover:text-red-300"
                              >
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            )}
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
