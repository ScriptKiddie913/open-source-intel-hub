import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Input } from '@/components/ui/input';
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
} from 'lucide-react';
import {
  getSearchHistory,
  deleteSearchHistory,
  clearAllSearchHistory,
  type SearchHistoryItem,
} from '@/services/userDataService';
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
};

export function SearchHistoryPage() {
  const navigate = useNavigate();
  const [history, setHistory] = useState<SearchHistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchFilter, setSearchFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState<string | null>(null);

  useEffect(() => {
    loadHistory();
  }, []);

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

  const handleRerun = (item: SearchHistoryItem) => {
    const config = SEARCH_TYPE_CONFIG[item.search_type];
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

  const groupedByDate = filteredHistory.reduce((acc, item) => {
    const date = new Date(item.created_at).toLocaleDateString();
    if (!acc[date]) acc[date] = [];
    acc[date].push(item);
    return acc;
  }, {} as Record<string, SearchHistoryItem[]>);

  const uniqueTypes = [...new Set(history.map(h => h.search_type))];

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
          <p className="text-muted-foreground">Your previous OSINT searches</p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={loadHistory}>
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
            <div className="flex items-center gap-2 flex-wrap">
              <Button
                variant={typeFilter === null ? "default" : "outline"}
                size="sm"
                onClick={() => setTypeFilter(null)}
              >
                All
              </Button>
              {uniqueTypes.map(type => {
                const config = SEARCH_TYPE_CONFIG[type];
                const Icon = config?.icon || Search;
                return (
                  <Button
                    key={type}
                    variant={typeFilter === type ? "default" : "outline"}
                    size="sm"
                    onClick={() => setTypeFilter(type)}
                  >
                    <Icon className="h-3 w-3 mr-1" />
                    {config?.label || type}
                  </Button>
                );
              })}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* History List */}
      <Card className="bg-slate-900/50 border-slate-800">
        <CardHeader>
          <CardTitle>Recent Searches</CardTitle>
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
    </div>
  );
}
