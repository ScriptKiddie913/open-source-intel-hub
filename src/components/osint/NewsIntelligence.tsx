// src/components/osint/NewsIntelligence.tsx
import { useState, useEffect } from 'react';
import {
  Newspaper,
  Search,
  Filter,
  TrendingUp,
  Globe,
  Calendar,
  Bookmark,
  Bell,
  RefreshCw,
  Download,
  ExternalLink,
  BarChart3,
  Loader2,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';
import {
  searchNews,
  getTrendingNews,
  calculateNewsStats,
  type NewsArticle,
  type NewsSearchParams,
  type NewsStats,
  saveSaveSearch,
  getSavedSearches,
  type SavedSearch,
} from '@/services/newsService';

export function NewsIntelligence() {
  const [query, setQuery] = useState('');
  const [articles, setArticles] = useState<NewsArticle[]>([]);
  const [loading, setLoading] = useState(false);
  const [stats, setStats] = useState<NewsStats | null>(null);
  const [savedSearches, setSavedSearches] = useState<SavedSearch[]>([]);
  
  const [filters, setFilters] = useState<NewsSearchParams>({
    query: '',
    category: undefined,
    country: undefined,
    language: 'en',
    sortBy:  'date',
  });

  const [activeTab, setActiveTab] = useState<'search' | 'trending' | 'saved'>('search');

  useEffect(() => {
    loadSavedSearches();
    loadTrendingNews();
  }, []);

  const loadSavedSearches = async () => {
    const searches = await getSavedSearches();
    setSavedSearches(searches);
  };

  const loadTrendingNews = async () => {
    setLoading(true);
    try {
      const trending = await getTrendingNews('cybersecurity');
      setArticles(trending. slice(0, 20));
      const newsStats = calculateNewsStats(trending);
      setStats(newsStats);
    } catch (error) {
      console.error('Failed to load trending news:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = async () => {
    if (!query. trim()) {
      toast.error('Please enter a search query');
      return;
    }

    setLoading(true);
    setArticles([]);
    setStats(null);

    try {
      const params:  NewsSearchParams = {
        ... filters,
        query:  query.trim(),
      };

      const results = await searchNews(params);
      setArticles(results);

      if (results.length > 0) {
        const newsStats = calculateNewsStats(results);
        setStats(newsStats);
        toast.success(`Found ${results.length} articles`);
      } else {
        toast.info('No articles found for this query');
      }
    } catch (error) {
      console.error('Search error:', error);
      toast.error('Failed to search news');
    } finally {
      setLoading(false);
    }
  };

  const handleSaveSearch = async () => {
    if (!query.trim()) return;

    try {
      await saveSaveSearch({
        name: query,
        params: { ...filters, query },
        alertEnabled: false,
      });
      toast.success('Search saved! ');
      loadSavedSearches();
    } catch (error) {
      toast.error('Failed to save search');
    }
  };

  const handleLoadSavedSearch = async (search: SavedSearch) => {
    setQuery(search.params.query);
    setFilters(search.params);
    setActiveTab('search');
    
    setLoading(true);
    try {
      const results = await searchNews(search.params);
      setArticles(results);
      const newsStats = calculateNewsStats(results);
      setStats(newsStats);
    } catch (error) {
      toast.error('Failed to load saved search');
    } finally {
      setLoading(false);
    }
  };

  const exportResults = () => {
    const csv = [
      ['Title', 'Source', 'Date', 'URL', 'Category', 'Sentiment']. join(','),
      ...articles. map(a => [
        `"${a.title. replace(/"/g, '""')}"`,
        a.source.name,
        new Date(a.publishedAt).toLocaleDateString(),
        a.url,
        a.category,
        a.sentiment || 'neutral',
      ]. join(',')),
    ].join('\n');

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL. createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `news-intel-${Date.now()}.csv`;
    a.click();
    toast.success('Exported to CSV');
  };

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Newspaper className="h-8 w-8 text-primary" />
            News Intelligence
          </h1>
          <p className="text-muted-foreground mt-2">
            Real-time news monitoring from global sources
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={loadTrendingNews}
          disabled={loading}
        >
          <RefreshCw className={cn('h-4 w-4 mr-2', loading && 'animate-spin')} />
          Refresh
        </Button>
      </div>

      {/* Search Bar */}
      <Card className="border-primary/30">
        <CardContent className="pt-6">
          <div className="flex gap-3">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                placeholder="Search news by keyword, name, place, or topic..."
                className="pl-10"
              />
            </div>
            <Button onClick={handleSearch} disabled={loading}>
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                'Search'
              )}
            </Button>
            <Button variant="outline" onClick={handleSaveSearch}>
              <Bookmark className="h-4 w-4" />
            </Button>
          </div>

          {/* Filters */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">
            <Select
              value={filters.category}
              onValueChange={(v) => setFilters({ ...filters, category: v as any })}
            >
              <SelectTrigger>
                <SelectValue placeholder="Category" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="cybersecurity">Cybersecurity</SelectItem>
                <SelectItem value="crime">Crime</SelectItem>
                <SelectItem value="technology">Technology</SelectItem>
                <SelectItem value="business">Business</SelectItem>
                <SelectItem value="politics">Politics</SelectItem>
                <SelectItem value="general">General</SelectItem>
              </SelectContent>
            </Select>

            <Select
              value={filters.language}
              onValueChange={(v) => setFilters({ ...filters, language: v })}
            >
              <SelectTrigger>
                <SelectValue placeholder="Language" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="en">English</SelectItem>
                <SelectItem value="es">Spanish</SelectItem>
                <SelectItem value="fr">French</SelectItem>
                <SelectItem value="de">German</SelectItem>
                <SelectItem value="ru">Russian</SelectItem>
                <SelectItem value="zh">Chinese</SelectItem>
              </SelectContent>
            </Select>

            <Select
              value={filters.sortBy}
              onValueChange={(v) => setFilters({ ... filters, sortBy: v as any })}
            >
              <SelectTrigger>
                <SelectValue placeholder="Sort By" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="date">Latest First</SelectItem>
                <SelectItem value="relevance">Most Relevant</SelectItem>
                <SelectItem value="popularity">Most Popular</SelectItem>
              </SelectContent>
            </Select>

            {articles.length > 0 && (
              <Button variant="outline" onClick={exportResults} className="w-full">
                <Download className="h-4 w-4 mr-2" />
                Export CSV
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Statistics */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card>
            <CardContent className="pt-6">
              <div className="text-center">
                <div className="text-3xl font-bold text-primary">{stats.totalArticles}</div>
                <div className="text-sm text-muted-foreground mt-1">Total Articles</div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="text-center">
                <div className="text-3xl font-bold text-cyan-500">{stats.sources}</div>
                <div className="text-sm text-muted-foreground mt-1">News Sources</div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="text-center">
                <div className="flex items-center justify-center gap-2">
                  <span className="text-2xl">😊</span>
                  <span className="text-xl font-bold">{stats.sentiment. positive}</span>
                </div>
                <div className="text-sm text-muted-foreground mt-1">Positive</div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="text-center">
                <div className="flex items-center justify-center gap-2">
                  <span className="text-2xl">😟</span>
                  <span className="text-xl font-bold text-red-500">{stats. sentiment.negative}</span>
                </div>
                <div className="text-sm text-muted-foreground mt-1">Negative</div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as any)}>
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="search">
            <Search className="h-4 w-4 mr-2" />
            Search Results
          </TabsTrigger>
          <TabsTrigger value="trending">
            <TrendingUp className="h-4 w-4 mr-2" />
            Trending
          </TabsTrigger>
          <TabsTrigger value="saved">
            <Bookmark className="h-4 w-4 mr-2" />
            Saved Searches ({savedSearches.length})
          </TabsTrigger>
        </TabsList>

        <TabsContent value="search" className="space-y-4 mt-6">
          {loading && (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
            </div>
          )}

          {! loading && articles.length === 0 && (
            <Card className="border-dashed">
              <CardContent className="pt-12 pb-12 text-center">
                <Newspaper className="h-16 w-16 mx-auto text-muted-foreground opacity-50 mb-4" />
                <p className="text-muted-foreground">
                  Enter a search query to find relevant news articles
                </p>
              </CardContent>
            </Card>
          )}

          {! loading && articles.map((article) => (
            <NewsArticleCard key={article.id} article={article} />
          ))}
        </TabsContent>

        <TabsContent value="trending" className="space-y-4 mt-6">
          {articles.map((article) => (
            <NewsArticleCard key={article. id} article={article} />
          ))}
        </TabsContent>

        <TabsContent value="saved" className="space-y-4 mt-6">
          {savedSearches.length === 0 && (
            <Card className="border-dashed">
              <CardContent className="pt-12 pb-12 text-center">
                <Bookmark className="h-16 w-16 mx-auto text-muted-foreground opacity-50 mb-4" />
                <p className="text-muted-foreground">
                  No saved searches yet. Save a search to monitor it over time. 
                </p>
              </CardContent>
            </Card>
          )}

          {savedSearches.map((search) => (
            <Card
              key={search.id}
              className="cursor-pointer hover:border-primary/50 transition-colors"
              onClick={() => handleLoadSavedSearch(search)}
            >
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="font-semibold">{search.name}</h3>
                    <p className="text-sm text-muted-foreground mt-1">
                      Category: {search.params.category || 'All'} • 
                      Language: {search. params.language || 'en'}
                    </p>
                  </div>
                  <Button variant="outline" size="sm">
                    <Search className="h-4 w-4 mr-2" />
                    Run Search
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </TabsContent>
      </Tabs>
    </div>
  );
}

/* ============================================================================
   NEWS ARTICLE CARD COMPONENT
============================================================================ */

function NewsArticleCard({ article }:  { article: NewsArticle }) {
  const getSentimentColor = (sentiment?:  string) => {
    switch (sentiment) {
      case 'positive':  return 'text-green-500';
      case 'negative':  return 'text-red-500';
      default: return 'text-muted-foreground';
    }
  };

  const getCategoryColor = (category:  string) => {
    const colors:  Record<string, string> = {
      cybersecurity: 'bg-red-500/10 text-red-500 border-red-500/30',
      crime: 'bg-orange-500/10 text-orange-500 border-orange-500/30',
      technology: 'bg-blue-500/10 text-blue-500 border-blue-500/30',
      business: 'bg-green-500/10 text-green-500 border-green-500/30',
      politics: 'bg-purple-500/10 text-purple-500 border-purple-500/30',
      general: 'bg-gray-500/10 text-gray-500 border-gray-500/30',
    };
    return colors[category] || colors.general;
  };

  return (
    <Card className="hover:border-primary/50 transition-all">
      <CardContent className="pt-6">
        <div className="flex gap-4">
          {article.imageUrl && (
            <img
              src={article.imageUrl}
              alt={article.title}
              className="w-32 h-32 object-cover rounded-lg flex-shrink-0"
              onError={(e) => {
                (e.target as HTMLImageElement).style.display = 'none';
              }}
            />
          )}

          <div className="flex-1 min-w-0">
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1">
                <h3 className="font-semibold text-lg line-clamp-2 hover:text-primary cursor-pointer">
                  <a href={article.url} target="_blank" rel="noopener noreferrer">
                    {article.title}
                  </a>
                </h3>
                <p className="text-sm text-muted-foreground mt-2 line-clamp-2">
                  {article.description}
                </p>
              </div>

              <div className="flex flex-col items-end gap-2">
                <Badge variant="outline" className={getCategoryColor(article.category)}>
                  {article.category}
                </Badge>
                <div className={cn('text-xs font-semibold', getSentimentColor(article.sentiment))}>
                  {article.sentiment === 'positive' && '😊 Positive'}
                  {article. sentiment === 'negative' && '😟 Negative'}
                  {article.sentiment === 'neutral' && '😐 Neutral'}
                </div>
              </div>
            </div>

            <div className="flex items-center gap-4 mt-4 text-sm text-muted-foreground">
              <div className="flex items-center gap-1">
                <Globe className="h-3 w-3" />
                {article. source.name}
              </div>
              <div className="flex items-center gap-1">
                <Calendar className="h-3 w-3" />
                {new Date(article.publishedAt).toLocaleDateString()}
              </div>
              {article.relevanceScore > 0 && (
                <div className="flex items-center gap-1">
                  <BarChart3 className="h-3 w-3" />
                  {article.relevanceScore.toFixed(0)}% relevant
                </div>
              )}
            </div>

            {article.keywords. length > 0 && (
              <div className="flex flex-wrap gap-2 mt-3">
                {article.keywords. map((keyword) => (
                  <Badge key={keyword} variant="secondary" className="text-xs">
                    {keyword}
                  </Badge>
                ))}
              </div>
            )}

            <div className="mt-4">
              <Button variant="outline" size="sm" asChild>
                <a href={article.url} target="_blank" rel="noopener noreferrer">
                  <ExternalLink className="h-3 w-3 mr-2" />
                  Read Full Article
                </a>
              </Button>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
