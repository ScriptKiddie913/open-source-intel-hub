import { useState, useEffect } from "react";
import { 
  Newspaper, 
  Search, 
  Filter, 
  Clock, 
  ExternalLink, 
  TrendingUp, 
  Globe, 
  Eye, 
  RefreshCw,
  Bookmark,
  Share2,
  Calendar,
  Tag,
  AlertTriangle
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import { fetchNewsIntelligence, NewsArticle, NewsAnalysis, getNewsTopics } from "@/services/newsIntelService";

interface SavedSearch {
  id: string;
  query: string;
  filters: {
    timeframe: string;
    sources: string[];
    category: string;
  };
  timestamp: Date;
  alertEnabled: boolean;
}

export function NewsIntelligenceScanner() {
  const [activeTab, setActiveTab] = useState("search");
  const [loading, setLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [articles, setArticles] = useState<NewsArticle[]>([]);
  const [analysis, setAnalysis] = useState<NewsAnalysis | null>(null);
  const [savedSearches, setSavedSearches] = useState<SavedSearch[]>([]);
  const [newsTopics, setNewsTopics] = useState<string[]>([]);

  // Filters
  const [selectedTimeframe, setSelectedTimeframe] = useState("7d");
  const [selectedSources, setSelectedSources] = useState<string[]>([]);
  const [selectedCategory, setSelectedCategory] = useState("all");

  // Custom analysis
  const [analysisQuery, setAnalysisQuery] = useState("");
  const [analysisLoading, setAnalysisLoading] = useState(false);

  useEffect(() => {
    loadNewsTopics();
  }, []);

  const loadNewsTopics = async () => {
    try {
      const topics = await getNewsTopics();
      setNewsTopics(topics);
    } catch (error) {
      console.error("Failed to load news topics:", error);
    }
  };

  const handleSearch = async () => {
    if (!searchQuery.trim()) return;

    setLoading(true);
    try {
      const results = await fetchNewsIntelligence({
        query: searchQuery,
        timeframe: selectedTimeframe,
        sources: selectedSources,
        category: selectedCategory === 'all' ? undefined : selectedCategory
      });

      setArticles(results.articles);
      setAnalysis(results.analysis);
    } catch (error) {
      console.error("News search failed:", error);
    } finally {
      setLoading(false);
    }
  };

  const handleCustomAnalysis = async () => {
    if (!analysisQuery.trim()) return;

    setAnalysisLoading(true);
    try {
      const results = await fetchNewsIntelligence({
        query: analysisQuery,
        timeframe: selectedTimeframe,
        analysis: true
      });

      setAnalysis(results.analysis);
    } catch (error) {
      console.error("Analysis failed:", error);
    } finally {
      setAnalysisLoading(false);
    }
  };

  const saveSearch = () => {
    const savedSearch: SavedSearch = {
      id: Date.now().toString(),
      query: searchQuery,
      filters: {
        timeframe: selectedTimeframe,
        sources: selectedSources,
        category: selectedCategory
      },
      timestamp: new Date(),
      alertEnabled: false
    };

    setSavedSearches(prev => [savedSearch, ...prev]);
  };

  const formatTimeAgo = (date: Date) => {
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days}d ago`;
    if (hours > 0) return `${hours}h ago`;
    return 'Just now';
  };

  const getRelevanceColor = (score: number) => {
    if (score >= 0.8) return 'text-green-500';
    if (score >= 0.6) return 'text-yellow-500';
    if (score >= 0.4) return 'text-orange-500';
    return 'text-red-500';
  };

  const getSentimentColor = (sentiment: string) => {
    switch (sentiment) {
      case 'positive': return 'text-green-500 bg-green-500/10';
      case 'negative': return 'text-red-500 bg-red-500/10';
      case 'neutral': return 'text-gray-500 bg-gray-500/10';
      default: return 'text-gray-500 bg-gray-500/10';
    }
  };

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground flex items-center gap-2">
            <Newspaper className="h-8 w-8 text-primary" />
            News Intelligence Scanner
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Real-time news monitoring, analysis, and intelligence gathering
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={loadNewsTopics}>
            <RefreshCw className="h-4 w-4" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-gradient-to-br from-blue-500/10 to-blue-600/5 border-blue-500/20">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-500/10">
                <Newspaper className="h-5 w-5 text-blue-500" />
              </div>
              <div>
                <p className="text-2xl font-bold text-foreground">{articles.length}</p>
                <p className="text-sm text-muted-foreground">Articles Found</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-green-500/10 to-green-600/5 border-green-500/20">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-green-500/10">
                <TrendingUp className="h-5 w-5 text-green-500" />
              </div>
              <div>
                <p className="text-2xl font-bold text-foreground">
                  {analysis?.sentiment === 'positive' ? '↗' : analysis?.sentiment === 'negative' ? '↘' : '→'}
                </p>
                <p className="text-sm text-muted-foreground">Trend Direction</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-purple-500/10 to-purple-600/5 border-purple-500/20">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-500/10">
                <Eye className="h-5 w-5 text-purple-500" />
              </div>
              <div>
                <p className="text-2xl font-bold text-foreground">{savedSearches.length}</p>
                <p className="text-sm text-muted-foreground">Saved Searches</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-orange-500/10 to-orange-600/5 border-orange-500/20">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-orange-500/10">
                <AlertTriangle className="h-5 w-5 text-orange-500" />
              </div>
              <div>
                <p className="text-2xl font-bold text-foreground">
                  {analysis?.riskLevel === 'high' ? 'HIGH' : analysis?.riskLevel === 'medium' ? 'MED' : 'LOW'}
                </p>
                <p className="text-sm text-muted-foreground">Risk Level</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Content */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="search" className="flex items-center gap-2">
            <Search className="h-4 w-4" />
            Search & Monitor
          </TabsTrigger>
          <TabsTrigger value="analysis" className="flex items-center gap-2">
            <TrendingUp className="h-4 w-4" />
            Analysis
          </TabsTrigger>
          <TabsTrigger value="topics" className="flex items-center gap-2">
            <Tag className="h-4 w-4" />
            Trending Topics
          </TabsTrigger>
          <TabsTrigger value="saved" className="flex items-center gap-2">
            <Bookmark className="h-4 w-4" />
            Saved Searches
          </TabsTrigger>
        </TabsList>

        {/* Search & Monitor Tab */}
        <TabsContent value="search" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Search className="h-5 w-5" />
                News Intelligence Search
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-4">
                <Input
                  placeholder="Enter keywords, entities, or topics to monitor..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="flex-1"
                  onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                />
                <Button onClick={handleSearch} disabled={loading || !searchQuery.trim()}>
                  {loading ? (
                    <RefreshCw className="h-4 w-4 animate-spin" />
                  ) : (
                    <Search className="h-4 w-4" />
                  )}
                  Search
                </Button>
              </div>

              <div className="flex items-center gap-4 flex-wrap">
                <Select value={selectedTimeframe} onValueChange={setSelectedTimeframe}>
                  <SelectTrigger className="w-[140px]">
                    <SelectValue placeholder="Timeframe" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="1h">Last Hour</SelectItem>
                    <SelectItem value="24h">24 Hours</SelectItem>
                    <SelectItem value="7d">7 Days</SelectItem>
                    <SelectItem value="30d">30 Days</SelectItem>
                  </SelectContent>
                </Select>

                <Select value={selectedCategory} onValueChange={setSelectedCategory}>
                  <SelectTrigger className="w-[140px]">
                    <SelectValue placeholder="Category" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Categories</SelectItem>
                    <SelectItem value="cybersecurity">Cybersecurity</SelectItem>
                    <SelectItem value="breaches">Data Breaches</SelectItem>
                    <SelectItem value="malware">Malware</SelectItem>
                    <SelectItem value="vulnerabilities">Vulnerabilities</SelectItem>
                    <SelectItem value="technology">Technology</SelectItem>
                    <SelectItem value="business">Business</SelectItem>
                  </SelectContent>
                </Select>

                {searchQuery && (
                  <Button variant="outline" size="sm" onClick={saveSearch}>
                    <Bookmark className="h-4 w-4" />
                    Save Search
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Search Results */}
          {articles.length > 0 && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold text-foreground">Search Results</h3>
                <span className="text-sm text-muted-foreground">{articles.length} articles found</span>
              </div>

              <div className="grid gap-4">
                {articles.map((article) => (
                  <Card key={article.id} className="hover:border-primary/50 transition-colors">
                    <CardContent className="p-6">
                      <div className="space-y-4">
                        <div className="flex items-start justify-between gap-4">
                          <div className="space-y-2 flex-1">
                            <h4 className="font-semibold text-lg text-foreground leading-tight">
                              {article.title}
                            </h4>
                            <p className="text-muted-foreground line-clamp-2">
                              {article.description}
                            </p>
                          </div>
                          <Button variant="outline" size="sm" asChild>
                            <a href={article.url} target="_blank" rel="noopener noreferrer">
                              <ExternalLink className="h-4 w-4" />
                            </a>
                          </Button>
                        </div>

                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-4 text-sm text-muted-foreground">
                            <span className="flex items-center gap-1">
                              <Globe className="h-4 w-4" />
                              {article.source}
                            </span>
                            <span className="flex items-center gap-1">
                              <Clock className="h-4 w-4" />
                              {formatTimeAgo(article.publishedAt)}
                            </span>
                            {article.relevanceScore && (
                              <span className={cn(
                                "flex items-center gap-1 font-medium",
                                getRelevanceColor(article.relevanceScore)
                              )}>
                                <TrendingUp className="h-4 w-4" />
                                {Math.round(article.relevanceScore * 100)}% relevant
                              </span>
                            )}
                          </div>

                          <div className="flex items-center gap-2">
                            {article.sentiment && (
                              <Badge className={cn("text-xs", getSentimentColor(article.sentiment))}>
                                {article.sentiment}
                              </Badge>
                            )}
                            {article.category && (
                              <Badge variant="outline" className="text-xs">
                                {article.category}
                              </Badge>
                            )}
                          </div>
                        </div>

                        {article.entities && article.entities.length > 0 && (
                          <div className="space-y-2">
                            <span className="text-sm font-medium text-foreground">Key Entities:</span>
                            <div className="flex flex-wrap gap-1">
                              {article.entities.slice(0, 5).map((entity) => (
                                <Badge key={entity} variant="secondary" className="text-xs">
                                  {entity}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </div>
          )}
        </TabsContent>

        {/* Analysis Tab */}
        <TabsContent value="analysis" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <TrendingUp className="h-5 w-5" />
                Custom Intelligence Analysis
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <Textarea
                placeholder="Describe what you want to analyze... (e.g., 'Latest cybersecurity threats targeting financial institutions')"
                value={analysisQuery}
                onChange={(e) => setAnalysisQuery(e.target.value)}
                rows={3}
              />
              <Button onClick={handleCustomAnalysis} disabled={analysisLoading || !analysisQuery.trim()}>
                {analysisLoading ? (
                  <RefreshCw className="h-4 w-4 animate-spin" />
                ) : (
                  <TrendingUp className="h-4 w-4" />
                )}
                Analyze
              </Button>
            </CardContent>
          </Card>

          {analysis && (
            <Card>
              <CardHeader>
                <CardTitle>Intelligence Analysis Results</CardTitle>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid gap-4 md:grid-cols-3">
                  <div className="p-4 border border-border rounded-lg">
                    <div className="flex items-center gap-2 mb-2">
                      <TrendingUp className="h-4 w-4 text-primary" />
                      <span className="font-medium">Sentiment</span>
                    </div>
                    <div className={cn(
                      "text-lg font-bold capitalize",
                      getSentimentColor(analysis.sentiment).split(' ')[0]
                    )}>
                      {analysis.sentiment}
                    </div>
                  </div>

                  <div className="p-4 border border-border rounded-lg">
                    <div className="flex items-center gap-2 mb-2">
                      <AlertTriangle className="h-4 w-4 text-primary" />
                      <span className="font-medium">Risk Level</span>
                    </div>
                    <div className={cn(
                      "text-lg font-bold capitalize",
                      analysis.riskLevel === 'high' ? 'text-red-500' :
                      analysis.riskLevel === 'medium' ? 'text-yellow-500' : 'text-green-500'
                    )}>
                      {analysis.riskLevel}
                    </div>
                  </div>

                  <div className="p-4 border border-border rounded-lg">
                    <div className="flex items-center gap-2 mb-2">
                      <Eye className="h-4 w-4 text-primary" />
                      <span className="font-medium">Confidence</span>
                    </div>
                    <div className="text-lg font-bold">
                      {Math.round((analysis.confidence || 0) * 100)}%
                    </div>
                  </div>
                </div>

                {analysis.summary && (
                  <div>
                    <h4 className="font-medium text-foreground mb-2">Summary</h4>
                    <p className="text-muted-foreground">{analysis.summary}</p>
                  </div>
                )}

                {analysis.keyTopics && analysis.keyTopics.length > 0 && (
                  <div>
                    <h4 className="font-medium text-foreground mb-2">Key Topics</h4>
                    <div className="flex flex-wrap gap-2">
                      {analysis.keyTopics.map((topic) => (
                        <Badge key={topic} variant="secondary">
                          {topic}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {analysis.recommendations && analysis.recommendations.length > 0 && (
                  <div>
                    <h4 className="font-medium text-foreground mb-2">Recommendations</h4>
                    <ul className="space-y-1">
                      {analysis.recommendations.map((rec, index) => (
                        <li key={index} className="text-muted-foreground text-sm">
                          • {rec}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Trending Topics Tab */}
        <TabsContent value="topics" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Tag className="h-5 w-5" />
                Trending Topics
              </CardTitle>
            </CardHeader>
            <CardContent>
              {newsTopics.length > 0 ? (
                <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
                  {newsTopics.map((topic, index) => (
                    <div
                      key={topic}
                      className="p-4 border border-border rounded-lg hover:border-primary/50 transition-colors cursor-pointer"
                      onClick={() => setSearchQuery(topic)}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-medium text-foreground">{topic}</span>
                        <Badge variant="outline" className="text-xs">
                          #{index + 1}
                        </Badge>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8">
                  <Tag className="h-12 w-12 text-muted-foreground/30 mx-auto mb-2" />
                  <p className="text-muted-foreground">Loading trending topics...</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Saved Searches Tab */}
        <TabsContent value="saved" className="space-y-4">
          {savedSearches.length > 0 ? (
            <div className="grid gap-4">
              {savedSearches.map((search) => (
                <Card key={search.id} className="hover:border-primary/50 transition-colors">
                  <CardContent className="p-6">
                    <div className="flex items-center justify-between">
                      <div className="space-y-2">
                        <h4 className="font-medium text-foreground">{search.query}</h4>
                        <div className="flex items-center gap-4 text-sm text-muted-foreground">
                          <span className="flex items-center gap-1">
                            <Clock className="h-4 w-4" />
                            {formatTimeAgo(search.timestamp)}
                          </span>
                          <span className="flex items-center gap-1">
                            <Calendar className="h-4 w-4" />
                            {search.filters.timeframe}
                          </span>
                          <span className="flex items-center gap-1">
                            <Tag className="h-4 w-4" />
                            {search.filters.category}
                          </span>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            setSearchQuery(search.query);
                            setSelectedTimeframe(search.filters.timeframe);
                            setSelectedCategory(search.filters.category);
                            setActiveTab("search");
                          }}
                        >
                          <Search className="h-4 w-4" />
                          Run
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <Card>
              <CardContent className="p-12 text-center">
                <Bookmark className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-foreground">No saved searches</h3>
                <p className="text-muted-foreground">Create and save searches to monitor them over time</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}