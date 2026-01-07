// src/components/osint/UsernameEnumeration.tsx
import { useState } from 'react';
import { User, Search, Loader2, ExternalLink, Bot, Check, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { enumerateUsername, summarizeUsernameResults, UsernameResult } from '@/services/enhancedThreatService';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

export function UsernameEnumeration() {
  const [username, setUsername] = useState('');
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState<UsernameResult[]>([]);
  const [aiSummary, setAiSummary] = useState<string>('');
  const [filterType, setFilterType] = useState<string>('all');

  const platformTypes = ['all', 'social', 'dev', 'gaming', 'professional', 'creative'];

  const handleSearch = async () => {
    if (!username.trim()) {
      toast.error('Please enter a username');
      return;
    }

    setLoading(true);
    setProgress(0);
    setResults([]);
    setAiSummary('');

    try {
      // Simulate progress
      const progressInterval = setInterval(() => {
        setProgress(prev => Math.min(prev + 10, 90));
      }, 500);

      const foundResults = await enumerateUsername(username.trim());
      clearInterval(progressInterval);
      setProgress(100);
      
      setResults(foundResults);
      toast.success(`Found ${foundResults.length} platforms`);

      // Generate AI summary
      if (foundResults.length > 0) {
        const summary = await summarizeUsernameResults(username, foundResults);
        setAiSummary(summary);
      }
    } catch (error) {
      toast.error('Enumeration failed');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const filteredResults = filterType === 'all' 
    ? results 
    : results.filter(r => {
        const url = r.url.toLowerCase();
        if (filterType === 'social') return url.includes('twitter') || url.includes('instagram') || url.includes('facebook') || url.includes('reddit');
        if (filterType === 'dev') return url.includes('github') || url.includes('gitlab') || url.includes('stackoverflow');
        if (filterType === 'gaming') return url.includes('steam') || url.includes('twitch') || url.includes('discord');
        if (filterType === 'professional') return url.includes('linkedin') || url.includes('medium');
        if (filterType === 'creative') return url.includes('behance') || url.includes('dribbble') || url.includes('patreon');
        return true;
      });

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground">Username Enumeration</h1>
        <p className="text-muted-foreground text-sm mt-1">
          Search across 100+ platforms with AI-powered analysis
        </p>
      </div>

      {/* Search */}
      <Card className="bg-card border-border">
        <CardContent className="p-4">
          <div className="flex gap-3">
            <div className="relative flex-1">
              <User className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                placeholder="Enter username to enumerate..."
                className="pl-10 bg-background"
              />
            </div>
            <Button onClick={handleSearch} disabled={loading} className="min-w-[120px]">
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <>
                  <Search className="h-4 w-4 mr-2" />
                  Search
                </>
              )}
            </Button>
          </div>

          {loading && (
            <div className="mt-4 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">Checking platforms...</span>
                <span className="font-mono text-primary">{progress}%</span>
              </div>
              <Progress value={progress} className="h-2" />
            </div>
          )}
        </CardContent>
      </Card>

      {/* AI Summary */}
      {aiSummary && (
        <Card className="bg-gradient-to-r from-primary/10 to-accent/10 border-primary/30">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-foreground">
              <Bot className="h-5 w-5 text-primary" />
              AI Analysis
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-foreground leading-relaxed">{aiSummary}</p>
          </CardContent>
        </Card>
      )}

      {/* Results */}
      {results.length > 0 && (
        <div className="space-y-4">
          {/* Stats */}
          <Card className="bg-card border-border">
            <CardContent className="p-4">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold font-mono text-primary">{results.length}</div>
                  <div className="text-xs text-muted-foreground">Platforms Found</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold font-mono text-success">{results.filter(r => r.exists).length}</div>
                  <div className="text-xs text-muted-foreground">Confirmed</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold font-mono text-cyan-500">
                    {new Set(results.map(r => r.url.split('.')[0])).size}
                  </div>
                  <div className="text-xs text-muted-foreground">Unique Domains</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold font-mono text-orange-500">
                    {Math.round((results.length / 100) * 100)}%
                  </div>
                  <div className="text-xs text-muted-foreground">Coverage</div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Filter */}
          <div className="flex flex-wrap gap-2">
            {platformTypes.map((type) => (
              <Button
                key={type}
                variant={filterType === type ? 'default' : 'outline'}
                size="sm"
                onClick={() => setFilterType(type)}
              >
                {type.charAt(0).toUpperCase() + type.slice(1)}
              </Button>
            ))}
          </div>

          {/* Platform Results */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {filteredResults.map((result) => (
              <Card
                key={result.platform}
                className="bg-card border hover:border-primary/50 transition-all group"
              >
                <CardContent className="p-4">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-2">
                      {result.exists ? (
                        <div className="p-1.5 rounded bg-success/20">
                          <Check className="h-3 w-3 text-success" />
                        </div>
                      ) : (
                        <div className="p-1.5 rounded bg-muted">
                          <X className="h-3 w-3 text-muted-foreground" />
                        </div>
                      )}
                      <div>
                        <h3 className="font-semibold text-foreground text-sm">
                          {result.platform}
                        </h3>
                        <p className="text-xs text-muted-foreground font-mono">
                          @{result.username}
                        </p>
                      </div>
                    </div>
                    <a
                      href={result.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="opacity-0 group-hover:opacity-100 transition-opacity"
                    >
                      <ExternalLink className="h-4 w-4 text-primary" />
                    </a>
                  </div>

                  <div className="flex items-center justify-between text-xs">
                    <Badge variant="outline" className="text-xs">
                      {result.exists ? 'Found' : 'Not Found'}
                    </Badge>
                    <span className="text-muted-foreground font-mono">
                      {new Date(result.lastChecked).toLocaleTimeString()}
                    </span>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>

          {filteredResults.length === 0 && (
            <Card className="bg-card border-border">
              <CardContent className="p-8 text-center">
                <p className="text-muted-foreground">No platforms found for this filter</p>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* Empty State */}
      {!loading && results.length === 0 && (
        <Card className="bg-card border-border">
          <CardContent className="p-12 text-center">
            <User className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
            <p className="text-muted-foreground mb-2">Enter a username to begin enumeration</p>
            <p className="text-xs text-muted-foreground/60">
              Checks 100+ platforms including social media, dev sites, gaming, and more
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
