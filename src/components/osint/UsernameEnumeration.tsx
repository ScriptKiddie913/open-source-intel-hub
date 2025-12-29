// src/components/osint/UsernameEnumeration.tsx
import { useState } from 'react';
import {
  User,
  Search,
  Loader2,
  ExternalLink,
  Download,
  Filter,
  BarChart3,
  Clock,
  CheckCircle2,
  XCircle,
  AlertCircle,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { toast } from 'sonner';
import {
  enumerateUsername,
  calculateStats,
  getPlatformCategories,
  type UsernameResult,
} from '@/services/usernameService';

export function UsernameEnumeration() {
  const [username, setUsername] = useState('');
  const [results, setResults] = useState<UsernameResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [totalPlatforms, setTotalPlatforms] = useState(0);
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [sortBy, setSortBy] = useState<'name' | 'category' | 'responseTime'>('name');

  const handleSearch = async () => {
    if (!username. trim()) {
      toast.error('Please enter a username');
      return;
    }

    setLoading(true);
    setResults([]);
    setProgress(0);

    try {
      const foundAccounts = await enumerateUsername(
        username. trim(),
        (completed, total) => {
          setProgress((completed / total) * 100);
          setTotalPlatforms(total);
        }
      );

      setResults(foundAccounts);

      if (foundAccounts.length === 0) {
        toast.info('No accounts found with this username');
      } else {
        toast. success(`Found ${foundAccounts.length} accounts! `);
      }
    } catch (error) {
      console.error('Username enumeration error:', error);
      toast.error('Search failed. Please try again.');
    } finally {
      setLoading(false);
      setProgress(0);
    }
  };

  const exportResults = () => {
    const csv = [
      ['Platform', 'Username', 'URL', 'Category', 'Response Time (ms)']. join(','),
      ...results.map(r => [
        r.platform,
        r.username,
        r.url,
        r.category,
        r.responseTime,
      ].join(',')),
    ].join('\n');

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `username-${username}-${Date.now()}.csv`;
    a.click();
    toast.success('Results exported');
  };

  const filteredResults = results.filter(r => 
    filterCategory === 'all' || r.category === filterCategory
  );

  const sortedResults = [...filteredResults]. sort((a, b) => {
    switch (sortBy) {
      case 'name':
        return a.platform.localeCompare(b. platform);
      case 'category':
        return a.category. localeCompare(b.category);
      case 'responseTime':
        return a.responseTime - b.responseTime;
      default:
        return 0;
    }
  });

  const stats = results.length > 0 ? calculateStats(results) : null;

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      <div>
        <h1 className="text-3xl font-bold flex items-center gap-3">
          <User className="h-8 w-8 text-primary" />
          Username Enumeration
        </h1>
        <p className="text-muted-foreground mt-2">
          Search for a username across 60+ platforms - Only shows accounts that actually exist
        </p>
      </div>

      <Card className="border-primary/30">
        <CardContent className="pt-6">
          <div className="flex gap-3">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && ! loading && handleSearch()}
                placeholder="Enter username to search..."
                className="pl-10"
                disabled={loading}
              />
            </div>
            <Button onClick={handleSearch} disabled={loading || !username.trim()}>
              {loading ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Searching...
                </>
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
              <div className="flex justify-between text-sm text-muted-foreground">
                <span>Checking platforms...</span>
                <span>{Math.round(progress)}%</span>
              </div>
              <div className="w-full bg-secondary rounded-full h-2">
                <div
                  className="bg-primary h-2 rounded-full transition-all duration-300"
                  style={{ width:  `${progress}%` }}
                />
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card>
            <CardContent className="pt-6">
              <div className="text-center">
                <CheckCircle2 className="h-6 w-6 mx-auto text-green-500 mb-2" />
                <div className="text-3xl font-bold text-green-500">{stats.totalFound}</div>
                <div className="text-sm text-muted-foreground">Accounts Found</div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="text-center">
                <BarChart3 className="h-6 w-6 mx-auto text-cyan-500 mb-2" />
                <div className="text-3xl font-bold text-cyan-500">{stats.totalChecked}</div>
                <div className="text-sm text-muted-foreground">Platforms Checked</div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="text-center">
                <Clock className="h-6 w-6 mx-auto text-orange-500 mb-2" />
                <div className="text-3xl font-bold text-orange-500">{stats.avgResponseTime}ms</div>
                <div className="text-sm text-muted-foreground">Avg Response</div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="text-center">
                <Filter className="h-6 w-6 mx-auto text-purple-500 mb-2" />
                <div className="text-3xl font-bold text-purple-500">{Object.keys(stats.byCategory).length}</div>
                <div className="text-sm text-muted-foreground">Categories</div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {results.length > 0 && (
        <Card>
          <CardContent className="pt-6">
            <div className="flex flex-wrap gap-3 items-center">
              <Select value={filterCategory} onValueChange={setFilterCategory}>
                <SelectTrigger className="w-48">
                  <SelectValue placeholder="Filter by category" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Categories</SelectItem>
                  {getPlatformCategories().map(cat => (
                    <SelectItem key={cat} value={cat}>{cat}</SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <Select value={sortBy} onValueChange={(v) => setSortBy(v as any)}>
                <SelectTrigger className="w-48">
                  <SelectValue placeholder="Sort by" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="name">Platform Name</SelectItem>
                  <SelectItem value="category">Category</SelectItem>
                  <SelectItem value="responseTime">Response Time</SelectItem>
                </SelectContent>
              </Select>

              <div className="flex-1" />

              <Badge variant="secondary">
                Showing {filteredResults.length} of {results.length} results
              </Badge>

              <Button variant="outline" size="sm" onClick={exportResults}>
                <Download className="h-4 w-4 mr-2" />
                Export CSV
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      {! loading && results.length === 0 && username && (
        <Card className="border-dashed">
          <CardContent className="pt-12 pb-12 text-center">
            <XCircle className="h-16 w-16 mx-auto text-muted-foreground opacity-50 mb-4" />
            <p className="text-muted-foreground">
              No accounts found for username "<strong>{username}</strong>"
            </p>
            <p className="text-sm text-muted-foreground mt-2">
              Try a different username or check the spelling
            </p>
          </CardContent>
        </Card>
      )}

      {sortedResults.length > 0 && (
        <div className="grid grid-cols-1 md: grid-cols-2 lg:grid-cols-3 gap-4">
          {sortedResults.map((result) => (
            <Card key={result. platform} className="hover:border-primary/50 transition-all">
              <CardContent className="pt-6">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <div className="text-3xl">{result.icon}</div>
                    <div>
                      <h3 className="font-semibold">{result.platform}</h3>
                      <Badge variant="secondary" className="text-xs mt-1">
                        {result.category}
                      </Badge>
                    </div>
                  </div>
                  <CheckCircle2 className="h-5 w-5 text-green-500" />
                </div>

                <div className="space-y-2 text-sm">
                  <div className="flex items-center gap-2 text-muted-foreground">
                    <User className="h-3 w-3" />
                    <span className="font-mono">{result.username}</span>
                  </div>

                  {result.profileData && (
                    <div className="flex gap-4 text-xs text-muted-foreground">
                      {result.profileData.followers !== undefined && (
                        <span>👥 {result.profileData. followers}</span>
                      )}
                      {result.profileData.posts !== undefined && (
                        <span>📝 {result. profileData.posts}</span>
                      )}
                      {result.profileData.verified && (
                        <span>✓ Verified</span>
                      )}
                    </div>
                  )}

                  <div className="flex items-center gap-2 text-xs text-muted-foreground">
                    <Clock className="h-3 w-3" />
                    <span>{result. responseTime}ms</span>
                  </div>
                </div>

                <Button
                  variant="outline"
                  size="sm"
                  className="w-full mt-4"
                  asChild
                >
                  <a href={result.url} target="_blank" rel="noopener noreferrer">
                    <ExternalLink className="h-3 w-3 mr-2" />
                    View Profile
                  </a>
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      <Card className="border-primary/40 bg-primary/5">
        <CardContent className="p-4 flex gap-3">
          <AlertCircle className="h-5 w-5 text-primary shrink-0" />
          <div>
            <h3 className="font-semibold text-primary">Verification Method</h3>
            <p className="text-sm text-muted-foreground mt-1">
              This tool only shows accounts that actually exist. We verify each platform using
              HTTP status codes, page content analysis, and official APIs where available.
              False positives are eliminated. 
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
