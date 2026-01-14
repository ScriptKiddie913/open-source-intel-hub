'use client';

import { useState, useCallback, useMemo } from 'react';
import {
  Send,
  Search,
  Loader2,
  AlertTriangle,
  Database,
  MessageSquare,
  Users,
  Clock,
  RefreshCcw,
  Shield,
  Hash,
  ExternalLink,
  Download,
  Eye,
  User,
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Card,
  CardContent,
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@/components/ui/tabs';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';

import {
  searchTelegramLeaks,
  searchTelegramChannels,
  searchTelegramUsers,
  type TelegramLeak,
  type TelegramChannel,
  type TelegramUser,
} from '@/services/telegramService';

import { toast } from 'sonner';
import { cn } from '@/lib/utils';

type SearchType = 'leaks' | 'channels' | 'users';
type LeakType = 'email' | 'username' | 'phone' | 'password' | 'domain' | 'keyword';

const SEVERITY_COLORS: Record<'critical' | 'high' | 'medium' | 'low', string> = {
  critical: 'border-red-500/40 bg-red-500/10 text-red-400',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-400',
  medium: 'border-yellow-500/40 bg-yellow-500/10 text-yellow-400',
  low: 'border-blue-500/40 bg-blue-500/10 text-blue-400',
};

export function TelegramIntelligence() {
  const [query, setQuery] = useState('');
  const [searchType, setSearchType] = useState<SearchType>('leaks');
  const [leakType, setLeakType] = useState<LeakType>('email');
  const [loading, setLoading] = useState(false);

  const [leaks, setLeaks] = useState<TelegramLeak[]>([]);
  const [channels, setChannels] = useState<TelegramChannel[]>([]);
  const [users, setUsers] = useState<TelegramUser[]>([]);

  const runSearch = useCallback(async () => {
    if (!query.trim()) {
      toast.error('Enter a search term (email, username, keyword, etc.)');
      return;
    }

    setLoading(true);
    setLeaks([]);
    setChannels([]);
    setUsers([]);

    try {
      if (searchType === 'leaks') {
        const results = await searchTelegramLeaks(query, leakType);
        setLeaks(results);
        toast.success(`Found ${results.length} leak mentions`);
      } else if (searchType === 'channels') {
        const results = await searchTelegramChannels(query);
        setChannels(results);
        toast.success(`Found ${results.length} channels`);
      } else {
        const results = await searchTelegramUsers(query);
        setUsers(results);
        toast.success(`Found ${results.length} user profiles`);
      }
    } catch (err) {
      console.error(err);
      toast.error('Search failed. Check console for details.');
    } finally {
      setLoading(false);
    }
  }, [query, searchType, leakType]);

  const stats = useMemo(() => {
    const criticalLeaks = leaks.filter(l => l.severity === 'critical').length;
    const highLeaks = leaks.filter(l => l.severity === 'high').length;
    const verifiedChannels = channels.filter(c => c.verified).length;
    const totalMembers = channels.reduce((sum, c) => sum + c.members, 0);

    return {
      totalLeaks: leaks.length,
      criticalLeaks,
      highLeaks,
      totalChannels: channels.length,
      verifiedChannels,
      totalMembers,
      totalUsers: users.length,
    };
  }, [leaks, channels, users]);

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* HEADER */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Send className="h-8 w-8 text-primary" />
            Telegram Intelligence Monitor
          </h1>
          <p className="text-muted-foreground mt-2">
            Real-time leak detection, channel monitoring, and user intelligence from Telegram
          </p>
        </div>

        <Button
          variant="outline"
          size="sm"
          onClick={runSearch}
          disabled={loading}
        >
          <RefreshCcw className={cn('h-4 w-4 mr-2', loading && 'animate-spin')} />
          Refresh
        </Button>
      </div>

      {/* LEGAL NOTICE */}
      <Card className="border-yellow-500/40 bg-yellow-500/10">
        <CardContent className="p-4 flex gap-3">
          <AlertTriangle className="h-5 w-5 text-yellow-500 shrink-0 mt-1" />
          <div>
            <h3 className="font-semibold text-yellow-600 dark:text-yellow-500">
              Public OSINT Intelligence (Legal & Ethical)
            </h3>
            <p className="text-sm text-muted-foreground mt-1">
              This tool aggregates data from <strong>public Telegram channels, leak databases, and indexed sources</strong>.  
              No private message scraping.  No account compromise. All data comes from public OSINT feeds and legitimate breach databases.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* SEARCH INTERFACE */}
      <Card className="border-primary/30">
        <CardContent className="pt-6 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Select value={searchType} onValueChange={(v) => setSearchType(v as SearchType)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="leaks">
                  <div className="flex items-center gap-2">
                    <Database className="h-4 w-4" />
                    Leak Detection
                  </div>
                </SelectItem>
                <SelectItem value="channels">
                  <div className="flex items-center gap-2">
                    <MessageSquare className="h-4 w-4" />
                    Channel Search
                  </div>
                </SelectItem>
                <SelectItem value="users">
                  <div className="flex items-center gap-2">
                    <Users className="h-4 w-4" />
                    User Intelligence
                  </div>
                </SelectItem>
              </SelectContent>
            </Select>

            {searchType === 'leaks' && (
              <Select value={leakType} onValueChange={(v) => setLeakType(v as LeakType)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="email">Email Address</SelectItem>
                  <SelectItem value="username">Username</SelectItem>
                  <SelectItem value="phone">Phone Number</SelectItem>
                  <SelectItem value="domain">Domain</SelectItem>
                  <SelectItem value="password">Password Hash</SelectItem>
                  <SelectItem value="keyword">Keyword</SelectItem>
                </SelectContent>
              </Select>
            )}
          </div>

          <div className="flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                value={query}
                onChange={e => setQuery(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && runSearch()}
                placeholder={
                  searchType === 'leaks'
                    ? `Search for ${leakType}... `
                    : searchType === 'channels'
                    ? 'Channel name or keyword...'
                    : 'Username, ID, or phone.. .'
                }
                className="pl-10"
              />
            </div>

            <Button onClick={runSearch} disabled={loading}>
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <>
                  <Eye className="h-4 w-4 mr-2" />
                  Search
                </>
              )}
            </Button>
          </div>

          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Shield className="h-3 w-3" />
            <span>
              Try: "example@company.com", "john_doe", "CompanyName", or any identifier
            </span>
          </div>
        </CardContent>
      </Card>

      {/* STATS DASHBOARD */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <Database className="h-5 w-5 mx-auto text-primary mb-2" />
              <div className="text-2xl font-bold">{stats.totalLeaks}</div>
              <div className="text-xs text-muted-foreground">Total Leaks</div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <AlertTriangle className="h-5 w-5 mx-auto text-red-500 mb-2" />
              <div className="text-2xl font-bold text-red-500">{stats.criticalLeaks}</div>
              <div className="text-xs text-muted-foreground">Critical</div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <MessageSquare className="h-5 w-5 mx-auto text-cyan-500 mb-2" />
              <div className="text-2xl font-bold">{stats.totalChannels}</div>
              <div className="text-xs text-muted-foreground">Channels</div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <Shield className="h-5 w-5 mx-auto text-green-500 mb-2" />
              <div className="text-2xl font-bold">{stats.verifiedChannels}</div>
              <div className="text-xs text-muted-foreground">Verified</div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <Users className="h-5 w-5 mx-auto text-purple-500 mb-2" />
              <div className="text-2xl font-bold">{stats.totalMembers.toLocaleString()}</div>
              <div className="text-xs text-muted-foreground">Members</div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <User className="h-5 w-5 mx-auto text-orange-500 mb-2" />
              <div className="text-2xl font-bold">{stats.totalUsers}</div>
              <div className="text-xs text-muted-foreground">Users</div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* RESULTS TABS */}
      <Tabs value={searchType} onValueChange={(v) => setSearchType(v as SearchType)}>
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="leaks">
            <Database className="h-4 w-4 mr-2" />
            Leaks ({leaks.length})
          </TabsTrigger>
          <TabsTrigger value="channels">
            <MessageSquare className="h-4 w-4 mr-2" />
            Channels ({channels.length})
          </TabsTrigger>
          <TabsTrigger value="users">
            <Users className="h-4 w-4 mr-2" />
            Users ({users.length})
          </TabsTrigger>
        </TabsList>

        {/* LEAKS TAB */}
        <TabsContent value="leaks" className="mt-6 space-y-3">
          {loading && <LoadingState />}
          {!loading && leaks.length === 0 && (
            <EmptyState
              icon={Database}
              message="No leaks found. Try a different search term or identifier."
            />
          )}
          {!loading && leaks.map(leak => (
            <LeakCard key={leak.id} leak={leak} />
          ))}
        </TabsContent>

        {/* CHANNELS TAB */}
        <TabsContent value="channels" className="mt-6 space-y-3">
          {loading && <LoadingState />}
          {!loading && channels.length === 0 && (
            <EmptyState
              icon={MessageSquare}
              message="No channels found. Try searching for cybersecurity, leak, or breach-related terms."
            />
          )}
          {!loading && channels.map(channel => (
            <ChannelCard key={channel.id} channel={channel} />
          ))}
        </TabsContent>

        {/* USERS TAB */}
        <TabsContent value="users" className="mt-6 space-y-3">
          {loading && <LoadingState />}
          {!loading && users.length === 0 && (
            <EmptyState
              icon={Users}
              message="No users found. Try searching with a username, phone, or user ID."
            />
          )}
          {!loading && users.map(user => (
            <UserCard key={user.id} user={user} />
          ))}
        </TabsContent>
      </Tabs>

      {/* DATA SOURCES */}
      <Card className="border-primary/40 bg-primary/5">
        <CardContent className="p-4 flex gap-3">
          <Database className="h-5 w-5 text-primary shrink-0" />
          <div>
            <h3 className="font-semibold">Real Intelligence Sources</h3>
            <p className="text-sm text-muted-foreground mt-1">
              <strong>Leak Detection:</strong> Psbdmp, HaveIBeenPwned, Telegram Indexes
              {' • '}
              <strong>Channel Indexing:</strong> Telemetr.io, Tgstat, Lyzem
              {' • '}
              <strong>User OSINT:</strong> TelegramDB, Telegram Search APIs
              {' • '}
              <strong>Real-time Monitoring:</strong> Public channel scrapers via MTProto proxies
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

/* ============================================================================
   RESULT CARD COMPONENTS
============================================================================ */

function LeakCard({ leak }: { leak: TelegramLeak }) {
  return (
    <Card className={cn('border-2', SEVERITY_COLORS[leak.severity])}>
      <CardContent className="pt-6">
        <div className="flex items-start justify-between gap-4 mb-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold">{leak.title}</h3>
              <Badge variant="outline" className={SEVERITY_COLORS[leak.severity]}>
                {leak.severity.toUpperCase()}
              </Badge>
              <Badge variant="secondary">{leak.type}</Badge>
            </div>

            <div className="space-y-2 text-sm">
              <div className="flex items-center gap-2">
                <span className="text-muted-foreground">Identifier:</span>
                <code className="bg-secondary px-2 py-1 rounded text-xs font-mono">
                  {leak.identifier}
                </code>
              </div>

              {leak.channel && (
                <div className="flex items-center gap-2">
                  <MessageSquare className="h-3 w-3 text-muted-foreground" />
                  <span className="text-muted-foreground">Channel:</span>
                  <span className="font-medium">{leak.channel}</span>
                </div>
              )}

              {leak.context && (
                <p className="text-muted-foreground">{leak.context}</p>
              )}

              {leak.exposedData && leak.exposedData.length > 0 && (
                <div className="flex flex-wrap gap-2 mt-2">
                  {leak.exposedData.map(data => (
                    <Badge key={data} variant="outline" className="text-xs">
                      {data}
                    </Badge>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="flex justify-between items-center pt-3 border-t border-border">
          <div className="flex items-center gap-4 text-xs text-muted-foreground">
            <span className="flex items-center gap-1">
              <Clock className="h-3 w-3" />
              {new Date(leak.timestamp).toLocaleString()}
            </span>
            <span className="flex items-center gap-1">
              <Database className="h-3 w-3" />
              {leak.source}
            </span>
          </div>

          {leak.url && (
            <Button size="sm" variant="outline" asChild>
              <a href={leak.url} target="_blank" rel="noopener noreferrer">
                <ExternalLink className="h-3 w-3 mr-2" />
                View Source
              </a>
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function ChannelCard({ channel }: { channel: TelegramChannel }) {
  return (
    <Card className="hover:border-primary/50 transition-colors">
      <CardContent className="pt-6">
        <div className="flex items-start gap-4 mb-4">
          {channel.photo && (
            <img
              src={channel.photo}
              alt={channel.title}
              className="w-12 h-12 rounded-full object-cover"
            />
          )}

          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <h3 className="font-semibold">{channel.title}</h3>
              {channel.verified && (
                <Shield className="h-4 w-4 text-primary" />
              )}
            </div>

            <p className="text-xs text-muted-foreground font-mono mb-2">
              @{channel.username || channel.id}
            </p>

            {channel.description && (
              <p className="text-sm text-muted-foreground line-clamp-2">
                {channel.description}
              </p>
            )}

            <div className="flex flex-wrap gap-3 mt-3 text-xs text-muted-foreground">
              <span className="flex items-center gap-1">
                <Users className="h-3 w-3" />
                {channel.members.toLocaleString()} members
              </span>
              {channel.category && (
                <Badge variant="outline" className="text-xs">
                  {channel.category}
                </Badge>
              )}
            </div>
          </div>
        </div>

        <div className="flex justify-between items-center pt-3 border-t border-border">
          <span className="text-xs text-muted-foreground flex items-center gap-1">
            <Clock className="h-3 w-3" />
            {new Date(channel.lastActive).toLocaleString()}
          </span>

          <Button size="sm" variant="outline" asChild>
            <a
              href={`https://t.me/${channel.username || `c/${channel.id}`}`}
              target="_blank"
              rel="noopener noreferrer"
            >
              <Send className="h-3 w-3 mr-2" />
              Open in Telegram
            </a>
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function UserCard({ user }: { user: TelegramUser }) {
  return (
    <Card className="hover:border-primary/50 transition-colors">
      <CardContent className="pt-6">
        <div className="flex items-start gap-4">
          {user.photo && (
            <img
              src={user.photo}
              alt={user.firstName}
              className="w-12 h-12 rounded-full object-cover"
            />
          )}

          <div className="flex-1">
            <div className="flex items-center gap-2 mb-1">
              <h3 className="font-semibold">
                {user.firstName} {user.lastName}
              </h3>
              {user.verified && <Shield className="h-4 w-4 text-primary" />}
              {user.premium && (
                <Badge variant="secondary" className="text-xs">Premium</Badge>
              )}
            </div>

            {user.username && (
              <p className="text-xs text-muted-foreground font-mono mb-2">
                @{user.username}
              </p>
            )}

            {user.bio && (
              <p className="text-sm text-muted-foreground line-clamp-2 mt-2">
                {user.bio}
              </p>
            )}

            {user.phone && (
              <div className="flex items-center gap-2 mt-2 text-xs">
                <span className="text-muted-foreground">Phone:</span>
                <code className="bg-secondary px-2 py-1 rounded font-mono">
                  {user.phone}
                </code>
              </div>
            )}

            <div className="flex justify-between items-center pt-3 mt-3 border-t border-border">
              <span className="text-xs text-muted-foreground">
                ID: {user.id}
              </span>

              {user.username && (
                <Button size="sm" variant="outline" asChild>
                  <a
                    href={`https://t.me/${user.username}`}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    <Send className="h-3 w-3 mr-2" />
                    Contact
                  </a>
                </Button>
              )}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function LoadingState() {
  return (
    <div className="flex items-center justify-center py-12">
      <Loader2 className="h-8 w-8 animate-spin text-primary" />
    </div>
  );
}

function EmptyState({ icon: Icon, message }: { icon: any; message: string }) {
  return (
    <Card className="border-dashed">
      <CardContent className="pt-12 pb-12 text-center">
        <Icon className="h-16 w-16 mx-auto text-muted-foreground opacity-50 mb-4" />
        <p className="text-muted-foreground">{message}</p>
      </CardContent>
    </Card>
  );
}
