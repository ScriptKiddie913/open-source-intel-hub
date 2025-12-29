import { useEffect, useMemo, useState } from 'react';

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';

import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@/components/ui/tabs';

import { ScrollArea } from '@/components/ui/scroll-area';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Separator } from '@/components/ui/separator';

import { telegramApi, DEFAULT_LEAK_CHANNELS } from '@/services/telegramApi';
import {
  TelegramMessage,
  TelegramChannel,
  ScanResult,
} from '@/types/telegram';

import {
  Send,
  Search,
  AlertTriangle,
  Eye,
  Loader2,
  Radio,
  Zap,
  Clock,
  TrendingUp,
  Users,
  MessageSquare,
  ExternalLink,
  Link as LinkIcon,
} from 'lucide-react';

/* ============================================================================
   TELEGRAM SCANNER COMPONENT
============================================================================ */

export function TelegramScanner() {
  const [channelInput, setChannelInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [autoScanning, setAutoScanning] = useState(false);

  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  const [selectedResult, setSelectedResult] = useState<ScanResult | null>(null);

  const [activeTab, setActiveTab] = useState<'scanner' | 'results' | 'messages'>(
    'scanner'
  );

  /* ============================================================================
     INITIAL DEFAULT SCAN
  ========================================================================== */

  useEffect(() => {
    if (scanResults.length === 0) {
      quickScanDefaults();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /* ============================================================================
     ACTIONS
  ========================================================================== */

  async function quickScanDefaults() {
    setLoading(true);
    try {
      const results = await telegramApi.scanMultipleChannels(
        DEFAULT_LEAK_CHANNELS.slice(0, 3),
        20
      );

      setScanResults(results);
      if (results.length > 0) {
        setSelectedResult(results[0]);
      }
    } catch (err) {
      console.error('Quick scan failed:', err);
    } finally {
      setLoading(false);
    }
  }

  async function handleScanChannel() {
    const channel = channelInput.trim();
    if (!channel) return;

    setLoading(true);
    try {
      const result = await telegramApi.scrapeChannel(channel, 50);
      setScanResults(prev => [result, ...prev]);
      setSelectedResult(result);
      setChannelInput('');
      setActiveTab('results');
    } catch (err) {
      console.error('Channel scan failed:', err);
    } finally {
      setLoading(false);
    }
  }

  async function handleBulkScan() {
    setLoading(true);
    setAutoScanning(true);
    try {
      const results = await telegramApi.scanMultipleChannels(
        DEFAULT_LEAK_CHANNELS,
        30
      );
      setScanResults(results);
      setActiveTab('results');
    } catch (err) {
      console.error('Bulk scan failed:', err);
    } finally {
      setAutoScanning(false);
      setLoading(false);
    }
  }

  /* ============================================================================
     HELPERS
  ========================================================================== */

  function categoryVariant(category: TelegramMessage['category']) {
    if (
      category === 'breach' ||
      category === 'credentials' ||
      category === 'ransomware'
    )
      return 'destructive';
    return 'secondary';
  }

  function riskVariant(level: TelegramChannel['riskLevel']) {
    if (level === 'critical' || level === 'high') return 'destructive';
    if (level === 'medium') return 'secondary';
    return 'outline';
  }

  const totalMessages = useMemo(
    () => scanResults.reduce((s, r) => s + r.totalMessages, 0),
    [scanResults]
  );

  const totalLeaks = useMemo(
    () => scanResults.reduce((s, r) => s + r.leaksFound, 0),
    [scanResults]
  );

  const avgSensitivity = useMemo(() => {
    if (!selectedResult || selectedResult.messages.length === 0) return 0;
    return (
      selectedResult.messages.reduce(
        (s, m) => s + m.sensitivityScore,
        0
      ) / selectedResult.messages.length
    );
  }, [selectedResult]);

  /* ============================================================================
     RENDER
  ========================================================================== */

  return (
    <div className="p-6 space-y-6">
      {/* HEADER */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Send className="h-8 w-8 text-blue-500" />
            Telegram Leak Scanner
          </h1>
          <p className="text-muted-foreground">
            Monitor public Telegram channels for breaches and leaks
          </p>
        </div>

        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={quickScanDefaults}
            disabled={loading}
          >
            <Zap className="mr-2 h-4 w-4" />
            Quick Scan
          </Button>

          <Button
            onClick={handleBulkScan}
            disabled={loading || autoScanning}
          >
            {autoScanning ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Radio className="mr-2 h-4 w-4" />
            )}
            Bulk Scan
          </Button>
        </div>
      </div>

      {/* STATS */}
      <div className="grid md:grid-cols-4 gap-4">
        <StatCard title="Channels" value={scanResults.length} icon={Users} />
        <StatCard title="Messages" value={totalMessages} icon={MessageSquare} />
        <StatCard
          title="Leaks"
          value={totalLeaks}
          icon={AlertTriangle}
          danger
        />
        <StatCard
          title="Avg Sensitivity"
          value={`${avgSensitivity.toFixed(0)}%`}
          icon={TrendingUp}
        />
      </div>

      {/* INPUT */}
      <Card>
        <CardContent className="pt-6 flex gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
            <Input
              className="pl-10"
              placeholder="Telegram channel username"
              value={channelInput}
              onChange={e => setChannelInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleScanChannel()}
            />
          </div>
          <Button onClick={handleScanChannel} disabled={loading}>
            <Eye className="mr-2 h-4 w-4" />
            Scan
          </Button>
        </CardContent>
      </Card>

      {/* TABS */}
      <Tabs value={activeTab} onValueChange={v => setActiveTab(v as any)}>
        <TabsList className="grid grid-cols-3">
          <TabsTrigger value="scanner">Defaults</TabsTrigger>
          <TabsTrigger value="results">Results</TabsTrigger>
          <TabsTrigger value="messages">Messages</TabsTrigger>
        </TabsList>

        {/* DEFAULTS */}
        <TabsContent value="scanner">
          <Card>
            <CardHeader>
              <CardTitle>Default Leak Channels</CardTitle>
              <CardDescription>
                Frequently monitored public Telegram sources
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              {DEFAULT_LEAK_CHANNELS.map(ch => (
                <div
                  key={ch}
                  className="flex justify-between items-center border rounded-lg p-3"
                >
                  <span className="font-mono">t.me/{ch}</span>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => {
                      setChannelInput(ch);
                      handleScanChannel();
                    }}
                  >
                    Scan
                  </Button>
                </div>
              ))}
            </CardContent>
          </Card>
        </TabsContent>

        {/* RESULTS */}
        <TabsContent value="results">
          {scanResults.length === 0 ? (
            <Alert>
              <AlertDescription>No results yet</AlertDescription>
            </Alert>
          ) : (
            <div className="grid md:grid-cols-2 gap-4">
              {scanResults.map(result => (
                <Card
                  key={result.channel.username}
                  className="cursor-pointer hover:ring-2 hover:ring-primary"
                  onClick={() => {
                    setSelectedResult(result);
                    setActiveTab('messages');
                  }}
                >
                  <CardHeader>
                    <CardTitle>@{result.channel.username}</CardTitle>
                    <CardDescription>
                      {result.totalMessages} messages · {result.leaksFound} leaks
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="flex justify-between">
                    <Badge variant={riskVariant(result.channel.riskLevel)}>
                      {result.channel.riskLevel}
                    </Badge>
                    <span className="text-xs text-muted-foreground">
                      {(result.scanDuration / 1000).toFixed(1)}s
                    </span>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* MESSAGES */}
        <TabsContent value="messages">
          {!selectedResult ? (
            <Alert>
              <AlertDescription>Select a scan result</AlertDescription>
            </Alert>
          ) : (
            <Card>
              <CardHeader>
                <CardTitle>
                  Messages from @{selectedResult.channel.username}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[600px]">
                  <div className="space-y-4">
                    {selectedResult.messages
                      .slice()
                      .sort(
                        (a, b) => b.sensitivityScore - a.sensitivityScore
                      )
                      .map(msg => (
                        <Card
                          key={msg.id}
                          className={
                            msg.leakIndicators.length > 0
                              ? 'border-red-500'
                              : ''
                          }
                        >
                          <CardContent className="pt-4 space-y-3">
                            <div className="flex justify-between text-xs">
                              <Badge variant={categoryVariant(msg.category)}>
                                {msg.category}
                              </Badge>
                              <span>
                                <Clock className="inline h-3 w-3 mr-1" />
                                {new Date(msg.date).toLocaleString()}
                              </span>
                            </div>

                            <p className="text-sm">{msg.message}</p>

                            {msg.links.length > 0 && (
                              <>
                                <Separator />
                                {msg.links.map(l => (
                                  <a
                                    key={l}
                                    href={l}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-xs text-blue-500 flex items-center gap-1"
                                  >
                                    <ExternalLink className="h-3 w-3" />
                                    {l}
                                  </a>
                                ))}
                              </>
                            )}
                          </CardContent>
                        </Card>
                      ))}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}

/* ============================================================================
   SMALL STAT CARD
============================================================================ */

function StatCard({
  title,
  value,
  icon: Icon,
  danger,
}: {
  title: string;
  value: string | number;
  icon: any;
  danger?: boolean;
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row justify-between pb-2">
        <CardTitle className="text-sm">{title}</CardTitle>
        <Icon className={`h-4 w-4 ${danger ? 'text-red-500' : ''}`} />
      </CardHeader>
      <CardContent>
        <div className={`text-2xl font-bold ${danger ? 'text-red-500' : ''}`}>
          {value}
        </div>
      </CardContent>
    </Card>
  );
}
