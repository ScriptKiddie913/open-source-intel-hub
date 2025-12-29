import { useState, useEffect, useCallback } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Separator } from '@/components/ui/separator';
import { telegramApi, DEFAULT_LEAK_CHANNELS } from '@/services/telegramApi';
import { TelegramMessage, TelegramChannel, ScanResult } from '@/types/telegram';
import {
  Send,
  Search,
  AlertTriangle,
  Shield,
  Database,
  Activity,
  Hash,
  Link as LinkIcon,
  Eye,
  Loader2,
  Radio,
  Zap,
  FileWarning,
  Clock,
  TrendingUp,
  Users,
  MessageSquare,
  ExternalLink,
} from 'lucide-react';

export function TelegramScanner() {
  const [channelInput, setChannelInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  const [selectedResult, setSelectedResult] = useState<ScanResult | null>(null);
  const [autoScanning, setAutoScanning] = useState(false);
  const [activeTab, setActiveTab] = useState('scanner');
  const [hasInitialized, setHasInitialized] = useState(false);

  // Use useCallback to memoize the function
  const quickScanDefaults = useCallback(async () => {
    if (hasInitialized) return; // Prevent multiple calls
    
    setLoading(true);
    setHasInitialized(true);
    try {
      const results = await telegramApi.scanMultipleChannels(DEFAULT_LEAK_CHANNELS. slice(0, 3), 20);
      setScanResults(results);
      if (results.length > 0) {
        setSelectedResult(results[0]);
      }
    } catch (error) {
      console.error('Error scanning defaults:', error);
    } finally {
      setLoading(false);
    }
  }, [hasInitialized]);

  useEffect(() => {
    // Only run once on mount
    if (scanResults.length === 0 && !hasInitialized) {
      quickScanDefaults();
    }
  }, []); // Empty dependency array - run once

  const handleScanChannel = async () => {
    if (!channelInput.trim()) return;

    setLoading(true);
    try {
      const result = await telegramApi.scrapeChannel(channelInput, 50);
      setScanResults(prev => [result, ...prev]);
      setSelectedResult(result);
      setChannelInput('');
      setActiveTab('results');
    } catch (error) {
      console.error('Error scanning channel:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleBulkScan = async () => {
    setLoading(true);
    setAutoScanning(true);
    try {
      const results = await telegramApi.scanMultipleChannels(DEFAULT_LEAK_CHANNELS, 30);
      setScanResults(results);
      setActiveTab('results');
    } catch (error) {
      console.error('Error bulk scanning:', error);
    } finally {
      setLoading(false);
      setAutoScanning(false);
    }
  };

  const manualQuickScan = () => {
    setHasInitialized(false); // Reset to allow manual trigger
    quickScanDefaults();
  };

  const getCategoryColor = (category: TelegramMessage['category']) => {
    switch (category) {
      case 'breach':  return 'destructive';
      case 'ransomware': return 'destructive';
      case 'credentials': return 'destructive';
      case 'database': return 'default';
      case 'leak': return 'default';
      default: return 'secondary';
    }
  };

  const getRiskLevelColor = (level: TelegramChannel['riskLevel']) => {
    switch (level) {
      case 'critical': return 'destructive';
      case 'high': return 'destructive';
      case 'medium': return 'default';
      case 'low':  return 'secondary';
    }
  };

  const totalLeaks = scanResults.reduce((sum, r) => sum + r.leaksFound, 0);
  const totalMessages = scanResults.reduce((sum, r) => sum + r.totalMessages, 0);
  const avgSensitivity = selectedResult 
    ? (selectedResult.messages.reduce((sum, m) => sum + m.sensitivityScore, 0) / selectedResult.messages.length) || 0
    : 0;

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Send className="h-8 w-8 text-blue-500" />
            Telegram Leak Scanner
          </h1>
          <p className="text-muted-foreground mt-1">
            Monitor public Telegram channels for data leaks and breaches
          </p>
        </div>
        <div className="flex gap-2">
          <Button onClick={manualQuickScan} variant="outline" disabled={loading}>
            <Zap className={`mr-2 h-4 w-4 ${loading ? 'animate-pulse' : ''}`} />
            Quick Scan
          </Button>
          <Button onClick={handleBulkScan} disabled={loading || autoScanning}>
            {autoScanning ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> :  <Radio className="mr-2 h-4 w-4" />}
            Bulk Scan
          </Button>
        </div>
      </div>

      {/* Stats Overview */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Channels Scanned</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{scanResults.length}</div>
            <p className="text-xs text-muted-foreground">Active monitoring</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Messages</CardTitle>
            <MessageSquare className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalMessages}</div>
            <p className="text-xs text-muted-foreground">Analyzed</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Leaks Detected</CardTitle>
            <AlertTriangle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-500">{totalLeaks}</div>
            <p className="text-xs text-muted-foreground">Potential threats</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Avg Sensitivity</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{avgSensitivity.toFixed(0)}%</div>
            <p className="text-xs text-muted-foreground">Risk score</p>
          </CardContent>
        </Card>
      </div>

      {/* Scanner Input */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Enter Telegram channel username (e.g., @channelname or channelname)"
                value={channelInput}
                onChange={(e) => setChannelInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleScanChannel()}
                className="pl-10"
              />
            </div>
            <Button onClick={handleScanChannel} disabled={loading || !channelInput.trim()}>
              {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Eye className="mr-2 h-4 w-4" />}
              Scan Channel
            </Button>
          </div>
          <p className="text-xs text-muted-foreground mt-2">
            Note: Only public Telegram channels can be scanned. Private channels require authentication.
          </p>
        </CardContent>
      </Card>

      {/* Main Content Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="scanner">Default Channels</TabsTrigger>
          <TabsTrigger value="results">
            Scan Results
            {scanResults.length > 0 && (
              <Badge variant="secondary" className="ml-2">{scanResults.length}</Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="messages">Messages</TabsTrigger>
        </TabsList>

        {/* Default Channels Tab */}
        <TabsContent value="scanner" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Popular Leak Channels</CardTitle>
              <CardDescription>
                Commonly monitored public channels known for posting data breaches and leaks
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-2">
                {DEFAULT_LEAK_CHANNELS.map((channel) => (
                  <div key={channel} className="flex items-center justify-between p-3 border rounded-lg">
                    <div className="flex items-center gap-3">
                      <Send className="h-4 w-4 text-blue-500" />
                      <span className="font-mono">t.me/{channel}</span>
                    </div>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        setChannelInput(channel);
                        handleScanChannel();
                      }}
                      disabled={loading}
                    >
                      Scan
                    </Button>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Results Tab */}
        <TabsContent value="results" className="space-y-4">
          {scanResults.length === 0 ? (
            <Card>
              <CardContent className="pt-6">
                <Alert>
                  <AlertDescription>
                    No scan results yet. Enter a channel username above or use Quick Scan to get started.
                  </AlertDescription>
                </Alert>
              </CardContent>
            </Card>
          ) : (
            <div className="grid gap-4 md:grid-cols-2">
              {scanResults.map((result, index) => (
                <Card 
                  key={index} 
                  className={`cursor-pointer transition-all ${selectedResult === result ? 'ring-2 ring-primary' : ''}`}
                  onClick={() => {
                    setSelectedResult(result);
                    setActiveTab('messages');
                  }}
                >
                  <CardHeader>
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <CardTitle className="flex items-center gap-2">
                          <Send className="h-5 w-5 text-blue-500" />
                          {result.channel. title}
                        </CardTitle>
                        <CardDescription className="font-mono text-xs mt-1">
                          @{result.channel.username}
                        </CardDescription>
                      </div>
                      <Badge variant={getRiskLevelColor(result.channel.riskLevel)}>
                        {result.channel.riskLevel}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {result.channel.description && (
                      <p className="text-sm text-muted-foreground line-clamp-2">
                        {result.channel.description}
                      </p>
                    )}
                    
                    <div className="grid grid-cols-3 gap-2 text-sm">
                      <div>
                        <div className="text-muted-foreground">Messages</div>
                        <div className="font-bold">{result.totalMessages}</div>
                      </div>
                      <div>
                        <div className="text-muted-foreground">Leaks</div>
                        <div className="font-bold text-red-500">{result. leaksFound}</div>
                      </div>
                      <div>
                        <div className="text-muted-foreground">Scan Time</div>
                        <div className="font-bold">{(result.scanDuration / 1000).toFixed(1)}s</div>
                      </div>
                    </div>

                    {result.channel.subscriberCount > 0 && (
                      <div className="flex items-center gap-2 text-xs text-muted-foreground">
                        <Users className="h-3 w-3" />
                        {result.channel. subscriberCount. toLocaleString()} subscribers
                      </div>
                    )}

                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                      <Clock className="h-3 w-3" />
                      Last scanned: {new Date(result. channel.lastScanned || '').toLocaleString()}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* Messages Tab */}
        <TabsContent value="messages" className="space-y-4">
          {! selectedResult ? (
            <Card>
              <CardContent className="pt-6">
                <Alert>
                  <AlertDescription>
                    Select a channel from the Scan Results tab to view its messages.
                  </AlertDescription>
                </Alert>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardHeader>
                <CardTitle>Messages from @{selectedResult.channel.username}</CardTitle>
                <CardDescription>
                  Showing {selectedResult.messages.length} messages with leak detection analysis
                </CardDescription>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[600px]">
                  <div className="space-y-4">
                    {selectedResult. messages
                      .sort((a, b) => b.sensitivityScore - a.sensitivityScore)
                      .map((message) => (
                        <Card key={message.id} className={message.leakIndicators.length > 0 ? 'border-red-500' : ''}>
                          <CardContent className="pt-6">
                            <div className="space-y-3">
                              {/* Message Header */}
                              <div className="flex items-start justify-between">
                                <div className="flex items-center gap-2">
                                  <Badge variant={getCategoryColor(message.category)}>
                                    {message.category}
                                  </Badge>
                                  {message.sensitivityScore > 50 && (
                                    <Badge variant="destructive">
                                      {message.sensitivityScore}% Sensitive
                                    </Badge>
                                  )}
                                </div>
                                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                                  <Clock className="h-3 w-3" />
                                  {new Date(message.date).toLocaleString()}
                                </div>
                              </div>

                              {/* Message Content */}
                              <div className="text-sm">
                                {message.message}
                              </div>

                              {/* Leak Indicators */}
                              {message. leakIndicators.length > 0 && (
                                <div className="space-y-2">
                                  <Separator />
                                  <div>
                                    <h4 className="text-sm font-semibold flex items-center gap-2 mb-2">
                                      <AlertTriangle className="h-4 w-4 text-red-500" />
                                      Leak Indicators Detected
                                    </h4>
                                    <div className="space-y-1">
                                      {message.leakIndicators.map((indicator, idx) => (
                                        <div key={idx} className="flex items-center gap-2 text-xs">
                                          <Badge variant="outline">{indicator. type}</Badge>
                                          <span className="font-mono">{indicator.matched}</span>
                                          <span className="text-muted-foreground">
                                            ({(indicator.confidence * 100).toFixed(0)}% confidence)
                                          </span>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                </div>
                              )}

                              {/* Links */}
                              {message. links. length > 0 && (
                                <div className="space-y-1">
                                  <h4 className="text-xs font-semibold flex items-center gap-1">
                                    <LinkIcon className="h-3 w-3" />
                                    Links ({message.links.length})
                                  </h4>
                                  <div className="space-y-1">
                                    {message.links.map((link, idx) => (
                                      <div key={idx} className="flex items-center gap-2 text-xs font-mono">
                                        <ExternalLink className="h-3 w-3" />
                                        <a href={link} target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:underline truncate">
                                          {link}
                                        </a>
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}

                              {/* Metadata */}
                              <div className="flex items-center gap-4 text-xs text-muted-foreground">
                                <div className="flex items-center gap-1">
                                  <Eye className="h-3 w-3" />
                                  {message.views. toLocaleString()} views
                                </div>
                                {message.hashtags.length > 0 && (
                                  <div className="flex gap-1">
                                    {message.hashtags.map(tag => (
                                      <span key={tag}>{tag}</span>
                                    ))}
                                  </div>
                                )}
                              </div>
                            </div>
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
