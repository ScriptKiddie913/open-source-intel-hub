// ============================================================================
// StealthMoleScanner.tsx
// STEALTHMOLE-STYLE UNIFIED THREAT INTELLIGENCE DASHBOARD
// ============================================================================
// ✔ Deep dark web scanning
// ✔ Malware activity tracking
// ✔ Stealer log detection
// ✔ Ransomware monitoring
// ✔ Telegram intelligence
// ✔ LLM-powered analysis
// ✔ MITRE ATT&CK mapping
// ============================================================================

'use client';

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';

import {
  Radar,
  Search,
  Loader2,
  AlertTriangle,
  Globe,
  Database,
  Eye,
  Clock,
  RefreshCcw,
  Layers,
  Shield,
  Activity,
  ExternalLink,
  Hash,
  Info,
  Brain,
  Zap,
  Bug,
  Skull,
  MessageSquare,
  Server,
  Key,
  Lock,
  FileWarning,
  BarChart3,
  Network,
  Target,
  AlertOctagon,
  ShieldAlert,
  Fingerprint,
  Radio,
  Flame,
  Users,
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from '@/components/ui/accordion';

// Services
import {
  searchMalwareActivity,
  type MalwareSearchResult,
  type MalwareIndicator,
  type RansomwareGroup,
  type StealerLog,
  type C2Server,
  type MalwareSample,
} from '@/services/malwareTrackingService';

import {
  deepSearchTelegram,
  type TelegramSearchResult,
  type TelegramIntelResult,
} from '@/services/advancedTelegramService';

import {
  deepSearchDarkWeb,
  discoverOnionSites,
  type OnionSite,
  type LeakSignal,
  type DeepSearchResult,
} from '@/services/torService';

import {
  analyzeLeakIntelligence,
  extractEntities,
  type LeakAnalysis,
  type ExtractedEntity,
} from '@/services/llmAnalysisService';

import {
  queryThreatIntel,
  type ThreatIntelResult,
} from '@/services/threatIntelService';

import { toast } from 'sonner';
import { cn } from '@/lib/utils';

/* ============================================================================
   TYPES
============================================================================ */

type TabMode = 
  | 'overview' 
  | 'leaks' 
  | 'malware' 
  | 'ransomware' 
  | 'stealers' 
  | 'telegram' 
  | 'c2' 
  | 'onions'
  | 'analysis';

interface UnifiedSearchResult {
  // Core results
  darkWebSignals: LeakSignal[];
  onionSites: OnionSite[];
  
  // Malware tracking
  malwareIndicators: MalwareIndicator[];
  ransomwareGroups: RansomwareGroup[];
  stealerLogs: StealerLog[];
  c2Servers: C2Server[];
  malwareSamples: MalwareSample[];
  
  // Hash verification results
  hashAnalysis: ThreatIntelResult | null;
  
  // Telegram intelligence
  telegramResults: TelegramIntelResult[];
  telegramStealerLogs: TelegramIntelResult[];
  telegramRansomware: TelegramIntelResult[];
  
  // Analysis
  entities: ExtractedEntity[];
  analysis: LeakAnalysis | null;
  
  // Stats
  stats: {
    totalFindings: number;
    criticalThreats: number;
    highThreats: number;
    malwareIOCs: number;
    ransomwareHits: number;
    stealerLogHits: number;
    activeC2s: number;
    telegramHits: number;
    entitiesExtracted: number;
    sourcesScanned: number;
  };
  
  // Meta
  searchTime: number;
  searchQuery: string;
}

/* ============================================================================
   CONSTANTS
============================================================================ */

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'border-red-500/40 bg-red-500/10 text-red-400',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-400',
  medium: 'border-yellow-500/40 bg-yellow-500/10 text-yellow-400',
  low: 'border-blue-500/40 bg-blue-500/10 text-blue-400',
  info: 'border-gray-500/40 bg-gray-500/10 text-gray-400',
};

const MITRE_DESCRIPTIONS: Record<string, string> = {
  'T1078': 'Valid Accounts',
  'T1110': 'Brute Force',
  'T1552': 'Unsecured Credentials',
  'T1486': 'Data Encrypted for Impact',
  'T1490': 'Inhibit System Recovery',
  'T1489': 'Service Stop',
  'T1555': 'Credentials from Password Stores',
  'T1539': 'Steal Web Session Cookie',
  'T1056': 'Input Capture',
  'T1113': 'Screen Capture',
  'T1219': 'Remote Access Software',
  'T1071': 'Application Layer Protocol',
  'T1105': 'Ingress Tool Transfer',
  'T1547': 'Boot or Logon Autostart Execution',
  'T1583': 'Acquire Infrastructure',
  'T1584': 'Compromise Infrastructure',
  'T1090': 'Proxy',
  'T1573': 'Encrypted Channel',
  'T1059': 'Command and Scripting Interpreter',
};

/* ============================================================================
   UTILITY FUNCTIONS
============================================================================ */

// Detect if input is a hash and return its type
function detectHashType(input: string): 'md5' | 'sha1' | 'sha256' | 'sha512' | null {
  const trimmed = input.trim().replace(/[^a-fA-F0-9]/g, '');
  
  // Only consider it a hash if the entire trimmed input matches hash pattern
  // and original input doesn't contain spaces or other non-hex characters (except case)
  const originalClean = input.trim().replace(/[^a-fA-F0-9]/gi, '');
  if (trimmed !== originalClean.toLowerCase()) {
    return null; // Contains invalid characters for a hash
  }
  
  if (/^[a-fA-F0-9]{32}$/.test(trimmed)) {
    return 'md5';
  } else if (/^[a-fA-F0-9]{40}$/.test(trimmed)) {
    return 'sha1';
  } else if (/^[a-fA-F0-9]{64}$/.test(trimmed)) {
    return 'sha256';
  } else if (/^[a-fA-F0-9]{128}$/.test(trimmed)) {
    return 'sha512';
  }
  
  return null;
}

/* ============================================================================
   MAIN COMPONENT
============================================================================ */

export function StealthMoleScanner() {
  // State
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState<TabMode>('overview');
  
  // Search options
  const [enableMalwareTracking, setEnableMalwareTracking] = useState(true);
  const [enableTelegramIntel, setEnableTelegramIntel] = useState(true);
  const [enableDarkWebScan, setEnableDarkWebScan] = useState(true);
  const [enableLLMAnalysis, setEnableLLMAnalysis] = useState(true);
  
  // Results
  const [results, setResults] = useState<UnifiedSearchResult | null>(null);
  
  // Refresh timer
  const refreshTimer = useRef<number | null>(null);

  /* --------------------------------------------------------------------------
     SEARCH FUNCTION
  -------------------------------------------------------------------------- */
  
  const runUnifiedSearch = useCallback(async () => {
    if (!query.trim()) {
      toast.error('Enter a search indicator (domain, email, IP, company, etc.)');
      return;
    }
    
    setLoading(true);
    const startTime = Date.now();
    
    console.log(`\n${'='.repeat(60)}`);
    console.log(`[StealthMole] UNIFIED DEEP SCAN: "${query}"`);
    const hashType = detectHashType(query);
    if (hashType) {
      console.log(`[StealthMole] 🔍 HASH DETECTED: ${hashType.toUpperCase()} - Enhanced malware analysis enabled`);
    }
    console.log(`${'='.repeat(60)}\n`);
    
    try {
      // Initialize result structure
      const unifiedResult: UnifiedSearchResult = {
        darkWebSignals: [],
        onionSites: [],
        malwareIndicators: [],
        ransomwareGroups: [],
        stealerLogs: [],
        c2Servers: [],
        malwareSamples: [],
        hashAnalysis: null,
        telegramResults: [],
        telegramStealerLogs: [],
        telegramRansomware: [],
        entities: [],
        analysis: null,
        stats: {
          totalFindings: 0,
          criticalThreats: 0,
          highThreats: 0,
          malwareIOCs: 0,
          ransomwareHits: 0,
          stealerLogHits: 0,
          activeC2s: 0,
          telegramHits: 0,
          entitiesExtracted: 0,
          sourcesScanned: 0,
        },
        searchTime: 0,
        searchQuery: query,
      };
      
      // Run all searches in parallel
      const searchPromises: Promise<void>[] = [];
      
      // 1. Dark Web Search
      if (enableDarkWebScan) {
        searchPromises.push(
          (async () => {
            try {
              const [darkWebResult, onions] = await Promise.all([
                deepSearchDarkWeb({
                  indicator: query,
                  includeBreachDatabases: true,
                  includeDarkWebSearch: true,
                  includeCodeSearch: true,
                  includePasteSites: true,
                  includeLeakArchives: true,
                  includeSocialMedia: true,
                  maxResultsPerSource: 25,
                  enableLLMAnalysis: false, // We'll do unified analysis
                }),
                discoverOnionSites(query),
              ]);
              
              unifiedResult.darkWebSignals = darkWebResult.signals;
              unifiedResult.onionSites = onions;
              unifiedResult.entities.push(...darkWebResult.entities);
              console.log(`[DarkWeb] ✅ ${darkWebResult.signals.length} signals, ${onions.length} onions`);
            } catch (err) {
              console.error('[DarkWeb] ❌ Error:', err);
            }
          })()
        );
      }
      
      // 2. Malware Tracking with Enhanced Hash Checking
      if (enableMalwareTracking) {
        searchPromises.push(
          (async () => {
            try {
              // Check if input is a hash and run dedicated hash analysis
              const hashType = detectHashType(query);
              if (hashType) {
                console.log(`[Hash] Detected ${hashType.toUpperCase()} hash, running threat intel check`);
                try {
                  const hashResult = await queryThreatIntel('hash', query.trim(), ['virustotal', 'abuse', 'circl']);
                  unifiedResult.hashAnalysis = hashResult;
                  
                  if (hashResult.success && hashResult.formatted) {
                    console.log(`[Hash] ✅ Hash analysis complete - Risk: ${hashResult.formatted.riskLevel}, Score: ${hashResult.formatted.riskScore}`);
                    
                    // Convert hash analysis to malware indicators if malicious
                    if (hashResult.formatted.riskLevel === 'critical' || hashResult.formatted.riskLevel === 'high') {
                      unifiedResult.malwareIndicators.push({
                        id: `hash_${Date.now()}`,
                        type: 'hash',
                        value: query.trim(),
                        malwareFamily: hashResult.formatted.categories[0] || 'Unknown',
                        category: 'unknown',
                        severity: hashResult.formatted.riskLevel as 'critical' | 'high',
                        firstSeen: new Date().toISOString(),
                        lastSeen: new Date().toISOString(),
                        source: 'Threat Intelligence',
                        sourceUrl: '',
                        confidence: hashResult.formatted.riskScore,
                        tags: hashResult.formatted.categories,
                        mitreAttack: [],
                        description: hashResult.formatted.summary,
                      });
                    }
                  }
                } catch (hashError) {
                  console.error('[Hash] ❌ Hash analysis failed:', hashError);
                }
              }
              
              // Run standard malware activity search
              const malwareResult = await searchMalwareActivity(query);
              unifiedResult.malwareIndicators.push(...malwareResult.indicators);
              unifiedResult.ransomwareGroups = malwareResult.ransomwareGroups;
              unifiedResult.stealerLogs = malwareResult.stealerLogs;
              unifiedResult.c2Servers = malwareResult.c2Servers;
              unifiedResult.malwareSamples = malwareResult.malwareSamples;
              
              console.log(`[Malware] ✅ ${unifiedResult.malwareIndicators.length} total IOCs (${hashType ? 'including hash analysis' : 'standard search'})`);
            } catch (err) {
              console.error('[Malware] ❌ Error:', err);
            }
          })()
        );
      }
      
      // 3. Telegram Intelligence
      if (enableTelegramIntel) {
        searchPromises.push(
          (async () => {
            try {
              const telegramResult = await deepSearchTelegram(query);
              unifiedResult.telegramResults = telegramResult.results;
              unifiedResult.telegramStealerLogs = telegramResult.stealerLogs;
              unifiedResult.telegramRansomware = telegramResult.ransomwareLeaks;
              console.log(`[Telegram] ✅ ${telegramResult.stats.totalResults} results`);
            } catch (err) {
              console.error('[Telegram] ❌ Error:', err);
            }
          })()
        );
      }
      
      // Wait for all searches
      await Promise.allSettled(searchPromises);
      
      // 4. LLM Analysis (on combined data)
      if (enableLLMAnalysis) {
        try {
          // Combine all findings for analysis
          const allFindings = [
            ...unifiedResult.darkWebSignals.map(s => ({
              source: s.source,
              title: s.title,
              context: s.context,
              timestamp: s.timestamp,
            })),
            ...unifiedResult.malwareIndicators.map(i => ({
              source: i.source,
              title: `${i.malwareFamily} - ${i.type}`,
              context: i.description,
              timestamp: i.firstSeen,
            })),
            ...unifiedResult.telegramResults.map(t => ({
              source: t.source,
              title: t.title,
              context: t.rawSnippet,
              timestamp: t.timestamp,
            })),
          ];
          
          if (allFindings.length > 0) {
            // Extract additional entities
            const allText = allFindings.map(f => `${f.title} ${f.context}`).join('\n');
            const additionalEntities = extractEntities(allText, query);
            unifiedResult.entities.push(...additionalEntities);
            
            // Deduplicate entities
            unifiedResult.entities = Array.from(
              new Map(unifiedResult.entities.map(e => [`${e.type}:${e.value}`, e])).values()
            );
            
            // Run full analysis
            unifiedResult.analysis = await analyzeLeakIntelligence(query, allFindings);
            console.log(`[LLM] ✅ Analysis complete, score: ${unifiedResult.analysis.threatAssessment.score}`);
          }
        } catch (err) {
          console.error('[LLM] ❌ Analysis error:', err);
        }
      }
      
      // Calculate stats
      const hashThreatCount = unifiedResult.hashAnalysis?.formatted?.riskLevel === 'critical' || 
                             unifiedResult.hashAnalysis?.formatted?.riskLevel === 'high' ? 1 : 0;
      
      unifiedResult.stats = {
        totalFindings: 
          unifiedResult.darkWebSignals.length +
          unifiedResult.malwareIndicators.length +
          unifiedResult.telegramResults.length +
          hashThreatCount,
        criticalThreats: 
          unifiedResult.darkWebSignals.filter(s => s.severity === 'critical').length +
          unifiedResult.malwareIndicators.filter(i => i.severity === 'critical').length +
          unifiedResult.telegramResults.filter(t => t.severity === 'critical').length +
          (unifiedResult.hashAnalysis?.formatted?.riskLevel === 'critical' ? 1 : 0),
        highThreats:
          unifiedResult.darkWebSignals.filter(s => s.severity === 'high').length +
          unifiedResult.malwareIndicators.filter(i => i.severity === 'high').length +
          unifiedResult.telegramResults.filter(t => t.severity === 'high').length +
          (unifiedResult.hashAnalysis?.formatted?.riskLevel === 'high' ? 1 : 0),
        malwareIOCs: unifiedResult.malwareIndicators.length + hashThreatCount,
        ransomwareHits: unifiedResult.ransomwareGroups.length + unifiedResult.telegramRansomware.length,
        stealerLogHits: unifiedResult.stealerLogs.length + unifiedResult.telegramStealerLogs.length,
        activeC2s: unifiedResult.c2Servers.filter(c => c.status === 'active').length,
        telegramHits: unifiedResult.telegramResults.length,
        entitiesExtracted: unifiedResult.entities.length,
        sourcesScanned: 20, // Approximate
      };
      
      unifiedResult.searchTime = Date.now() - startTime;
      
      setResults(unifiedResult);
      
      // Show toast
      if (unifiedResult.stats.totalFindings === 0) {
        const hashType = detectHashType(query);
        if (hashType && unifiedResult.hashAnalysis?.formatted?.riskLevel === 'info') {
          toast.info(`Hash ${hashType.toUpperCase()} analyzed - appears clean from threat databases.`);
        } else {
          toast.info('No threats found. The indicator appears clean.');
        }
      } else {
        const hashType = detectHashType(query);
        const hashNote = hashType && unifiedResult.hashAnalysis ? ' (including hash analysis)' : '';
        toast.success(
          `Found ${unifiedResult.stats.totalFindings} findings (${unifiedResult.stats.criticalThreats} critical) in ${(unifiedResult.searchTime / 1000).toFixed(1)}s${hashNote}`
        );
      }
      
      console.log(`\n[StealthMole] Search completed in ${unifiedResult.searchTime}ms`);
      console.log(`[StealthMole] Total findings: ${unifiedResult.stats.totalFindings}\n`);
      
    } catch (err) {
      console.error('[StealthMole] Search failed:', err);
      toast.error('Search failed. Check console for details.');
    } finally {
      setLoading(false);
    }
  }, [query, enableMalwareTracking, enableTelegramIntel, enableDarkWebScan, enableLLMAnalysis]);

  /* --------------------------------------------------------------------------
     AUTO REFRESH
  -------------------------------------------------------------------------- */
  
  useEffect(() => {
    if (refreshTimer.current) {
      window.clearInterval(refreshTimer.current);
    }
    
    refreshTimer.current = window.setInterval(() => {
      if (query.trim() && !loading) {
        console.log('[StealthMole] Auto-refresh triggered');
        runUnifiedSearch();
      }
    }, 600000); // 10 minutes
    
    return () => {
      if (refreshTimer.current) {
        window.clearInterval(refreshTimer.current);
      }
    };
  }, [query, loading, runUnifiedSearch]);

  /* --------------------------------------------------------------------------
     RENDER
  -------------------------------------------------------------------------- */
  
  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* HEADER */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Radar className="h-8 w-8 text-primary animate-pulse" />
            StealthMole Intelligence Platform
            <Badge variant="outline" className="ml-2 text-xs bg-red-500/10 border-red-500/40">
              <Skull className="h-3 w-3 mr-1" />
              HARDCORE MODE
            </Badge>
          </h1>
          <p className="text-muted-foreground mt-2">
            Unified threat intelligence: Dark Web • Malware • Ransomware • Stealers • Telegram • C2
          </p>
        </div>

        <div className="flex items-center gap-4 flex-wrap">
          <div className="flex items-center gap-2">
            <Switch id="malware" checked={enableMalwareTracking} onCheckedChange={setEnableMalwareTracking} />
            <Label htmlFor="malware" className="text-xs">Malware</Label>
          </div>
          <div className="flex items-center gap-2">
            <Switch id="telegram" checked={enableTelegramIntel} onCheckedChange={setEnableTelegramIntel} />
            <Label htmlFor="telegram" className="text-xs">Telegram</Label>
          </div>
          <div className="flex items-center gap-2">
            <Switch id="darkweb" checked={enableDarkWebScan} onCheckedChange={setEnableDarkWebScan} />
            <Label htmlFor="darkweb" className="text-xs">Dark Web</Label>
          </div>
          <div className="flex items-center gap-2">
            <Switch id="llm" checked={enableLLMAnalysis} onCheckedChange={setEnableLLMAnalysis} />
            <Label htmlFor="llm" className="text-xs">AI Analysis</Label>
          </div>
          <Button variant="outline" size="sm" onClick={runUnifiedSearch} disabled={loading}>
            <RefreshCcw className={cn('h-4 w-4 mr-2', loading && 'animate-spin')} />
            Scan
          </Button>
        </div>
      </div>

      {/* SEARCH BAR */}
      <Card className="border-primary/30 bg-gradient-to-r from-primary/5 to-transparent">
        <CardContent className="pt-6">
          <div className="flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-muted-foreground" />
              <Input
                value={query}
                onChange={e => setQuery(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && runUnifiedSearch()}
                placeholder="Enter indicator: domain, email, IP, company, malware name, hash..."
                className="pl-11 text-lg h-12"
              />
            </div>
            <Button onClick={runUnifiedSearch} disabled={loading} size="lg" className="px-8">
              {loading ? (
                <Loader2 className="h-5 w-5 animate-spin" />
              ) : (
                <>
                  <Eye className="h-5 w-5 mr-2" />
                  Hunt
                </>
              )}
            </Button>
          </div>
          <div className="mt-3 flex items-center gap-2 text-xs text-muted-foreground">
            <Info className="h-3 w-3" />
            <span>
              Examples: "lockbit", "redline stealer", "example.com", "user@email.com", "192.168.1.1", "CVE-2024-*", "a1b2c3d4..."
            </span>
          </div>
        </CardContent>
      </Card>

      {/* STATS GRID */}
      {results && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 xl:grid-cols-10 gap-3">
          <StatCard icon={Target} label="Total" value={results.stats.totalFindings} color="text-primary" />
          <StatCard icon={AlertOctagon} label="Critical" value={results.stats.criticalThreats} color="text-red-500" />
          <StatCard icon={ShieldAlert} label="High" value={results.stats.highThreats} color="text-orange-500" />
          <StatCard icon={Bug} label="Malware IOCs" value={results.stats.malwareIOCs} color="text-purple-500" />
          <StatCard icon={Skull} label="Ransomware" value={results.stats.ransomwareHits} color="text-red-600" />
          <StatCard icon={Key} label="Stealer Logs" value={results.stats.stealerLogHits} color="text-yellow-500" />
          <StatCard icon={Server} label="Active C2" value={results.stats.activeC2s} color="text-cyan-500" />
          <StatCard icon={MessageSquare} label="Telegram" value={results.stats.telegramHits} color="text-blue-500" />
          <StatCard icon={Fingerprint} label="Entities" value={results.stats.entitiesExtracted} color="text-green-500" />
          <StatCard icon={Zap} label="Time" value={`${(results.searchTime / 1000).toFixed(1)}s`} color="text-yellow-400" />
        </div>
      )}

      {/* MAIN TABS */}
      <Tabs value={tab} onValueChange={v => setTab(v as TabMode)}>
        <TabsList className="grid w-full grid-cols-5 lg:grid-cols-9">
          <TabsTrigger value="overview" className="text-xs">
            <BarChart3 className="h-3 w-3 mr-1" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="leaks" className="text-xs">
            <Database className="h-3 w-3 mr-1" />
            Leaks
          </TabsTrigger>
          <TabsTrigger value="malware" className="text-xs">
            <Bug className="h-3 w-3 mr-1" />
            Malware
          </TabsTrigger>
          <TabsTrigger value="ransomware" className="text-xs">
            <Skull className="h-3 w-3 mr-1" />
            Ransom
          </TabsTrigger>
          <TabsTrigger value="stealers" className="text-xs">
            <Key className="h-3 w-3 mr-1" />
            Stealers
          </TabsTrigger>
          <TabsTrigger value="telegram" className="text-xs">
            <MessageSquare className="h-3 w-3 mr-1" />
            Telegram
          </TabsTrigger>
          <TabsTrigger value="c2" className="text-xs">
            <Server className="h-3 w-3 mr-1" />
            C2
          </TabsTrigger>
          <TabsTrigger value="onions" className="text-xs">
            <Globe className="h-3 w-3 mr-1" />
            Onions
          </TabsTrigger>
          <TabsTrigger value="analysis" className="text-xs">
            <Brain className="h-3 w-3 mr-1" />
            AI
          </TabsTrigger>
        </TabsList>

        {/* OVERVIEW TAB */}
        <TabsContent value="overview" className="mt-6">
          {!results && !loading && (
            <EmptyState 
              icon={Radar} 
              title="Ready to Hunt"
              description="Enter an indicator above to begin deep threat intelligence scanning"
            />
          )}
          
          {loading && <LoadingState />}
          
          {results && !loading && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Threat Assessment */}
              {results.analysis && (
                <ThreatAssessmentCard analysis={results.analysis} />
              )}
              
              {/* Top Threats */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Flame className="h-5 w-5 text-red-500" />
                    Top Threats
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <ScrollArea className="h-[300px]">
                    {[
                      ...results.malwareIndicators.filter(i => i.severity === 'critical').slice(0, 3),
                      ...results.telegramStealerLogs.slice(0, 2),
                      ...results.darkWebSignals.filter(s => s.severity === 'critical').slice(0, 2),
                    ].map((item, i) => (
                      <ThreatItem key={i} item={item} />
                    ))}
                    {results.stats.criticalThreats === 0 && (
                      <p className="text-center text-muted-foreground py-8">
                        No critical threats detected
                      </p>
                    )}
                  </ScrollArea>
                </CardContent>
              </Card>
              
              {/* Entity Breakdown */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Fingerprint className="h-5 w-5 text-green-500" />
                    Extracted Entities
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-2">
                    {Object.entries(
                      results.entities.reduce((acc, e) => {
                        acc[e.type] = (acc[e.type] || 0) + 1;
                        return acc;
                      }, {} as Record<string, number>)
                    ).map(([type, count]) => (
                      <div key={type} className="flex justify-between p-2 bg-secondary/50 rounded">
                        <span className="text-sm uppercase">{type}</span>
                        <Badge variant="outline">{count}</Badge>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
              
              {/* MITRE ATT&CK */}
              {results.analysis?.threatAssessment.ttps && results.analysis.threatAssessment.ttps.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Network className="h-5 w-5 text-purple-500" />
                      MITRE ATT&CK TTPs
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {results.analysis.threatAssessment.ttps.map(ttp => (
                        <div key={ttp} className="flex items-center gap-2 p-2 bg-purple-500/10 rounded border border-purple-500/20">
                          <Badge className="bg-purple-500">{ttp}</Badge>
                          <span className="text-sm">{MITRE_DESCRIPTIONS[ttp] || 'Unknown Technique'}</span>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          )}
        </TabsContent>

        {/* LEAKS TAB */}
        <TabsContent value="leaks" className="mt-6 space-y-3">
          {loading && <LoadingState />}
          {!loading && results?.darkWebSignals.length === 0 && (
            <EmptyState icon={Database} title="No Leak Signals" description="No data exposures found for this indicator" />
          )}
          {!loading && results?.darkWebSignals.map(signal => (
            <SignalCard key={signal.id} signal={signal} />
          ))}
        </TabsContent>

        {/* MALWARE TAB */}
        <TabsContent value="malware" className="mt-6 space-y-3">
          {loading && <LoadingState />}
          
          {/* Hash Analysis Section */}
          {!loading && results?.hashAnalysis && (
            <Card className={cn(
              'border-2',
              results.hashAnalysis.formatted?.riskLevel === 'critical' ? 'border-red-500/50 bg-red-500/5' :
              results.hashAnalysis.formatted?.riskLevel === 'high' ? 'border-orange-500/50 bg-orange-500/5' :
              results.hashAnalysis.formatted?.riskLevel === 'medium' ? 'border-yellow-500/50 bg-yellow-500/5' :
              'border-green-500/50 bg-green-500/5'
            )}>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="flex items-center gap-2">
                    <Hash className="h-5 w-5" />
                    Hash Analysis Results
                    <Badge className={cn(
                      'ml-2',
                      results.hashAnalysis.formatted?.riskLevel === 'critical' ? 'bg-red-500' :
                      results.hashAnalysis.formatted?.riskLevel === 'high' ? 'bg-orange-500' :
                      results.hashAnalysis.formatted?.riskLevel === 'medium' ? 'bg-yellow-500' :
                      'bg-green-500'
                    )}>
                      {results.hashAnalysis.formatted?.riskLevel?.toUpperCase()}
                    </Badge>
                  </CardTitle>
                  <Badge variant="outline">
                    Score: {results.hashAnalysis.formatted?.riskScore || 0}/100
                  </Badge>
                </div>
                <CardDescription>
                  {detectHashType(results.searchQuery)?.toUpperCase()} Hash: {results.searchQuery}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <h4 className="font-semibold mb-2">Analysis Summary</h4>
                  <p className="text-sm text-muted-foreground">
                    {results.hashAnalysis.formatted?.summary || 'Hash analysis completed'}
                  </p>
                </div>
                
                {results.hashAnalysis.formatted?.indicators && results.hashAnalysis.formatted.indicators.length > 0 && (
                  <div>
                    <h4 className="font-semibold mb-2">Threat Indicators</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {results.hashAnalysis.formatted.indicators.map((indicator, i) => (
                        <div key={i} className="p-2 bg-muted rounded border">
                          <div className="flex items-center justify-between">
                            <span className="text-sm font-medium">{indicator.type}</span>
                            <Badge variant="outline" className={cn(
                              indicator.severity === 'critical' ? 'border-red-500 text-red-500' :
                              indicator.severity === 'high' ? 'border-orange-500 text-orange-500' :
                              indicator.severity === 'medium' ? 'border-yellow-500 text-yellow-500' :
                              'border-blue-500 text-blue-500'
                            )}>
                              {indicator.severity}
                            </Badge>
                          </div>
                          <div className="text-xs text-muted-foreground mt-1">{indicator.value}</div>
                          <div className="text-xs text-muted-foreground">{indicator.source}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                
                {results.hashAnalysis.formatted?.detections && (
                  <div>
                    <h4 className="font-semibold mb-2">Detection Results</h4>
                    <div className="grid grid-cols-4 gap-4 text-center">
                      <div>
                        <div className="text-2xl font-bold text-red-500">
                          {results.hashAnalysis.formatted.detections.malicious}
                        </div>
                        <div className="text-xs text-muted-foreground">Malicious</div>
                      </div>
                      <div>
                        <div className="text-2xl font-bold text-orange-500">
                          {results.hashAnalysis.formatted.detections.suspicious}
                        </div>
                        <div className="text-xs text-muted-foreground">Suspicious</div>
                      </div>
                      <div>
                        <div className="text-2xl font-bold text-green-500">
                          {results.hashAnalysis.formatted.detections.clean}
                        </div>
                        <div className="text-xs text-muted-foreground">Clean</div>
                      </div>
                      <div>
                        <div className="text-2xl font-bold text-gray-500">
                          {results.hashAnalysis.formatted.detections.undetected}
                        </div>
                        <div className="text-xs text-muted-foreground">Undetected</div>
                      </div>
                    </div>
                  </div>
                )}
                
                {results.hashAnalysis.formatted?.recommendations && results.hashAnalysis.formatted.recommendations.length > 0 && (
                  <div>
                    <h4 className="font-semibold mb-2">Recommendations</h4>
                    <ul className="space-y-1">
                      {results.hashAnalysis.formatted.recommendations.map((rec, i) => (
                        <li key={i} className="text-sm text-muted-foreground flex items-start gap-2">
                          <AlertTriangle className="h-3 w-3 mt-0.5 text-yellow-500" />
                          {rec}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
          
          {!loading && results?.malwareIndicators.length === 0 && !results?.hashAnalysis && (
            <EmptyState icon={Bug} title="No Malware IOCs" description="No malware indicators found" />
          )}
          {!loading && results?.malwareIndicators.map(ioc => (
            <MalwareIOCCard key={ioc.id} ioc={ioc} />
          ))}
        </TabsContent>

        {/* RANSOMWARE TAB */}
        <TabsContent value="ransomware" className="mt-6 space-y-4">
          {loading && <LoadingState />}
          {!loading && results?.ransomwareGroups.length === 0 && results?.telegramRansomware.length === 0 && (
            <EmptyState icon={Skull} title="No Ransomware Activity" description="No ransomware groups or activity detected" />
          )}
          {!loading && results?.ransomwareGroups.map(group => (
            <RansomwareGroupCard key={group.id} group={group} />
          ))}
          {!loading && results?.telegramRansomware.map(item => (
            <TelegramIntelCard key={item.id} item={item} />
          ))}
        </TabsContent>

        {/* STEALERS TAB */}
        <TabsContent value="stealers" className="mt-6 space-y-3">
          {loading && <LoadingState />}
          {!loading && results?.stealerLogs.length === 0 && results?.telegramStealerLogs.length === 0 && (
            <EmptyState icon={Key} title="No Stealer Logs" description="No info-stealer logs detected" />
          )}
          {!loading && (
            <>
              {results?.stealerLogs.map(log => (
                <StealerLogCard key={log.id} log={log} />
              ))}
              {results?.telegramStealerLogs.map(item => (
                <TelegramIntelCard key={item.id} item={item} />
              ))}
            </>
          )}
        </TabsContent>

        {/* TELEGRAM TAB */}
        <TabsContent value="telegram" className="mt-6 space-y-3">
          {loading && <LoadingState />}
          {!loading && results?.telegramResults.length === 0 && (
            <EmptyState icon={MessageSquare} title="No Telegram Intel" description="No Telegram intelligence found" />
          )}
          {!loading && results?.telegramResults.map(item => (
            <TelegramIntelCard key={item.id} item={item} />
          ))}
        </TabsContent>

        {/* C2 TAB */}
        <TabsContent value="c2" className="mt-6 space-y-3">
          {loading && <LoadingState />}
          {!loading && results?.c2Servers.length === 0 && (
            <EmptyState icon={Server} title="No C2 Servers" description="No command & control servers detected" />
          )}
          {!loading && results?.c2Servers.map(c2 => (
            <C2ServerCard key={c2.id} c2={c2} />
          ))}
        </TabsContent>

        {/* ONIONS TAB */}
        <TabsContent value="onions" className="mt-6 space-y-3">
          {loading && <LoadingState />}
          {!loading && results?.onionSites.length === 0 && (
            <EmptyState icon={Globe} title="No Onion Sites" description="No .onion sites discovered" />
          )}
          {!loading && results?.onionSites.map(site => (
            <OnionSiteCard key={site.url} site={site} />
          ))}
        </TabsContent>

        {/* AI ANALYSIS TAB */}
        <TabsContent value="analysis" className="mt-6 space-y-4">
          {loading && <LoadingState />}
          {!loading && !results?.analysis && (
            <EmptyState icon={Brain} title="No Analysis" description="Run a search with AI Analysis enabled" />
          )}
          {!loading && results?.analysis && (
            <>
              <ThreatAssessmentCard analysis={results.analysis} fullWidth />
              
              {/* Entities */}
              <Card>
                <CardHeader>
                  <CardTitle>Extracted Entities ({results.entities.length})</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                    {results.entities.slice(0, 30).map((entity, i) => (
                      <EntityCard key={i} entity={entity} />
                    ))}
                  </div>
                </CardContent>
              </Card>
              
              {/* Timeline */}
              {results.analysis.exposureTimeline.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle>Exposure Timeline</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {results.analysis.exposureTimeline.map((event, i) => (
                        <div key={i} className="flex gap-3 items-start">
                          <div className="w-2 h-2 rounded-full bg-primary mt-2 shrink-0" />
                          <div>
                            <p className="text-xs text-muted-foreground">
                              {new Date(event.date).toLocaleDateString()}
                            </p>
                            <p className="text-sm">{event.event}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </>
          )}
        </TabsContent>
      </Tabs>

      {/* FOOTER */}
      <Card className="border-primary/40 bg-primary/5">
        <CardContent className="p-4 flex gap-3">
          <Radio className="h-5 w-5 text-primary shrink-0 animate-pulse" />
          <div>
            <h3 className="font-semibold">20+ Real-Time Intelligence Sources</h3>
            <p className="text-sm text-muted-foreground mt-1">
              <strong>🦠 Malware:</strong> ThreatFox, URLhaus, MalwareBazaar, FeodoTracker, SSLBL
              {' • '}
              <strong>🔐 Breaches:</strong> Psbdmp, Archive.org, GitHub, Reddit, HackerNews
              {' • '}
              <strong>💀 Ransomware:</strong> Ransomware.live, VX Underground
              {' • '}
              <strong>📱 Telegram:</strong> Breach channels, Stealer logs, Market monitoring
              {' • '}
              <strong>🧅 Onion:</strong> Ahmia.fi, DDoSecrets, WikiLeaks
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

/* ============================================================================
   SUB COMPONENTS
============================================================================ */

function StatCard({ icon: Icon, label, value, color }: { 
  icon: any; 
  label: string; 
  value: string | number; 
  color: string;
}) {
  return (
    <Card>
      <CardContent className="pt-4 pb-4">
        <div className="text-center">
          <Icon className={cn('h-4 w-4 mx-auto mb-1', color)} />
          <div className="text-xl font-bold">{value}</div>
          <div className="text-[10px] text-muted-foreground uppercase">{label}</div>
        </div>
      </CardContent>
    </Card>
  );
}

function EmptyState({ icon: Icon, title, description }: { icon: any; title: string; description: string }) {
  return (
    <Card className="border-dashed">
      <CardContent className="pt-12 pb-12 text-center">
        <Icon className="h-16 w-16 mx-auto text-muted-foreground opacity-30 mb-4" />
        <h3 className="text-lg font-semibold text-muted-foreground">{title}</h3>
        <p className="text-sm text-muted-foreground mt-1">{description}</p>
      </CardContent>
    </Card>
  );
}

function LoadingState() {
  return (
    <div className="flex flex-col items-center justify-center py-12">
      <Loader2 className="h-12 w-12 animate-spin text-primary mb-4" />
      <p className="text-muted-foreground">Scanning 20+ intelligence sources...</p>
      <p className="text-xs text-muted-foreground mt-1">This may take 15-30 seconds</p>
    </div>
  );
}

function ThreatAssessmentCard({ analysis, fullWidth }: { analysis: LeakAnalysis; fullWidth?: boolean }) {
  const { threatAssessment } = analysis;
  
  return (
    <Card className={cn(
      'border-2',
      threatAssessment.severity === 'critical' ? 'border-red-500/50 bg-red-500/5' :
      threatAssessment.severity === 'high' ? 'border-orange-500/50 bg-orange-500/5' :
      threatAssessment.severity === 'medium' ? 'border-yellow-500/50 bg-yellow-500/5' :
      'border-green-500/50 bg-green-500/5',
      fullWidth && 'col-span-full'
    )}>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Threat Assessment
          </CardTitle>
          <Badge className={cn(
            'text-xl px-4 py-1',
            threatAssessment.severity === 'critical' ? 'bg-red-500' :
            threatAssessment.severity === 'high' ? 'bg-orange-500' :
            threatAssessment.severity === 'medium' ? 'bg-yellow-500' :
            'bg-green-500'
          )}>
            {threatAssessment.score}/100
          </Badge>
        </div>
        <CardDescription>{threatAssessment.category}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div>
          <div className="flex justify-between text-sm mb-1">
            <span>Threat Level</span>
            <span className="uppercase font-bold">{threatAssessment.severity}</span>
          </div>
          <Progress 
            value={threatAssessment.score} 
            className={cn(
              threatAssessment.severity === 'critical' ? '[&>div]:bg-red-500' :
              threatAssessment.severity === 'high' ? '[&>div]:bg-orange-500' :
              threatAssessment.severity === 'medium' ? '[&>div]:bg-yellow-500' :
              '[&>div]:bg-green-500'
            )}
          />
        </div>
        
        <div>
          <h4 className="font-semibold mb-2">Summary</h4>
          <p className="text-sm text-muted-foreground">{analysis.summary}</p>
        </div>
        
        {threatAssessment.recommendations.length > 0 && (
          <div>
            <h4 className="font-semibold mb-2">Recommended Actions</h4>
            <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground">
              {threatAssessment.recommendations.slice(0, 5).map((rec, i) => (
                <li key={i}>{rec}</li>
              ))}
            </ul>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function ThreatItem({ item }: { item: any }) {
  return (
    <div className={cn(
      'p-3 rounded-lg border mb-2',
      SEVERITY_COLORS[item.severity] || SEVERITY_COLORS.medium
    )}>
      <div className="flex items-center justify-between mb-1">
        <Badge className="text-xs">{item.severity?.toUpperCase()}</Badge>
        <span className="text-xs text-muted-foreground">{item.source}</span>
      </div>
      <p className="text-sm font-medium truncate">{item.title || item.value}</p>
      <p className="text-xs text-muted-foreground truncate">{item.context || item.description}</p>
    </div>
  );
}

function SignalCard({ signal }: { signal: LeakSignal }) {
  return (
    <Card className={cn('border-l-4', SEVERITY_COLORS[signal.severity])}>
      <CardContent className="pt-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold truncate">{signal.title}</h3>
              <Badge variant="secondary" className="shrink-0">{signal.source}</Badge>
            </div>
            <p className="text-sm text-muted-foreground line-clamp-2">{signal.context}</p>
          </div>
          <Badge className={SEVERITY_COLORS[signal.severity]}>{signal.severity}</Badge>
        </div>
        <div className="flex justify-between items-center mt-3">
          <span className="text-xs text-muted-foreground">
            <Clock className="h-3 w-3 inline mr-1" />
            {new Date(signal.timestamp).toLocaleString()}
          </span>
          <Button size="sm" variant="outline" asChild>
            <a href={signal.url} target="_blank" rel="noreferrer">
              <ExternalLink className="h-3 w-3 mr-1" />
              View
            </a>
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function MalwareIOCCard({ ioc }: { ioc: MalwareIndicator }) {
  return (
    <Card className={cn('border-l-4', SEVERITY_COLORS[ioc.severity])}>
      <CardContent className="pt-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2">
              <Badge variant="outline">{ioc.type.toUpperCase()}</Badge>
              <Badge className="bg-purple-500">{ioc.malwareFamily}</Badge>
              <Badge variant="secondary">{ioc.category}</Badge>
            </div>
            <p className="font-mono text-sm break-all">{ioc.value}</p>
            <p className="text-xs text-muted-foreground mt-1">{ioc.description}</p>
          </div>
          <Badge className={SEVERITY_COLORS[ioc.severity]}>{ioc.severity}</Badge>
        </div>
        {ioc.mitreAttack && ioc.mitreAttack.length > 0 && (
          <div className="flex gap-1 mt-2 flex-wrap">
            {ioc.mitreAttack.slice(0, 3).map(ttp => (
              <Badge key={ttp} variant="outline" className="text-xs bg-purple-500/10">
                {ttp}
              </Badge>
            ))}
          </div>
        )}
        <div className="flex justify-between items-center mt-3">
          <span className="text-xs text-muted-foreground">
            Confidence: {ioc.confidence}% | {ioc.source}
          </span>
          <Button size="sm" variant="outline" asChild>
            <a href={ioc.sourceUrl} target="_blank" rel="noreferrer">
              <ExternalLink className="h-3 w-3 mr-1" />
              Source
            </a>
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function RansomwareGroupCard({ group }: { group: RansomwareGroup }) {
  return (
    <Card className="border-red-500/40 bg-red-500/5">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="flex items-center gap-2">
            <Skull className="h-5 w-5 text-red-500" />
            {group.name}
          </CardTitle>
          <Badge className={group.active ? 'bg-red-500' : 'bg-gray-500'}>
            {group.active ? 'ACTIVE' : 'INACTIVE'}
          </Badge>
        </div>
        {group.aliases.length > 0 && (
          <CardDescription>
            Also known as: {group.aliases.join(', ')}
          </CardDescription>
        )}
      </CardHeader>
      <CardContent>
        <p className="text-sm text-muted-foreground mb-3">{group.description}</p>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <span className="text-muted-foreground">Victims:</span>
            <span className="ml-2 font-bold">{group.victimCount}</span>
          </div>
          <div>
            <span className="text-muted-foreground">First Seen:</span>
            <span className="ml-2">{new Date(group.firstSeen).toLocaleDateString()}</span>
          </div>
        </div>
        {group.ttps.length > 0 && (
          <div className="flex gap-1 mt-3 flex-wrap">
            {group.ttps.slice(0, 5).map(ttp => (
              <Badge key={ttp} variant="outline" className="text-xs">
                {ttp}
              </Badge>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function StealerLogCard({ log }: { log: StealerLog }) {
  return (
    <Card className={cn('border-l-4', SEVERITY_COLORS[log.severity])}>
      <CardContent className="pt-4">
        <div className="flex items-start justify-between gap-4 mb-3">
          <div>
            <Badge className="bg-yellow-500 mb-2">{log.stealerFamily}</Badge>
            <p className="text-sm font-medium">Domain: {log.affectedDomain}</p>
          </div>
          <Badge className={SEVERITY_COLORS[log.severity]}>{log.severity}</Badge>
        </div>
        <div className="grid grid-cols-4 gap-2 text-center mb-3">
          <div className="p-2 bg-secondary/50 rounded">
            <div className="text-lg font-bold">{log.credentialCount}</div>
            <div className="text-xs text-muted-foreground">Creds</div>
          </div>
          <div className="p-2 bg-secondary/50 rounded">
            <div className="text-lg font-bold">{log.cookieCount}</div>
            <div className="text-xs text-muted-foreground">Cookies</div>
          </div>
          <div className="p-2 bg-secondary/50 rounded">
            <div className="text-lg font-bold">{log.cardCount}</div>
            <div className="text-xs text-muted-foreground">Cards</div>
          </div>
          <div className="p-2 bg-secondary/50 rounded">
            <div className="text-lg font-bold">{log.walletCount}</div>
            <div className="text-xs text-muted-foreground">Wallets</div>
          </div>
        </div>
        <p className="text-xs text-muted-foreground line-clamp-2">{log.preview}</p>
        <div className="flex justify-between items-center mt-3">
          <span className="text-xs text-muted-foreground">{log.source}</span>
          <Button size="sm" variant="outline" asChild>
            <a href={log.sourceUrl} target="_blank" rel="noreferrer">
              <ExternalLink className="h-3 w-3 mr-1" />
              View
            </a>
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function TelegramIntelCard({ item }: { item: TelegramIntelResult }) {
  return (
    <Card className={cn('border-l-4', SEVERITY_COLORS[item.severity])}>
      <CardContent className="pt-4">
        <div className="flex items-start justify-between gap-4 mb-2">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2 flex-wrap">
              <Badge variant="secondary">{item.category}</Badge>
              {item.stealerFamily && <Badge className="bg-yellow-500">{item.stealerFamily}</Badge>}
              {item.ransomwareGroup && <Badge className="bg-red-500">{item.ransomwareGroup}</Badge>}
              <Badge variant="outline">{item.channel}</Badge>
            </div>
            <h3 className="font-semibold">{item.title}</h3>
          </div>
          <Badge className={SEVERITY_COLORS[item.severity]}>{item.severity}</Badge>
        </div>
        <p className="text-sm text-muted-foreground line-clamp-2">{item.rawSnippet}</p>
        {item.credentialCount > 0 && (
          <p className="text-xs text-yellow-500 mt-2">
            <Key className="h-3 w-3 inline mr-1" />
            {item.credentialCount} credentials detected
          </p>
        )}
        <div className="flex justify-between items-center mt-3">
          <span className="text-xs text-muted-foreground">
            {new Date(item.timestamp).toLocaleString()}
          </span>
          <Button size="sm" variant="outline" asChild>
            <a href={item.messageUrl} target="_blank" rel="noreferrer">
              <ExternalLink className="h-3 w-3 mr-1" />
              View
            </a>
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function C2ServerCard({ c2 }: { c2: C2Server }) {
  return (
    <Card className={cn(
      'border-l-4',
      c2.status === 'active' ? 'border-red-500 bg-red-500/5' :
      c2.status === 'sinkholed' ? 'border-green-500 bg-green-500/5' :
      'border-gray-500'
    )}>
      <CardContent className="pt-4">
        <div className="flex items-start justify-between gap-4 mb-3">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Badge className={c2.status === 'active' ? 'bg-red-500' : 'bg-gray-500'}>
                {c2.status.toUpperCase()}
              </Badge>
              <Badge className="bg-purple-500">{c2.malwareFamily}</Badge>
            </div>
            <p className="font-mono text-lg">{c2.ip}:{c2.port}</p>
            {c2.domain && <p className="text-sm text-muted-foreground">{c2.domain}</p>}
          </div>
          <Server className={cn(
            'h-8 w-8',
            c2.status === 'active' ? 'text-red-500 animate-pulse' : 'text-gray-500'
          )} />
        </div>
        {c2.geoLocation && (
          <div className="flex gap-4 text-sm text-muted-foreground">
            <span>🌍 {c2.geoLocation.country}</span>
            {c2.geoLocation.asn && <span>ASN: {c2.geoLocation.asn}</span>}
          </div>
        )}
        <div className="flex justify-between items-center mt-3">
          <span className="text-xs text-muted-foreground">
            First seen: {new Date(c2.firstSeen).toLocaleDateString()}
          </span>
          <span className="text-xs">Confidence: {c2.confidence}%</span>
        </div>
      </CardContent>
    </Card>
  );
}

function OnionSiteCard({ site }: { site: OnionSite }) {
  return (
    <Card className={cn('border-l-4', SEVERITY_COLORS[site.riskLevel])}>
      <CardContent className="pt-4">
        <div className="flex items-start justify-between gap-4 mb-2">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2">
              <Globe className="h-4 w-4 text-purple-500" />
              <Badge variant="secondary">{site.category}</Badge>
              <Badge className={cn(
                site.status === 'online' ? 'bg-green-500' : 'bg-gray-500'
              )}>
                {site.status}
              </Badge>
            </div>
            <h3 className="font-semibold">{site.title}</h3>
            <p className="font-mono text-xs break-all text-muted-foreground">{site.url}</p>
          </div>
          <Badge className={SEVERITY_COLORS[site.riskLevel]}>{site.riskLevel}</Badge>
        </div>
        <p className="text-sm text-muted-foreground line-clamp-2">{site.description}</p>
        {site.tags.length > 0 && (
          <div className="flex gap-1 mt-2 flex-wrap">
            {site.tags.slice(0, 5).map(tag => (
              <Badge key={tag} variant="outline" className="text-xs">{tag}</Badge>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function EntityCard({ entity }: { entity: ExtractedEntity }) {
  return (
    <div className={cn(
      'p-3 rounded-lg border',
      entity.type === 'password' ? 'border-red-500/40 bg-red-500/5' :
      entity.type === 'email' ? 'border-blue-500/40 bg-blue-500/5' :
      entity.type === 'ip' ? 'border-green-500/40 bg-green-500/5' :
      entity.type === 'domain' ? 'border-purple-500/40 bg-purple-500/5' :
      entity.type === 'crypto_wallet' ? 'border-yellow-500/40 bg-yellow-500/5' :
      'border-gray-500/40 bg-gray-500/5'
    )}>
      <div className="flex items-center justify-between mb-1">
        <Badge variant="outline" className="text-xs uppercase">{entity.type}</Badge>
        <span className="text-xs text-muted-foreground">
          {Math.round(entity.confidence * 100)}%
        </span>
      </div>
      <p className="font-mono text-sm break-all">{entity.value}</p>
    </div>
  );
}

export default StealthMoleScanner;
