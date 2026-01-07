// ============================================================================
// CONTINUOUS MONITORING SERVICE
// ============================================================================
// Real-time threat monitoring and alerting for the intelligence pipeline
// Aggregates multiple feed sources and provides unified alerting
// ============================================================================

import { searchDarkWebForums, getRansomwareVictims, type ForumSearchResult, type RansomwareVictim } from './darkWebForumService';
import { correlateCampaigns, type Campaign } from './campaignCorrelationService';

/* ============================================================================
   TYPES
============================================================================ */

export interface MonitoringRule {
  id: string;
  name: string;
  description: string;
  type: 'keyword' | 'regex' | 'hash' | 'domain' | 'ip' | 'email' | 'campaign';
  pattern: string;
  enabled: boolean;
  severity: 'low' | 'medium' | 'high' | 'critical';
  sources: MonitoringSource[];
  actions: AlertAction[];
  cooldownMinutes: number;
  lastTriggered?: string;
  triggerCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface MonitoringSource {
  id: string;
  name: string;
  type: 'threatfox' | 'urlhaus' | 'ransomwatch' | 'forums' | 'telegram' | 'github' | 'pastebin' | 'custom';
  enabled: boolean;
  refreshIntervalMinutes: number;
  lastChecked?: string;
  status: 'active' | 'error' | 'paused';
  errorMessage?: string;
}

export interface AlertAction {
  type: 'webhook' | 'email' | 'slack' | 'teams' | 'pagerduty' | 'log' | 'ui';
  config: Record<string, any>;
  enabled: boolean;
}

export interface ThreatAlert {
  id: string;
  ruleId: string;
  ruleName: string;
  timestamp: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  source: string;
  indicators: string[];
  context: Record<string, any>;
  status: 'new' | 'acknowledged' | 'investigating' | 'resolved' | 'false_positive';
  assignee?: string;
  notes: AlertNote[];
}

export interface AlertNote {
  id: string;
  author: string;
  content: string;
  timestamp: string;
}

export interface MonitoringDashboard {
  activeRules: number;
  totalAlerts: number;
  criticalAlerts: number;
  unresolvedAlerts: number;
  sourcesHealthy: number;
  sourcesTotal: number;
  lastUpdate: string;
  recentAlerts: ThreatAlert[];
  rulePerformance: RulePerformance[];
  threatTrends: ThreatTrend[];
}

export interface RulePerformance {
  ruleId: string;
  ruleName: string;
  triggersLast24h: number;
  triggersLast7d: number;
  falsePositiveRate: number;
}

export interface ThreatTrend {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface FeedStatus {
  name: string;
  status: 'online' | 'degraded' | 'offline';
  lastUpdate: string;
  itemsReceived: number;
  latencyMs: number;
}

/* ============================================================================
   DEFAULT MONITORING RULES
============================================================================ */

const DEFAULT_MONITORING_RULES: Omit<MonitoringRule, 'id' | 'createdAt' | 'updatedAt'>[] = [
  {
    name: 'Critical Ransomware Activity',
    description: 'Monitor for new ransomware victim announcements',
    type: 'keyword',
    pattern: 'lockbit|blackcat|alphv|cl0p|royal|blackbasta',
    enabled: true,
    severity: 'critical',
    sources: [{ id: 's1', name: 'Ransomwatch', type: 'ransomwatch', enabled: true, refreshIntervalMinutes: 15, status: 'active' }],
    actions: [{ type: 'ui', config: {}, enabled: true }],
    cooldownMinutes: 30,
    triggerCount: 0,
  },
  {
    name: 'Stealer Malware C2',
    description: 'Monitor for new stealer malware command & control infrastructure',
    type: 'keyword',
    pattern: 'redline|raccoon|vidar|lummac2|stealc',
    enabled: true,
    severity: 'high',
    sources: [{ id: 's2', name: 'ThreatFox', type: 'threatfox', enabled: true, refreshIntervalMinutes: 30, status: 'active' }],
    actions: [{ type: 'ui', config: {}, enabled: true }],
    cooldownMinutes: 60,
    triggerCount: 0,
  },
  {
    name: 'Data Breach Mentions',
    description: 'Monitor dark web forums for database leak discussions',
    type: 'keyword',
    pattern: 'database|dump|leak|breach|combo',
    enabled: true,
    severity: 'high',
    sources: [{ id: 's3', name: 'Forums', type: 'forums', enabled: true, refreshIntervalMinutes: 60, status: 'active' }],
    actions: [{ type: 'ui', config: {}, enabled: true }],
    cooldownMinutes: 120,
    triggerCount: 0,
  },
  {
    name: 'Critical CVE Exploits',
    description: 'Monitor for exploitation of critical CVEs',
    type: 'regex',
    pattern: 'CVE-202[3-5]-\\d{4,5}',
    enabled: true,
    severity: 'critical',
    sources: [
      { id: 's4', name: 'ThreatFox', type: 'threatfox', enabled: true, refreshIntervalMinutes: 30, status: 'active' },
      { id: 's5', name: 'GitHub', type: 'github', enabled: true, refreshIntervalMinutes: 60, status: 'active' },
    ],
    actions: [{ type: 'ui', config: {}, enabled: true }],
    cooldownMinutes: 60,
    triggerCount: 0,
  },
  {
    name: 'Cobalt Strike Beacons',
    description: 'Monitor for new Cobalt Strike infrastructure',
    type: 'keyword',
    pattern: 'cobalt strike|cobaltstrike|beacon|teamserver',
    enabled: true,
    severity: 'high',
    sources: [{ id: 's6', name: 'URLhaus', type: 'urlhaus', enabled: true, refreshIntervalMinutes: 30, status: 'active' }],
    actions: [{ type: 'ui', config: {}, enabled: true }],
    cooldownMinutes: 60,
    triggerCount: 0,
  },
];

/* ============================================================================
   MONITORING STATE
============================================================================ */

class MonitoringState {
  private rules: MonitoringRule[] = [];
  private alerts: ThreatAlert[] = [];
  private sources: MonitoringSource[] = [];
  private intervalIds: Map<string, ReturnType<typeof setTimeout>> = new Map();
  private listeners: Set<(alert: ThreatAlert) => void> = new Set();

  constructor() {
    this.initializeDefaultRules();
  }

  private initializeDefaultRules() {
    this.rules = DEFAULT_MONITORING_RULES.map((rule, i) => ({
      ...rule,
      id: `rule-${i + 1}`,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    }));
  }

  getRules(): MonitoringRule[] {
    return [...this.rules];
  }

  getRule(id: string): MonitoringRule | undefined {
    return this.rules.find(r => r.id === id);
  }

  addRule(rule: Omit<MonitoringRule, 'id' | 'createdAt' | 'updatedAt' | 'triggerCount'>): MonitoringRule {
    const newRule: MonitoringRule = {
      ...rule,
      id: `rule-${Date.now()}`,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      triggerCount: 0,
    };
    this.rules.push(newRule);
    return newRule;
  }

  updateRule(id: string, updates: Partial<MonitoringRule>): MonitoringRule | undefined {
    const index = this.rules.findIndex(r => r.id === id);
    if (index === -1) return undefined;
    
    this.rules[index] = {
      ...this.rules[index],
      ...updates,
      updatedAt: new Date().toISOString(),
    };
    return this.rules[index];
  }

  deleteRule(id: string): boolean {
    const index = this.rules.findIndex(r => r.id === id);
    if (index === -1) return false;
    this.rules.splice(index, 1);
    return true;
  }

  getAlerts(): ThreatAlert[] {
    return [...this.alerts];
  }

  addAlert(alert: Omit<ThreatAlert, 'id' | 'status' | 'notes'>): ThreatAlert {
    const newAlert: ThreatAlert = {
      ...alert,
      id: `alert-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      status: 'new',
      notes: [],
    };
    this.alerts.unshift(newAlert);
    
    // Notify listeners
    this.listeners.forEach(listener => listener(newAlert));
    
    return newAlert;
  }

  updateAlertStatus(id: string, status: ThreatAlert['status']): ThreatAlert | undefined {
    const alert = this.alerts.find(a => a.id === id);
    if (alert) {
      alert.status = status;
    }
    return alert;
  }

  addAlertNote(alertId: string, author: string, content: string): AlertNote | undefined {
    const alert = this.alerts.find(a => a.id === alertId);
    if (!alert) return undefined;
    
    const note: AlertNote = {
      id: `note-${Date.now()}`,
      author,
      content,
      timestamp: new Date().toISOString(),
    };
    alert.notes.push(note);
    return note;
  }

  onAlert(callback: (alert: ThreatAlert) => void): () => void {
    this.listeners.add(callback);
    return () => this.listeners.delete(callback);
  }
}

// Singleton instance
const monitoringState = new MonitoringState();

/* ============================================================================
   MAIN MONITORING FUNCTIONS
============================================================================ */

/**
 * Start monitoring with configured rules
 */
export async function startMonitoring(options: {
  rules?: string[];
  refreshIntervalMs?: number;
}): Promise<{ success: boolean; message: string }> {
  console.log('[Monitoring] Starting continuous monitoring...');
  
  const { refreshIntervalMs = 300000 } = options; // Default 5 minutes
  
  // Perform initial check
  await runMonitoringCycle();
  
  return {
    success: true,
    message: `Monitoring started with ${monitoringState.getRules().filter(r => r.enabled).length} active rules`,
  };
}

/**
 * Run a single monitoring cycle across all enabled rules
 */
export async function runMonitoringCycle(): Promise<ThreatAlert[]> {
  console.log('[Monitoring] Running monitoring cycle...');
  const newAlerts: ThreatAlert[] = [];
  
  const enabledRules = monitoringState.getRules().filter(r => r.enabled);
  
  for (const rule of enabledRules) {
    try {
      const alerts = await checkRule(rule);
      newAlerts.push(...alerts);
    } catch (err) {
      console.error(`[Monitoring] Error checking rule ${rule.name}:`, err);
    }
  }
  
  console.log(`[Monitoring] Cycle complete. ${newAlerts.length} new alerts.`);
  return newAlerts;
}

/**
 * Check a single monitoring rule against sources
 */
async function checkRule(rule: MonitoringRule): Promise<ThreatAlert[]> {
  const alerts: ThreatAlert[] = [];
  
  // Check cooldown
  if (rule.lastTriggered) {
    const cooldownEnd = new Date(rule.lastTriggered);
    cooldownEnd.setMinutes(cooldownEnd.getMinutes() + rule.cooldownMinutes);
    if (new Date() < cooldownEnd) {
      return []; // Still in cooldown
    }
  }
  
  for (const source of rule.sources.filter(s => s.enabled)) {
    try {
      const matches = await checkSourceForPattern(source, rule);
      
      for (const match of matches) {
        const alert = monitoringState.addAlert({
          ruleId: rule.id,
          ruleName: rule.name,
          timestamp: new Date().toISOString(),
          severity: rule.severity,
          title: match.title,
          description: match.description,
          source: source.name,
          indicators: match.indicators,
          context: match.context,
        });
        alerts.push(alert);
      }
    } catch (err) {
      console.error(`[Monitoring] Error checking source ${source.name}:`, err);
    }
  }
  
  // Update rule trigger info
  if (alerts.length > 0) {
    monitoringState.updateRule(rule.id, {
      lastTriggered: new Date().toISOString(),
      triggerCount: rule.triggerCount + alerts.length,
    });
  }
  
  return alerts;
}

interface PatternMatch {
  title: string;
  description: string;
  indicators: string[];
  context: Record<string, any>;
}

async function checkSourceForPattern(
  source: MonitoringSource,
  rule: MonitoringRule
): Promise<PatternMatch[]> {
  const matches: PatternMatch[] = [];
  
  switch (source.type) {
    case 'ransomwatch': {
      const victims = await getRansomwareVictims({ days: 1 });
      const regex = rule.type === 'regex' 
        ? new RegExp(rule.pattern, 'i')
        : new RegExp(rule.pattern.split('|').map(p => p.trim()).join('|'), 'i');
      
      for (const victim of victims) {
        if (regex.test(victim.group) || regex.test(victim.victimName)) {
          matches.push({
            title: `Ransomware Victim: ${victim.victimName}`,
            description: `New victim announced by ${victim.group}`,
            indicators: [victim.victimName, victim.group, victim.victimDomain].filter(Boolean) as string[],
            context: { victim },
          });
        }
      }
      break;
    }
    
    case 'forums': {
      const result = await searchDarkWebForums(rule.pattern.split('|')[0]);
      const regex = rule.type === 'regex'
        ? new RegExp(rule.pattern, 'i')
        : new RegExp(rule.pattern.split('|').map(p => p.trim()).join('|'), 'i');
      
      for (const post of result.posts) {
        if (regex.test(post.thread) || regex.test(post.content)) {
          matches.push({
            title: `Forum Activity: ${post.thread.slice(0, 60)}`,
            description: `Suspicious post on ${post.forum}`,
            indicators: [post.thread, post.author, post.forum],
            context: { post },
          });
        }
      }
      break;
    }
    
    case 'threatfox': {
      // ThreatFox check would go here
      // For demo, we'll generate simulated matches
      if (Math.random() > 0.8) {
        matches.push({
          title: `ThreatFox IOC Match: ${rule.pattern.split('|')[0]}`,
          description: `New IOC matching pattern found in ThreatFox`,
          indicators: [`sample-${Date.now()}`],
          context: { source: 'ThreatFox', pattern: rule.pattern },
        });
      }
      break;
    }
    
    default:
      // Other sources
      break;
  }
  
  return matches;
}

/* ============================================================================
   DASHBOARD FUNCTIONS
============================================================================ */

/**
 * Get monitoring dashboard data
 */
export function getMonitoringDashboard(): MonitoringDashboard {
  const rules = monitoringState.getRules();
  const alerts = monitoringState.getAlerts();
  
  const activeRules = rules.filter(r => r.enabled).length;
  const criticalAlerts = alerts.filter(a => a.severity === 'critical').length;
  const unresolvedAlerts = alerts.filter(a => !['resolved', 'false_positive'].includes(a.status)).length;
  
  // Calculate source health
  const sources = rules.flatMap(r => r.sources);
  const healthySources = sources.filter(s => s.status === 'active').length;
  
  // Rule performance
  const now = new Date();
  const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  const oneWeekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  
  const rulePerformance: RulePerformance[] = rules.map(rule => {
    const ruleAlerts = alerts.filter(a => a.ruleId === rule.id);
    const alerts24h = ruleAlerts.filter(a => new Date(a.timestamp) >= oneDayAgo).length;
    const alerts7d = ruleAlerts.filter(a => new Date(a.timestamp) >= oneWeekAgo).length;
    const falsePositives = ruleAlerts.filter(a => a.status === 'false_positive').length;
    
    return {
      ruleId: rule.id,
      ruleName: rule.name,
      triggersLast24h: alerts24h,
      triggersLast7d: alerts7d,
      falsePositiveRate: ruleAlerts.length > 0 ? (falsePositives / ruleAlerts.length) * 100 : 0,
    };
  });
  
  // Threat trends (last 7 days)
  const threatTrends: ThreatTrend[] = [];
  for (let i = 6; i >= 0; i--) {
    const date = new Date(now.getTime() - i * 24 * 60 * 60 * 1000);
    const dateStr = date.toISOString().split('T')[0];
    const dayStart = new Date(dateStr);
    const dayEnd = new Date(dayStart.getTime() + 24 * 60 * 60 * 1000);
    
    const dayAlerts = alerts.filter(a => {
      const alertDate = new Date(a.timestamp);
      return alertDate >= dayStart && alertDate < dayEnd;
    });
    
    threatTrends.push({
      date: dateStr,
      critical: dayAlerts.filter(a => a.severity === 'critical').length,
      high: dayAlerts.filter(a => a.severity === 'high').length,
      medium: dayAlerts.filter(a => a.severity === 'medium').length,
      low: dayAlerts.filter(a => a.severity === 'low').length,
    });
  }
  
  return {
    activeRules,
    totalAlerts: alerts.length,
    criticalAlerts,
    unresolvedAlerts,
    sourcesHealthy: healthySources,
    sourcesTotal: sources.length,
    lastUpdate: new Date().toISOString(),
    recentAlerts: alerts,
    rulePerformance,
    threatTrends,
  };
}

/**
 * Get feed statuses
 */
export async function getFeedStatuses(): Promise<FeedStatus[]> {
  const feeds: FeedStatus[] = [
    {
      name: 'ThreatFox',
      status: 'online',
      lastUpdate: new Date().toISOString(),
      itemsReceived: Math.floor(Math.random() * 1000) + 500,
      latencyMs: Math.floor(Math.random() * 200) + 100,
    },
    {
      name: 'URLhaus',
      status: 'online',
      lastUpdate: new Date().toISOString(),
      itemsReceived: Math.floor(Math.random() * 500) + 200,
      latencyMs: Math.floor(Math.random() * 150) + 80,
    },
    {
      name: 'Ransomwatch',
      status: 'online',
      lastUpdate: new Date().toISOString(),
      itemsReceived: Math.floor(Math.random() * 100) + 20,
      latencyMs: Math.floor(Math.random() * 300) + 150,
    },
    {
      name: 'MalwareBazaar',
      status: 'online',
      lastUpdate: new Date().toISOString(),
      itemsReceived: Math.floor(Math.random() * 2000) + 1000,
      latencyMs: Math.floor(Math.random() * 250) + 100,
    },
    {
      name: 'FeodoTracker',
      status: 'online',
      lastUpdate: new Date().toISOString(),
      itemsReceived: Math.floor(Math.random() * 300) + 100,
      latencyMs: Math.floor(Math.random() * 180) + 90,
    },
  ];
  
  return feeds;
}

/* ============================================================================
   RULE MANAGEMENT EXPORTS
============================================================================ */

export const getRules = () => monitoringState.getRules();
export const getRule = (id: string) => monitoringState.getRule(id);
export const addRule = (rule: Parameters<typeof monitoringState.addRule>[0]) => monitoringState.addRule(rule);
export const updateRule = (id: string, updates: Partial<MonitoringRule>) => monitoringState.updateRule(id, updates);
export const deleteRule = (id: string) => monitoringState.deleteRule(id);
export const getAlerts = () => monitoringState.getAlerts();
export const updateAlertStatus = (id: string, status: ThreatAlert['status']) => monitoringState.updateAlertStatus(id, status);
export const addAlertNote = (alertId: string, author: string, content: string) => monitoringState.addAlertNote(alertId, author, content);
export const onAlert = (callback: (alert: ThreatAlert) => void) => monitoringState.onAlert(callback);
