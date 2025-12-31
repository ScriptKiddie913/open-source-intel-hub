// ============================================================================
// DETECTION ENGINE SERVICE
// ============================================================================
// Generates detection artifacts: YARA rules, Sigma rules, IOC lists
// Creates risk scores and priority assessments
// ============================================================================

/* ============================================================================
   TYPES
============================================================================ */

export interface YARARule {
  id: string;
  name: string;
  description: string;
  author: string;
  date: string;
  family?: string;
  tags: string[];
  strings: YARAString[];
  condition: string;
  ruleContent: string;
  confidence: number;
}

export interface YARAString {
  id: string;
  type: 'text' | 'hex' | 'regex';
  value: string;
  modifiers?: string[];
}

export interface SigmaRule {
  id: string;
  title: string;
  description: string;
  status: 'experimental' | 'test' | 'stable';
  author: string;
  date: string;
  logsource: {
    category?: string;
    product?: string;
    service?: string;
  };
  detection: Record<string, any>;
  level: 'informational' | 'low' | 'medium' | 'high' | 'critical';
  tags: string[];
  falsepositives: string[];
  ruleContent: string;
}

export interface IOCList {
  id: string;
  name: string;
  description: string;
  family?: string;
  generated: string;
  expiry?: string;
  format: 'stix' | 'csv' | 'json' | 'misp' | 'openioc';
  indicators: IOCIndicator[];
  stats: {
    total: number;
    byType: Record<string, number>;
    bySeverity: Record<string, number>;
  };
}

export interface IOCIndicator {
  type: 'ip' | 'domain' | 'url' | 'hash_md5' | 'hash_sha1' | 'hash_sha256' | 'email' | 'mutex' | 'registry' | 'file_path';
  value: string;
  confidence: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  firstSeen?: string;
  lastSeen?: string;
  tags: string[];
  context?: string;
}

export interface NetworkBlocklist {
  id: string;
  name: string;
  description: string;
  format: 'plain' | 'hosts' | 'dnsmasq' | 'bind' | 'unbound' | 'pfsense';
  entries: string[];
  generated: string;
  stats: {
    ips: number;
    domains: number;
    total: number;
  };
}

export interface RiskAssessment {
  indicator: string;
  riskScore: number;
  priority: 'info' | 'low' | 'medium' | 'high' | 'critical';
  factors: RiskFactor[];
  recommendation: string;
  mitigations: string[];
  ttps: string[];
  affectedAssets: string[];
}

export interface RiskFactor {
  name: string;
  weight: number;
  score: number;
  description: string;
}

export interface DetectionPackage {
  yaraRules: YARARule[];
  sigmaRules: SigmaRule[];
  iocLists: IOCList[];
  networkBlocklists: NetworkBlocklist[];
  riskAssessments: RiskAssessment[];
  summary: {
    totalRules: number;
    totalIOCs: number;
    criticalFindings: number;
    generatedAt: string;
  };
}

/* ============================================================================
   CONSTANTS
============================================================================ */

// MITRE ATT&CK mapping for detection
const MITRE_DETECTIONS: Record<string, { logsource: string; detection_patterns: string[] }> = {
  'T1059.001': { // PowerShell
    logsource: 'windows/powershell',
    detection_patterns: ['ScriptBlockText', 'CommandInvocation', '-enc', '-nop', 'IEX'],
  },
  'T1059.003': { // Windows Command Shell
    logsource: 'windows/process_creation',
    detection_patterns: ['cmd.exe', '/c', '/k', 'whoami', 'net user'],
  },
  'T1555': { // Credentials from Password Stores
    logsource: 'windows/file_access',
    detection_patterns: ['Login Data', 'logins.json', 'key3.db', 'key4.db', 'cookies.sqlite'],
  },
  'T1539': { // Steal Web Session Cookie
    logsource: 'windows/file_access',
    detection_patterns: ['Cookies', 'cookies.sqlite', 'Local State'],
  },
  'T1552': { // Unsecured Credentials
    logsource: 'windows/file_access',
    detection_patterns: ['.env', 'credentials', 'config.json', 'secrets'],
  },
  'T1486': { // Data Encrypted for Impact
    logsource: 'windows/file_event',
    detection_patterns: ['ransomware', '.encrypted', '.locked', 'ransom'],
  },
  'T1071.001': { // Application Layer Protocol: Web
    logsource: 'network/proxy',
    detection_patterns: ['POST', 'User-Agent', 'Content-Type'],
  },
  'T1105': { // Ingress Tool Transfer
    logsource: 'windows/process_creation',
    detection_patterns: ['certutil', 'bitsadmin', 'curl', 'wget', 'powershell downloadstring'],
  },
};

// Known malware string patterns for YARA
const MALWARE_SIGNATURES: Record<string, { strings: string[]; hex: string[] }> = {
  'RedLine': {
    strings: ['RedLine', 'Authorization: Bearer', '/api/check', 'hwid=', 'Yandex\\YaAddon'],
    hex: ['52 65 64 4C 69 6E 65'], // "RedLine" in hex
  },
  'Raccoon': {
    strings: ['raccoon', 'machineId', 'configId', 'libs_to_grab'],
    hex: ['72 61 63 63 6F 6F 6E'],
  },
  'Vidar': {
    strings: ['vidar', 'profile_id', 'ftp_', 'wallet_'],
    hex: [],
  },
  'LummaC2': {
    strings: ['LummaC', 'c2conf', 'gate=', 'build_id'],
    hex: [],
  },
  'LockBit': {
    strings: ['LockBit', 'Restore-My-Files.txt', '.lockbit', 'YOUR DATA ARE STOLEN'],
    hex: [],
  },
  'Cobalt Strike': {
    strings: ['sleeptime', 'jitter', 'publickey', 'C2Server'],
    hex: ['FC E8 89 00 00 00'], // Beacon shellcode start
  },
};

/* ============================================================================
   MAIN GENERATION FUNCTIONS
============================================================================ */

/**
 * Generate complete detection package from IOCs and malware data
 */
export function generateDetectionPackage(
  malwareFamily: string,
  indicators: IOCIndicator[],
  ttps: string[] = []
): DetectionPackage {
  console.log(`[DetectionEngine] Generating package for ${malwareFamily}`);
  
  const yaraRules = generateYARARules(malwareFamily, indicators);
  const sigmaRules = generateSigmaRules(malwareFamily, indicators, ttps);
  const iocLists = generateIOCLists(malwareFamily, indicators);
  const networkBlocklists = generateNetworkBlocklists(malwareFamily, indicators);
  const riskAssessments = generateRiskAssessments(malwareFamily, indicators, ttps);
  
  return {
    yaraRules,
    sigmaRules,
    iocLists,
    networkBlocklists,
    riskAssessments,
    summary: {
      totalRules: yaraRules.length + sigmaRules.length,
      totalIOCs: indicators.length,
      criticalFindings: riskAssessments.filter(r => r.priority === 'critical').length,
      generatedAt: new Date().toISOString(),
    },
  };
}

/* ============================================================================
   YARA RULE GENERATION
============================================================================ */

export function generateYARARules(family: string, indicators: IOCIndicator[]): YARARule[] {
  const rules: YARARule[] = [];
  const signatures = MALWARE_SIGNATURES[family];
  
  // Main family detection rule
  if (signatures) {
    const yaraStrings: YARAString[] = [];
    
    // Add text strings
    signatures.strings.forEach((str, i) => {
      yaraStrings.push({
        id: `$s${i + 1}`,
        type: 'text',
        value: str,
        modifiers: ['ascii', 'wide', 'nocase'],
      });
    });
    
    // Add hex patterns
    signatures.hex.forEach((hex, i) => {
      yaraStrings.push({
        id: `$h${i + 1}`,
        type: 'hex',
        value: hex,
      });
    });
    
    // Add hash indicators
    const hashIndicators = indicators.filter(i => i.type.startsWith('hash_'));
    hashIndicators.slice(0, 5).forEach((ind, i) => {
      if (ind.type === 'hash_sha256') {
        yaraStrings.push({
          id: `$hash${i + 1}`,
          type: 'hex',
          value: ind.value,
        });
      }
    });
    
    const condition = yaraStrings.length > 3 
      ? `2 of ($s*) or any of ($h*)`
      : `any of them`;
    
    const ruleContent = formatYARARule({
      name: `${family.replace(/[^a-zA-Z0-9]/g, '_')}_Detector`,
      description: `Detects ${family} malware family`,
      author: 'OSINT Hub Detection Engine',
      date: new Date().toISOString().split('T')[0],
      tags: [`malware.${family.toLowerCase()}`, 'auto_generated'],
      strings: yaraStrings,
      condition,
    });
    
    rules.push({
      id: `yara-${family.toLowerCase()}-main`,
      name: `${family}_Detector`,
      description: `Detects ${family} malware family based on known signatures`,
      author: 'OSINT Hub Detection Engine',
      date: new Date().toISOString().split('T')[0],
      family,
      tags: ['malware', family.toLowerCase(), 'auto_generated'],
      strings: yaraStrings,
      condition,
      ruleContent,
      confidence: 85,
    });
  }
  
  // IOC-based rule
  const urlIndicators = indicators.filter(i => i.type === 'url' || i.type === 'domain');
  if (urlIndicators.length > 0) {
    const urlStrings: YARAString[] = urlIndicators.slice(0, 20).map((ind, i) => ({
      id: `$url${i + 1}`,
      type: 'text',
      value: ind.value,
      modifiers: ['ascii', 'wide'],
    }));
    
    const ruleContent = formatYARARule({
      name: `${family.replace(/[^a-zA-Z0-9]/g, '_')}_Network_IOCs`,
      description: `Network indicators for ${family}`,
      author: 'OSINT Hub Detection Engine',
      date: new Date().toISOString().split('T')[0],
      tags: [`malware.${family.toLowerCase()}`, 'network', 'auto_generated'],
      strings: urlStrings,
      condition: 'any of them',
    });
    
    rules.push({
      id: `yara-${family.toLowerCase()}-network`,
      name: `${family}_Network_IOCs`,
      description: `Network-based detection for ${family}`,
      author: 'OSINT Hub Detection Engine',
      date: new Date().toISOString().split('T')[0],
      family,
      tags: ['network', 'ioc', family.toLowerCase()],
      strings: urlStrings,
      condition: 'any of them',
      ruleContent,
      confidence: 75,
    });
  }
  
  return rules;
}

function formatYARARule(config: {
  name: string;
  description: string;
  author: string;
  date: string;
  tags: string[];
  strings: YARAString[];
  condition: string;
}): string {
  const tagsStr = config.tags.map(t => `"${t}"`).join(' ');
  
  let stringsSection = '';
  for (const s of config.strings) {
    if (s.type === 'text') {
      const mods = s.modifiers?.join(' ') || '';
      stringsSection += `        ${s.id} = "${s.value}" ${mods}\n`;
    } else if (s.type === 'hex') {
      stringsSection += `        ${s.id} = { ${s.value} }\n`;
    } else if (s.type === 'regex') {
      stringsSection += `        ${s.id} = /${s.value}/\n`;
    }
  }
  
  return `rule ${config.name} {
    meta:
        description = "${config.description}"
        author = "${config.author}"
        date = "${config.date}"
        tags = ${tagsStr}
    
    strings:
${stringsSection}
    condition:
        ${config.condition}
}`;
}

/* ============================================================================
   SIGMA RULE GENERATION
============================================================================ */

export function generateSigmaRules(
  family: string,
  indicators: IOCIndicator[],
  ttps: string[]
): SigmaRule[] {
  const rules: SigmaRule[] = [];
  
  // Generate rules based on TTPs
  for (const ttp of ttps) {
    const detection = MITRE_DETECTIONS[ttp];
    if (!detection) continue;
    
    const rule = generateSigmaFromTTP(family, ttp, detection);
    if (rule) rules.push(rule);
  }
  
  // Network IOC detection rule
  const networkIndicators = indicators.filter(i => 
    i.type === 'ip' || i.type === 'domain' || i.type === 'url'
  );
  
  if (networkIndicators.length > 0) {
    const detectionValues = networkIndicators.slice(0, 50).map(i => i.value);
    
    rules.push({
      id: `sigma-${family.toLowerCase()}-network`,
      title: `${family} Network IOC Detection`,
      description: `Detects network connections to known ${family} infrastructure`,
      status: 'experimental',
      author: 'OSINT Hub Detection Engine',
      date: new Date().toISOString().split('T')[0],
      logsource: {
        category: 'network_connection',
        product: 'any',
      },
      detection: {
        selection: {
          DestinationHostname: detectionValues.filter(v => !v.match(/^\d+\.\d+\.\d+\.\d+$/)),
          DestinationIp: detectionValues.filter(v => v.match(/^\d+\.\d+\.\d+\.\d+$/)),
        },
        condition: 'selection',
      },
      level: 'high',
      tags: [`attack.${family.toLowerCase()}`, 'attack.command_and_control'],
      falsepositives: ['Legitimate traffic to shared hosting'],
      ruleContent: formatSigmaRule({
        title: `${family} Network IOC Detection`,
        status: 'experimental',
        logsource: { category: 'network_connection', product: 'any' },
        detection: {
          selection: { DestinationHostname: detectionValues.slice(0, 10) },
          condition: 'selection',
        },
        level: 'high',
      }),
    });
  }
  
  // Process creation rule (generic malware behavior)
  rules.push({
    id: `sigma-${family.toLowerCase()}-process`,
    title: `${family} Suspicious Process Execution`,
    description: `Detects suspicious process patterns associated with ${family}`,
    status: 'experimental',
    author: 'OSINT Hub Detection Engine',
    date: new Date().toISOString().split('T')[0],
    logsource: {
      category: 'process_creation',
      product: 'windows',
    },
    detection: {
      selection: {
        CommandLine: [
          `*${family.toLowerCase()}*`,
          '*-enc*',
          '*downloadstring*',
          '*hidden*',
        ],
      },
      condition: 'selection',
    },
    level: 'medium',
    tags: [`attack.${family.toLowerCase()}`, 'attack.execution'],
    falsepositives: ['Legitimate administrative tools'],
    ruleContent: formatSigmaRule({
      title: `${family} Suspicious Process Execution`,
      status: 'experimental',
      logsource: { category: 'process_creation', product: 'windows' },
      detection: {
        selection: { CommandLine: [`*${family.toLowerCase()}*`] },
        condition: 'selection',
      },
      level: 'medium',
    }),
  });
  
  return rules;
}

function generateSigmaFromTTP(
  family: string,
  ttp: string,
  detection: { logsource: string; detection_patterns: string[] }
): SigmaRule | null {
  const [category, product] = detection.logsource.split('/');
  
  return {
    id: `sigma-${family.toLowerCase()}-${ttp.toLowerCase()}`,
    title: `${family} - ${ttp} Detection`,
    description: `Detects ${ttp} technique used by ${family}`,
    status: 'experimental',
    author: 'OSINT Hub Detection Engine',
    date: new Date().toISOString().split('T')[0],
    logsource: {
      category,
      product: product || 'any',
    },
    detection: {
      selection: {
        CommandLine: detection.detection_patterns.map(p => `*${p}*`),
      },
      condition: 'selection',
    },
    level: 'high',
    tags: [`attack.${ttp.toLowerCase()}`, `attack.${family.toLowerCase()}`],
    falsepositives: ['Legitimate administrative activity'],
    ruleContent: formatSigmaRule({
      title: `${family} - ${ttp} Detection`,
      status: 'experimental',
      logsource: { category, product: product || 'any' },
      detection: {
        selection: { CommandLine: detection.detection_patterns.map(p => `*${p}*`) },
        condition: 'selection',
      },
      level: 'high',
    }),
  };
}

function formatSigmaRule(config: {
  title: string;
  status: string;
  logsource: Record<string, string>;
  detection: Record<string, any>;
  level: string;
}): string {
  return `title: ${config.title}
status: ${config.status}
logsource:
    category: ${config.logsource.category || 'any'}
    product: ${config.logsource.product || 'any'}
detection:
    selection:
${Object.entries(config.detection.selection || {}).map(([k, v]) => 
  `        ${k}:\n${Array.isArray(v) ? v.map(val => `            - '${val}'`).join('\n') : `            - '${v}'`}`
).join('\n')}
    condition: selection
level: ${config.level}`;
}

/* ============================================================================
   IOC LIST GENERATION
============================================================================ */

export function generateIOCLists(family: string, indicators: IOCIndicator[]): IOCList[] {
  const lists: IOCList[] = [];
  
  // Group by type
  const byType = new Map<string, IOCIndicator[]>();
  for (const ind of indicators) {
    if (!byType.has(ind.type)) byType.set(ind.type, []);
    byType.get(ind.type)!.push(ind);
  }
  
  // Full IOC list (JSON format)
  lists.push({
    id: `ioc-${family.toLowerCase()}-full`,
    name: `${family} Complete IOC List`,
    description: `All indicators of compromise for ${family}`,
    family,
    generated: new Date().toISOString(),
    format: 'json',
    indicators,
    stats: {
      total: indicators.length,
      byType: Object.fromEntries([...byType.entries()].map(([k, v]) => [k, v.length])),
      bySeverity: {
        critical: indicators.filter(i => i.severity === 'critical').length,
        high: indicators.filter(i => i.severity === 'high').length,
        medium: indicators.filter(i => i.severity === 'medium').length,
        low: indicators.filter(i => i.severity === 'low').length,
      },
    },
  });
  
  // CSV export
  lists.push({
    id: `ioc-${family.toLowerCase()}-csv`,
    name: `${family} IOC List (CSV)`,
    description: `CSV format IOC list for import into security tools`,
    family,
    generated: new Date().toISOString(),
    format: 'csv',
    indicators,
    stats: {
      total: indicators.length,
      byType: Object.fromEntries([...byType.entries()].map(([k, v]) => [k, v.length])),
      bySeverity: {},
    },
  });
  
  return lists;
}

/* ============================================================================
   NETWORK BLOCKLIST GENERATION
============================================================================ */

export function generateNetworkBlocklists(family: string, indicators: IOCIndicator[]): NetworkBlocklist[] {
  const blocklists: NetworkBlocklist[] = [];
  
  const ips = indicators.filter(i => i.type === 'ip').map(i => i.value);
  const domains = indicators.filter(i => i.type === 'domain').map(i => i.value);
  
  // Plain text format
  blocklists.push({
    id: `blocklist-${family.toLowerCase()}-plain`,
    name: `${family} Network Blocklist (Plain)`,
    description: 'One entry per line, suitable for most firewalls',
    format: 'plain',
    entries: [...ips, ...domains],
    generated: new Date().toISOString(),
    stats: { ips: ips.length, domains: domains.length, total: ips.length + domains.length },
  });
  
  // Hosts file format
  blocklists.push({
    id: `blocklist-${family.toLowerCase()}-hosts`,
    name: `${family} Hosts File Blocklist`,
    description: 'Hosts file format (0.0.0.0 domain)',
    format: 'hosts',
    entries: domains.map(d => `0.0.0.0 ${d}`),
    generated: new Date().toISOString(),
    stats: { ips: 0, domains: domains.length, total: domains.length },
  });
  
  // pfSense format
  blocklists.push({
    id: `blocklist-${family.toLowerCase()}-pfsense`,
    name: `${family} pfSense Alias`,
    description: 'pfSense firewall alias format',
    format: 'pfsense',
    entries: ips,
    generated: new Date().toISOString(),
    stats: { ips: ips.length, domains: 0, total: ips.length },
  });
  
  return blocklists;
}

/* ============================================================================
   RISK ASSESSMENT
============================================================================ */

export function generateRiskAssessments(
  family: string,
  indicators: IOCIndicator[],
  ttps: string[]
): RiskAssessment[] {
  const assessments: RiskAssessment[] = [];
  
  // Calculate overall risk
  const factors: RiskFactor[] = [
    {
      name: 'Malware Severity',
      weight: 0.25,
      score: getMalwareSeverityScore(family),
      description: `${family} is a ${getMalwareType(family)} with significant impact potential`,
    },
    {
      name: 'Active Infrastructure',
      weight: 0.20,
      score: indicators.filter(i => i.type === 'ip' || i.type === 'domain').length > 5 ? 85 : 50,
      description: `${indicators.length} active indicators detected`,
    },
    {
      name: 'TTP Coverage',
      weight: 0.20,
      score: Math.min(100, ttps.length * 15),
      description: `${ttps.length} MITRE ATT&CK techniques identified`,
    },
    {
      name: 'IOC Confidence',
      weight: 0.15,
      score: indicators.length > 0 
        ? Math.round(indicators.reduce((sum, i) => sum + i.confidence, 0) / indicators.length)
        : 0,
      description: 'Average confidence of collected indicators',
    },
    {
      name: 'Recent Activity',
      weight: 0.20,
      score: hasRecentActivity(indicators) ? 90 : 40,
      description: hasRecentActivity(indicators) ? 'Active in last 30 days' : 'No recent activity detected',
    },
  ];
  
  const totalScore = Math.round(
    factors.reduce((sum, f) => sum + f.score * f.weight, 0)
  );
  
  const priority: RiskAssessment['priority'] = 
    totalScore >= 80 ? 'critical' :
    totalScore >= 60 ? 'high' :
    totalScore >= 40 ? 'medium' :
    totalScore >= 20 ? 'low' : 'info';
  
  assessments.push({
    indicator: family,
    riskScore: totalScore,
    priority,
    factors,
    recommendation: generateRecommendation(priority, family),
    mitigations: generateMitigations(family, ttps),
    ttps,
    affectedAssets: inferAffectedAssets(family),
  });
  
  return assessments;
}

/* ============================================================================
   UTILITY FUNCTIONS
============================================================================ */

function getMalwareSeverityScore(family: string): number {
  const scores: Record<string, number> = {
    'LockBit': 95,
    'BlackCat': 92,
    'Cl0p': 90,
    'Cobalt Strike': 88,
    'RedLine': 75,
    'Raccoon': 72,
    'Vidar': 70,
    'LummaC2': 73,
    'Qakbot': 80,
    'Emotet': 82,
  };
  return scores[family] || 60;
}

function getMalwareType(family: string): string {
  const types: Record<string, string> = {
    'LockBit': 'ransomware',
    'BlackCat': 'ransomware',
    'RedLine': 'infostealer',
    'Raccoon': 'infostealer',
    'Vidar': 'infostealer',
    'LummaC2': 'infostealer',
    'Qakbot': 'loader/banking trojan',
    'Emotet': 'loader/botnet',
    'Cobalt Strike': 'post-exploitation framework',
  };
  return types[family] || 'malware';
}

function hasRecentActivity(indicators: IOCIndicator[]): boolean {
  const thirtyDaysAgo = new Date();
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
  
  return indicators.some(i => {
    if (!i.lastSeen) return false;
    return new Date(i.lastSeen) >= thirtyDaysAgo;
  });
}

function generateRecommendation(priority: string, family: string): string {
  switch (priority) {
    case 'critical':
      return `IMMEDIATE ACTION REQUIRED: ${family} poses critical threat. Implement blocking rules immediately, hunt for indicators across environment, and prepare incident response.`;
    case 'high':
      return `HIGH PRIORITY: Deploy detection rules for ${family}, block known infrastructure, and monitor for related activity.`;
    case 'medium':
      return `Monitor for ${family} indicators and ensure detection rules are deployed. Review exposure and update defenses.`;
    case 'low':
      return `Track ${family} for intelligence purposes. Update blocklists periodically.`;
    default:
      return `Continue monitoring ${family} threat landscape.`;
  }
}

function generateMitigations(family: string, ttps: string[]): string[] {
  const mitigations = [
    'Deploy generated YARA and Sigma rules to detection stack',
    'Add IOCs to network and endpoint blocklists',
    'Enable enhanced logging for process creation and network connections',
  ];
  
  if (ttps.includes('T1555') || ttps.includes('T1539')) {
    mitigations.push('Implement credential manager with MFA');
    mitigations.push('Deploy browser security extensions');
  }
  
  if (ttps.includes('T1486')) {
    mitigations.push('Ensure offline backups are current and tested');
    mitigations.push('Implement network segmentation');
  }
  
  if (ttps.includes('T1059.001')) {
    mitigations.push('Enable PowerShell Constrained Language Mode');
    mitigations.push('Configure PowerShell script block logging');
  }
  
  return mitigations;
}

function inferAffectedAssets(family: string): string[] {
  const assetMap: Record<string, string[]> = {
    'RedLine': ['endpoints', 'browsers', 'crypto_wallets', 'email_clients'],
    'Raccoon': ['endpoints', 'browsers', 'crypto_wallets'],
    'LockBit': ['servers', 'workstations', 'network_shares', 'databases'],
    'BlackCat': ['linux_servers', 'esxi_hosts', 'windows_servers'],
    'Qakbot': ['workstations', 'email_servers', 'domain_controllers'],
    'Cobalt Strike': ['domain_controllers', 'servers', 'high_value_targets'],
  };
  return assetMap[family] || ['endpoints', 'servers'];
}

export { MITRE_DETECTIONS, MALWARE_SIGNATURES };
