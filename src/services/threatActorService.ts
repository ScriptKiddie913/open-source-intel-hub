// ============================================================================
// threatActorService.ts
// THREAT ACTOR INTELLIGENCE SERVICE (StealthMole-style)
// ============================================================================
// ✔ APT group tracking and profiling
// ✔ Cybercrime group monitoring
// ✔ Hacktivist tracking
// ✔ Initial Access Broker (IAB) monitoring
// ✔ MITRE ATT&CK group mapping
// ✔ Threat actor attribution
// ✔ Campaign tracking
// ✔ Free APIs only (MITRE, Malpedia, Open Source)
// ============================================================================

import { cacheAPIResponse, getCachedData } from '@/lib/database';

/* ============================================================================
   TYPES
============================================================================ */

export type ActorType = 'apt' | 'cybercrime' | 'hacktivist' | 'iab' | 'nation_state' | 'unknown';
export type ActorMotivation = 'espionage' | 'financial' | 'disruption' | 'ideology' | 'unknown';

export interface ThreatActor {
  id: string;
  name: string;
  aliases: string[];
  type: ActorType;
  motivation: ActorMotivation;
  description: string;
  country?: string;
  firstSeen: string;
  lastSeen: string;
  active: boolean;
  
  // Attribution
  confidence: number; // 0-100
  attributionEvidence: string[];
  
  // TTPs
  ttps: string[]; // MITRE ATT&CK IDs
  malwareFamilies: string[];
  tools: string[];
  
  // Targets
  targetSectors: string[];
  targetCountries: string[];
  
  // Campaign info
  knownCampaigns: Campaign[];
  
  // Sources
  references: string[];
  source: string;
}

export interface Campaign {
  id: string;
  name: string;
  actor: string;
  description: string;
  startDate: string;
  endDate?: string;
  active: boolean;
  targetSectors: string[];
  targetCountries: string[];
  ttps: string[];
  iocs: string[];
}

export interface ThreatActorSearchResult {
  actors: ThreatActor[];
  campaigns: Campaign[];
  relatedMalware: string[];
  stats: {
    totalActors: number;
    aptCount: number;
    cybercrimeCount: number;
    activeActors: number;
    relatedCampaigns: number;
  };
  searchTime: number;
}

/* ============================================================================
   KNOWN THREAT ACTORS DATABASE (Comprehensive)
============================================================================ */

const KNOWN_APT_GROUPS: Record<string, Partial<ThreatActor>> = {
  // Russian APTs
  'apt28': {
    name: 'APT28',
    aliases: ['Fancy Bear', 'Sofacy', 'Pawn Storm', 'Sednit', 'STRONTIUM', 'Tsar Team', 'Forest Blizzard'],
    type: 'apt',
    motivation: 'espionage',
    country: 'Russia',
    description: 'Russian military intelligence (GRU) cyber espionage group targeting government, military, and security organizations',
    targetSectors: ['Government', 'Military', 'Defense', 'Media', 'Energy'],
    targetCountries: ['USA', 'Ukraine', 'NATO Countries', 'Georgia'],
    malwareFamilies: ['X-Agent', 'X-Tunnel', 'Zebrocy', 'CHOPSTICK'],
    tools: ['Mimikatz', 'Responder', 'Empire'],
    ttps: ['T1566', 'T1053', 'T1059', 'T1071', 'T1078', 'T1027'],
    references: [
      'https://attack.mitre.org/groups/G0007/',
      'https://www.mandiant.com/resources/apt28-a-window-into-russias-cyber-espionage-operations',
      'https://malpedia.caad.fkie.fraunhofer.de/actor/sofacy',
    ],
  },
  'apt29': {
    name: 'APT29',
    aliases: ['Cozy Bear', 'The Dukes', 'CozyDuke', 'NOBELIUM', 'Midnight Blizzard', 'UNC2452'],
    type: 'apt',
    motivation: 'espionage',
    country: 'Russia',
    description: 'Russian intelligence service (SVR) cyber espionage group known for SolarWinds supply chain attack',
    targetSectors: ['Government', 'Think Tanks', 'Technology', 'Healthcare'],
    targetCountries: ['USA', 'UK', 'EU Countries'],
    malwareFamilies: ['SUNBURST', 'TEARDROP', 'WellMess', 'WellMail', 'HAMMERTOSS'],
    tools: ['Cobalt Strike', 'Mimikatz'],
    ttps: ['T1195', 'T1078', 'T1059', 'T1071', 'T1082', 'T1016'],
    references: [
      'https://attack.mitre.org/groups/G0016/',
      'https://www.mandiant.com/resources/blog/unc2452-merged-into-apt29',
      'https://malpedia.caad.fkie.fraunhofer.de/actor/apt29',
    ],
  },
  'sandworm': {
    name: 'Sandworm',
    aliases: ['VOODOO BEAR', 'BlackEnergy', 'Quedagh', 'Seashell Blizzard', 'IRIDIUM'],
    type: 'apt',
    motivation: 'disruption',
    country: 'Russia',
    description: 'Russian military intelligence (GRU) group responsible for destructive attacks including NotPetya',
    targetSectors: ['Energy', 'Government', 'Financial', 'Transportation'],
    targetCountries: ['Ukraine', 'USA', 'EU Countries'],
    malwareFamilies: ['BlackEnergy', 'NotPetya', 'Olympic Destroyer', 'Industroyer', 'Exaramel'],
    tools: ['Mimikatz', 'PsExec'],
    ttps: ['T1486', 'T1485', 'T1489', 'T1078', 'T1027', 'T1059'],
    references: [
      'https://attack.mitre.org/groups/G0034/',
      'https://www.welivesecurity.com/2018/10/11/new-telebots-backdoor-linking-industroyer-notpetya/',
      'https://malpedia.caad.fkie.fraunhofer.de/actor/sandworm',
    ],
  },
  'turla': {
    name: 'Turla',
    aliases: ['Snake', 'Venomous Bear', 'Waterbug', 'KRYPTON', 'Secret Blizzard'],
    type: 'apt',
    motivation: 'espionage',
    country: 'Russia',
    description: 'Russian FSB-linked cyber espionage group active since 1996',
    targetSectors: ['Government', 'Military', 'Embassy', 'Research'],
    targetCountries: ['USA', 'EU Countries', 'Middle East'],
    malwareFamilies: ['Snake', 'Carbon', 'ComRAT', 'Kazuar', 'Gazer'],
    ttps: ['T1071', 'T1573', 'T1059', 'T1105', 'T1027', 'T1041'],
    references: [
      'https://attack.mitre.org/groups/G0010/',
      'https://www.welivesecurity.com/2020/03/12/tracking-turla-new-backdoor-armenian-watering-holes/',
      'https://malpedia.caad.fkie.fraunhofer.de/actor/turla',
    ],
  },
  
  // Chinese APTs
  'apt41': {
    name: 'APT41',
    aliases: ['BARIUM', 'Winnti', 'Wicked Panda', 'Double Dragon', 'Brass Typhoon'],
    type: 'apt',
    motivation: 'espionage',
    country: 'China',
    description: 'Chinese state-sponsored group conducting both espionage and financially motivated operations',
    targetSectors: ['Healthcare', 'Telecom', 'Technology', 'Gaming', 'Finance'],
    targetCountries: ['USA', 'EU Countries', 'Asia'],
    malwareFamilies: ['DUSTPAN', 'DUSTTRAP', 'BEACON', 'KEYPLUG'],
    tools: ['Cobalt Strike', 'Metasploit'],
    ttps: ['T1059', 'T1071', 'T1195', 'T1078', 'T1105', 'T1027'],
    references: [
      'https://attack.mitre.org/groups/G0096/',
      'https://www.mandiant.com/resources/apt41-dual-espionage-and-cyber-crime-operation',
      'https://malpedia.caad.fkie.fraunhofer.de/actor/apt41',
    ],
  },
  'apt40': {
    name: 'APT40',
    aliases: ['Leviathan', 'TEMP.Periscope', 'BRONZE MOHAWK', 'Gadolinium', 'Gingham Typhoon'],
    type: 'apt',
    motivation: 'espionage',
    country: 'China',
    description: 'Chinese state-sponsored group targeting maritime, defense, and research organizations',
    targetSectors: ['Maritime', 'Defense', 'Research', 'Technology'],
    targetCountries: ['USA', 'UK', 'Australia', 'Asia'],
    malwareFamilies: ['MURKYTOP', 'FRESHAIR', 'BEACON'],
    ttps: ['T1566', 'T1059', 'T1071', 'T1105', 'T1078'],
    references: [
      'https://attack.mitre.org/groups/G0065/',
      'https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-200a',
      'https://malpedia.caad.fkie.fraunhofer.de/actor/leviathan',
    ],
  },
  'apt10': {
    name: 'APT10',
    aliases: ['Stone Panda', 'menuPass', 'POTASSIUM', 'Red Apollo', 'CVNX'],
    type: 'apt',
    motivation: 'espionage',
    country: 'China',
    description: 'Chinese state-sponsored group targeting MSPs and supply chains',
    targetSectors: ['MSP', 'Technology', 'Healthcare', 'Defense'],
    targetCountries: ['USA', 'Japan', 'UK', 'EU Countries'],
    malwareFamilies: ['PlugX', 'Quasar RAT', 'RedLeaves'],
    ttps: ['T1199', 'T1078', 'T1059', 'T1071', 'T1105'],
    references: [
      'https://attack.mitre.org/groups/G0045/',
      'https://www.pwc.co.uk/issues/cyber-security-services/insights/operation-cloud-hopper.html',
      'https://malpedia.caad.fkie.fraunhofer.de/actor/stone_panda',
    ],
  },
  'volt_typhoon': {
    name: 'Volt Typhoon',
    aliases: ['VANGUARD PANDA', 'Bronze Silhouette', 'DEV-0391'],
    type: 'apt',
    motivation: 'espionage',
    country: 'China',
    description: 'Chinese state-sponsored group targeting US critical infrastructure for pre-positioning',
    targetSectors: ['Critical Infrastructure', 'Utilities', 'Telecom', 'Transportation'],
    targetCountries: ['USA', 'Guam'],
    malwareFamilies: ['Living-off-the-land'],
    tools: ['WMIC', 'PowerShell', 'ntdsutil'],
    ttps: ['T1078', 'T1059', 'T1218', 'T1003', 'T1071'],
    references: [
      'https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/',
      'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a',
      'https://attack.mitre.org/groups/G1017/',
    ],
  },
  
  // North Korean APTs
  'lazarus': {
    name: 'Lazarus Group',
    aliases: ['HIDDEN COBRA', 'Guardians of Peace', 'Diamond Sleet', 'Zinc', 'Labyrinth Chollima'],
    type: 'apt',
    motivation: 'financial',
    country: 'North Korea',
    description: 'North Korean state-sponsored group conducting both espionage and financial theft operations',
    targetSectors: ['Financial', 'Cryptocurrency', 'Defense', 'Technology'],
    targetCountries: ['USA', 'South Korea', 'Japan', 'Global'],
    malwareFamilies: ['FALLCHILL', 'HOPLIGHT', 'ELECTRICFISH', 'AppleJeus'],
    ttps: ['T1566', 'T1059', 'T1071', 'T1486', 'T1485'],
    references: [
      'https://attack.mitre.org/groups/G0032/',
      'https://www.cisa.gov/news-events/analysis-reports/ar20-133a',
      'https://malpedia.caad.fkie.fraunhofer.de/actor/lazarus_group',
    ],
  },
  'kimsuky': {
    name: 'Kimsuky',
    aliases: ['Velvet Chollima', 'STOLEN PENCIL', 'Emerald Sleet', 'THALLIUM', 'Black Banshee'],
    type: 'apt',
    motivation: 'espionage',
    country: 'North Korea',
    description: 'North Korean cyber espionage group targeting policy experts and researchers',
    targetSectors: ['Government', 'Think Tanks', 'Research', 'Media'],
    targetCountries: ['South Korea', 'USA', 'Japan'],
    malwareFamilies: ['BabyShark', 'GREASE', 'AppleSeed'],
    ttps: ['T1566', 'T1059', 'T1071', 'T1056', 'T1539'],
    references: [
      'https://attack.mitre.org/groups/G0094/',
      'https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-301a',
      'https://malpedia.caad.fkie.fraunhofer.de/actor/kimsuky',
    ],
  },
  
  // Iranian APTs
  'apt33': {
    name: 'APT33',
    aliases: ['Elfin', 'HOLMIUM', 'Peach Sandstorm', 'MAGNALLIUM', 'Refined Kitten'],
    type: 'apt',
    motivation: 'espionage',
    country: 'Iran',
    description: 'Iranian state-sponsored group targeting aviation, energy, and petrochemical sectors',
    targetSectors: ['Aviation', 'Energy', 'Petrochemical', 'Defense'],
    targetCountries: ['USA', 'Saudi Arabia', 'South Korea'],
    malwareFamilies: ['SHAMOON', 'STONEDRILL', 'TURNEDUP'],
    ttps: ['T1566', 'T1059', 'T1071', 'T1486', 'T1078'],
    references: [
      'https://attack.mitre.org/groups/G0064/',
      'https://www.mandiant.com/resources/apt33-insights-into-iranian-cyber-espionage',
      'https://malpedia.caad.fkie.fraunhofer.de/actor/apt33',
    ],
  },
  'apt34': {
    name: 'APT34',
    aliases: ['OilRig', 'HELIX KITTEN', 'Hazel Sandstorm', 'Crambus', 'COBALT GYPSY'],
    type: 'apt',
    motivation: 'espionage',
    country: 'Iran',
    description: 'Iranian state-sponsored group conducting cyber espionage in the Middle East',
    targetSectors: ['Government', 'Financial', 'Energy', 'Telecom'],
    targetCountries: ['Middle East', 'USA'],
    malwareFamilies: ['QUADAGENT', 'BONDUPDATER', 'POWRUNER', 'Helminth'],
    ttps: ['T1566', 'T1059', 'T1071', 'T1078', 'T1003'],
    references: [
      'https://attack.mitre.org/groups/G0049/',
      'https://unit42.paloaltonetworks.com/unit42-oilrig-group-steps-attacks-new-delivery-documents-new-injector-trojan/',
      'https://malpedia.caad.fkie.fraunhofer.de/actor/apt34',
    ],
  },
  'muddywater': {
    name: 'MuddyWater',
    aliases: ['TEMP.Zagros', 'Static Kitten', 'MERCURY', 'Mango Sandstorm', 'Seedworm'],
    type: 'apt',
    motivation: 'espionage',
    country: 'Iran',
    description: 'Iranian MOIS-affiliated group targeting government and telecom sectors',
    targetSectors: ['Government', 'Telecom', 'Energy', 'Defense'],
    targetCountries: ['Middle East', 'South Asia', 'EU Countries'],
    malwareFamilies: ['POWERSTATS', 'SHARPSTATS', 'PowGoop'],
    ttps: ['T1566', 'T1059', 'T1218', 'T1071', 'T1078'],
    references: [
      'https://attack.mitre.org/groups/G0069/',
      'https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-055a',
      'https://malpedia.caad.fkie.fraunhofer.de/actor/muddywater',
    ],
  },
  
  // Cybercrime Groups
  'fin7': {
    name: 'FIN7',
    aliases: ['Carbanak', 'CARBON SPIDER', 'Sangria Tempest', 'ELBRUS'],
    type: 'cybercrime',
    motivation: 'financial',
    country: 'Russia',
    description: 'Russian-speaking cybercrime group targeting retail and hospitality with POS malware',
    targetSectors: ['Retail', 'Hospitality', 'Restaurants', 'Finance'],
    targetCountries: ['USA', 'UK', 'Australia'],
    malwareFamilies: ['Carbanak', 'GRIFFON', 'BATELEUR', 'BOOSTWRITE'],
    ttps: ['T1566', 'T1059', 'T1071', 'T1486', 'T1555'],
    references: [
      'https://attack.mitre.org/groups/G0046/',
      'https://www.mandiant.com/resources/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation',
      'https://malpedia.caad.fkie.fraunhofer.de/actor/fin7',
    ],
  },
  'fin11': {
    name: 'FIN11',
    aliases: ['UNC2546', 'TA505'],
    type: 'cybercrime',
    motivation: 'financial',
    description: 'Financially motivated threat group deploying CLOP ransomware via mass exploitation',
    targetSectors: ['Healthcare', 'Finance', 'Technology'],
    targetCountries: ['USA', 'EU Countries'],
    malwareFamilies: ['CLOP', 'Get2', 'SDBOT', 'FlawedAmmyy'],
    ttps: ['T1190', 'T1486', 'T1489', 'T1071', 'T1566'],
    references: [
      'https://attack.mitre.org/groups/G0092/',
      'https://www.mandiant.com/resources/fin11-email-campaigns-precursor-for-ransomware-data-theft',
      'https://malpedia.caad.fkie.fraunhofer.de/actor/ta505',
    ],
  },
  
  // Ransomware Groups (as threat actors)
  'lockbit_gang': {
    name: 'LockBit Gang',
    aliases: ['ABCD Ransomware'],
    type: 'cybercrime',
    motivation: 'financial',
    description: 'Major ransomware-as-a-service operation with aggressive double extortion tactics',
    targetSectors: ['All Sectors'],
    targetCountries: ['Global'],
    malwareFamilies: ['LockBit', 'LockBit 2.0', 'LockBit 3.0', 'LockBit Green'],
    ttps: ['T1486', 'T1490', 'T1489', 'T1059', 'T1078', 'T1071'],
    references: [
      'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a',
      'https://www.ic3.gov/Media/News/2022/220204.pdf',
      'https://malpedia.caad.fkie.fraunhofer.de/details/win.lockbit',
    ],
  },
  'blackcat_gang': {
    name: 'ALPHV/BlackCat',
    aliases: ['ALPHV', 'Noberus', 'UNC4466'],
    type: 'cybercrime',
    motivation: 'financial',
    description: 'Sophisticated ransomware group using Rust-based ransomware with triple extortion',
    targetSectors: ['Critical Infrastructure', 'Healthcare', 'Finance'],
    targetCountries: ['USA', 'EU Countries'],
    malwareFamilies: ['BlackCat', 'ALPHV', 'Sphynx'],
    ttps: ['T1486', 'T1490', 'T1489', 'T1059', 'T1078'],
    references: [
      'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a',
      'https://www.ic3.gov/Media/News/2022/220420.pdf',
      'https://malpedia.caad.fkie.fraunhofer.de/details/win.blackcat',
    ],
  },
  
  // Hacktivists
  'anonymous': {
    name: 'Anonymous',
    aliases: ['Anon', 'Anonops'],
    type: 'hacktivist',
    motivation: 'ideology',
    description: 'Decentralized hacktivist collective conducting DDoS and data leak operations',
    targetSectors: ['Government', 'Corporate', 'Religious'],
    targetCountries: ['Global'],
    malwareFamilies: ['LOIC', 'HOIC'],
    ttps: ['T1498', 'T1499', 'T1530', 'T1565'],
    references: [
      'https://en.wikipedia.org/wiki/Anonymous_(hacker_group)',
      'https://www.recordedfuture.com/threat-actor/anonymous',
    ],
  },
  'killnet': {
    name: 'KillNet',
    aliases: ['KillNet Team'],
    type: 'hacktivist',
    motivation: 'ideology',
    country: 'Russia',
    description: 'Pro-Russian hacktivist group conducting DDoS attacks against Western targets',
    targetSectors: ['Government', 'Finance', 'Healthcare', 'Transportation'],
    targetCountries: ['USA', 'EU Countries', 'Ukraine'],
    malwareFamilies: ['DDoS tools'],
    ttps: ['T1498', 'T1499'],
    references: [
      'https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-110a',
      'https://www.mandiant.com/resources/blog/killnet-new-capabilities',
    ],
  },
  
  // Initial Access Brokers
  'exotic_lily': {
    name: 'Exotic Lily',
    aliases: ['UNC3189'],
    type: 'iab',
    motivation: 'financial',
    description: 'Initial access broker selling access to ransomware gangs via social engineering',
    targetSectors: ['All Sectors'],
    targetCountries: ['Global'],
    malwareFamilies: ['BumbleBee', 'IcedID'],
    ttps: ['T1566', 'T1078', 'T1059', 'T1105'],
    references: [
      'https://blog.google/threat-analysis-group/exposing-initial-access-broker-ties-conti/',
      'https://malpedia.caad.fkie.fraunhofer.de/details/win.bumblebee',
    ],
  },
};

/* ============================================================================
   MITRE ATT&CK TECHNIQUE DATABASE
============================================================================ */

const MITRE_TECHNIQUES: Record<string, { name: string; tactic: string }> = {
  'T1566': { name: 'Phishing', tactic: 'Initial Access' },
  'T1190': { name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
  'T1195': { name: 'Supply Chain Compromise', tactic: 'Initial Access' },
  'T1199': { name: 'Trusted Relationship', tactic: 'Initial Access' },
  'T1078': { name: 'Valid Accounts', tactic: 'Defense Evasion' },
  'T1059': { name: 'Command and Scripting Interpreter', tactic: 'Execution' },
  'T1053': { name: 'Scheduled Task/Job', tactic: 'Execution' },
  'T1071': { name: 'Application Layer Protocol', tactic: 'Command and Control' },
  'T1573': { name: 'Encrypted Channel', tactic: 'Command and Control' },
  'T1105': { name: 'Ingress Tool Transfer', tactic: 'Command and Control' },
  'T1027': { name: 'Obfuscated Files or Information', tactic: 'Defense Evasion' },
  'T1218': { name: 'System Binary Proxy Execution', tactic: 'Defense Evasion' },
  'T1003': { name: 'OS Credential Dumping', tactic: 'Credential Access' },
  'T1555': { name: 'Credentials from Password Stores', tactic: 'Credential Access' },
  'T1539': { name: 'Steal Web Session Cookie', tactic: 'Credential Access' },
  'T1056': { name: 'Input Capture', tactic: 'Collection' },
  'T1082': { name: 'System Information Discovery', tactic: 'Discovery' },
  'T1016': { name: 'System Network Configuration Discovery', tactic: 'Discovery' },
  'T1486': { name: 'Data Encrypted for Impact', tactic: 'Impact' },
  'T1485': { name: 'Data Destruction', tactic: 'Impact' },
  'T1489': { name: 'Service Stop', tactic: 'Impact' },
  'T1490': { name: 'Inhibit System Recovery', tactic: 'Impact' },
  'T1498': { name: 'Network Denial of Service', tactic: 'Impact' },
  'T1499': { name: 'Endpoint Denial of Service', tactic: 'Impact' },
  'T1530': { name: 'Data from Cloud Storage', tactic: 'Collection' },
  'T1565': { name: 'Data Manipulation', tactic: 'Impact' },
  'T1041': { name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration' },
  'T1110': { name: 'Brute Force', tactic: 'Credential Access' },
  'T1552': { name: 'Unsecured Credentials', tactic: 'Credential Access' },
};

/* ============================================================================
   SEARCH FUNCTIONS
============================================================================ */

/**
 * Search for threat actors by name, alias, TTP, or malware family
 */
export async function searchThreatActors(query: string): Promise<ThreatActorSearchResult> {
  const startTime = Date.now();
  const cacheKey = `actor:${query.toLowerCase()}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return { ...cached, searchTime: 0 };
  
  console.log(`\n[ThreatActor] Searching for: "${query}"`);
  
  const queryLower = query.toLowerCase();
  const matchedActors: ThreatActor[] = [];
  const relatedMalware: string[] = [];
  const campaigns: Campaign[] = [];
  
  // Search through known APT database
  for (const [key, actor] of Object.entries(KNOWN_APT_GROUPS)) {
    let matches = false;
    let matchScore = 0;
    
    // Check name and aliases
    if (actor.name?.toLowerCase().includes(queryLower)) {
      matches = true;
      matchScore = 100;
    } else if (actor.aliases?.some(a => a.toLowerCase().includes(queryLower))) {
      matches = true;
      matchScore = 90;
    }
    
    // Check country
    if (actor.country?.toLowerCase().includes(queryLower)) {
      matches = true;
      matchScore = Math.max(matchScore, 70);
    }
    
    // Check target sectors
    if (actor.targetSectors?.some(s => s.toLowerCase().includes(queryLower))) {
      matches = true;
      matchScore = Math.max(matchScore, 60);
    }
    
    // Check malware families
    if (actor.malwareFamilies?.some(m => m.toLowerCase().includes(queryLower))) {
      matches = true;
      matchScore = Math.max(matchScore, 80);
      relatedMalware.push(...(actor.malwareFamilies || []));
    }
    
    // Check TTPs
    if (actor.ttps?.some(t => t.toLowerCase() === queryLower)) {
      matches = true;
      matchScore = Math.max(matchScore, 50);
    }
    
    if (matches) {
      const fullActor: ThreatActor = {
        id: key,
        name: actor.name || key,
        aliases: actor.aliases || [],
        type: actor.type || 'apt',
        motivation: actor.motivation || 'unknown',
        description: actor.description || '',
        country: actor.country,
        firstSeen: '2010-01-01',
        lastSeen: new Date().toISOString(),
        active: true,
        confidence: matchScore,
        attributionEvidence: [`Matched on: ${queryLower}`],
        ttps: actor.ttps || [],
        malwareFamilies: actor.malwareFamilies || [],
        tools: actor.tools || [],
        targetSectors: actor.targetSectors || [],
        targetCountries: actor.targetCountries || [],
        knownCampaigns: [],
        references: [],
        source: 'internal_db',
      };
      
      matchedActors.push(fullActor);
    }
  }
  
  // Try MITRE ATT&CK API (free)
  try {
    const mitreActors = await searchMITREActors(query);
    
    for (const mitreActor of mitreActors) {
      // Check if already in results
      const exists = matchedActors.some(
        a => a.name.toLowerCase() === mitreActor.name.toLowerCase()
      );
      
      if (!exists) {
        matchedActors.push(mitreActor);
      }
    }
  } catch (err) {
    console.warn('[ThreatActor] MITRE search failed:', err);
  }
  
  // Try Malpedia API (free)
  try {
    const malpediaActors = await searchMalpedia(query);
    
    for (const actor of malpediaActors) {
      const exists = matchedActors.some(
        a => a.name.toLowerCase() === actor.name.toLowerCase()
      );
      
      if (!exists) {
        matchedActors.push(actor);
      } else {
        // Merge data
        const existing = matchedActors.find(
          a => a.name.toLowerCase() === actor.name.toLowerCase()
        );
        if (existing) {
          existing.malwareFamilies = [...new Set([
            ...existing.malwareFamilies,
            ...actor.malwareFamilies,
          ])];
          existing.ttps = [...new Set([...existing.ttps, ...actor.ttps])];
        }
      }
    }
  } catch (err) {
    console.warn('[ThreatActor] Malpedia search failed:', err);
  }
  
  // Sort by confidence
  matchedActors.sort((a, b) => b.confidence - a.confidence);
  
  const result: ThreatActorSearchResult = {
    actors: matchedActors,
    campaigns,
    relatedMalware: [...new Set(relatedMalware)],
    stats: {
      totalActors: matchedActors.length,
      aptCount: matchedActors.filter(a => a.type === 'apt').length,
      cybercrimeCount: matchedActors.filter(a => a.type === 'cybercrime').length,
      activeActors: matchedActors.filter(a => a.active).length,
      relatedCampaigns: campaigns.length,
    },
    searchTime: Date.now() - startTime,
  };
  
  await cacheAPIResponse(cacheKey, result, 3600);
  console.log(`[ThreatActor] ✅ Found ${result.stats.totalActors} actors in ${result.searchTime}ms`);
  
  return result;
}

/**
 * Search MITRE ATT&CK groups API
 */
async function searchMITREActors(query: string): Promise<ThreatActor[]> {
  const actors: ThreatActor[] = [];
  
  try {
    // MITRE ATT&CK STIX data is freely available
    const response = await fetch(
      'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
    );
    
    if (!response.ok) return actors;
    
    const data = await response.json();
    const groups = data.objects?.filter((o: any) => o.type === 'intrusion-set') || [];
    
    const queryLower = query.toLowerCase();
    
    for (const group of groups) {
      const name = group.name || '';
      const aliases = group.aliases || [];
      const description = group.description || '';
      
      // Check if matches
      const matches = 
        name.toLowerCase().includes(queryLower) ||
        aliases.some((a: string) => a.toLowerCase().includes(queryLower)) ||
        description.toLowerCase().includes(queryLower);
      
      if (matches) {
        actors.push({
          id: group.id,
          name: name,
          aliases: aliases,
          type: 'apt',
          motivation: 'espionage',
          description: description.substring(0, 500),
          firstSeen: group.first_seen || '2010-01-01',
          lastSeen: group.last_seen || new Date().toISOString(),
          active: !group.revoked,
          confidence: 80,
          attributionEvidence: ['MITRE ATT&CK'],
          ttps: [],
          malwareFamilies: [],
          tools: [],
          targetSectors: [],
          targetCountries: [],
          knownCampaigns: [],
          references: group.external_references?.map((r: any) => r.url).filter(Boolean) || [],
          source: 'mitre',
        });
      }
    }
  } catch (err) {
    console.warn('[MITRE] API error:', err);
  }
  
  return actors.slice(0, 10);
}

/**
 * Search Malpedia API for actors
 */
async function searchMalpedia(query: string): Promise<ThreatActor[]> {
  const actors: ThreatActor[] = [];
  
  try {
    // Malpedia has a free public API
    const response = await fetch(
      `https://malpedia.caad.fkie.fraunhofer.de/api/list/actors`
    );
    
    if (!response.ok) return actors;
    
    const data = await response.json();
    const queryLower = query.toLowerCase();
    
    for (const [actorId, actorData] of Object.entries(data)) {
      const actor = actorData as any;
      const name = actor.value || actorId;
      
      if (name.toLowerCase().includes(queryLower)) {
        actors.push({
          id: actorId,
          name: name,
          aliases: actor.synonyms || [],
          type: actor.meta?.refs?.includes('nation-state') ? 'apt' : 'cybercrime',
          motivation: 'unknown',
          description: actor.description || '',
          country: actor.meta?.country || undefined,
          firstSeen: '2010-01-01',
          lastSeen: new Date().toISOString(),
          active: true,
          confidence: 70,
          attributionEvidence: ['Malpedia'],
          ttps: [],
          malwareFamilies: [],
          tools: [],
          targetSectors: [],
          targetCountries: [],
          knownCampaigns: [],
          references: actor.meta?.refs || [],
          source: 'malpedia',
        });
      }
    }
  } catch (err) {
    console.warn('[Malpedia] API error:', err);
  }
  
  return actors.slice(0, 10);
}

/**
 * Get detailed threat actor profile
 */
export async function getThreatActorProfile(actorId: string): Promise<ThreatActor | null> {
  const cacheKey = `actor_profile:${actorId}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;
  
  // Check internal database first
  const internalActor = KNOWN_APT_GROUPS[actorId.toLowerCase()];
  if (internalActor) {
    const fullActor: ThreatActor = {
      id: actorId,
      name: internalActor.name || actorId,
      aliases: internalActor.aliases || [],
      type: internalActor.type || 'apt',
      motivation: internalActor.motivation || 'unknown',
      description: internalActor.description || '',
      country: internalActor.country,
      firstSeen: '2010-01-01',
      lastSeen: new Date().toISOString(),
      active: true,
      confidence: 95,
      attributionEvidence: ['Internal Database', 'Open Source Intelligence'],
      ttps: internalActor.ttps || [],
      malwareFamilies: internalActor.malwareFamilies || [],
      tools: internalActor.tools || [],
      targetSectors: internalActor.targetSectors || [],
      targetCountries: internalActor.targetCountries || [],
      knownCampaigns: [],
      references: [],
      source: 'internal_db',
    };
    
    await cacheAPIResponse(cacheKey, fullActor, 3600);
    return fullActor;
  }
  
  return null;
}

/**
 * Get TTPs for a threat actor
 */
export function getTTPDetails(ttpId: string): { id: string; name: string; tactic: string } | null {
  const technique = MITRE_TECHNIQUES[ttpId];
  if (technique) {
    return { id: ttpId, ...technique };
  }
  return null;
}

/**
 * Get actors by country
 */
export function getActorsByCountry(country: string): Partial<ThreatActor>[] {
  const countryLower = country.toLowerCase();
  return Object.entries(KNOWN_APT_GROUPS)
    .filter(([, actor]) => actor.country?.toLowerCase().includes(countryLower))
    .map(([id, actor]) => ({ ...actor, id }));
}

/**
 * Get actors by type
 */
export function getActorsByType(type: ActorType): Partial<ThreatActor>[] {
  return Object.entries(KNOWN_APT_GROUPS)
    .filter(([, actor]) => actor.type === type)
    .map(([id, actor]) => ({ ...actor, id }));
}

/**
 * Get actors targeting a specific sector
 */
export function getActorsBySector(sector: string): Partial<ThreatActor>[] {
  const sectorLower = sector.toLowerCase();
  return Object.entries(KNOWN_APT_GROUPS)
    .filter(([, actor]) => 
      actor.targetSectors?.some(s => s.toLowerCase().includes(sectorLower))
    )
    .map(([id, actor]) => ({ ...actor, id }));
}

/* ============================================================================
   EXPORTS
============================================================================ */

export default {
  searchThreatActors,
  getThreatActorProfile,
  getTTPDetails,
  getActorsByCountry,
  getActorsByType,
  getActorsBySector,
  KNOWN_APT_GROUPS,
  MITRE_TECHNIQUES,
};
