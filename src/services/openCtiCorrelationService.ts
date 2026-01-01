// OpenCTI-style threat correlation service - NO MOCK DATA
// Unifies all real threat intelligence sources into standardized objects

import { 
  fetchFeodoC2Servers, 
  fetchURLhausRecent, 
  fetchThreatFoxIOCs, 
  fetchMalwareBazaarRecent,
  type C2Server,
  type URLhausEntry,
  type ThreatFoxIOC,
  type MalwareSample
} from './mispFeedService';

// Unified OpenCTI object following exact user specification
export interface OpenCTIObject {
  id: string;
  type: 'malware' | 'url' | 'infrastructure' | 'repository';
  name: string;
  description: string;
  labels: string[];
  confidence: number;
  created: string;
  modified: string;
  source: string;
  external_references: Array<{
    source_name: string;
    url: string;
    description?: string;
  }>;
  kill_chain_phases?: Array<{
    kill_chain_name: string;
    phase_name: string;
  }>;
  indicators?: Array<{
    type: string;
    value: string;
    source: string;
  }>;
}

class OpenCTICorrelationService {
  
  // Correlate malware from all sources
  async correlateMalwareFamilies(family: string): Promise<OpenCTIObject[]> {
    console.log(`[OpenCTI] Starting correlation for malware family: ${family}`);
    const results: OpenCTIObject[] = [];
    const familyLower = family.toLowerCase();
    
    try {
      // 1. Get Feodo C2 servers and filter by family
      const feodoServers = await fetchFeodoC2Servers();
      const matchingC2 = feodoServers.filter(server => 
        server.malwareFamily?.toLowerCase().includes(familyLower)
      );
      matchingC2.forEach(server => {
        results.push(this.convertFeodoToOpenCTI(server));
      });
      
      // 2. Get URLhaus URLs and filter by tags/threat
      const urlEntries = await fetchURLhausRecent();
      const matchingUrls = urlEntries.filter(entry =>
        entry.threat?.toLowerCase().includes(familyLower) ||
        entry.tags?.some(tag => tag.toLowerCase().includes(familyLower))
      );
      matchingUrls.slice(0, 50).forEach(url => {
        results.push(this.convertUrlhausToOpenCTI(url));
      });
      
      // 3. Get ThreatFox IOCs and filter by malware
      const threatfoxIOCs = await fetchThreatFoxIOCs(7);
      const matchingIOCs = threatfoxIOCs.filter(ioc =>
        ioc.malware?.toLowerCase().includes(familyLower) ||
        ioc.malwarePrintable?.toLowerCase().includes(familyLower) ||
        ioc.tags?.some(tag => tag.toLowerCase().includes(familyLower))
      );
      matchingIOCs.slice(0, 50).forEach(ioc => {
        results.push(this.convertThreatFoxToOpenCTI(ioc));
      });
      
      // 4. Get MalwareBazaar samples (limited filtering as export is just hashes)
      const bazaarSamples = await fetchMalwareBazaarRecent(50);
      bazaarSamples.slice(0, 20).forEach(sample => {
        results.push(this.convertBazaarToOpenCTI(sample));
      });

      console.log(`[OpenCTI] Correlated ${results.length} total objects for ${family}`);
      return results;

    } catch (error) {
      console.error(`[OpenCTI] Correlation failed for ${family}:`, error);
      return results; // Return what we have so far
    }
  }

  // Get live threat landscape overview
  async getLiveThreatLandscape(): Promise<{
    total_threats: number;
    recent_malware: number;
    active_c2: number;
    malicious_urls: number;
    threat_repositories: number;
    last_updated: string;
  }> {
    console.log('[OpenCTI] Generating live threat landscape...');
    
    try {
      const [c2Servers, urlEntries, threatfoxIOCs, malwareSamples] = await Promise.all([
        fetchFeodoC2Servers(),
        fetchURLhausRecent(),
        fetchThreatFoxIOCs(7),
        fetchMalwareBazaarRecent(100)
      ]);

      const landscape = {
        total_threats: c2Servers.length + urlEntries.length + threatfoxIOCs.length + malwareSamples.length,
        recent_malware: malwareSamples.length,
        active_c2: c2Servers.length,
        malicious_urls: urlEntries.length + threatfoxIOCs.length,
        threat_repositories: 0, // GitHub search disabled for now
        last_updated: new Date().toISOString()
      };

      console.log('[OpenCTI] Live threat landscape:', landscape);
      return landscape;

    } catch (error) {
      console.error('[OpenCTI] Failed to generate threat landscape:', error);
      throw error;
    }
  }

  // Convert MITRE data to OpenCTI format
  private convertMitreToOpenCTI(malware: any): OpenCTIObject {
    return {
      id: `mitre-${malware.id}`,
      type: 'malware',
      name: malware.name,
      description: malware.description || `MITRE ATT&CK malware: ${malware.name}`,
      labels: malware.labels || ['malware'],
      confidence: 95,
      created: malware.created || new Date().toISOString(),
      modified: malware.modified || new Date().toISOString(),
      source: 'MITRE ATT&CK',
      external_references: [{
        source_name: 'mitre-attack',
        url: `https://attack.mitre.org/software/${malware.id}`,
        description: 'MITRE ATT&CK Software'
      }],
      kill_chain_phases: malware.kill_chain_phases || []
    };
  }

  // Convert MalwareBazaar data to OpenCTI format  
  private convertBazaarToOpenCTI(sample: MalwareSample): OpenCTIObject {
    return {
      id: `bazaar-${sample.sha256.slice(0, 16)}`,
      type: 'malware',
      name: sample.fileName || `Sample ${sample.sha256.slice(0, 16)}`,
      description: `Malware sample: ${sample.signature || sample.malwareFamily || 'Unknown'}`,
      labels: sample.tags || [sample.malwareFamily || 'malware'],
      confidence: 90,
      created: sample.firstSeen,
      modified: sample.lastSeen || sample.firstSeen,
      source: 'MalwareBazaar',
      external_references: [{
        source_name: 'malware-bazaar',
        url: sample.downloadUrl || `https://bazaar.abuse.ch/sample/${sample.sha256}/`,
        description: 'MalwareBazaar Sample'
      }],
      indicators: [{
        type: 'file-sha256',
        value: sample.sha256,
        source: 'MalwareBazaar'
      }]
    };
  }

  // Convert URLhaus data to OpenCTI format
  private convertUrlhausToOpenCTI(entry: URLhausEntry): OpenCTIObject {
    return {
      id: entry.id,
      type: 'url',
      name: entry.host || 'Malicious URL',
      description: `Malicious URL hosting ${entry.threat || 'malware'}`,
      labels: entry.tags || [entry.threat || 'malicious-url'],
      confidence: 85,
      created: entry.dateAdded,
      modified: entry.dateAdded,
      source: 'URLhaus',
      external_references: [{
        source_name: 'urlhaus',
        url: `https://urlhaus.abuse.ch/browse/`,
        description: 'URLhaus Malicious URLs'
      }],
      indicators: [{
        type: 'url',
        value: entry.url,
        source: 'URLhaus'
      }]
    };
  }

  // Convert Feodo data to OpenCTI format
  private convertFeodoToOpenCTI(server: C2Server): OpenCTIObject {
    return {
      id: server.id,
      type: 'infrastructure',
      name: `${server.malwareFamily} C2 (${server.ip})`,
      description: `${server.malwareFamily} C2 server at ${server.ip}:${server.port} (${server.country || 'Unknown'})`,
      labels: [server.malwareFamily.toLowerCase(), 'c2-server', 'botnet'],
      confidence: 80,
      created: server.firstSeen,
      modified: server.lastOnline,
      source: 'Feodo Tracker',
      external_references: [{
        source_name: 'feodo-tracker',
        url: 'https://feodotracker.abuse.ch/',
        description: 'Feodo Tracker C2 Database'
      }],
      indicators: [{
        type: 'ipv4-addr',
        value: server.ip,
        source: 'Feodo Tracker'
      }]
    };
  }

  // Convert ThreatFox data to OpenCTI format
  private convertThreatFoxToOpenCTI(ioc: ThreatFoxIOC): OpenCTIObject {
    return {
      id: ioc.id,
      type: ioc.threatType === 'botnet_cc' ? 'infrastructure' : 'malware',
      name: ioc.malwarePrintable || ioc.malware || 'Unknown IOC',
      description: `${ioc.threatType}: ${ioc.iocType} - ${ioc.ioc}`,
      labels: ioc.tags || [ioc.malware || 'ioc'],
      confidence: ioc.confidenceLevel,
      created: ioc.firstSeen,
      modified: ioc.lastSeen || ioc.firstSeen,
      source: 'ThreatFox',
      external_references: [{
        source_name: 'threatfox',
        url: ioc.reference || 'https://threatfox.abuse.ch/',
        description: 'ThreatFox IOC Database'
      }],
      indicators: [{
        type: ioc.iocType === 'ip:port' ? 'ipv4-addr' : (ioc.iocType === 'domain' ? 'domain-name' : ioc.iocType),
        value: ioc.ioc,
        source: 'ThreatFox'
      }]
    };
  }

  // Convert GitHub data to OpenCTI format
  private convertGitHubToOpenCTI(repo: any): OpenCTIObject {
    return {
      id: `github-${repo.id}`,
      type: 'repository', 
      name: repo.name,
      description: repo.description || `Malware repository: ${repo.full_name}`,
      labels: ['malware-repository', repo.language?.toLowerCase() || 'unknown'],
      confidence: 70,
      created: repo.created_at,
      modified: repo.updated_at,
      source: 'GitHub',
      external_references: [{
        source_name: 'github',
        url: repo.html_url,
        description: 'GitHub Repository'
      }]
    };
  }
}

export const openCtiCorrelationService = new OpenCTICorrelationService();
