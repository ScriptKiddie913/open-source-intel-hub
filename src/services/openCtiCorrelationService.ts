// OpenCTI-style threat correlation service - NO MOCK DATA
// Unifies all real threat intelligence sources into standardized objects

import { mitreAttackService } from './mitreAttackService';
import { malwareBazaarService } from './malwareBazaarService';
import { urlhausService } from './urlhausService';
import { feodoTrackerService } from './feodoTrackerService';
import { gitHubMalwareService } from './githubMalwareService';

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
    
    try {
      // 1. Get MITRE ATT&CK data
      const mitreData = await mitreAttackService.getMalwareByName(family);
      if (mitreData.length > 0) {
        mitreData.forEach(malware => {
          results.push(this.convertMitreToOpenCTI(malware));
        });
      }

      // 2. Get MalwareBazaar samples  
      const bazaarData = await malwareBazaarService.searchMalwareFamily(family);
      if (bazaarData.data && bazaarData.data.length > 0) {
        bazaarData.data.forEach(sample => {
          results.push(this.convertBazaarToOpenCTI(sample));
        });
      }

      // 3. Get URLhaus URLs
      const urlData = await urlhausService.searchUrlsByTag(family);
      if (urlData.urls && urlData.urls.length > 0) {
        urlData.urls.forEach(url => {
          results.push(this.convertUrlhausToOpenCTI(url));
        });
      }

      // 4. Get Feodo C2 servers
      const feodoData = await feodoTrackerService.getC2ServersByMalware(family);
      if (feodoData.length > 0) {
        feodoData.forEach(server => {
          results.push(this.convertFeodoToOpenCTI(server));
        });
      }

      // 5. Get GitHub repositories
      const githubData = await gitHubMalwareService.searchMalwareRepositories(family);
      if (githubData.length > 0) {
        githubData.forEach(repo => {
          results.push(this.convertGitHubToOpenCTI(repo));
        });
      }

      console.log(`[OpenCTI] Correlated ${results.length} total objects for ${family}`);
      return results;

    } catch (error) {
      console.error(`[OpenCTI] Correlation failed for ${family}:`, error);
      throw new Error(`OpenCTI correlation failed: ${error.message}`);
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
      const [malwareCount, c2Count, urlCount, repoCount] = await Promise.all([
        malwareBazaarService.fetchRecentSamples(100),
        feodoTrackerService.fetchActiveC2Servers(),
        urlhausService.fetchRecentUrls(100), 
        gitHubMalwareService.searchMalwareRepositories('apt', 50)
      ]);

      const landscape = {
        total_threats: malwareCount.data.length + c2Count.data.length + urlCount.urls.length + repoCount.length,
        recent_malware: malwareCount.data.length,
        active_c2: c2Count.data.length,
        malicious_urls: urlCount.urls.length,
        threat_repositories: repoCount.length,
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
  private convertBazaarToOpenCTI(sample: any): OpenCTIObject {
    return {
      id: `bazaar-${sample.sha256_hash}`,
      type: 'malware',
      name: sample.file_name || 'Unknown Sample',
      description: `Malware sample: ${sample.signature || 'Unknown'} (${sample.file_type})`,
      labels: sample.tags || [sample.signature || 'malware'],
      confidence: 90,
      created: sample.first_seen,
      modified: sample.last_seen || sample.first_seen,
      source: 'MalwareBazaar',
      external_references: [{
        source_name: 'malware-bazaar',
        url: `https://bazaar.abuse.ch/sample/${sample.sha256_hash}/`,
        description: 'MalwareBazaar Sample'
      }],
      indicators: [{
        type: 'file-sha256',
        value: sample.sha256_hash,
        source: 'MalwareBazaar'
      }]
    };
  }

  // Convert URLhaus data to OpenCTI format
  private convertUrlhausToOpenCTI(url: any): OpenCTIObject {
    return {
      id: `urlhaus-${url.id}`,
      type: 'url',
      name: url.host || 'Malicious URL',
      description: `Malicious URL hosting ${url.threat || 'malware'}`,
      labels: url.tags || [url.threat || 'malicious-url'],
      confidence: 85,
      created: url.date_added,
      modified: url.date_added,
      source: 'URLhaus',
      external_references: [{
        source_name: 'urlhaus',
        url: `https://urlhaus.abuse.ch/browse/`,
        description: 'URLhaus Malicious URLs'
      }],
      indicators: [{
        type: 'url',
        value: url.url,
        source: 'URLhaus'
      }]
    };
  }

  // Convert Feodo data to OpenCTI format
  private convertFeodoToOpenCTI(server: any): OpenCTIObject {
    return {
      id: `feodo-${server.id}`,
      type: 'infrastructure',
      name: server.hostname || server.ip,
      description: `${server.malware} C2 server at ${server.ip}:${server.port}`,
      labels: [server.malware.toLowerCase(), 'c2-server', 'botnet'],
      confidence: parseInt(server.confidence) || 80,
      created: server.first_seen,
      modified: server.last_seen,
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
