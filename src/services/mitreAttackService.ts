// Real MITRE ATT&CK TAXII service - NO MOCK DATA
// Fetches live malware families from MITRE ATT&CK

export interface MitreMalware {
  id: string;
  name: string;
  is_family: boolean;
  description: string;
  aliases: string[];
  created: string;
  modified: string;
  external_references: Array<{
    source_name: string;
    external_id: string;
    url: string;
  }>;
}

export interface MitreAttackResponse {
  malware_families: MitreMalware[];
  total_count: number;
  last_updated: string;
}

class MitreAttackService {
  private readonly baseUrl = 'https://cti-taxii.mitre.org/taxii';
  private readonly apiRoot = 'https://cti-taxii.mitre.org/taxii/collections/95ecc380-afe9-11e4-9b6c-751b66dd541e';

  // Fetch real malware families from MITRE ATT&CK TAXII
  async fetchMalwareFamilies(): Promise<MitreAttackResponse> {
    try {
      console.log('[MITRE] Fetching real malware families from TAXII...');
      
      // Use the objects endpoint to get malware objects
      const response = await fetch(`${this.apiRoot}/objects?type=malware&limit=100`, {
        method: 'GET',
        headers: {
          'Accept': 'application/vnd.oasis.stix+json; version=2.1',
          'User-Agent': 'OSINT-Hub/1.0'
        }
      });

      if (!response.ok) {
        throw new Error(`MITRE ATT&CK API failed: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      console.log('[MITRE] Raw TAXII response:', data);
      
      if (!data.objects || !Array.isArray(data.objects)) {
        throw new Error('Invalid MITRE ATT&CK response structure');
      }

      // Filter for malware objects only
      const malwareObjects = data.objects.filter((obj: any) => 
        obj.type === 'malware' && obj.is_family === true
      );

      const malwareFamilies: MitreMalware[] = malwareObjects.map((obj: any) => ({
        id: obj.id,
        name: obj.name,
        is_family: obj.is_family || true,
        description: obj.description || 'No description available',
        aliases: obj.x_mitre_aliases || obj.aliases || [],
        created: obj.created,
        modified: obj.modified,
        external_references: obj.external_references || []
      }));

      console.log('[MITRE] Successfully fetched', malwareFamilies.length, 'real malware families');
      
      return {
        malware_families: malwareFamilies,
        total_count: malwareFamilies.length,
        last_updated: new Date().toISOString()
      };

    } catch (error) {
      console.error('[MITRE] Failed to fetch real malware families:', error);
      throw new Error(`MITRE ATT&CK fetch failed: ${error.message}`);
    }
  }

  // Get specific malware by name from MITRE
  async getMalwareByName(name: string): Promise<MitreMalware | null> {
    try {
      const response = await this.fetchMalwareFamilies();
      const malware = response.malware_families.find(m => 
        m.name.toLowerCase() === name.toLowerCase() ||
        m.aliases.some(alias => alias.toLowerCase() === name.toLowerCase())
      );
      
      return malware || null;
    } catch (error) {
      console.error('[MITRE] Failed to get malware by name:', error);
      return null;
    }
  }
}

export const mitreAttackService = new MitreAttackService();
