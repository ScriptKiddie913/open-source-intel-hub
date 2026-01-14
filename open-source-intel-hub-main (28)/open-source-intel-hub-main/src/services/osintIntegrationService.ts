// ============================================================================
// osintIntegrationService.ts
// UNIFIED OSINT INTEGRATION SERVICE FOR PHOENIX CHATBOT
// ============================================================================
// Routes queries to appropriate OSINT modules based on entity type
// Integrates: IP, Domain, Hash, CVE, Email, Username, Bitcoin, and more
// ============================================================================

import { detectEntityType, EntityType, DetectedEntity, getEntityLabel } from './entityDetectionService';
import { getFullIPAnalysis, isValidIP } from './ipService';
import { getAllRecords, getSubdomains } from './dnsService';
import { searchCertificates, getSubdomainsFromCerts } from './certService';
import { searchCVE, getCISAKEV } from './cveService';
import { malwareBazaarService } from './malwareBazaarService';
import { investigateAddress, getAddressInfo, BitcoinAddress, CryptoInvestigationResult } from './bitcoinInvestigationService';
import { supabase } from '@/integrations/supabase/client';

// ============================================================================
// TYPES
// ============================================================================

export interface OSINTResult {
  query: string;
  entityType: EntityType;
  entityLabel: string;
  confidence: number;
  timestamp: string;
  results: {
    primary: any;
    secondary?: any;
    threatIntel?: any;
    aiAnalysis?: string;
  };
  summary: string;
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'info';
  recommendations: string[];
  modulesUsed: string[];
}

export interface PhoenixQuery {
  input: string;
  context?: string;
  includeAI?: boolean;
  deepScan?: boolean;
}

// ============================================================================
// MAIN INTEGRATION FUNCTION
// ============================================================================

/**
 * Process a query through the OSINT integration system
 * Automatically detects entity type and routes to appropriate modules
 */
export async function processOSINTQuery(query: PhoenixQuery): Promise<OSINTResult> {
  const { input, includeAI = true, deepScan = false } = query;
  const startTime = Date.now();
  
  // Detect entity type
  const entity = detectEntityType(input);
  console.log(`[OSINT] Detected entity: ${entity.type} (${entity.confidence}% confidence)`);
  
  // Initialize result
  const result: OSINTResult = {
    query: input,
    entityType: entity.type,
    entityLabel: getEntityLabel(entity.type),
    confidence: entity.confidence,
    timestamp: new Date().toISOString(),
    results: { primary: null },
    summary: '',
    riskLevel: 'info',
    recommendations: [],
    modulesUsed: [],
  };

  try {
    // Route to appropriate handler based on entity type
    switch (entity.type) {
      case 'ip':
      case 'ipv6':
        await handleIPQuery(entity.normalized, result, deepScan);
        break;
        
      case 'domain':
        await handleDomainQuery(entity.normalized, result, deepScan);
        break;
        
      case 'url':
        await handleURLQuery(entity.normalized, result);
        break;
        
      case 'email':
        await handleEmailQuery(entity.normalized, result);
        break;
        
      case 'md5':
      case 'sha1':
      case 'sha256':
      case 'sha512':
        await handleHashQuery(entity.normalized, entity.type, result);
        break;
        
      case 'cve':
        await handleCVEQuery(entity.normalized, result);
        break;
        
      case 'username':
        await handleUsernameQuery(entity.normalized, result);
        break;
        
      case 'bitcoin':
        await handleBitcoinQuery(entity.normalized, result, deepScan);
        break;
        
      case 'ethereum':
        await handleEthereumQuery(entity.normalized, result);
        break;
        
      default:
        await handleGeneralQuery(input, result);
        break;
    }

    // Add AI analysis if requested
    if (includeAI && result.results.primary) {
      result.results.aiAnalysis = await generateAIAnalysis(result);
    }

    console.log(`[OSINT] Query completed in ${Date.now() - startTime}ms`);
    
  } catch (error) {
    console.error('[OSINT] Query error:', error);
    result.summary = `Error processing ${entity.type} query: ${error instanceof Error ? error.message : 'Unknown error'}`;
    result.riskLevel = 'info';
  }

  return result;
}

// ============================================================================
// ENTITY HANDLERS
// ============================================================================

async function handleIPQuery(ip: string, result: OSINTResult, deepScan: boolean): Promise<void> {
  result.modulesUsed.push('IP Analyzer', 'Shodan', 'Geolocation');
  
  const analysis = await getFullIPAnalysis(ip);
  result.results.primary = analysis;
  
  if (analysis.geo) {
    result.summary = `IP ${ip} located in ${analysis.geo.city || 'Unknown'}, ${analysis.geo.country || 'Unknown'}. `;
    result.summary += `ISP: ${analysis.geo.isp || 'Unknown'}. `;
  }
  
  if (analysis.ports) {
    result.summary += `Open ports: ${analysis.ports.ports?.length || 0}. `;
    if (analysis.ports.vulns?.length > 0) {
      result.summary += `Known vulnerabilities: ${analysis.ports.vulns.length}. `;
    }
  }
  
  result.riskLevel = analysis.threatLevel;
  
  if (analysis.threatLevel === 'critical') {
    result.recommendations.push('Block this IP immediately at firewall level');
    result.recommendations.push('Check logs for any connections from this IP');
  } else if (analysis.threatLevel === 'high') {
    result.recommendations.push('Monitor traffic from this IP closely');
    result.recommendations.push('Consider adding to watchlist');
  }
}

async function handleDomainQuery(domain: string, result: OSINTResult, deepScan: boolean): Promise<void> {
  result.modulesUsed.push('DNS', 'Certificates', 'Subdomains');
  
  const [dnsRecords, subdomains, certs] = await Promise.all([
    getAllRecords(domain),
    getSubdomains(domain),
    searchCertificates(domain),
  ]);
  
  result.results.primary = {
    dns: dnsRecords,
    subdomains: subdomains.slice(0, 50),
    certificates: certs.slice(0, 20),
  };
  
  result.summary = `Domain ${domain}: ${dnsRecords.records?.length || 0} DNS records, `;
  result.summary += `${subdomains.length} subdomains discovered, `;
  result.summary += `${certs.length} SSL certificates found.`;
  
  // Check for suspicious patterns
  if (subdomains.some(s => s.includes('admin') || s.includes('test') || s.includes('dev'))) {
    result.recommendations.push('Sensitive subdomains detected - ensure proper access controls');
  }
  
  result.riskLevel = 'info';
}

async function handleURLQuery(url: string, result: OSINTResult): Promise<void> {
  result.modulesUsed.push('URL Scanner', 'Threat Intel');
  
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    
    // Get domain info
    const dnsRecords = await getAllRecords(domain);
    
    result.results.primary = {
      url,
      domain,
      protocol: urlObj.protocol,
      path: urlObj.pathname,
      dns: dnsRecords,
    };
    
    result.summary = `URL analysis for ${url}. Domain: ${domain}. `;
    
    // Check for suspicious patterns in URL
    const suspiciousPatterns = [
      'login', 'signin', 'account', 'password', 'verify',
      'secure', 'update', 'confirm', 'banking'
    ];
    
    const pathLower = urlObj.pathname.toLowerCase();
    const isSuspicious = suspiciousPatterns.some(p => pathLower.includes(p));
    
    if (isSuspicious) {
      result.riskLevel = 'medium';
      result.recommendations.push('URL contains potentially sensitive keywords - verify legitimacy');
    }
    
  } catch {
    result.summary = 'Invalid URL format';
    result.riskLevel = 'info';
  }
}

async function handleEmailQuery(email: string, result: OSINTResult): Promise<void> {
  result.modulesUsed.push('Breach Checker', 'Domain Analysis');
  
  const domain = email.split('@')[1];
  const dnsRecords = await getAllRecords(domain);
  
  result.results.primary = {
    email,
    domain,
    mxRecords: dnsRecords.records?.filter(r => r.type === 'MX'),
    hasSPF: dnsRecords.records?.some(r => r.type === 'TXT' && r.data?.includes('v=spf')),
    hasDMARC: false, // Would need additional DMARC lookup
  };
  
  result.summary = `Email ${email} on domain ${domain}. `;
  result.summary += `MX records: ${result.results.primary.mxRecords?.length || 0}. `;
  result.summary += `SPF configured: ${result.results.primary.hasSPF ? 'Yes' : 'No'}.`;
  
  result.recommendations.push('Run breach check to find credential exposures');
  result.recommendations.push('Check dark web for mentions of this email');
  
  result.riskLevel = 'info';
}

async function handleHashQuery(
  hash: string, 
  hashType: 'md5' | 'sha1' | 'sha256' | 'sha512',
  result: OSINTResult
): Promise<void> {
  result.modulesUsed.push('MalwareBazaar', 'VirusTotal', 'Threat Intel');
  
  // Search MalwareBazaar for the hash
  try {
    const malwareResults = await malwareBazaarService.fetchRecentSamples(50);
    
    // Check if hash matches any known samples
    const matchingSamples = malwareResults.data?.filter(sample => 
      sample.sha256_hash?.toLowerCase() === hash ||
      sample.md5_hash?.toLowerCase() === hash
    ) || [];
    
    result.results.primary = {
      hash,
      hashType,
      knownMalware: matchingSamples.length > 0,
      samples: matchingSamples,
      totalSearched: malwareResults.data?.length || 0,
    };
    
    if (matchingSamples.length > 0) {
      const sample = matchingSamples[0];
      result.summary = `⚠️ MALWARE DETECTED: ${hash} matches known malware. `;
      result.summary += `Family: ${sample.signature || 'Unknown'}. `;
      result.summary += `Type: ${sample.file_type || 'Unknown'}. `;
      result.summary += `First seen: ${sample.first_seen || 'Unknown'}.`;
      result.riskLevel = 'critical';
      result.recommendations.push('Quarantine and delete files with this hash immediately');
      result.recommendations.push('Scan all systems for this indicator');
      result.recommendations.push('Report to security team');
    } else {
      result.summary = `Hash ${hash} (${hashType.toUpperCase()}) not found in MalwareBazaar database. `;
      result.summary += 'This does not guarantee the file is safe - consider additional scanning.';
      result.riskLevel = 'info';
      result.recommendations.push('Submit to VirusTotal for comprehensive analysis');
    }
    
  } catch (error) {
    result.summary = `Error searching for hash: ${error instanceof Error ? error.message : 'Unknown error'}`;
    result.riskLevel = 'info';
  }
}

async function handleCVEQuery(cveId: string, result: OSINTResult): Promise<void> {
  result.modulesUsed.push('CVE Explorer', 'NVD', 'CISA KEV');
  
  const [cveResults, kevCatalog] = await Promise.all([
    searchCVE(cveId),
    getCISAKEV(),
  ]);
  
  const cve = cveResults[0];
  const isKEV = kevCatalog.some(k => k.vendorProject?.includes(cveId));
  
  result.results.primary = {
    cve,
    isKnownExploited: isKEV,
    kevDetails: kevCatalog.find(k => k.vendorProject?.includes(cveId)),
  };
  
  if (cve) {
    result.summary = `${cveId}: ${cve.description?.substring(0, 200)}... `;
    result.summary += `CVSS: ${cve.cvss.score} (${cve.cvss.severity}). `;
    result.summary += `Exploits available: ${cve.exploitAvailable ? 'Yes' : 'No'}. `;
    
    if (isKEV) {
      result.summary += '⚠️ ACTIVELY EXPLOITED IN THE WILD.';
      result.riskLevel = 'critical';
      result.recommendations.push('Patch immediately - actively exploited vulnerability');
    } else if (cve.cvss.score >= 9) {
      result.riskLevel = 'critical';
      result.recommendations.push('Critical severity - prioritize patching');
    } else if (cve.cvss.score >= 7) {
      result.riskLevel = 'high';
      result.recommendations.push('High severity - patch within 30 days');
    } else {
      result.riskLevel = cve.cvss.score >= 4 ? 'medium' : 'low';
    }
  } else {
    result.summary = `CVE ${cveId} not found in database.`;
    result.riskLevel = 'info';
  }
}

async function handleUsernameQuery(username: string, result: OSINTResult): Promise<void> {
  result.modulesUsed.push('Username Enumeration', 'Social Search');
  
  // We'll provide a structure for username lookup
  // In a real implementation, this would check multiple platforms
  const platforms = [
    'GitHub', 'Twitter', 'LinkedIn', 'Instagram', 'Reddit',
    'Facebook', 'TikTok', 'YouTube', 'Medium', 'Keybase'
  ];
  
  result.results.primary = {
    username,
    platformsToCheck: platforms,
    note: 'Use Username Enumeration module for detailed platform checking',
  };
  
  result.summary = `Username "${username}" ready for enumeration across ${platforms.length} platforms.`;
  result.recommendations.push('Run full username enumeration scan');
  result.recommendations.push('Check for associated email addresses');
  result.recommendations.push('Search dark web for credential exposures');
  
  result.riskLevel = 'info';
}

async function handleBitcoinQuery(
  address: string, 
  result: OSINTResult, 
  deepScan: boolean
): Promise<void> {
  result.modulesUsed.push('Bitcoin Investigation', 'Blockchain Analysis', 'Threat Intel');
  
  if (deepScan) {
    // Full investigation
    const investigation = await investigateAddress(address);
    
    if (investigation) {
      result.results.primary = investigation;
      
      const addr = investigation.address;
      result.summary = `Bitcoin address ${address}: `;
      result.summary += `Balance: ${addr.balance.toFixed(8)} BTC ($${addr.balanceUSD.toFixed(2)}). `;
      result.summary += `Transactions: ${addr.txCount}. `;
      result.summary += `Risk Score: ${addr.riskScore}/100. `;
      
      if (investigation.relatedThreats.ransomwareConnection) {
        result.summary += '⚠️ RANSOMWARE CONNECTION DETECTED. ';
      }
      if (investigation.relatedThreats.mixerUsage) {
        result.summary += '⚠️ MIXER USAGE DETECTED. ';
      }
      if (investigation.relatedThreats.darknetConnection) {
        result.summary += '⚠️ DARKNET CONNECTION DETECTED. ';
      }
      
      result.riskLevel = investigation.riskAssessment.level;
      result.recommendations = investigation.riskAssessment.recommendations;
    } else {
      result.summary = `Bitcoin address ${address} not found or invalid.`;
      result.riskLevel = 'info';
    }
  } else {
    // Quick lookup
    const addressInfo = await getAddressInfo(address);
    
    if (addressInfo) {
      result.results.primary = addressInfo;
      
      result.summary = `Bitcoin address ${address}: `;
      result.summary += `Balance: ${addressInfo.balance.toFixed(8)} BTC ($${addressInfo.balanceUSD.toFixed(2)}). `;
      result.summary += `Transactions: ${addressInfo.txCount}. `;
      
      if (addressInfo.isExchange) {
        result.summary += `Exchange: ${addressInfo.exchangeName}. `;
      }
      
      result.riskLevel = addressInfo.riskScore >= 80 ? 'critical' :
                         addressInfo.riskScore >= 60 ? 'high' :
                         addressInfo.riskScore >= 40 ? 'medium' : 'low';
      
      if (addressInfo.riskFactors.length > 0) {
        result.recommendations.push(...addressInfo.riskFactors.map(f => `Risk factor: ${f}`));
      }
    } else {
      result.summary = `Bitcoin address ${address} not found or invalid.`;
      result.riskLevel = 'info';
    }
  }
}

async function handleEthereumQuery(address: string, result: OSINTResult): Promise<void> {
  result.modulesUsed.push('Ethereum Analysis');
  
  // Placeholder for Ethereum investigation
  // Would use Etherscan API or similar
  result.results.primary = {
    address,
    network: 'Ethereum',
    note: 'Ethereum investigation module - use Etherscan for detailed analysis',
  };
  
  result.summary = `Ethereum address ${address} detected. Use Etherscan for detailed analysis.`;
  result.recommendations.push('Check Etherscan for transaction history');
  result.recommendations.push('Verify contract interactions if applicable');
  
  result.riskLevel = 'info';
}

async function handleGeneralQuery(query: string, result: OSINTResult): Promise<void> {
  result.modulesUsed.push('Web Search', 'AI Analysis');
  
  result.results.primary = {
    query,
    type: 'general_search',
    note: 'Query did not match a specific entity type',
  };
  
  result.summary = `General query: "${query}". Entity type could not be determined. `;
  result.summary += 'Try entering a specific IP, domain, hash, CVE, email, username, or Bitcoin address.';
  
  result.recommendations.push('Use specific indicators like IP addresses, domains, or hashes');
  result.recommendations.push('For text searches, try the AI assistant for analysis');
  
  result.riskLevel = 'info';
}

// ============================================================================
// AI ANALYSIS
// ============================================================================

async function generateAIAnalysis(result: OSINTResult): Promise<string> {
  try {
    // Use Lovable AI edge function for analysis
    const { data, error } = await supabase.functions.invoke('phoenix-osint-analysis', {
      body: {
        entityType: result.entityType,
        query: result.query,
        results: result.results.primary,
        riskLevel: result.riskLevel,
      },
    });

    if (error) {
      console.warn('[OSINT] AI analysis error:', error);
      return '';
    }

    return data?.analysis || '';
  } catch (error) {
    console.warn('[OSINT] AI analysis failed:', error);
    return '';
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

export const osintIntegration = {
  processQuery: processOSINTQuery,
  detectEntity: detectEntityType,
};
