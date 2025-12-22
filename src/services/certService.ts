// Certificate Transparency Service using crt.sh

import { API_ENDPOINTS } from '@/data/publicApiEndpoints';
import { Certificate } from '@/types/osint';
import { CrtShCertificate } from '@/types/api';
import { cacheAPIResponse, getCachedData } from '@/lib/database';

const CERT_CACHE_TTL = 120; // minutes

export async function searchCertificates(domain: string): Promise<Certificate[]> {
  const cacheKey = `certs:${domain}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const response = await fetch(
      `${API_ENDPOINTS.certs.base}/?q=${encodeURIComponent(domain)}&output=json`
    );
    
    if (!response.ok) throw new Error(`Certificate lookup failed: ${response.statusText}`);

    const data: CrtShCertificate[] = await response.json();
    
    // Deduplicate by serial number and limit results
    const seen = new Set<string>();
    const certificates: Certificate[] = [];
    
    for (const cert of data) {
      if (!seen.has(cert.serial_number) && certificates.length < 100) {
        seen.add(cert.serial_number);
        certificates.push({
          id: cert.id,
          issuerCaId: cert.issuer_ca_id,
          issuerName: cert.issuer_name,
          commonName: cert.common_name,
          nameValue: cert.name_value,
          notBefore: cert.not_before,
          notAfter: cert.not_after,
          serialNumber: cert.serial_number,
        });
      }
    }

    await cacheAPIResponse(cacheKey, certificates, CERT_CACHE_TTL);
    return certificates;
  } catch (error) {
    console.error('Certificate search error:', error);
    throw error;
  }
}

export async function getSubdomainsFromCerts(domain: string): Promise<string[]> {
  const cacheKey = `cert-subdomains:${domain}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const certs = await searchCertificates(`%.${domain}`);
    const subdomains = new Set<string>();

    certs.forEach((cert) => {
      const names = cert.nameValue?.split('\n') || [];
      names.forEach((name) => {
        const cleaned = name.replace(/^\*\./, '').toLowerCase().trim();
        if (
          cleaned.endsWith(domain.toLowerCase()) &&
          cleaned !== domain.toLowerCase() &&
          !cleaned.startsWith('*')
        ) {
          subdomains.add(cleaned);
        }
      });
      
      // Also check common name
      if (cert.commonName && cert.commonName.endsWith(domain)) {
        const cleaned = cert.commonName.replace(/^\*\./, '').toLowerCase();
        if (cleaned !== domain.toLowerCase()) {
          subdomains.add(cleaned);
        }
      }
    });

    const result = Array.from(subdomains).sort();
    await cacheAPIResponse(cacheKey, result, CERT_CACHE_TTL);
    return result;
  } catch (error) {
    console.error('Subdomain from certs error:', error);
    return [];
  }
}

export function getCertificateStatus(notAfter: string): {
  status: 'valid' | 'expiring' | 'expired';
  daysRemaining: number;
} {
  const expiryDate = new Date(notAfter);
  const now = new Date();
  const daysRemaining = Math.floor((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

  if (daysRemaining < 0) {
    return { status: 'expired', daysRemaining };
  } else if (daysRemaining < 30) {
    return { status: 'expiring', daysRemaining };
  }
  return { status: 'valid', daysRemaining };
}

export function analyzeCertificates(certificates: Certificate[]): {
  totalCerts: number;
  uniqueSubdomains: number;
  expiringCerts: number;
  expiredCerts: number;
  issuers: { name: string; count: number }[];
  timeline: { date: string; issued: number; expired: number }[];
} {
  const subdomains = new Set<string>();
  const issuerCounts: { [key: string]: number } = {};
  let expiringCerts = 0;
  let expiredCerts = 0;
  const timelineData: { [date: string]: { issued: number; expired: number } } = {};

  certificates.forEach((cert) => {
    // Count subdomains
    cert.nameValue?.split('\n').forEach((name) => {
      const cleaned = name.replace(/^\*\./, '').toLowerCase().trim();
      if (cleaned) subdomains.add(cleaned);
    });

    // Count issuers
    const issuer = cert.issuerName.split(',')[0].replace('C=', '').trim();
    issuerCounts[issuer] = (issuerCounts[issuer] || 0) + 1;

    // Check expiry status
    const { status } = getCertificateStatus(cert.notAfter);
    if (status === 'expired') expiredCerts++;
    else if (status === 'expiring') expiringCerts++;

    // Timeline data
    const issuedDate = cert.notBefore.split('T')[0];
    const expiredDate = cert.notAfter.split('T')[0];
    
    if (!timelineData[issuedDate]) timelineData[issuedDate] = { issued: 0, expired: 0 };
    timelineData[issuedDate].issued++;
    
    if (!timelineData[expiredDate]) timelineData[expiredDate] = { issued: 0, expired: 0 };
    timelineData[expiredDate].expired++;
  });

  const issuers = Object.entries(issuerCounts)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  const timeline = Object.entries(timelineData)
    .map(([date, data]) => ({ date, ...data }))
    .sort((a, b) => a.date.localeCompare(b.date))
    .slice(-30);

  return {
    totalCerts: certificates.length,
    uniqueSubdomains: subdomains.size,
    expiringCerts,
    expiredCerts,
    issuers,
    timeline,
  };
}
