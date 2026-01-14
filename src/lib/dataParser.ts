// Data Import Parsers for CSV, JSON, TXT

import { BreachRecord } from '@/types/osint';

export function detectFileFormat(file: File): 'csv' | 'json' | 'txt' | 'unknown' {
  const extension = file.name.split('.').pop()?.toLowerCase();
  if (extension === 'csv') return 'csv';
  if (extension === 'json') return 'json';
  if (extension === 'txt') return 'txt';
  
  // Check MIME type
  if (file.type.includes('csv')) return 'csv';
  if (file.type.includes('json')) return 'json';
  if (file.type.includes('text')) return 'txt';
  
  return 'unknown';
}

export async function parseCSVFile(file: File): Promise<any[]> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    
    reader.onload = (event) => {
      try {
        const text = event.target?.result as string;
        const lines = text.split('\n').filter(line => line.trim());
        
        if (lines.length < 2) {
          resolve([]);
          return;
        }

        // Parse header
        const header = parseCSVLine(lines[0]);
        
        // Parse data rows
        const data = lines.slice(1).map((line, index) => {
          const values = parseCSVLine(line);
          const row: any = { _rowIndex: index };
          
          header.forEach((col, i) => {
            row[col.trim().toLowerCase().replace(/\s+/g, '_')] = values[i]?.trim() || '';
          });
          
          return row;
        });

        resolve(data);
      } catch (error) {
        reject(error);
      }
    };
    
    reader.onerror = () => reject(new Error('Failed to read file'));
    reader.readAsText(file);
  });
}

function parseCSVLine(line: string): string[] {
  const result: string[] = [];
  let current = '';
  let inQuotes = false;
  
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    
    if (char === '"') {
      inQuotes = !inQuotes;
    } else if (char === ',' && !inQuotes) {
      result.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  
  result.push(current);
  return result;
}

export async function parseJSONFile(file: File): Promise<any[]> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    
    reader.onload = (event) => {
      try {
        const text = event.target?.result as string;
        const data = JSON.parse(text);
        
        // Handle both array and object with data property
        if (Array.isArray(data)) {
          resolve(data);
        } else if (data.data && Array.isArray(data.data)) {
          resolve(data.data);
        } else if (typeof data === 'object') {
          // Convert object to array of entries
          resolve([data]);
        } else {
          reject(new Error('Invalid JSON format'));
        }
      } catch (error) {
        reject(error);
      }
    };
    
    reader.onerror = () => reject(new Error('Failed to read file'));
    reader.readAsText(file);
  });
}

export async function parseTXTFile(file: File): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    
    reader.onload = (event) => {
      try {
        const text = event.target?.result as string;
        const lines = text.split('\n')
          .map(line => line.trim())
          .filter(line => line.length > 0);
        resolve(lines);
      } catch (error) {
        reject(error);
      }
    };
    
    reader.onerror = () => reject(new Error('Failed to read file'));
    reader.readAsText(file);
  });
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  stats: {
    totalRows: number;
    validRows: number;
    invalidRows: number;
  };
}

export function validateBreachData(data: any[]): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  let validRows = 0;
  let invalidRows = 0;

  if (!data || data.length === 0) {
    return {
      valid: false,
      errors: ['No data found in file'],
      warnings: [],
      stats: { totalRows: 0, validRows: 0, invalidRows: 0 },
    };
  }

  // Check for required fields
  const firstRow = data[0];
  const hasEmail = 'email' in firstRow || 'mail' in firstRow || 'e-mail' in firstRow;
  
  if (!hasEmail) {
    errors.push('Missing required field: email');
  }

  // Validate each row
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  
  data.forEach((row, index) => {
    const email = row.email || row.mail || row['e-mail'];
    
    if (!email) {
      invalidRows++;
    } else if (!emailRegex.test(email)) {
      invalidRows++;
      if (invalidRows <= 5) {
        warnings.push(`Row ${index + 1}: Invalid email format`);
      }
    } else {
      validRows++;
    }
  });

  if (invalidRows > 0) {
    warnings.push(`${invalidRows} rows have invalid or missing email addresses`);
  }

  return {
    valid: errors.length === 0 && validRows > 0,
    errors,
    warnings,
    stats: {
      totalRows: data.length,
      validRows,
      invalidRows,
    },
  };
}

export function normalizeBreachData(data: any[], source: string): BreachRecord[] {
  return data
    .map((row, index) => {
      const email = (row.email || row.mail || row['e-mail'] || '').toLowerCase().trim();
      
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return null;
      }

      const dataTypes: string[] = [];
      if (row.password || row.hash) dataTypes.push('password');
      if (row.username || row.user) dataTypes.push('username');
      if (row.ip || row.ip_address) dataTypes.push('ip');
      if (row.name || row.full_name) dataTypes.push('name');
      if (row.phone || row.mobile) dataTypes.push('phone');

      return {
        id: `${source}-${index}-${Date.now()}`,
        email,
        password: row.password || row.hash || undefined,
        source,
        date: row.date || row.breach_date || new Date().toISOString().split('T')[0],
        dataTypes: dataTypes.length > 0 ? dataTypes : ['email'],
      } as BreachRecord;
    })
    .filter((record): record is BreachRecord => record !== null);
}

export function normalizeDomainList(data: string[]): string[] {
  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;
  
  return data
    .map(line => line.toLowerCase().trim().replace(/^https?:\/\//, '').split('/')[0])
    .filter(domain => domainRegex.test(domain))
    .filter((domain, index, self) => self.indexOf(domain) === index);
}

export function normalizeIPList(data: string[]): string[] {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  
  return data
    .map(line => line.trim())
    .filter(ip => {
      if (!ipv4Regex.test(ip)) return false;
      return ip.split('.').every(octet => parseInt(octet) <= 255);
    })
    .filter((ip, index, self) => self.indexOf(ip) === index);
}
