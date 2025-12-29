export interface TelegramMessage {
  id: number;
  channelUsername: string;
  channelTitle: string;
  date: string;
  message: string;
  views: number;
  forwards: number;
  mediaType?:  'photo' | 'video' | 'document' | 'none';
  mediaUrl?: string;
  hasLinks: boolean;
  links:  string[];
  mentions: string[];
  hashtags: string[];
  leakIndicators: LeakIndicator[];
  sensitivityScore: number;
  category: 'breach' | 'leak' | 'database' | 'credentials' | 'ransomware' | 'general';
}

export interface LeakIndicator {
  type: 'email' | 'password' | 'credit_card' | 'phone' | 'api_key' | 'hash' | 'ip' | 'domain' | 'database';
  matched: string;
  confidence: number;
}

export interface TelegramChannel {
  username: string;
  title: string;
  description: string;
  subscriberCount: number;
  lastScanned?:  string;
  totalLeaks: number;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
}

export interface ScanResult {
  channel: TelegramChannel;
  messages: TelegramMessage[];
  totalMessages: number;
  leaksFound: number;
  scanDuration: number;
}
