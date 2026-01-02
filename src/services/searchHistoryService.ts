// ============================================================================
// searchHistoryService.ts
// ENHANCED SEARCH HISTORY WITH CATEGORIES AND SESSION TRACKING
// ============================================================================

import { supabase } from '@/integrations/supabase/client';

/* ============================================================================
   TYPES
============================================================================ */

export type SearchCategory = 
  | 'pipeline'
  | 'graph'
  | 'stealthmole'
  | 'darkweb'
  | 'malware'
  | 'domain'
  | 'ip'
  | 'breach'
  | 'cve'
  | 'threat_intel'
  | 'telegram'
  | 'ransomware'
  | 'general';

export interface EnhancedSearchHistory {
  id: string;
  user_id: string;
  query: string;
  search_type: string;
  category: SearchCategory;
  results_count: number;
  metadata: Record<string, any>;
  search_results?: Record<string, any>;
  session_id?: string;
  created_at: string;
}

export interface ChatSession {
  id: string;
  user_id: string;
  search_id?: string;
  category: SearchCategory;
  context_data: Record<string, any>;
  messages: Array<{
    role: 'user' | 'assistant' | 'system';
    content: string;
    timestamp: string;
  }>;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  expires_at: string;
}

export interface SearchHistoryFilter {
  category?: SearchCategory;
  searchType?: string;
  dateFrom?: string;
  dateTo?: string;
  limit?: number;
}

/* ============================================================================
   SEARCH HISTORY OPERATIONS
============================================================================ */

/**
 * Save search with enhanced metadata
 */
export async function saveEnhancedSearch(
  query: string,
  category: SearchCategory,
  searchType: string,
  resultsCount: number = 0,
  searchResults: Record<string, any> = {},
  metadata: Record<string, any> = {}
): Promise<EnhancedSearchHistory | null> {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) {
    console.warn('[SearchHistory] No authenticated user, saving to localStorage');
    return saveToLocalStorage(query, category, searchType, resultsCount, searchResults, metadata);
  }

  try {
    const sessionId = generateSessionId();
    
    // Store in search_history table with enhanced metadata
    const { data, error } = await supabase
      .from('search_history')
      .insert({
        user_id: user.id,
        query,
        search_type: searchType,
        results_count: resultsCount,
        metadata: {
          ...metadata,
          category,
          search_results: searchResults,
          session_id: sessionId,
          timestamp: new Date().toISOString(),
        },
      })
      .select()
      .single();

    if (error) {
      console.error('[SearchHistory] Save error:', error);
      return saveToLocalStorage(query, category, searchType, resultsCount, searchResults, metadata);
    }

    console.log(`[SearchHistory] Saved search: ${query} (${category})`);
    
    // Transform to EnhancedSearchHistory format
    return {
      id: data.id,
      user_id: data.user_id,
      query: data.query,
      search_type: data.search_type,
      category: (data.metadata as any)?.category || 'general',
      results_count: data.results_count || 0,
      metadata: data.metadata as Record<string, any>,
      search_results: (data.metadata as any)?.search_results,
      session_id: (data.metadata as any)?.session_id,
      created_at: data.created_at,
    };
  } catch (err) {
    console.error('[SearchHistory] Exception:', err);
    return saveToLocalStorage(query, category, searchType, resultsCount, searchResults, metadata);
  }
}

/**
 * Fallback to localStorage for unauthenticated users
 */
function saveToLocalStorage(
  query: string,
  category: SearchCategory,
  searchType: string,
  resultsCount: number,
  searchResults: Record<string, any>,
  metadata: Record<string, any>
): EnhancedSearchHistory {
  const id = `local-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  const entry: EnhancedSearchHistory = {
    id,
    user_id: 'local',
    query,
    search_type: searchType,
    category,
    results_count: resultsCount,
    metadata,
    search_results: searchResults,
    session_id: generateSessionId(),
    created_at: new Date().toISOString(),
  };
  
  const existing = JSON.parse(localStorage.getItem('search_history') || '[]');
  existing.unshift(entry);
  // Keep only last 100 entries
  localStorage.setItem('search_history', JSON.stringify(existing.slice(0, 100)));
  
  return entry;
}

/**
 * Generate unique session ID
 */
function generateSessionId(): string {
  return `session-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Get search history with filters
 */
export async function getEnhancedSearchHistory(
  filters: SearchHistoryFilter = {}
): Promise<EnhancedSearchHistory[]> {
  const { data: { user } } = await supabase.auth.getUser();
  
  // Check localStorage for local entries
  const localEntries: EnhancedSearchHistory[] = JSON.parse(
    localStorage.getItem('search_history') || '[]'
  );
  
  if (!user) {
    return filterLocalEntries(localEntries, filters);
  }

  try {
    let query = supabase
      .from('search_history')
      .select('*')
      .eq('user_id', user.id)
      .order('created_at', { ascending: false });

    if (filters.searchType) {
      query = query.eq('search_type', filters.searchType);
    }
    if (filters.dateFrom) {
      query = query.gte('created_at', filters.dateFrom);
    }
    if (filters.dateTo) {
      query = query.lte('created_at', filters.dateTo);
    }
    
    query = query.limit(filters.limit || 50);

    const { data, error } = await query;

    if (error) {
      console.error('[SearchHistory] Fetch error:', error);
      return filterLocalEntries(localEntries, filters);
    }

    // Transform database results to EnhancedSearchHistory
    const dbEntries: EnhancedSearchHistory[] = (data || []).map(item => ({
      id: item.id,
      user_id: item.user_id,
      query: item.query,
      search_type: item.search_type,
      category: ((item.metadata as any)?.category || 'general') as SearchCategory,
      results_count: item.results_count || 0,
      metadata: item.metadata as Record<string, any>,
      search_results: (item.metadata as any)?.search_results,
      session_id: (item.metadata as any)?.session_id,
      created_at: item.created_at,
    }));

    // Merge with local entries
    const merged = [...dbEntries, ...localEntries];
    return filterLocalEntries(merged, filters);
  } catch (err) {
    console.error('[SearchHistory] Exception:', err);
    return filterLocalEntries(localEntries, filters);
  }
}

/**
 * Filter local entries
 */
function filterLocalEntries(
  entries: EnhancedSearchHistory[],
  filters: SearchHistoryFilter
): EnhancedSearchHistory[] {
  let filtered = entries;
  
  if (filters.category) {
    filtered = filtered.filter(e => e.category === filters.category);
  }
  if (filters.searchType) {
    filtered = filtered.filter(e => e.search_type === filters.searchType);
  }
  if (filters.dateFrom) {
    filtered = filtered.filter(e => e.created_at >= filters.dateFrom!);
  }
  if (filters.dateTo) {
    filtered = filtered.filter(e => e.created_at <= filters.dateTo!);
  }
  
  // Sort by date descending and limit
  filtered.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  return filtered.slice(0, filters.limit || 50);
}

/**
 * Get history grouped by category
 */
export async function getHistoryByCategory(): Promise<Record<SearchCategory, EnhancedSearchHistory[]>> {
  const allHistory = await getEnhancedSearchHistory({ limit: 200 });
  
  const grouped: Record<SearchCategory, EnhancedSearchHistory[]> = {
    pipeline: [],
    graph: [],
    stealthmole: [],
    darkweb: [],
    malware: [],
    domain: [],
    ip: [],
    breach: [],
    cve: [],
    threat_intel: [],
    telegram: [],
    ransomware: [],
    general: [],
  };
  
  allHistory.forEach(entry => {
    const category = entry.category || 'general';
    if (grouped[category]) {
      grouped[category].push(entry);
    } else {
      grouped.general.push(entry);
    }
  });
  
  return grouped;
}

/**
 * Delete search history entry
 */
export async function deleteSearchHistoryEntry(id: string): Promise<boolean> {
  // Handle local entries
  if (id.startsWith('local-')) {
    const entries = JSON.parse(localStorage.getItem('search_history') || '[]');
    const filtered = entries.filter((e: EnhancedSearchHistory) => e.id !== id);
    localStorage.setItem('search_history', JSON.stringify(filtered));
    return true;
  }
  
  try {
    const { error } = await supabase
      .from('search_history')
      .delete()
      .eq('id', id);
    
    return !error;
  } catch {
    return false;
  }
}

/**
 * Clear all search history
 */
export async function clearAllHistory(): Promise<boolean> {
  localStorage.removeItem('search_history');
  
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return true;
  
  try {
    const { error } = await supabase
      .from('search_history')
      .delete()
      .eq('user_id', user.id);
    
    return !error;
  } catch {
    return false;
  }
}

/* ============================================================================
   CHAT SESSION OPERATIONS (localStorage-based since no chat_sessions table)
============================================================================ */

/**
 * Create new chat session (localStorage only)
 */
export async function createChatSession(
  category: SearchCategory,
  contextData: Record<string, any>,
  searchId?: string
): Promise<ChatSession | null> {
  const session: ChatSession = {
    id: `chat-${Date.now()}`,
    user_id: 'local',
    search_id: searchId,
    category,
    context_data: contextData,
    messages: [],
    is_active: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
  };
  sessionStorage.setItem(`chat_session_${session.id}`, JSON.stringify(session));
  return session;
}

/**
 * Update chat session messages
 */
export async function updateChatMessages(
  sessionId: string,
  messages: ChatSession['messages']
): Promise<boolean> {
  const session = sessionStorage.getItem(`chat_session_${sessionId}`);
  if (session) {
    const parsed = JSON.parse(session);
    parsed.messages = messages;
    parsed.updated_at = new Date().toISOString();
    sessionStorage.setItem(`chat_session_${sessionId}`, JSON.stringify(parsed));
    return true;
  }
  return false;
}

/**
 * Get active chat session for a search
 */
export async function getChatSessionForSearch(searchId: string): Promise<ChatSession | null> {
  // Check sessionStorage for matching session
  for (let i = 0; i < sessionStorage.length; i++) {
    const key = sessionStorage.key(i);
    if (key?.startsWith('chat_session_')) {
      const session = JSON.parse(sessionStorage.getItem(key) || '{}');
      if (session.search_id === searchId && session.is_active) {
        return session as ChatSession;
      }
    }
  }
  return null;
}

/**
 * Deactivate chat session
 */
export async function deactivateChatSession(sessionId: string): Promise<boolean> {
  sessionStorage.removeItem(`chat_session_${sessionId}`);
  return true;
}

/* ============================================================================
   CATEGORY HELPERS
============================================================================ */

export const CATEGORY_CONFIG: Record<SearchCategory, {
  label: string;
  icon: string;
  color: string;
  description: string;
}> = {
  pipeline: {
    label: 'Threat Pipeline',
    icon: 'Workflow',
    color: 'purple',
    description: 'Malware analysis pipeline searches',
  },
  graph: {
    label: 'Graph Analysis',
    icon: 'Network',
    color: 'blue',
    description: 'Relationship and connection graphs',
  },
  stealthmole: {
    label: 'Deep Scanner',
    icon: 'Radar',
    color: 'cyan',
    description: 'Dark web and threat scanning',
  },
  darkweb: {
    label: 'Dark Web',
    icon: 'Globe',
    color: 'red',
    description: 'Dark web intelligence searches',
  },
  malware: {
    label: 'Malware',
    icon: 'Bug',
    color: 'orange',
    description: 'Malware sample analysis',
  },
  domain: {
    label: 'Domain',
    icon: 'Globe',
    color: 'green',
    description: 'Domain intelligence lookups',
  },
  ip: {
    label: 'IP Address',
    icon: 'Shield',
    color: 'indigo',
    description: 'IP threat analysis',
  },
  breach: {
    label: 'Breach',
    icon: 'Mail',
    color: 'pink',
    description: 'Data breach lookups',
  },
  cve: {
    label: 'CVE',
    icon: 'AlertTriangle',
    color: 'yellow',
    description: 'Vulnerability database searches',
  },
  threat_intel: {
    label: 'Threat Intel',
    icon: 'Shield',
    color: 'cyan',
    description: 'Threat intelligence queries',
  },
  telegram: {
    label: 'Telegram',
    icon: 'Hash',
    color: 'sky',
    description: 'Telegram channel monitoring',
  },
  ransomware: {
    label: 'Ransomware',
    icon: 'AlertTriangle',
    color: 'red',
    description: 'Ransomware tracking',
  },
  general: {
    label: 'General',
    icon: 'Search',
    color: 'gray',
    description: 'General searches',
  },
};
