// ============================================================================
// USER DATA SERVICE
// ============================================================================
// Full Supabase integration for user data persistence
// ============================================================================

import { supabase } from '@/integrations/supabase/client';

/* ============================================================================
   TYPES
============================================================================ */

export interface SearchHistoryItem {
  id: string;
  user_id: string;
  query: string;
  search_type: string;
  results_count: number;
  metadata: Record<string, any>;
  created_at: string;
}

export interface SavedGraph {
  id: string;
  user_id: string;
  name: string;
  description: string | null;
  graph_data: Record<string, any>;
  nodes_count: number;
  edges_count: number;
  created_at: string;
  updated_at: string;
}

export interface MonitoringItem {
  id: string;
  user_id: string;
  name: string;
  monitor_type: string;
  value: string;
  status: string;
  alert_threshold: string;
  last_checked_at: string | null;
  last_alert_at: string | null;
  alerts_count: number;
  metadata: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface MonitoringAlert {
  id: string;
  user_id: string;
  monitoring_item_id: string;
  severity: string;
  title: string;
  description: string | null;
  source: string | null;
  is_read: boolean;
  metadata: Record<string, any>;
  created_at: string;
}

export interface UserSession {
  id: string;
  user_id: string;
  session_name: string | null;
  session_data: Record<string, any>;
  last_active_at: string;
  created_at: string;
}

export interface UserProfile {
  id: string;
  user_id: string;
  email: string | null;
  display_name: string | null;
  avatar_url: string | null;
  created_at: string;
  updated_at: string;
}

/* ============================================================================
   PROFILE OPERATIONS
============================================================================ */

export async function getUserProfile(): Promise<UserProfile | null> {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return null;

  const { data, error } = await supabase
    .from('profiles')
    .select('*')
    .eq('user_id', user.id)
    .maybeSingle();

  if (error) {
    console.error('Error fetching profile:', error);
    return null;
  }

  return data as UserProfile;
}

export async function updateUserProfile(updates: Partial<UserProfile>): Promise<UserProfile | null> {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return null;

  const { data, error } = await supabase
    .from('profiles')
    .update(updates)
    .eq('user_id', user.id)
    .select()
    .single();

  if (error) {
    console.error('Error updating profile:', error);
    return null;
  }

  return data as UserProfile;
}

/* ============================================================================
   SEARCH HISTORY OPERATIONS
============================================================================ */

export async function saveSearchHistory(
  query: string,
  searchType: string,
  resultsCount: number = 0,
  metadata: Record<string, any> = {}
): Promise<SearchHistoryItem | null> {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return null;

  const { data, error } = await supabase
    .from('search_history')
    .insert({
      user_id: user.id,
      query,
      search_type: searchType,
      results_count: resultsCount,
      metadata,
    })
    .select()
    .single();

  if (error) {
    console.error('Error saving search history:', error);
    return null;
  }

  return data as SearchHistoryItem;
}

export async function getSearchHistory(limit: number = 50): Promise<SearchHistoryItem[]> {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return [];

  const { data, error } = await supabase
    .from('search_history')
    .select('*')
    .eq('user_id', user.id)
    .order('created_at', { ascending: false })
    .limit(limit);

  if (error) {
    console.error('Error fetching search history:', error);
    return [];
  }

  return data as SearchHistoryItem[];
}

export async function getSearchHistoryByType(searchType: string, limit: number = 20): Promise<SearchHistoryItem[]> {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return [];

  const { data, error } = await supabase
    .from('search_history')
    .select('*')
    .eq('user_id', user.id)
    .eq('search_type', searchType)
    .order('created_at', { ascending: false })
    .limit(limit);

  if (error) {
    console.error('Error fetching search history:', error);
    return [];
  }

  return data as SearchHistoryItem[];
}

export async function deleteSearchHistory(id: string): Promise<boolean> {
  const { error } = await supabase
    .from('search_history')
    .delete()
    .eq('id', id);

  if (error) {
    console.error('Error deleting search history:', error);
    return false;
  }

  return true;
}

export async function clearAllSearchHistory(): Promise<boolean> {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return false;

  const { error } = await supabase
    .from('search_history')
    .delete()
    .eq('user_id', user.id);

  if (error) {
    console.error('Error clearing search history:', error);
    return false;
  }

  return true;
}

/* ============================================================================
   SAVED GRAPHS OPERATIONS
============================================================================ */

export async function saveGraph(
  name: string,
  graphData: Record<string, any>,
  description?: string
): Promise<SavedGraph | null> {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return null;

  const nodesCount = graphData.nodes?.length || 0;
  const edgesCount = graphData.edges?.length || graphData.links?.length || 0;

  const { data, error } = await supabase
    .from('saved_graphs')
    .insert({
      user_id: user.id,
      name,
      description,
      graph_data: graphData,
      nodes_count: nodesCount,
      edges_count: edgesCount,
    })
    .select()
    .single();

  if (error) {
    console.error('Error saving graph:', error);
    return null;
  }

  return data as SavedGraph;
}

export async function getSavedGraphs(): Promise<SavedGraph[]> {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return [];

  const { data, error } = await supabase
    .from('saved_graphs')
    .select('*')
    .eq('user_id', user.id)
    .order('updated_at', { ascending: false });

  if (error) {
    console.error('Error fetching saved graphs:', error);
    return [];
  }

  return data as SavedGraph[];
}

export async function getGraph(id: string): Promise<SavedGraph | null> {
  const { data, error } = await supabase
    .from('saved_graphs')
    .select('*')
    .eq('id', id)
    .single();

  if (error) {
    console.error('Error fetching graph:', error);
    return null;
  }

  return data as SavedGraph;
}

export async function updateGraph(
  id: string,
  updates: { name?: string; description?: string; graph_data?: Record<string, any> }
): Promise<SavedGraph | null> {
  const updateData: any = { ...updates };
  
  if (updates.graph_data) {
    updateData.nodes_count = updates.graph_data.nodes?.length || 0;
    updateData.edges_count = updates.graph_data.edges?.length || updates.graph_data.links?.length || 0;
  }

  const { data, error } = await supabase
    .from('saved_graphs')
    .update(updateData)
    .eq('id', id)
    .select()
    .single();

  if (error) {
    console.error('Error updating graph:', error);
    return null;
  }

  return data as SavedGraph;
}

export async function deleteGraph(id: string): Promise<boolean> {
  const { error } = await supabase
    .from('saved_graphs')
    .delete()
    .eq('id', id);

  if (error) {
    console.error('Error deleting graph:', error);
    return false;
  }

  return true;
}

/* ============================================================================
   MONITORING OPERATIONS
============================================================================ */

export async function addMonitoringItem(
  name: string,
  monitorType: string,
  value: string,
  alertThreshold: string = 'any',
  metadata: Record<string, any> = {}
): Promise<MonitoringItem | null> {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return null;

  const { data, error } = await supabase
    .from('monitoring_items')
    .insert({
      user_id: user.id,
      name,
      monitor_type: monitorType,
      value,
      alert_threshold: alertThreshold,
      metadata,
    })
    .select()
    .single();

  if (error) {
    console.error('Error adding monitoring item:', error);
    return null;
  }

  return data as MonitoringItem;
}

export async function getMonitoringItems(): Promise<MonitoringItem[]> {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return [];

  const { data, error } = await supabase
    .from('monitoring_items')
    .select('*')
    .eq('user_id', user.id)
    .order('created_at', { ascending: false });

  if (error) {
    console.error('Error fetching monitoring items:', error);
    return [];
  }

  return data as MonitoringItem[];
}

export async function updateMonitoringItem(
  id: string,
  updates: Partial<MonitoringItem>
): Promise<MonitoringItem | null> {
  const { data, error } = await supabase
    .from('monitoring_items')
    .update(updates)
    .eq('id', id)
    .select()
    .single();

  if (error) {
    console.error('Error updating monitoring item:', error);
    return null;
  }

  return data as MonitoringItem;
}

export async function deleteMonitoringItem(id: string): Promise<boolean> {
  const { error } = await supabase
    .from('monitoring_items')
    .delete()
    .eq('id', id);

  if (error) {
    console.error('Error deleting monitoring item:', error);
    return false;
  }

  return true;
}

export async function pauseMonitoringItem(id: string): Promise<boolean> {
  const { error } = await supabase
    .from('monitoring_items')
    .update({ status: 'paused' })
    .eq('id', id);

  if (error) {
    console.error('Error pausing monitoring item:', error);
    return false;
  }

  return true;
}

export async function resumeMonitoringItem(id: string): Promise<boolean> {
  const { error } = await supabase
    .from('monitoring_items')
    .update({ status: 'active' })
    .eq('id', id);

  if (error) {
    console.error('Error resuming monitoring item:', error);
    return false;
  }

  return true;
}

/* ============================================================================
   MONITORING ALERTS OPERATIONS
============================================================================ */

export async function getMonitoringAlerts(unreadOnly: boolean = false): Promise<MonitoringAlert[]> {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return [];

  let query = supabase
    .from('monitoring_alerts')
    .select('*')
    .eq('user_id', user.id)
    .order('created_at', { ascending: false });

  if (unreadOnly) {
    query = query.eq('is_read', false);
  }

  const { data, error } = await query;

  if (error) {
    console.error('Error fetching monitoring alerts:', error);
    return [];
  }

  return data as MonitoringAlert[];
}

export async function markAlertAsRead(id: string): Promise<boolean> {
  const { error } = await supabase
    .from('monitoring_alerts')
    .update({ is_read: true })
    .eq('id', id);

  if (error) {
    console.error('Error marking alert as read:', error);
    return false;
  }

  return true;
}

export async function markAllAlertsAsRead(): Promise<boolean> {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return false;

  const { error } = await supabase
    .from('monitoring_alerts')
    .update({ is_read: true })
    .eq('user_id', user.id);

  if (error) {
    console.error('Error marking all alerts as read:', error);
    return false;
  }

  return true;
}

export async function deleteAlert(id: string): Promise<boolean> {
  const { error } = await supabase
    .from('monitoring_alerts')
    .delete()
    .eq('id', id);

  if (error) {
    console.error('Error deleting alert:', error);
    return false;
  }

  return true;
}

/* ============================================================================
   SESSION OPERATIONS
============================================================================ */

export async function saveSession(
  sessionName: string,
  sessionData: Record<string, any>
): Promise<UserSession | null> {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return null;

  const { data, error } = await supabase
    .from('user_sessions')
    .insert({
      user_id: user.id,
      session_name: sessionName,
      session_data: sessionData,
    })
    .select()
    .single();

  if (error) {
    console.error('Error saving session:', error);
    return null;
  }

  return data as UserSession;
}

export async function getSessions(): Promise<UserSession[]> {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return [];

  const { data, error } = await supabase
    .from('user_sessions')
    .select('*')
    .eq('user_id', user.id)
    .order('last_active_at', { ascending: false });

  if (error) {
    console.error('Error fetching sessions:', error);
    return [];
  }

  return data as UserSession[];
}

export async function getSession(id: string): Promise<UserSession | null> {
  const { data, error } = await supabase
    .from('user_sessions')
    .select('*')
    .eq('id', id)
    .single();

  if (error) {
    console.error('Error fetching session:', error);
    return null;
  }

  return data as UserSession;
}

export async function updateSession(
  id: string,
  sessionData: Record<string, any>
): Promise<UserSession | null> {
  const { data, error } = await supabase
    .from('user_sessions')
    .update({
      session_data: sessionData,
      last_active_at: new Date().toISOString(),
    })
    .eq('id', id)
    .select()
    .single();

  if (error) {
    console.error('Error updating session:', error);
    return null;
  }

  return data as UserSession;
}

export async function deleteSession(id: string): Promise<boolean> {
  const { error } = await supabase
    .from('user_sessions')
    .delete()
    .eq('id', id);

  if (error) {
    console.error('Error deleting session:', error);
    return false;
  }

  return true;
}

/* ============================================================================
   UTILITY FUNCTIONS
============================================================================ */

export async function isAuthenticated(): Promise<boolean> {
  const { data: { user } } = await supabase.auth.getUser();
  return !!user;
}

export async function getCurrentUserId(): Promise<string | null> {
  const { data: { user } } = await supabase.auth.getUser();
  return user?.id || null;
}

export async function signOut(): Promise<boolean> {
  const { error } = await supabase.auth.signOut();
  if (error) {
    console.error('Error signing out:', error);
    return false;
  }
  return true;
}
