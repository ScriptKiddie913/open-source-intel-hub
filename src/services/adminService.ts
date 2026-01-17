// Admin Service - Handles admin operations for user management and messaging
import { supabase } from '@/integrations/supabase/client';

export interface UserWithProfile {
  id: string;
  email: string;
  created_at: string;
  display_name: string | null;
  is_admin: boolean;
  monitoring_count: number;
  alerts_count: number;
  search_count: number;
  last_active: string | null;
}

export interface AdminMessage {
  id: string;
  from_user_id: string;
  to_user_id: string;
  title: string;
  message: string;
  is_read: boolean;
  severity: 'info' | 'warning' | 'critical';
  created_at: string;
  updated_at: string;
  from_user_email?: string;
  to_user_email?: string;
}

// Check if current user is admin
export async function isCurrentUserAdmin(): Promise<boolean> {
  try {
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return false;

    const { data, error } = await supabase
      .from('user_roles')
      .select('role')
      .eq('user_id', user.id)
      .eq('role', 'admin')
      .single();

    return !error && data !== null;
  } catch (error) {
    console.error('[AdminService] Error checking admin status:', error);
    return false;
  }
}

// Get all users with their profiles and stats
export async function getAllUsers(): Promise<UserWithProfile[]> {
  try {
    // Get all profiles
    const { data: profiles, error: profilesError } = await supabase
      .from('profiles')
      .select('*');

    if (profilesError) throw profilesError;

    // Get user roles
    const { data: roles, error: rolesError } = await supabase
      .from('user_roles')
      .select('user_id, role');

    // Get monitoring counts per user
    const { data: monitoringCounts, error: monitoringError } = await supabase
      .from('monitoring_items')
      .select('user_id');

    // Get search counts per user
    const { data: searchCounts, error: searchError } = await supabase
      .from('search_history')
      .select('user_id');

    // Get alerts counts per user
    const { data: alertsCounts, error: alertsError } = await supabase
      .from('monitoring_alerts')
      .select('user_id');

    // Get user sessions for last active
    const { data: sessions, error: sessionsError } = await supabase
      .from('user_sessions')
      .select('user_id, last_active_at')
      .order('last_active_at', { ascending: false });

    // Build the users array
    const users: UserWithProfile[] = (profiles || []).map(profile => {
      const adminRoles = roles?.filter(r => r.user_id === profile.user_id && r.role === 'admin') || [];
      const userMonitoring = monitoringCounts?.filter(m => m.user_id === profile.user_id) || [];
      const userSearches = searchCounts?.filter(s => s.user_id === profile.user_id) || [];
      const userAlerts = alertsCounts?.filter(a => a.user_id === profile.user_id) || [];
      const userSession = sessions?.find(s => s.user_id === profile.user_id);

      return {
        id: profile.user_id,
        email: profile.email || 'Unknown',
        created_at: profile.created_at,
        display_name: profile.display_name,
        is_admin: adminRoles.length > 0,
        monitoring_count: userMonitoring.length,
        alerts_count: userAlerts.length,
        search_count: userSearches.length,
        last_active: userSession?.last_active_at || null,
      };
    });

    return users;
  } catch (error) {
    console.error('[AdminService] Error getting users:', error);
    return [];
  }
}

// Make a user an admin
export async function makeUserAdmin(userId: string): Promise<boolean> {
  try {
    const { error } = await supabase
      .from('user_roles')
      .upsert({ 
        user_id: userId, 
        role: 'admin' 
      }, { 
        onConflict: 'user_id,role' 
      });

    return !error;
  } catch (error) {
    console.error('[AdminService] Error making user admin:', error);
    return false;
  }
}

// Remove admin role from user
export async function removeAdminRole(userId: string): Promise<boolean> {
  try {
    const { error } = await supabase
      .from('user_roles')
      .delete()
      .eq('user_id', userId)
      .eq('role', 'admin');

    return !error;
  } catch (error) {
    console.error('[AdminService] Error removing admin role:', error);
    return false;
  }
}

// Send message to user's monitoring section
export async function sendAdminMessage(
  toUserId: string, 
  title: string, 
  message: string,
  severity: 'info' | 'warning' | 'critical' = 'info'
): Promise<boolean> {
  try {
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return false;

    const { error } = await supabase
      .from('admin_messages')
      .insert({
        from_user_id: user.id,
        to_user_id: toUserId,
        title,
        message,
        severity,
      });

    return !error;
  } catch (error) {
    console.error('[AdminService] Error sending message:', error);
    return false;
  }
}

// Get messages for current user (to display in their monitoring section)
export async function getMyAdminMessages(): Promise<AdminMessage[]> {
  try {
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return [];

    const { data, error } = await supabase
      .from('admin_messages')
      .select('*')
      .eq('to_user_id', user.id)
      .order('created_at', { ascending: false });

    if (error) throw error;

    // Get sender emails
    const fromUserIds = [...new Set((data || []).map(m => m.from_user_id))];
    const { data: profiles } = await supabase
      .from('profiles')
      .select('user_id, email')
      .in('user_id', fromUserIds);

    return (data || []).map(msg => ({
      ...msg,
      severity: msg.severity as 'info' | 'warning' | 'critical',
      from_user_email: profiles?.find(p => p.user_id === msg.from_user_id)?.email || 'Admin',
    }));
  } catch (error) {
    console.error('[AdminService] Error getting messages:', error);
    return [];
  }
}

// Get unread message count for current user
export async function getUnreadMessageCount(): Promise<number> {
  try {
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return 0;

    const { count, error } = await supabase
      .from('admin_messages')
      .select('*', { count: 'exact', head: true })
      .eq('to_user_id', user.id)
      .eq('is_read', false);

    return error ? 0 : (count || 0);
  } catch (error) {
    console.error('[AdminService] Error getting unread count:', error);
    return 0;
  }
}

// Mark message as read
export async function markMessageAsRead(messageId: string): Promise<boolean> {
  try {
    const { error } = await supabase
      .from('admin_messages')
      .update({ is_read: true })
      .eq('id', messageId);

    return !error;
  } catch (error) {
    console.error('[AdminService] Error marking message as read:', error);
    return false;
  }
}

// Get all messages sent by admin (for admin to view)
export async function getSentMessages(): Promise<AdminMessage[]> {
  try {
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return [];

    const { data, error } = await supabase
      .from('admin_messages')
      .select('*')
      .eq('from_user_id', user.id)
      .order('created_at', { ascending: false });

    if (error) throw error;

    // Get recipient emails
    const toUserIds = [...new Set((data || []).map(m => m.to_user_id))];
    const { data: profiles } = await supabase
      .from('profiles')
      .select('user_id, email')
      .in('user_id', toUserIds);

    return (data || []).map(msg => ({
      ...msg,
      severity: msg.severity as 'info' | 'warning' | 'critical',
      to_user_email: profiles?.find(p => p.user_id === msg.to_user_id)?.email || 'Unknown User',
    }));
  } catch (error) {
    console.error('[AdminService] Error getting sent messages:', error);
    return [];
  }
}
