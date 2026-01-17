// Admin Dashboard Utility Functions
import { supabase } from '@/integrations/supabase/client';

/**
 * Make the current user an admin (for testing purposes)
 * This should only be used in development
 */
export async function makeCurrentUserAdmin(): Promise<boolean> {
  try {
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) {
      console.error('No user logged in');
      return false;
    }

    const { error } = await supabase
      .from('user_roles')
      .upsert({ 
        user_id: user.id, 
        role: 'admin' 
      }, { 
        onConflict: 'user_id,role' 
      });

    if (error) {
      console.error('Error making user admin:', error);
      return false;
    }

    console.log(`Made user ${user.email} an admin`);
    return true;
  } catch (error) {
    console.error('Error:', error);
    return false;
  }
}

/**
 * Check database health and admin table status
 */
export async function checkAdminDashboardHealth(): Promise<{
  tablesExist: boolean;
  userRolesCount: number;
  adminMessagesCount: number;
  currentUserIsAdmin: boolean;
  errors: string[];
}> {
  const result = {
    tablesExist: false,
    userRolesCount: 0,
    adminMessagesCount: 0,
    currentUserIsAdmin: false,
    errors: [] as string[]
  };

  try {
    // Check if tables exist by trying to query them
    const { data: userRoles, error: userRolesError } = await supabase
      .from('user_roles')
      .select('*', { count: 'exact', head: true });

    if (userRolesError) {
      result.errors.push(`User roles table error: ${userRolesError.message}`);
    } else {
      result.userRolesCount = userRoles?.length || 0;
    }

    const { data: adminMessages, error: adminMessagesError } = await supabase
      .from('admin_messages')
      .select('*', { count: 'exact', head: true });

    if (adminMessagesError) {
      result.errors.push(`Admin messages table error: ${adminMessagesError.message}`);
    } else {
      result.adminMessagesCount = adminMessages?.length || 0;
    }

    // Check if current user is admin
    const { data: { user } } = await supabase.auth.getUser();
    if (user) {
      const { data: adminRole, error: adminCheckError } = await supabase
        .from('user_roles')
        .select('*')
        .eq('user_id', user.id)
        .eq('role', 'admin')
        .single();

      if (adminCheckError && adminCheckError.code !== 'PGRST116') { // PGRST116 = no rows returned
        result.errors.push(`Admin check error: ${adminCheckError.message}`);
      } else {
        result.currentUserIsAdmin = !!adminRole;
      }
    }

    result.tablesExist = result.errors.length === 0;

  } catch (error) {
    result.errors.push(`General error: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }

  return result;
}

// Make functions available globally for debugging
if (typeof window !== 'undefined') {
  (window as any).makeCurrentUserAdmin = makeCurrentUserAdmin;
  (window as any).checkAdminDashboardHealth = checkAdminDashboardHealth;
}