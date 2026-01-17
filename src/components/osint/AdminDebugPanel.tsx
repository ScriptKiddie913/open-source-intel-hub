import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { makeCurrentUserAdmin, checkAdminDashboardHealth } from '@/lib/adminUtils';
import { Settings, CheckCircle, AlertCircle, Loader2 } from 'lucide-react';

export function AdminDebugPanel() {
  const [loading, setLoading] = useState(false);
  const [healthStatus, setHealthStatus] = useState<any>(null);

  const handleMakeAdmin = async () => {
    setLoading(true);
    const success = await makeCurrentUserAdmin();
    if (success) {
      alert('You are now an admin! Refresh the page to see changes.');
    } else {
      alert('Failed to make you an admin. Check console for details.');
    }
    setLoading(false);
  };

  const handleHealthCheck = async () => {
    setLoading(true);
    const status = await checkAdminDashboardHealth();
    setHealthStatus(status);
    setLoading(false);
  };

  return (
    <Card className="bg-slate-900/50 border-slate-800">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Settings className="h-5 w-5 text-primary" />
          Admin Debug Panel
        </CardTitle>
        <CardDescription>
          Development tools for testing admin functionality
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap gap-2">
          <Button
            variant="outline"
            onClick={handleMakeAdmin}
            disabled={loading}
            className="text-yellow-400 border-yellow-500/30 hover:bg-yellow-500/10"
          >
            {loading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
            Make Me Admin
          </Button>
          <Button
            variant="outline"
            onClick={handleHealthCheck}
            disabled={loading}
            className="text-blue-400 border-blue-500/30 hover:bg-blue-500/10"
          >
            {loading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
            Check Health
          </Button>
        </div>

        {healthStatus && (
          <div className="space-y-3 pt-4 border-t border-slate-800">
            <h4 className="font-medium text-sm">Health Status</h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
              <div className="flex items-center justify-between">
                <span>Tables Exist:</span>
                {healthStatus.tablesExist ? (
                  <CheckCircle className="h-4 w-4 text-green-400" />
                ) : (
                  <AlertCircle className="h-4 w-4 text-red-400" />
                )}
              </div>
              <div className="flex items-center justify-between">
                <span>Is Admin:</span>
                {healthStatus.currentUserIsAdmin ? (
                  <CheckCircle className="h-4 w-4 text-green-400" />
                ) : (
                  <AlertCircle className="h-4 w-4 text-red-400" />
                )}
              </div>
              <div className="flex items-center justify-between">
                <span>User Roles:</span>
                <Badge variant="outline">{healthStatus.userRolesCount}</Badge>
              </div>
              <div className="flex items-center justify-between">
                <span>Messages:</span>
                <Badge variant="outline">{healthStatus.adminMessagesCount}</Badge>
              </div>
            </div>
            {healthStatus.errors.length > 0 && (
              <div className="space-y-1">
                <h5 className="font-medium text-sm text-red-400">Errors:</h5>
                {healthStatus.errors.map((error: string, idx: number) => (
                  <p key={idx} className="text-xs text-red-400 bg-red-500/10 p-2 rounded">
                    {error}
                  </p>
                ))}
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}