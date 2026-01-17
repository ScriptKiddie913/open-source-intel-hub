import { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { toast } from 'sonner';
import { AdminDebugPanel } from '@/components/osint/AdminDebugPanel';
import {
  Users,
  Shield,
  ShieldCheck,
  ShieldX,
  MessageSquare,
  Send,
  Eye,
  Search,
  Bell,
  Clock,
  Mail,
  AlertTriangle,
  Info,
  AlertCircle,
  Loader2,
  RefreshCw,
  Crown,
  UserCheck,
  Activity,
} from 'lucide-react';
import {
  getAllUsers,
  makeUserAdmin,
  removeAdminRole,
  sendAdminMessage,
  getSentMessages,
  isCurrentUserAdmin,
  type UserWithProfile,
  type AdminMessage,
} from '@/services/adminService';
import { cn } from '@/lib/utils';
import { formatDistanceToNow } from 'date-fns';

export function AdminPanel() {
  const [users, setUsers] = useState<UserWithProfile[]>([]);
  const [sentMessages, setSentMessages] = useState<AdminMessage[]>([]);
  const [loading, setLoading] = useState(true);
  const [isAdmin, setIsAdmin] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [error, setError] = useState<string | null>(null);
  
  // Message form state
  const [selectedUserId, setSelectedUserId] = useState<string>('');
  const [messageTitle, setMessageTitle] = useState('');
  const [messageContent, setMessageContent] = useState('');
  const [messageSeverity, setMessageSeverity] = useState<'info' | 'warning' | 'critical'>('info');
  const [sendingMessage, setSendingMessage] = useState(false);
  const [messageDialogOpen, setMessageDialogOpen] = useState(false);

  useEffect(() => {
    checkAdminAndLoad();
  }, []);

  const checkAdminAndLoad = async () => {
    setLoading(true);
    setError(null);
    try {
      const adminStatus = await isCurrentUserAdmin();
      setIsAdmin(adminStatus);
      
      if (adminStatus) {
        await loadData();
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to load admin panel';
      setError(errorMessage);
      console.error('Admin panel error:', err);
    }
    setLoading(false);
  };

  const loadData = async () => {
    try {
      const [usersData, messagesData] = await Promise.all([
        getAllUsers(),
        getSentMessages(),
      ]);
      setUsers(usersData);
      setSentMessages(messagesData);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to load data';
      setError(errorMessage);
      console.error('Data loading error:', err);
    }
  };

  const handleToggleAdmin = async (user: UserWithProfile) => {
    if (user.is_admin) {
      const success = await removeAdminRole(user.id);
      if (success) {
        setUsers(prev => prev.map(u => u.id === user.id ? { ...u, is_admin: false } : u));
        toast.success(`Removed admin role from ${user.email}`);
      } else {
        toast.error('Failed to remove admin role');
      }
    } else {
      const success = await makeUserAdmin(user.id);
      if (success) {
        setUsers(prev => prev.map(u => u.id === user.id ? { ...u, is_admin: true } : u));
        toast.success(`Made ${user.email} an admin`);
      } else {
        toast.error('Failed to make user admin');
      }
    }
  };

  const handleSendMessage = async () => {
    if (!selectedUserId || !messageTitle.trim() || !messageContent.trim()) {
      toast.error('Please fill in all fields');
      return;
    }

    setSendingMessage(true);
    const success = await sendAdminMessage(selectedUserId, messageTitle, messageContent, messageSeverity);
    
    if (success) {
      toast.success('Message sent to user monitoring section');
      setMessageDialogOpen(false);
      setMessageTitle('');
      setMessageContent('');
      setMessageSeverity('info');
      setSelectedUserId('');
      // Reload sent messages
      const messages = await getSentMessages();
      setSentMessages(messages);
    } else {
      toast.error('Failed to send message');
    }
    setSendingMessage(false);
  };

  const openMessageDialog = (userId: string) => {
    setSelectedUserId(userId);
    setMessageDialogOpen(true);
  };

  const filteredUsers = users.filter(user => 
    user.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
    user.display_name?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  if (!isAdmin) {
    return (
      <div className="flex flex-col items-center justify-center h-full p-8">
        <ShieldX className="h-16 w-16 text-red-500 mb-4" />
        <h2 className="text-2xl font-bold mb-2">Access Denied</h2>
        <p className="text-muted-foreground text-center">
          You do not have administrator privileges to access this section.
        </p>
        {error && (
          <div className="mt-4 p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
            <p className="text-red-400 text-sm">{error}</p>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Crown className="h-6 w-6 text-yellow-500" />
            Admin Panel
          </h1>
          <p className="text-muted-foreground">Manage users, roles, and send monitoring messages</p>
        </div>
        <Button variant="outline" onClick={loadData}>
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4">
          <div className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 text-red-400" />
            <span className="text-red-400 font-medium">Error</span>
          </div>
          <p className="text-red-400 text-sm mt-1">{error}</p>
          <Button 
            variant="outline" 
            size="sm" 
            onClick={() => setError(null)}
            className="mt-2 text-red-400 border-red-500/30 hover:bg-red-500/10"
          >
            Dismiss
          </Button>
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-primary/10">
                <Users className="h-5 w-5 text-primary" />
              </div>
              <div>
                <p className="text-2xl font-bold">{users.length}</p>
                <p className="text-sm text-muted-foreground">Total Users</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-yellow-500/10">
                <Crown className="h-5 w-5 text-yellow-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{users.filter(u => u.is_admin).length}</p>
                <p className="text-sm text-muted-foreground">Admins</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-green-500/10">
                <MessageSquare className="h-5 w-5 text-green-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{sentMessages.length}</p>
                <p className="text-sm text-muted-foreground">Messages Sent</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-slate-900/50 border-slate-800">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-500/10">
                <Activity className="h-5 w-5 text-blue-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{users.reduce((acc, u) => acc + u.monitoring_count, 0)}</p>
                <p className="text-sm text-muted-foreground">Total Monitors</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="users" className="space-y-4">
        <TabsList className="bg-slate-800/50">
          <TabsTrigger value="users" className="data-[state=active]:bg-primary">
            <Users className="h-4 w-4 mr-2" />
            Users
          </TabsTrigger>
          <TabsTrigger value="messages" className="data-[state=active]:bg-primary">
            <MessageSquare className="h-4 w-4 mr-2" />
            Sent Messages
          </TabsTrigger>
          <TabsTrigger value="debug" className="data-[state=active]:bg-primary">
            <Crown className="h-4 w-4 mr-2" />
            Debug
          </TabsTrigger>
        </TabsList>

        <TabsContent value="users" className="space-y-4">
          {/* Search */}
          <div className="flex items-center gap-4">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search users by email..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10 bg-slate-800 border-slate-700"
              />
            </div>
          </div>

          {/* Users List */}
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle>All Users</CardTitle>
              <CardDescription>Manage user roles and send messages to their monitoring section</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                <div className="space-y-3">
                  {filteredUsers.map(user => (
                    <div
                      key={user.id}
                      className="p-4 rounded-lg border bg-slate-800/50 border-slate-700 hover:border-slate-600 transition-colors"
                    >
                      <div className="flex items-start justify-between">
                        <div className="flex items-start gap-3">
                          <div className={cn(
                            "p-2 rounded-lg",
                            user.is_admin ? "bg-yellow-500/20" : "bg-primary/10"
                          )}>
                            {user.is_admin ? (
                              <Crown className="h-5 w-5 text-yellow-400" />
                            ) : (
                              <Users className="h-5 w-5 text-primary" />
                            )}
                          </div>
                          <div>
                            <div className="flex items-center gap-2">
                              <h4 className="font-medium">{user.email}</h4>
                              {user.is_admin && (
                                <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30">
                                  Admin
                                </Badge>
                              )}
                            </div>
                            {user.display_name && (
                              <p className="text-sm text-muted-foreground">{user.display_name}</p>
                            )}
                            <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                              <span className="flex items-center gap-1">
                                <Eye className="h-3 w-3" />
                                {user.monitoring_count} monitors
                              </span>
                              <span className="flex items-center gap-1">
                                <Bell className="h-3 w-3" />
                                {user.alerts_count} alerts
                              </span>
                              <span className="flex items-center gap-1">
                                <Search className="h-3 w-3" />
                                {user.search_count} searches
                              </span>
                              {user.last_active && (
                                <span className="flex items-center gap-1">
                                  <Clock className="h-3 w-3" />
                                  {formatDistanceToNow(new Date(user.last_active), { addSuffix: true })}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => openMessageDialog(user.id)}
                            className="text-primary border-primary/30 hover:bg-primary/10"
                          >
                            <MessageSquare className="h-4 w-4 mr-1" />
                            Message
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleToggleAdmin(user)}
                            className={cn(
                              user.is_admin 
                                ? "text-red-400 border-red-500/30 hover:bg-red-500/10" 
                                : "text-green-400 border-green-500/30 hover:bg-green-500/10"
                            )}
                          >
                            {user.is_admin ? (
                              <>
                                <ShieldX className="h-4 w-4 mr-1" />
                                Remove Admin
                              </>
                            ) : (
                              <>
                                <ShieldCheck className="h-4 w-4 mr-1" />
                                Make Admin
                              </>
                            )}
                          </Button>
                        </div>
                      </div>
                    </div>
                  ))}
                  {filteredUsers.length === 0 && (
                    <div className="text-center py-8 text-muted-foreground">
                      No users found
                    </div>
                  )}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="messages">
          <Card className="bg-slate-900/50 border-slate-800">
            <CardHeader>
              <CardTitle>Sent Messages</CardTitle>
              <CardDescription>Messages you've sent to users' monitoring sections</CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                {sentMessages.length === 0 ? (
                  <div className="text-center py-12 text-muted-foreground">
                    <MessageSquare className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No messages sent yet</p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {sentMessages.map(msg => (
                      <div
                        key={msg.id}
                        className={cn(
                          "p-4 rounded-lg border",
                          msg.severity === 'critical' ? "bg-red-500/5 border-red-500/20" :
                          msg.severity === 'warning' ? "bg-yellow-500/5 border-yellow-500/20" :
                          "bg-slate-800/30 border-slate-700"
                        )}
                      >
                        <div className="flex items-start gap-3">
                          <div className={cn(
                            "p-2 rounded-lg",
                            msg.severity === 'critical' ? "bg-red-500/20" :
                            msg.severity === 'warning' ? "bg-yellow-500/20" : "bg-blue-500/20"
                          )}>
                            {msg.severity === 'critical' ? (
                              <AlertCircle className="h-4 w-4 text-red-400" />
                            ) : msg.severity === 'warning' ? (
                              <AlertTriangle className="h-4 w-4 text-yellow-400" />
                            ) : (
                              <Info className="h-4 w-4 text-blue-400" />
                            )}
                          </div>
                          <div className="flex-1">
                            <div className="flex items-center justify-between">
                              <h4 className="font-medium">{msg.title}</h4>
                              <div className="flex items-center gap-2">
                                <Badge variant="outline" className={cn(
                                  msg.severity === 'critical' ? "text-red-400 border-red-500/30" :
                                  msg.severity === 'warning' ? "text-yellow-400 border-yellow-500/30" :
                                  "text-blue-400 border-blue-500/30"
                                )}>
                                  {msg.severity}
                                </Badge>
                                {msg.is_read && (
                                  <Badge variant="outline" className="text-green-400 border-green-500/30">
                                    Read
                                  </Badge>
                                )}
                              </div>
                            </div>
                            <p className="text-sm text-muted-foreground mt-1">{msg.message}</p>
                            <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                              <span className="flex items-center gap-1">
                                <Mail className="h-3 w-3" />
                                To: {msg.to_user_email}
                              </span>
                              <span className="flex items-center gap-1">
                                <Clock className="h-3 w-3" />
                                {formatDistanceToNow(new Date(msg.created_at), { addSuffix: true })}
                              </span>
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="debug">
          <AdminDebugPanel />
        </TabsContent>
      </Tabs>

      {/* Message Dialog */}
      <Dialog open={messageDialogOpen} onOpenChange={setMessageDialogOpen}>
        <DialogContent className="bg-slate-900 border-slate-800">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <MessageSquare className="h-5 w-5 text-primary" />
              Send Message to User
            </DialogTitle>
            <DialogDescription>
              This message will appear in the user's monitoring section
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 mt-4">
            <div className="space-y-2">
              <Label>Recipient</Label>
              <Select value={selectedUserId} onValueChange={setSelectedUserId}>
                <SelectTrigger className="bg-slate-800 border-slate-700">
                  <SelectValue placeholder="Select user..." />
                </SelectTrigger>
                <SelectContent className="bg-slate-800 border-slate-700">
                  {users.map(user => (
                    <SelectItem key={user.id} value={user.id}>
                      {user.email}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Title</Label>
              <Input
                placeholder="Message title..."
                value={messageTitle}
                onChange={(e) => setMessageTitle(e.target.value)}
                className="bg-slate-800 border-slate-700"
              />
            </div>
            <div className="space-y-2">
              <Label>Severity</Label>
              <Select value={messageSeverity} onValueChange={(v: any) => setMessageSeverity(v)}>
                <SelectTrigger className="bg-slate-800 border-slate-700">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-slate-800 border-slate-700">
                  <SelectItem value="info">
                    <div className="flex items-center gap-2">
                      <Info className="h-4 w-4 text-blue-400" />
                      Info
                    </div>
                  </SelectItem>
                  <SelectItem value="warning">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 text-yellow-400" />
                      Warning
                    </div>
                  </SelectItem>
                  <SelectItem value="critical">
                    <div className="flex items-center gap-2">
                      <AlertCircle className="h-4 w-4 text-red-400" />
                      Critical
                    </div>
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label>Message</Label>
              <Textarea
                placeholder="Enter your message..."
                value={messageContent}
                onChange={(e) => setMessageContent(e.target.value)}
                className="bg-slate-800 border-slate-700 min-h-[100px]"
              />
            </div>
            <Button
              onClick={handleSendMessage}
              className="w-full bg-primary"
              disabled={sendingMessage}
            >
              {sendingMessage ? (
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
              ) : (
                <Send className="h-4 w-4 mr-2" />
              )}
              Send Message
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
