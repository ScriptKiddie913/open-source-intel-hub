import { useEffect, useState } from 'react';
import { Search, Shield, Database, Loader2, CheckCircle2, XCircle, AlertTriangle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { toast } from 'sonner';

interface BreachResponse {
  message: string;
  found: boolean;
  email?: string;
  password?: string;
  recommendations?: string[];
}

export function DarkLookups() {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<BreachResponse | null>(null);
  const [chatbotLoaded, setChatbotLoaded] = useState(false);

  useEffect(() => {
    // Load n8n chatbot script
    const script = document.createElement('script');
    script.type = 'module';
    script.innerHTML = `
      import Chatbot from 'https://cdn.jsdelivr.net/npm/@n8n/chat/dist/chat.bundle.es.js';

      Chatbot.createWidget({
        webhookUrl: 'https://grgrwgfvew.app.n8n.cloud/webhook/fd662c6c-6d5e-440c-a993-977fc933e90c/chat',
        initialMessages: [
          'Hi there! 👋',
          'My name is Nathan. How can I assist you today?'
        ],
        i18n: {
          en: {
            title: 'Data Breach Checker',
            subtitle: 'Check if your email has been compromised',
            footer: '',
            getStarted: 'Start Chat',
            inputPlaceholder: 'Type your email address...',
          },
        },
        theme: {
          primaryColor: '#06b6d4',
        },
        chatWindowConfig: {
          width: 400,
          height: 600,
        },
      });
    `;
    
    document.body.appendChild(script);
    setChatbotLoaded(true);

    return () => {
      // Cleanup script on unmount
      if (document.body.contains(script)) {
        document.body.removeChild(script);
      }
    };
  }, []);

  const handleSearch = async () => {
    if (!email.trim()) {
      toast.error('Please enter an email address');
      return;
    }

    // Basic email validation
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      toast.error('Please enter a valid email address');
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      console.log('[DarkLookups] Checking email:', email);
      
      // Send request to n8n webhook
      const response = await fetch('https://grgrwgfvew.app.n8n.cloud/webhook/fd662c6c-6d5e-440c-a993-977fc933e90c/chat', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          action: 'sendMessage',
          sessionId: `session-${Date.now()}`,
          chatInput: email.trim(),
        }),
      });

      if (!response.ok) {
        throw new Error(`API returned status ${response.status}`);
      }

      const data = await response.json();
      console.log('[DarkLookups] API Response:', data);

      // Parse the response
      let parsedResult: BreachResponse;
      
      if (data.output) {
        const message = data.output;
        const found = message.toLowerCase().includes('compromised') || message.toLowerCase().includes('found');
        
        // Extract password if mentioned
        const passwordMatch = message.match(/password is ["']([^"']+)["']/i);
        const password = passwordMatch ? passwordMatch[1] : undefined;

        // Extract recommendations
        const recommendations: string[] = [];
        const recLines = message.split('\n').filter((line: string) => 
          line.match(/^\d+\./) || line.includes('•')
        );
        recommendations.push(...recLines.map((line: string) => line.replace(/^\d+\.\s*/, '').replace(/^•\s*/, '').trim()));

        parsedResult = {
          message,
          found,
          email: email.trim(),
          password,
          recommendations: recommendations.length > 0 ? recommendations : undefined,
        };
      } else {
        parsedResult = {
          message: 'No breach data found for this email address.',
          found: false,
          email: email.trim(),
        };
      }

      setResult(parsedResult);
      
      if (parsedResult.found) {
        toast.error('⚠️ Email found in breach database!');
      } else {
        toast.success('✅ Email not found in breach database');
      }

    } catch (err) {
      console.error('[DarkLookups] Error:', err);
      toast.error('Failed to check email. Please try again.');
      setResult({
        message: 'An error occurred while checking the email address.',
        found: false,
      });
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !loading) {
      handleSearch();
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="space-y-2">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-primary/10 rounded-lg">
            <Database className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h2 className="text-2xl font-bold">Dark Lookups</h2>
            <p className="text-sm text-muted-foreground">
              Check if your email has been compromised in known data breaches
            </p>
          </div>
        </div>
      </div>

      {/* Search Card */}
      <Card className="border-primary/20 bg-card/50 backdrop-blur">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-primary" />
            Breach Database Search
          </CardTitle>
          <CardDescription>
            Enter an email address to check against our database of known breaches
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2">
            <Input
              type="email"
              placeholder="Enter email address..."
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              onKeyPress={handleKeyPress}
              className="flex-1"
              disabled={loading}
            />
            <Button onClick={handleSearch} disabled={loading} className="min-w-[120px]">
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Checking...
                </>
              ) : (
                <>
                  <Search className="mr-2 h-4 w-4" />
                  Check
                </>
              )}
            </Button>
          </div>

          {/* Results */}
          {result && (
            <Card className={`border-2 ${result.found ? 'border-destructive/50 bg-destructive/5' : 'border-primary/50 bg-primary/5'}`}>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  {result.found ? (
                    <>
                      <XCircle className="h-5 w-5 text-destructive" />
                      <span className="text-destructive">Breach Found</span>
                    </>
                  ) : (
                    <>
                      <CheckCircle2 className="h-5 w-5 text-green-500" />
                      <span className="text-green-500">No Breach Found</span>
                    </>
                  )}
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {result.email && (
                  <div className="space-y-1">
                    <p className="text-sm text-muted-foreground">Email Address:</p>
                    <p className="font-mono text-sm bg-black/20 px-3 py-2 rounded border border-primary/20">
                      {result.email}
                    </p>
                  </div>
                )}

                {result.password && (
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 text-destructive" />
                      <p className="text-sm font-semibold text-destructive">Exposed Password:</p>
                    </div>
                    <p className="font-mono text-sm bg-destructive/10 px-3 py-2 rounded border border-destructive/20">
                      {result.password}
                    </p>
                  </div>
                )}

                <div className="space-y-2">
                  <p className="text-sm whitespace-pre-wrap leading-relaxed">
                    {result.message}
                  </p>
                </div>

                {result.recommendations && result.recommendations.length > 0 && (
                  <div className="space-y-2">
                    <p className="text-sm font-semibold">Recommendations:</p>
                    <ul className="space-y-1">
                      {result.recommendations.map((rec, idx) => (
                        <li key={idx} className="text-sm text-muted-foreground flex items-start gap-2">
                          <span className="text-primary mt-0.5">•</span>
                          <span>{rec}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {result.found && (
                  <Badge variant="destructive" className="mt-2">
                    High Risk - Immediate Action Required
                  </Badge>
                )}
              </CardContent>
            </Card>
          )}
        </CardContent>
      </Card>

      {/* Info Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card className="border-primary/20">
          <CardHeader>
            <CardTitle className="text-base">What We Check</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground space-y-2">
            <p>• Known data breaches and leaks</p>
            <p>• Exposed passwords and credentials</p>
            <p>• Dark web monitoring results</p>
            <p>• Historical breach databases</p>
          </CardContent>
        </Card>

        <Card className="border-primary/20">
          <CardHeader>
            <CardTitle className="text-base">Privacy Notice</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground space-y-2">
            <p>• Queries are not logged or stored</p>
            <p>• Secure encrypted connections</p>
            <p>• No data shared with third parties</p>
            <p>• Results shown only to you</p>
          </CardContent>
        </Card>
      </div>

      {/* Chatbot indicator */}
      {chatbotLoaded && (
        <div className="flex items-center justify-center gap-2 text-xs text-muted-foreground">
          <CheckCircle2 className="h-3 w-3 text-green-500" />
          <span>Chat assistant available in bottom-right corner</span>
        </div>
      )}
    </div>
  );
}
