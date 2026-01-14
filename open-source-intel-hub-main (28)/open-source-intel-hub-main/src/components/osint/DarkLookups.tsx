import { Database } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';

export function DarkLookups() {

  return (
    <div className="space-y-4">
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

      {/* Breach Guard App Card */}
      <Card className="border-primary/20 bg-card/50 backdrop-blur overflow-hidden">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Database className="h-5 w-5 text-primary" />
            Breach Database Search
          </CardTitle>
          <CardDescription>
            Enter an email address to check against our database of known breaches
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="relative w-full" style={{ height: '800px' }}>
            <iframe
              src="https://breach-guard-7cd9915d.base44.app/"
              className="w-full h-full border-0"
              style={{
                marginTop: '-60px',
                height: 'calc(100% + 60px)',
              }}
              title="Breach Guard Database"
              sandbox="allow-same-origin allow-scripts allow-forms allow-popups"
            />
          </div>
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
    </div>
  );
}
