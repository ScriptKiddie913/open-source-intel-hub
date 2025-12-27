import { Globe, Shield } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

export function LiveThreatFeed() {
  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">
            Live Threat Intelligence
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Global real-time cyber attack visualization (Radware)
          </p>
        </div>
        <Badge variant="outline" className="text-xs">
          External Live Feed
        </Badge>
      </div>

      {/* Stats (Static Informational) */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card className="bg-card border-border">
          <CardContent className="p-4 text-center">
            <div className="text-xl font-bold text-primary">LIVE</div>
            <div className="text-xs text-muted-foreground">Attack Stream</div>
          </CardContent>
        </Card>

        <Card className="bg-card border-border">
          <CardContent className="p-4 text-center">
            <div className="text-xl font-bold text-red-500">DDoS</div>
            <div className="text-xs text-muted-foreground">Volumetric</div>
          </CardContent>
        </Card>

        <Card className="bg-card border-border">
          <CardContent className="p-4 text-center">
            <div className="text-xl font-bold text-orange-500">Web</div>
            <div className="text-xs text-muted-foreground">Application</div>
          </CardContent>
        </Card>

        <Card className="bg-card border-border">
          <CardContent className="p-4 text-center">
            <div className="text-xl font-bold text-yellow-500">Botnets</div>
            <div className="text-xs text-muted-foreground">C2 Traffic</div>
          </CardContent>
        </Card>

        <Card className="bg-card border-border">
          <CardContent className="p-4 text-center">
            <div className="text-xl font-bold text-purple-500">Global</div>
            <div className="text-xs text-muted-foreground">Attack Map</div>
          </CardContent>
        </Card>
      </div>

      {/* Threat Map */}
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Globe className="h-5 w-5 text-primary" />
            Global Live Threat Map
          </CardTitle>
        </CardHeader>

        <CardContent className="p-0">
          <div className="relative w-full h-[600px] overflow-hidden rounded-b-lg">
            <iframe
              src="https://livethreatmap.radware.com/"
              title="Radware Live Threat Map"
              className="w-full h-full border-0"
              sandbox="allow-scripts allow-same-origin allow-forms allow-popups"
              loading="lazy"
              referrerPolicy="no-referrer"
            />
          </div>
        </CardContent>
      </Card>

      {/* Attribution */}
      <div className="text-xs text-muted-foreground text-center">
        Threat visualization powered by Radware Live Threat Map
      </div>
    </div>
  );
}
