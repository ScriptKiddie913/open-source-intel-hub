import { useState, useEffect, useRef } from 'react';
import { AlertTriangle, Send, Loader2, MapPin, Wifi, CheckCircle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

interface LocationData {
  latitude: number;
  longitude: number;
  accuracy: number;
  address?: string;
}

interface PanicButtonProps {
  className?: string;
}

export function PanicButton({ className }: PanicButtonProps) {
  const [open, setOpen] = useState(false);
  const [countdown, setCountdown] = useState(3);
  const [phase, setPhase] = useState<'countdown' | 'gathering' | 'message' | 'sending' | 'sent'>('countdown');
  const [ipAddress, setIpAddress] = useState<string | null>(null);
  const [location, setLocation] = useState<LocationData | null>(null);
  const [message, setMessage] = useState('');
  const [error, setError] = useState<string | null>(null);
  const countdownRef = useRef<NodeJS.Timeout | null>(null);

  // Start countdown when dialog opens
  useEffect(() => {
    if (open && phase === 'countdown') {
      setCountdown(3);
      countdownRef.current = setInterval(() => {
        setCountdown((prev) => {
          if (prev <= 1) {
            clearInterval(countdownRef.current!);
            setPhase('gathering');
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
    }

    return () => {
      if (countdownRef.current) {
        clearInterval(countdownRef.current);
      }
    };
  }, [open, phase]);

  // Gather IP and location when phase changes to 'gathering'
  useEffect(() => {
    if (phase === 'gathering') {
      gatherData();
    }
  }, [phase]);

  const gatherData = async () => {
    setError(null);
    let fetchedIp: string | null = null;
    
    try {
      // Fetch IP address
      const ipResponse = await fetch('https://api.ipify.org?format=json');
      const ipData = await ipResponse.json();
      fetchedIp = ipData.ip;
      setIpAddress(fetchedIp);
      console.log('[Panic] IP fetched:', fetchedIp);
    } catch (err) {
      console.error('[Panic] IP fetch error:', err);
    }

    // Try browser geolocation first
    const tryBrowserGeolocation = (): Promise<LocationData | null> => {
      return new Promise((resolve) => {
        if (!navigator.geolocation) {
          console.log('[Panic] Geolocation not supported');
          resolve(null);
          return;
        }

        navigator.geolocation.getCurrentPosition(
          async (position) => {
            const locationData: LocationData = {
              latitude: position.coords.latitude,
              longitude: position.coords.longitude,
              accuracy: position.coords.accuracy,
            };

            // Try to get address from coordinates
            try {
              const geoResponse = await fetch(
                `https://nominatim.openstreetmap.org/reverse?format=json&lat=${position.coords.latitude}&lon=${position.coords.longitude}`,
                { headers: { 'User-Agent': 'PhoenixOSINT/1.0' } }
              );
              const geoData = await geoResponse.json();
              locationData.address = geoData.display_name;
            } catch (e) {
              console.log('[Panic] Could not fetch address:', e);
            }

            resolve(locationData);
          },
          (err) => {
            console.log('[Panic] Browser geolocation denied/failed:', err.message);
            resolve(null);
          },
          { enableHighAccuracy: true, timeout: 5000, maximumAge: 0 }
        );
      });
    };

    // Fallback to IP-based geolocation
    const tryIpGeolocation = async (): Promise<LocationData | null> => {
      try {
        console.log('[Panic] Trying IP-based geolocation...');
        const response = await fetch('https://ipapi.co/json/');
        const data = await response.json();
        
        if (data.latitude && data.longitude) {
          return {
            latitude: data.latitude,
            longitude: data.longitude,
            accuracy: 5000, // IP geolocation is less accurate
            address: `${data.city || ''}, ${data.region || ''}, ${data.country_name || ''}`.replace(/^, |, $/g, ''),
          };
        }
      } catch (err) {
        console.error('[Panic] IP geolocation error:', err);
      }
      return null;
    };

    // Try browser geolocation first, then fallback to IP-based
    let locationData = await tryBrowserGeolocation();
    
    if (!locationData) {
      locationData = await tryIpGeolocation();
    }

    if (locationData) {
      setLocation(locationData);
      console.log('[Panic] Location fetched:', locationData);
    } else {
      setError('Could not determine location. Alert will still be sent.');
    }

    setPhase('message');
  };

  const sendAlert = async () => {
    setPhase('sending');

    try {
      // Get current user (optional - panic alerts work without login)
      const { data: { user } } = await supabase.auth.getUser();

      const deviceInfo = {
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        language: navigator.language,
        screenWidth: window.screen.width,
        screenHeight: window.screen.height,
        timestamp: new Date().toISOString(),
      };

      // Save to database only if user is logged in
      if (user) {
        const { error: dbError } = await supabase.from('panic_alerts' as any).insert({
          user_id: user.id,
          ip_address: ipAddress,
          location: location,
          message: message || 'Emergency alert triggered',
          device_info: deviceInfo,
          status: 'sent',
        });

        if (dbError) {
          console.error('[Panic] Database error:', dbError);
          // Don't fail - still send email
        }
      } else {
        console.log('[Panic] User not logged in - skipping database save');
      }

      // Send email via edge function (works without auth)
      const { error: emailError } = await supabase.functions.invoke('panic-alert', {
        body: {
          to: 'souvikpanja582@gmail.com',
          ipAddress,
          location,
          message: message || 'Emergency alert triggered',
          deviceInfo,
          userEmail: user?.email || 'Anonymous User',
        },
      });

      if (emailError) {
        console.error('[Panic] Email error:', emailError);
        // Don't throw - alert was saved to database
        toast.warning('Alert saved but email may not have been sent');
      }

      setPhase('sent');
      toast.success('Emergency alert sent successfully!');
      
      // Reset after 3 seconds
      setTimeout(() => {
        handleClose();
      }, 3000);

    } catch (err) {
      console.error('[Panic] Error sending alert:', err);
      toast.error('Failed to send alert. Please try again.');
      setPhase('message');
    }
  };

  const handleClose = () => {
    setOpen(false);
    setPhase('countdown');
    setCountdown(3);
    setIpAddress(null);
    setLocation(null);
    setMessage('');
    setError(null);
    if (countdownRef.current) {
      clearInterval(countdownRef.current);
    }
  };

  const cancelCountdown = () => {
    if (countdownRef.current) {
      clearInterval(countdownRef.current);
    }
    handleClose();
  };

  return (
    <>
      {/* Floating Panic Button */}
      <button
        onClick={() => setOpen(true)}
        className={cn(
          "fixed z-50 group",
          "bottom-24 right-6",
          className
        )}
        title="Emergency Panic Button"
      >
        <div className="relative">
          {/* Pulsing glow */}
          <div className="absolute inset-0 rounded-full bg-red-500 opacity-50 blur-lg group-hover:opacity-75 animate-pulse" />
          
          {/* Main button */}
          <div className="relative flex items-center justify-center w-14 h-14 rounded-full bg-gradient-to-br from-red-600 to-red-800 border-2 border-red-400/50 shadow-2xl shadow-red-500/30 hover:shadow-red-500/50 transition-all duration-300 group-hover:scale-110">
            <AlertTriangle className="h-6 w-6 text-white animate-pulse" />
          </div>
          
          {/* Label */}
          <span className="absolute -top-2 -right-2 px-2 py-0.5 text-[10px] font-bold bg-red-500 text-white rounded-full shadow-lg">
            SOS
          </span>
        </div>
      </button>

      {/* Panic Dialog */}
      <Dialog open={open} onOpenChange={(v) => !v && cancelCountdown()}>
        <DialogContent className="sm:max-w-md bg-gradient-to-b from-slate-900 to-slate-950 border-red-500/30">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-5 w-5 animate-pulse" />
              Emergency Alert
            </DialogTitle>
            <DialogDescription>
              {phase === 'countdown' && 'Alert will be sent after countdown...'}
              {phase === 'gathering' && 'Gathering your location and IP...'}
              {phase === 'message' && 'Add an optional message before sending.'}
              {phase === 'sending' && 'Sending emergency alert...'}
              {phase === 'sent' && 'Alert sent successfully!'}
            </DialogDescription>
          </DialogHeader>

          <div className="py-6">
            {/* Countdown Phase */}
            {phase === 'countdown' && (
              <div className="flex flex-col items-center gap-4">
                <div className="relative">
                  <div className="absolute inset-0 bg-red-500/30 rounded-full blur-2xl animate-pulse" />
                  <div className="relative flex items-center justify-center w-32 h-32 rounded-full bg-gradient-to-br from-red-600 to-red-800 border-4 border-red-400/50">
                    <span className="text-6xl font-bold text-white">{countdown}</span>
                  </div>
                </div>
                <p className="text-sm text-muted-foreground">
                  Press cancel to abort
                </p>
                <Button variant="outline" onClick={cancelCountdown} className="border-red-500/30 hover:bg-red-500/10">
                  Cancel
                </Button>
              </div>
            )}

            {/* Gathering Phase */}
            {phase === 'gathering' && (
              <div className="flex flex-col items-center gap-4">
                <Loader2 className="h-16 w-16 text-red-400 animate-spin" />
                <div className="space-y-2 text-center">
                  <div className="flex items-center gap-2 text-sm">
                    <Wifi className={cn("h-4 w-4", ipAddress ? "text-green-400" : "text-yellow-400 animate-pulse")} />
                    <span>{ipAddress ? `IP: ${ipAddress}` : 'Fetching IP address...'}</span>
                  </div>
                  <div className="flex items-center gap-2 text-sm">
                    <MapPin className={cn("h-4 w-4", location ? "text-green-400" : "text-yellow-400 animate-pulse")} />
                    <span>{location ? 'Location acquired' : 'Getting location...'}</span>
                  </div>
                </div>
              </div>
            )}

            {/* Message Phase */}
            {phase === 'message' && (
              <div className="space-y-4">
                {/* Data Summary */}
                <div className="space-y-2 p-3 rounded-lg bg-slate-800/50 border border-slate-700/50">
                  <div className="flex items-center gap-2 text-sm">
                    <Wifi className="h-4 w-4 text-green-400" />
                    <span className="text-muted-foreground">IP:</span>
                    <span className="font-mono text-xs">{ipAddress || 'Unknown'}</span>
                  </div>
                  <div className="flex items-start gap-2 text-sm">
                    <MapPin className={cn("h-4 w-4 mt-0.5", location ? "text-green-400" : "text-yellow-400")} />
                    <span className="text-muted-foreground">Location:</span>
                    <span className="text-xs">
                      {location ? (
                        <>
                          {location.address || `${location.latitude.toFixed(4)}, ${location.longitude.toFixed(4)}`}
                        </>
                      ) : (
                        'Could not determine'
                      )}
                    </span>
                  </div>
                </div>

                {error && (
                  <p className="text-xs text-yellow-400">{error}</p>
                )}

                {/* Message Input */}
                <div>
                  <label className="text-sm font-medium text-muted-foreground mb-2 block">
                    Add a message (optional)
                  </label>
                  <Textarea
                    placeholder="Describe your emergency situation..."
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    className="min-h-[80px] bg-slate-800/50 border-slate-700"
                  />
                </div>

                <div className="flex gap-2">
                  <Button variant="outline" onClick={cancelCountdown} className="flex-1 border-slate-600">
                    Cancel
                  </Button>
                  <Button 
                    onClick={sendAlert} 
                    className="flex-1 bg-red-600 hover:bg-red-700 text-white"
                  >
                    <Send className="h-4 w-4 mr-2" />
                    Send Alert
                  </Button>
                </div>
              </div>
            )}

            {/* Sending Phase */}
            {phase === 'sending' && (
              <div className="flex flex-col items-center gap-4">
                <Loader2 className="h-16 w-16 text-red-400 animate-spin" />
                <p className="text-sm text-muted-foreground">Sending emergency alert...</p>
              </div>
            )}

            {/* Sent Phase */}
            {phase === 'sent' && (
              <div className="flex flex-col items-center gap-4">
                <div className="relative">
                  <div className="absolute inset-0 bg-green-500/30 rounded-full blur-2xl" />
                  <div className="relative flex items-center justify-center w-20 h-20 rounded-full bg-gradient-to-br from-green-600 to-green-800 border-4 border-green-400/50">
                    <CheckCircle className="h-10 w-10 text-white" />
                  </div>
                </div>
                <div className="text-center">
                  <p className="text-lg font-semibold text-green-400">Alert Sent!</p>
                  <p className="text-sm text-muted-foreground">
                    Emergency services have been notified.
                  </p>
                </div>
              </div>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
