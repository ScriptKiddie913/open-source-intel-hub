import { useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import {
  Shield,
  Globe,
  Search,
  Activity,
  Lock,
  Zap,
  ArrowRight,
  Database,
  Eye,
  Network,
  AlertTriangle,
  Radar,
  Terminal,
  Brain,
  ChevronRight,
} from 'lucide-react';
import { cn } from '@/lib/utils';

const FEATURES = [
  {
    icon: Globe,
    title: 'Domain Intelligence',
    description: 'DNS records, WHOIS data, subdomains, and certificate transparency logs.',
  },
  {
    icon: Search,
    title: 'Dark Web Monitoring',
    description: 'Scan onion sites, paste dumps, and breach databases for leaked data.',
  },
  {
    icon: Activity,
    title: 'Live Threat Map',
    description: 'Real-time visualization of global cyber attacks and threat indicators.',
  },
  {
    icon: Database,
    title: 'Breach Detection',
    description: 'Check if emails, domains, or credentials have been compromised.',
  },
  {
    icon: Network,
    title: 'IP Analysis',
    description: 'Geolocation, ASN info, reputation scoring, and port scanning.',
  },
  {
    icon: AlertTriangle,
    title: 'CVE Explorer',
    description: 'Search and analyze vulnerabilities with CVSS scoring and PoC tracking.',
  },
];

const STATS = [
  { value: '500M+', label: 'Threat Indicators' },
  { value: '150+', label: 'Data Sources' },
  { value: '24/7', label: 'Monitoring' },
  { value: '99.9%', label: 'Uptime' },
];

export default function Home() {
  const navigate = useNavigate();

  // Redirect if already logged in
  useEffect(() => {
    const { data: { subscription } } = supabase.auth.onAuthStateChange((event, session) => {
      if (session?.user) {
        navigate('/dashboard');
      }
    });

    supabase.auth.getSession().then(({ data: { session } }) => {
      if (session?.user) {
        navigate('/dashboard');
      }
    });

    return () => subscription.unsubscribe();
  }, [navigate]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-white">
      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-slate-950/80 backdrop-blur-xl border-b border-slate-800/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-primary/10 rounded-lg border border-primary/20">
                <Shield className="h-6 w-6 text-primary" />
              </div>
              <span className="text-xl font-bold bg-gradient-to-r from-primary to-cyan-400 bg-clip-text text-transparent">
                CIPHER OSINT
              </span>
            </div>
            <div className="flex items-center gap-4">
              <Link to="/about" className="text-slate-300 hover:text-white transition-colors">
                About
              </Link>
              <Link to="/auth">
                <Button variant="outline" className="border-primary/50 text-primary hover:bg-primary/10">
                  Sign In
                </Button>
              </Link>
              <Link to="/auth">
                <Button className="bg-gradient-to-r from-primary to-cyan-500 text-slate-900 font-semibold">
                  Get Started
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative pt-32 pb-20 overflow-hidden">
        {/* Background effects */}
        <div className="absolute inset-0">
          <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-primary/20 rounded-full blur-3xl" />
          <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-cyan-500/20 rounded-full blur-3xl" />
          <div className="absolute inset-0 bg-[linear-gradient(rgba(0,255,159,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(0,255,159,0.03)_1px,transparent_1px)] bg-[size:50px_50px]" />
        </div>

        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 mb-6">
              <Radar className="h-4 w-4 text-primary animate-pulse" />
              <span className="text-sm text-primary font-medium">Advanced Threat Intelligence</span>
            </div>
            
            <h1 className="text-5xl md:text-7xl font-bold mb-6">
              <span className="bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
                Cyber Intelligence
              </span>
              <br />
              <span className="bg-gradient-to-r from-primary via-cyan-400 to-purple-400 bg-clip-text text-transparent">
                Redefined
              </span>
            </h1>
            
            <p className="text-xl text-slate-400 max-w-3xl mx-auto mb-10">
              Harness the power of OSINT with real-time threat monitoring, dark web surveillance, 
              and comprehensive intelligence gathering. Your command center for cyber defense.
            </p>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <Link to="/auth">
                <Button size="lg" className="bg-gradient-to-r from-primary to-cyan-500 text-slate-900 font-semibold text-lg px-8 py-6">
                  Start Free Trial
                  <ArrowRight className="ml-2 h-5 w-5" />
                </Button>
              </Link>
              <Link to="/about">
                <Button size="lg" variant="outline" className="border-slate-700 text-slate-300 hover:bg-slate-800 text-lg px-8 py-6">
                  Learn More
                </Button>
              </Link>
            </div>
          </div>

          {/* Stats */}
          <div className="mt-20 grid grid-cols-2 md:grid-cols-4 gap-6">
            {STATS.map((stat, i) => (
              <div key={i} className="text-center p-6 rounded-xl bg-slate-900/50 border border-slate-800/50">
                <div className="text-3xl md:text-4xl font-bold bg-gradient-to-r from-primary to-cyan-400 bg-clip-text text-transparent">
                  {stat.value}
                </div>
                <div className="text-sm text-slate-400 mt-1">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 relative">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              Comprehensive Intelligence Suite
            </h2>
            <p className="text-slate-400 max-w-2xl mx-auto">
              Everything you need to monitor, analyze, and respond to cyber threats in one platform.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {FEATURES.map((feature, i) => (
              <Card key={i} className="bg-slate-900/50 border-slate-800/50 hover:border-primary/30 transition-all duration-300 group">
                <CardContent className="p-6">
                  <div className="p-3 rounded-xl bg-primary/10 w-fit mb-4 group-hover:bg-primary/20 transition-colors">
                    <feature.icon className="h-6 w-6 text-primary" />
                  </div>
                  <h3 className="text-lg font-semibold mb-2 text-white">{feature.title}</h3>
                  <p className="text-slate-400 text-sm">{feature.description}</p>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 relative">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="relative overflow-hidden rounded-3xl bg-gradient-to-r from-primary/20 via-cyan-500/20 to-purple-500/20 p-8 md:p-12 border border-primary/20">
            <div className="absolute inset-0 bg-slate-900/60" />
            <div className="relative z-10 text-center">
              <Brain className="h-12 w-12 text-primary mx-auto mb-6" />
              <h2 className="text-3xl md:text-4xl font-bold mb-4">
                Ready to elevate your threat intelligence?
              </h2>
              <p className="text-slate-300 mb-8 max-w-2xl mx-auto">
                Join security professionals worldwide who trust CIPHER for their OSINT needs.
              </p>
              <Link to="/auth">
                <Button size="lg" className="bg-gradient-to-r from-primary to-cyan-500 text-slate-900 font-semibold text-lg px-8">
                  Get Started Now
                  <ChevronRight className="ml-2 h-5 w-5" />
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 border-t border-slate-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-primary/10 rounded-lg border border-primary/20">
                <Shield className="h-5 w-5 text-primary" />
              </div>
              <span className="font-semibold text-slate-300">CIPHER OSINT</span>
            </div>
            <div className="flex items-center gap-6 text-sm text-slate-400">
              <Link to="/about" className="hover:text-white transition-colors">About</Link>
              <a href="#" className="hover:text-white transition-colors">Privacy</a>
              <a href="#" className="hover:text-white transition-colors">Terms</a>
            </div>
            <p className="text-sm text-slate-500">
              © 2026 CIPHER OSINT. All rights reserved.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
