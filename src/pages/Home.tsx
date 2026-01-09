import { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import {
  Globe,
  Search,
  Activity,
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
  Menu,
  X,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { LanguageSelector } from '@/components/LanguageSelector';

/* ===================================================================== */
/* CONSTANTS                                                              */
/* ===================================================================== */

const COMPANY_LOGO =
  'https://imagizer.imageshack.com/img922/3923/c1TVGF.png';

const FEATURES = [
  {
    icon: Globe,
    title: 'Domain Intelligence',
    description:
      'DNS records, WHOIS data, subdomains, and certificate transparency logs.',
  },
  {
    icon: Search,
    title: 'Dark Web Monitoring',
    description:
      'Scan onion sites, paste dumps, and breach databases for leaked data.',
  },
  {
    icon: Activity,
    title: 'Live Threat Map',
    description:
      'Real-time visualization of global cyber attacks and threat indicators.',
  },
  {
    icon: Database,
    title: 'Breach Detection',
    description:
      'Check if emails, domains, or credentials have been compromised.',
  },
  {
    icon: Network,
    title: 'IP Analysis',
    description:
      'Geolocation, ASN info, reputation scoring, and port scanning.',
  },
  {
    icon: AlertTriangle,
    title: 'CVE Explorer',
    description:
      'Search and analyze vulnerabilities with CVSS scoring and PoC tracking.',
  },
];

const STATS = [
  { value: '500M+', label: 'Threat Indicators' },
  { value: '150+', label: 'Data Sources' },
  { value: '24/7', label: 'Monitoring' },
  { value: '99.9%', label: 'Uptime' },
];

/* ===================================================================== */
/* HOME PAGE                                                              */
/* ===================================================================== */

export default function Home() {
  const navigate = useNavigate();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  /* ================= AUTH REDIRECT ================= */
  useEffect(() => {
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_, session) => {
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

  /* ================= RENDER ================= */
  return (
    <div className="relative min-h-screen text-white overflow-hidden">
      {/* ========================================================= */}
      {/* GLOBAL BACKGROUND IMAGE                                  */}
      {/* ========================================================= */}
      <div
        className="fixed inset-0 -z-20 bg-cover bg-center"
        style={{ backgroundImage: "url('/bg1111.png')" }}
      />

      {/* Dark overlay for readability */}
      <div className="fixed inset-0 -z-10 bg-slate-950/85 backdrop-blur-[1px]" />

      {/* ========================================================= */}
      {/* NAVBAR                                                    */}
      {/* ========================================================= */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-slate-950/80 backdrop-blur-xl border-b border-slate-800/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-14 sm:h-16">
            {/* Logo */}
            <div className="flex items-center gap-2 sm:gap-3">
              <div className="p-1.5 sm:p-2 rounded-lg border border-primary/20 bg-primary/10">
                <img
                  src={COMPANY_LOGO}
                  alt="Cipher OSINT Logo"
                  className="h-5 w-5 sm:h-6 sm:w-6 object-contain"
                />
              </div>
              <span className="text-lg sm:text-xl font-bold bg-gradient-to-r from-primary to-cyan-400 bg-clip-text text-transparent">
                SoTaNik OSINT
              </span>
            </div>

            {/* Desktop Navigation */}
            <div className="hidden md:flex items-center gap-4">
              <LanguageSelector />
              
              <Link
                to="/about"
                className="text-slate-300 hover:text-white transition-colors"
              >
                About
              </Link>

              <Link to="/auth">
                <Button
                  variant="outline"
                  className="border-primary/50 text-primary hover:bg-primary/10"
                >
                  Sign In
                </Button>
              </Link>

              <Link to="/auth">
                <Button className="bg-gradient-to-r from-primary to-cyan-500 text-slate-900 font-semibold">
                  Get Started
                </Button>
              </Link>
            </div>

            {/* Mobile Menu Button */}
            <div className="flex md:hidden items-center gap-2">
              <LanguageSelector variant="compact" />
              <Button
                variant="ghost"
                size="icon"
                onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
                className="text-slate-300"
              >
                {mobileMenuOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
              </Button>
            </div>
          </div>

          {/* Mobile Menu */}
          {mobileMenuOpen && (
            <div className="md:hidden py-4 border-t border-slate-800/50 animate-fade-in">
              <div className="flex flex-col gap-3">
                <Link
                  to="/about"
                  className="text-slate-300 hover:text-white transition-colors py-2"
                  onClick={() => setMobileMenuOpen(false)}
                >
                  About
                </Link>

                <Link to="/auth" onClick={() => setMobileMenuOpen(false)}>
                  <Button
                    variant="outline"
                    className="w-full border-primary/50 text-primary hover:bg-primary/10"
                  >
                    Sign In
                  </Button>
                </Link>

                <Link to="/auth" onClick={() => setMobileMenuOpen(false)}>
                  <Button className="w-full bg-gradient-to-r from-primary to-cyan-500 text-slate-900 font-semibold">
                    Get Started
                  </Button>
                </Link>
              </div>
            </div>
          )}
        </div>
      </nav>

      {/* ========================================================= */}
      {/* HERO                                                     */}
      {/* ========================================================= */}
      <section className="relative pt-24 sm:pt-32 pb-12 sm:pb-20 overflow-hidden">
        {/* Glow effects */}
        <div className="absolute inset-0">
          <div className="absolute top-1/4 left-1/4 w-48 sm:w-96 h-48 sm:h-96 bg-primary/20 rounded-full blur-3xl" />
          <div className="absolute bottom-1/4 right-1/4 w-48 sm:w-96 h-48 sm:h-96 bg-cyan-500/20 rounded-full blur-3xl" />
          <div className="absolute inset-0 bg-[linear-gradient(rgba(0,255,159,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(0,255,159,0.03)_1px,transparent_1px)] bg-[size:50px_50px]" />
        </div>

        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <div className="inline-flex items-center gap-2 px-3 sm:px-4 py-1.5 sm:py-2 rounded-full bg-primary/10 border border-primary/20 mb-4 sm:mb-6">
            <Radar className="h-3 w-3 sm:h-4 sm:w-4 text-primary animate-pulse" />
            <span className="text-xs sm:text-sm text-primary font-medium">
              Advanced Threat Intelligence
            </span>
          </div>

          <h1 className="text-3xl sm:text-5xl md:text-7xl font-bold mb-4 sm:mb-6">
            <span className="bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
              Cyber Intelligence
            </span>
            <br />
            <span className="bg-gradient-to-r from-primary via-cyan-400 to-purple-400 bg-clip-text text-transparent">
              Redefined
            </span>
          </h1>

          <p className="text-base sm:text-xl text-slate-400 max-w-3xl mx-auto mb-6 sm:mb-10 px-4">
            Harness the power of OSINT with real-time threat monitoring,
            dark web surveillance, and comprehensive intelligence gathering.
            Your command center for cyber defense.
          </p>

          <div className="flex flex-col sm:flex-row gap-3 sm:gap-4 justify-center px-4">
            <Link to="/auth">
              <Button
                size="lg"
                className="w-full sm:w-auto bg-gradient-to-r from-primary to-cyan-500 text-slate-900 font-semibold text-base sm:text-lg px-6 sm:px-8 py-5 sm:py-6"
              >
                Start Free Trial
                <ArrowRight className="ml-2 h-4 w-4 sm:h-5 sm:w-5" />
              </Button>
            </Link>

            <Link to="/about">
              <Button
                size="lg"
                variant="outline"
                className="w-full sm:w-auto border-slate-700 text-slate-300 hover:bg-slate-800 text-base sm:text-lg px-6 sm:px-8 py-5 sm:py-6"
              >
                Learn More
              </Button>
            </Link>
          </div>

          {/* Stats */}
          <div className="mt-12 sm:mt-20 grid grid-cols-2 md:grid-cols-4 gap-3 sm:gap-6 px-2">
            {STATS.map((stat, i) => (
              <div
                key={i}
                className="text-center p-4 sm:p-6 rounded-xl bg-slate-900/60 border border-slate-800/50 backdrop-blur"
              >
                <div className="text-xl sm:text-3xl md:text-4xl font-bold bg-gradient-to-r from-primary to-cyan-400 bg-clip-text text-transparent">
                  {stat.value}
                </div>
                <div className="text-xs sm:text-sm text-slate-400 mt-1">
                  {stat.label}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ========================================================= */}
      {/* FEATURES                                                 */}
      {/* ========================================================= */}
      <section className="py-12 sm:py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-10 sm:mb-16">
            <h2 className="text-2xl sm:text-3xl md:text-4xl font-bold mb-3 sm:mb-4">
              Comprehensive Intelligence Suite
            </h2>
            <p className="text-sm sm:text-base text-slate-400 max-w-2xl mx-auto px-4">
              Everything you need to monitor, analyze, and respond to
              cyber threats in one platform.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6">
            {FEATURES.map((feature, i) => (
              <Card
                key={i}
                className="bg-slate-900/60 border-slate-800/50 hover:border-primary/30 transition-all duration-300 group backdrop-blur"
              >
                <CardContent className="p-4 sm:p-6">
                  <div className="p-2 sm:p-3 rounded-xl bg-primary/10 w-fit mb-3 sm:mb-4 group-hover:bg-primary/20 transition-colors">
                    <feature.icon className="h-5 w-5 sm:h-6 sm:w-6 text-primary" />
                  </div>
                  <h3 className="text-base sm:text-lg font-semibold mb-2 text-white">
                    {feature.title}
                  </h3>
                  <p className="text-slate-400 text-xs sm:text-sm">
                    {feature.description}
                  </p>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* ========================================================= */}
      {/* CTA                                                      */}
      {/* ========================================================= */}
      <section className="py-12 sm:py-20">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="relative overflow-hidden rounded-2xl sm:rounded-3xl bg-gradient-to-r from-primary/20 via-cyan-500/20 to-purple-500/20 p-6 sm:p-8 md:p-12 border border-primary/20 backdrop-blur">
            <div className="absolute inset-0 bg-slate-900/60" />
            <div className="relative z-10 text-center">
              <Brain className="h-10 w-10 sm:h-12 sm:w-12 text-primary mx-auto mb-4 sm:mb-6" />
              <h2 className="text-2xl sm:text-3xl md:text-4xl font-bold mb-3 sm:mb-4">
                Ready To Elevate Your Threat Intelligence?
              </h2>
              <p className="text-sm sm:text-base text-slate-300 mb-6 sm:mb-8 max-w-2xl mx-auto px-4">
                Join security professionals worldwide who trust SoTaNik OSINT HUB
                for their OSINT needs.
              </p>
              <Link to="/auth">
                <Button
                  size="lg"
                  className="bg-gradient-to-r from-primary to-cyan-500 text-slate-900 font-semibold text-base sm:text-lg px-6 sm:px-8"
                >
                  Get Started Now
                  <ChevronRight className="ml-2 h-4 w-4 sm:h-5 sm:w-5" />
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* ========================================================= */}
      {/* FOOTER                                                   */}
      {/* ========================================================= */}
      <footer className="py-8 sm:py-12 border-t border-slate-800 bg-slate-950/70 backdrop-blur">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2 sm:gap-3">
              <div className="p-1.5 sm:p-2 rounded-lg border border-primary/20 bg-primary/10">
                <img
                  src={COMPANY_LOGO}
                  alt="Cipher OSINT Logo"
                  className="h-4 w-4 sm:h-5 sm:w-5 object-contain"
                />
              </div>
              <span className="font-semibold text-slate-300 text-sm sm:text-base">
                SoTaNik OSINT HUB
              </span>
            </div>

            <div className="flex items-center gap-4 sm:gap-6 text-xs sm:text-sm text-slate-400">
              <Link to="/about" className="hover:text-white transition-colors">
                About
              </Link>
              <a href="#" className="hover:text-white transition-colors">
                Privacy
              </a>
            </div>

            <p className="text-xs sm:text-sm text-slate-500">
              © 2026 SoTaNik OSINT HUB. All rights reserved.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
