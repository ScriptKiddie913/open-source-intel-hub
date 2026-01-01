import { useEffect, useRef } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import {
  Target,
  Eye,
  Users,
  Clock,
  Globe,
  Lock,
  Zap,
  ArrowRight,
  CheckCircle2,
  Server,
  Database,
} from 'lucide-react';

/* ===================================================================== */
/* CONSTANTS                                                              */
/* ===================================================================== */

const COMPANY_LOGO =
  'https://imagizer.imageshack.com/img922/3923/c1TVGF.png';

const CAPABILITIES = [
  'Real-time threat monitoring across 150+ data sources',
  'Dark web surveillance and leak detection',
  'Comprehensive breach database integration',
  'Advanced CVE tracking and vulnerability analysis',
  'IP and domain reputation scoring',
  'Certificate transparency monitoring',
  'Username enumeration across platforms',
  'Graph-based relationship visualization',
  'Automated alerting and notifications',
  'Secure session management and data persistence',
];

const TEAM_VALUES = [
  {
    icon: Target,
    title: 'Mission-Driven',
    description:
      'We believe in making advanced threat intelligence accessible to security professionals everywhere.',
  },
  {
    icon: Lock,
    title: 'Privacy-First',
    description:
      'Your data stays yours. We use encryption and strict access controls to protect your intelligence.',
  },
  {
    icon: Zap,
    title: 'Always Evolving',
    description:
      'The threat landscape never stops. Neither do we. Continuous updates and new features.',
  },
  {
    icon: Users,
    title: 'Community Focused',
    description:
      'Built by security researchers, for security researchers. Your feedback shapes our roadmap.',
  },
];

/* ===================================================================== */
/* ABOUT PAGE                                                             */
/* ===================================================================== */

export default function About() {
  const navigate = useNavigate();
  const eyeRef = useRef<HTMLDivElement>(null);
  const pupilRef = useRef<HTMLDivElement>(null);

  /* ================= AUTH REDIRECT ================= */
  useEffect(() => {
    const { data: { subscription } } =
      supabase.auth.onAuthStateChange((_, session) => {
        if (session?.user) navigate('/dashboard');
      });

    supabase.auth.getSession().then(({ data: { session } }) => {
      if (session?.user) navigate('/dashboard');
    });

    return () => subscription.unsubscribe();
  }, [navigate]);

  /* ================= EYE TRACKING ================= */
  useEffect(() => {
    const onMove = (e: MouseEvent) => {
      if (!eyeRef.current || !pupilRef.current) return;

      const cx = window.innerWidth / 2;
      const cy = window.innerHeight / 2;

      const dx = e.clientX - cx;
      const dy = e.clientY - cy;

      eyeRef.current.style.transform =
        `translate(-50%, -50%) rotateX(${dy / 60}deg) rotateY(${dx / 60}deg)`;

      pupilRef.current.style.transform =
        `translate(${dx * 0.02}px, ${dy * 0.02}px)`;
    };

    window.addEventListener('mousemove', onMove);
    return () => window.removeEventListener('mousemove', onMove);
  }, []);

  return (
    <div className="relative min-h-screen text-white bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 overflow-hidden">

      {/* ================= SENTIENT BACKGROUND ================= */}
      <div className="fixed inset-0 -z-20 pointer-events-none">
        <div
          ref={eyeRef}
          className="absolute top-1/2 left-1/2 w-[600px] h-[600px] rounded-full blur-3xl opacity-20"
          style={{
            background:
              'radial-gradient(circle, rgba(56,189,248,0.35), rgba(56,189,248,0.15) 40%, rgba(2,6,23,0.95) 70%)',
            animation: 'eyePulse 20s ease-in-out infinite',
          }}
        >
          <div
            ref={pupilRef}
            className="absolute top-1/2 left-1/2 w-[140px] h-[140px] -translate-x-1/2 -translate-y-1/2 rounded-full blur-xl"
            style={{
              background:
                'radial-gradient(circle, rgba(56,189,248,0.45), rgba(15,23,42,0.9) 70%)',
            }}
          />
        </div>
      </div>

      <div className="fixed inset-0 -z-10 bg-slate-950/85" />

      {/* ================= NAV ================= */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-slate-950/80 backdrop-blur-xl border-b border-slate-800/50">
        <div className="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3">
            <img src={COMPANY_LOGO} className="h-6 w-6" />
            <span className="text-xl font-bold bg-gradient-to-r from-primary to-cyan-400 bg-clip-text text-transparent">
              SoTaNik OSINT HUB
            </span>
          </Link>
          <div className="flex gap-4">
            <Link to="/">Home</Link>
            <Link to="/auth"><Button variant="outline">Sign In</Button></Link>
            <Link to="/auth"><Button>Get Started</Button></Link>
          </div>
        </div>
      </nav>

      {/* ================= HERO ================= */}
      <section className="pt-32 pb-16 text-center max-w-4xl mx-auto">
        <h1 className="text-5xl font-bold mb-6">
          About <span className="text-primary">CIPHER OSINT</span>
        </h1>
        <p className="text-xl text-slate-400">
          We’re building the next generation of open-source intelligence tools,
          empowering security professionals to stay ahead of emerging threats.
        </p>
      </section>

      {/* ================= MISSION ================= */}
      <section className="py-16 max-w-7xl mx-auto px-4 grid md:grid-cols-2 gap-12">
        <div>
          <h2 className="text-3xl font-bold mb-6">Our Mission</h2>
          <p className="text-slate-400 mb-4">
            In an era of increasingly sophisticated cyber threats, access to
            comprehensive threat intelligence should not be limited to large
            enterprises with deep pockets.
          </p>
          <p className="text-slate-400 mb-4">
            CIPHER OSINT democratizes threat intelligence by aggregating data
            from hundreds of sources into a single, actionable dashboard.
          </p>
          <p className="text-slate-400">
            Whether you’re a solo researcher, a small team, or an enterprise SOC,
            our platform scales while remaining accessible and intuitive.
          </p>
        </div>

        <Card className="bg-slate-900/80">
          <CardContent className="p-8">
            <div className="flex gap-4 mb-6">
              <Eye className="h-8 w-8 text-primary" />
              <div>
                <h3 className="text-xl font-semibold">Intelligence at Scale</h3>
                <p className="text-slate-400">Real-time data aggregation</p>
              </div>
            </div>

            <div className="space-y-3 text-slate-300">
              <div className="flex gap-2"><Server />150+ integrated data sources</div>
              <div className="flex gap-2"><Globe />Global threat coverage</div>
              <div className="flex gap-2"><Clock />Sub-second query response</div>
              <div className="flex gap-2"><Database />500M+ indicators</div>
            </div>
          </CardContent>
        </Card>
      </section>

      {/* ================= CAPABILITIES ================= */}
      <section className="py-16 bg-slate-900/30">
        <div className="max-w-4xl mx-auto grid md:grid-cols-2 gap-4 px-4">
          {CAPABILITIES.map((c, i) => (
            <div key={i} className="flex gap-3 p-4 bg-slate-900/50 rounded-xl">
              <CheckCircle2 className="text-primary" />
              <span>{c}</span>
            </div>
          ))}
        </div>
      </section>

      {/* ================= VALUES ================= */}
      <section className="py-16 max-w-7xl mx-auto px-4 grid md:grid-cols-4 gap-6">
        {TEAM_VALUES.map((v, i) => (
          <Card key={i} className="bg-slate-900/50">
            <CardContent className="p-6 text-center">
              <v.icon className="h-6 w-6 text-primary mx-auto mb-4" />
              <h3 className="font-semibold mb-2">{v.title}</h3>
              <p className="text-slate-400 text-sm">{v.description}</p>
            </CardContent>
          </Card>
        ))}
      </section>

      {/* ================= CTA ================= */}
      <section className="py-20 text-center">
        <h2 className="text-3xl font-bold mb-4">Ready to get started?</h2>
        <p className="text-slate-400 mb-8">
          Join thousands of security professionals already using CIPHER OSINT.
        </p>
        <Link to="/auth">
          <Button size="lg">
            Create Free Account <ArrowRight className="ml-2" />
          </Button>
        </Link>
      </section>

      {/* ================= FOOTER ================= */}
      <footer className="py-12 border-t border-slate-800 text-center text-slate-500">
        © 2026 CIPHER OSINT. All rights reserved.
      </footer>

      <style>{`
        @keyframes eyePulse {
          0% { opacity: .18; }
          50% { opacity: .28; }
          100% { opacity: .18; }
        }
      `}</style>
    </div>
  );
}
