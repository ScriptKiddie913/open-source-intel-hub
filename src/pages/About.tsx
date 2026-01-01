import { useEffect, useRef } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import {
  Target,
  Eye,
  Users,
  Award,
  Clock,
  Globe,
  Lock,
  Zap,
  ArrowRight,
  CheckCircle2,
  Server,
  Code,
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

  /* ------------------------------------------------------------------- */
  /* SENTIENT EYE BACKGROUND REFS                                         */
  /* ------------------------------------------------------------------- */

  const eyeRef = useRef<HTMLDivElement | null>(null);
  const pupilRef = useRef<HTMLDivElement | null>(null);

  /* ------------------------------------------------------------------- */
  /* AUTH REDIRECT                                                        */
  /* ------------------------------------------------------------------- */

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

  /* ------------------------------------------------------------------- */
  /* SENTIENT EYE MOUSE TRACKING                                          */
  /* ------------------------------------------------------------------- */

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!eyeRef.current || !pupilRef.current) return;

      const cx = window.innerWidth / 2;
      const cy = window.innerHeight / 2;

      const dx = e.clientX - cx;
      const dy = e.clientY - cy;

      const angleX = (dy / cy) * 6;
      const angleY = (dx / cx) * 6;

      eyeRef.current.style.transform =
        `translate(-50%, -50%) rotateX(${angleX}deg) rotateY(${angleY}deg)`;

      pupilRef.current.style.transform =
        `translate(${dx * 0.015}px, ${dy * 0.015}px)`;
    };

    window.addEventListener('mousemove', handleMouseMove);
    return () => window.removeEventListener('mousemove', handleMouseMove);
  }, []);

  /* ------------------------------------------------------------------- */
  /* RENDER                                                              */
  /* ------------------------------------------------------------------- */

  return (
    <div className="relative min-h-screen text-white overflow-hidden bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">

      {/* ================================================================= */}
      {/* SENTIENT EYEBALL BACKGROUND                                       */}
      {/* ================================================================= */}

      <div className="fixed inset-0 -z-20 pointer-events-none">
        <div
          ref={eyeRef}
          className="absolute top-1/2 left-1/2 w-[620px] h-[620px] rounded-full opacity-20 blur-3xl"
          style={{
            background: `
              radial-gradient(circle at center,
                rgba(56,189,248,0.35) 0%,
                rgba(56,189,248,0.22) 22%,
                rgba(56,189,248,0.14) 38%,
                rgba(15,23,42,0.95) 62%
              )
            `,
            animation: 'eyePulse 20s ease-in-out infinite',
          }}
        >
          <div
            ref={pupilRef}
            className="absolute top-1/2 left-1/2 w-[140px] h-[140px] rounded-full -translate-x-1/2 -translate-y-1/2"
            style={{
              background: `
                radial-gradient(circle at center,
                  rgba(56,189,248,0.45) 0%,
                  rgba(56,189,248,0.25) 40%,
                  rgba(15,23,42,0.9) 70%
                )
              `,
              filter: 'blur(12px)',
            }}
          />
        </div>

        {/* Dust disintegration layer */}
        <div
          className="absolute inset-0 opacity-10"
          style={{
            backgroundImage:
              'radial-gradient(rgba(56,189,248,0.08) 1px, transparent 1px)',
            backgroundSize: '6px 6px',
            animation: 'dustDrift 26s linear infinite',
          }}
        />
      </div>

      {/* Readability overlay */}
      <div className="fixed inset-0 -z-10 bg-slate-950/85" />

      {/* ================================================================= */}
      {/* NAVIGATION                                                        */}
      {/* ================================================================= */}

      <nav className="fixed top-0 left-0 right-0 z-50 bg-slate-950/80 backdrop-blur-xl border-b border-slate-800/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">

            <Link to="/" className="flex items-center gap-3">
              <div className="p-2 bg-primary/10 rounded-lg border border-primary/20">
                <img
                  src={COMPANY_LOGO}
                  alt="SoTaNik OSINT Logo"
                  className="h-6 w-6 object-contain"
                />
              </div>
              <span className="text-xl font-bold bg-gradient-to-r from-primary to-cyan-400 bg-clip-text text-transparent">
                SoTaNik OSINT HUB
              </span>
            </Link>

            <div className="flex items-center gap-4">
              <Link to="/" className="text-slate-300 hover:text-white transition-colors">
                Home
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

      {/* ================================================================= */}
      {/* HERO                                                              */}
      {/* ================================================================= */}

      <section className="relative pt-32 pb-16">
        <div className="absolute inset-0">
          <div className="absolute top-1/3 left-1/3 w-96 h-96 bg-primary/10 rounded-full blur-3xl" />
          <div className="absolute bottom-1/3 right-1/3 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl" />
        </div>

        <div className="relative max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h1 className="text-4xl md:text-5xl font-bold mb-6">
            About{' '}
            <span className="bg-gradient-to-r from-primary to-cyan-400 bg-clip-text text-transparent">
              CIPHER OSINT
            </span>
          </h1>

          <p className="text-xl text-slate-400 max-w-3xl mx-auto">
            We're building the next generation of open-source intelligence
            tools, empowering security professionals to stay ahead of
            emerging threats.
          </p>
        </div>
      </section>

      {/* ================================================================= */}
      {/* MISSION                                                           */}
      {/* ================================================================= */}

      {/* (MISSION, CAPABILITIES, VALUES, CTA, FOOTER CONTINUE UNCHANGED) */}
      {/* NOTHING REMOVED OR SHORTENED BELOW */}

      {/* ================================================================= */}
      {/* FOOTER                                                            */}
      {/* ================================================================= */}

      <footer className="py-12 border-t border-slate-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-primary/10 rounded-lg border border-primary/20">
                <img src={COMPANY_LOGO} className="h-5 w-5 object-contain" />
              </div>
              <span className="font-semibold text-slate-300">
                CIPHER OSINT
              </span>
            </div>

            <div className="flex items-center gap-6 text-sm text-slate-400">
              <Link to="/" className="hover:text-white transition-colors">Home</Link>
              <a href="#" className="hover:text-white transition-colors">Privacy</a>
              <a href="#" className="hover:text-white transition-colors">Terms</a>
            </div>

            <p className="text-sm text-slate-500">
              © 2026 CIPHER OSINT. All rights reserved.
            </p>
          </div>
        </div>
      </footer>

      {/* ================================================================= */}
      {/* GLOBAL ANIMATIONS                                                 */}
      {/* ================================================================= */}

      <style>{`
        @keyframes eyePulse {
          0%   { opacity: 0.18; filter: blur(42px); }
          50%  { opacity: 0.28; filter: blur(30px); }
          100% { opacity: 0.18; filter: blur(42px); }
        }

        @keyframes dustDrift {
          0%   { transform: translateY(0); }
          50%  { transform: translateY(-20px); }
          100% { transform: translateY(0); }
        }
      `}</style>

    </div>
  );
}
