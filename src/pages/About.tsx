import { useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import {
  Shield,
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
import AnimatedOrb from '@/components/AnimatedOrb';

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
    description: 'We believe in making advanced threat intelligence accessible to security professionals everywhere.',
  },
  {
    icon: Lock,
    title: 'Privacy-First',
    description: 'Your data stays yours. We use encryption and strict access controls to protect your intelligence.',
  },
  {
    icon: Zap,
    title: 'Always Evolving',
    description: 'The threat landscape never stops. Neither do we. Continuous updates and new features.',
  },
  {
    icon: Users,
    title: 'Community Focused',
    description: 'Built by security researchers, for security researchers. Your feedback shapes our roadmap.',
  },
];

export default function About() {
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
      {/* Animated Orb Background */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none z-0">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px]">
          <AnimatedOrb size={280} particleCount={1000} cycleSpeed={0.0006} />
        </div>
      </div>
      
      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 z-50 bg-slate-950/80 backdrop-blur-xl border-b border-slate-800/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <Link to="/" className="flex items-center gap-3">
              <div className="p-2 bg-primary/10 rounded-lg border border-primary/20">
                <Shield className="h-6 w-6 text-primary" />
              </div>
              <span className="text-xl font-bold bg-gradient-to-r from-primary to-cyan-400 bg-clip-text text-transparent">
                CIPHER OSINT
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

      {/* Hero Section */}
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
            We're building the next generation of open-source intelligence tools, 
            empowering security professionals to stay ahead of emerging threats.
          </p>
        </div>
      </section>

      {/* Mission Section */}
      <section className="py-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid md:grid-cols-2 gap-12 items-center">
            <div>
              <h2 className="text-3xl font-bold mb-6">Our Mission</h2>
              <p className="text-slate-400 mb-4">
                In an era of increasingly sophisticated cyber threats, access to comprehensive 
                threat intelligence shouldn't be limited to large enterprises with deep pockets.
              </p>
              <p className="text-slate-400 mb-4">
                CIPHER OSINT democratizes threat intelligence by providing powerful, 
                easy-to-use tools that aggregate data from hundreds of sources into a 
                single, actionable dashboard.
              </p>
              <p className="text-slate-400">
                Whether you're a solo security researcher, a small security team, or an 
                enterprise SOC, our platform scales to meet your needs while remaining 
                accessible and intuitive.
              </p>
            </div>
            <div className="relative">
              <div className="absolute inset-0 bg-gradient-to-r from-primary/20 to-cyan-500/20 rounded-3xl blur-xl" />
              <Card className="relative bg-slate-900/80 border-slate-800">
                <CardContent className="p-8">
                  <div className="flex items-center gap-4 mb-6">
                    <div className="p-3 bg-primary/10 rounded-xl">
                      <Eye className="h-8 w-8 text-primary" />
                    </div>
                    <div>
                      <h3 className="text-xl font-semibold">Intelligence at Scale</h3>
                      <p className="text-slate-400">Real-time data aggregation</p>
                    </div>
                  </div>
                  <div className="space-y-3">
                    <div className="flex items-center gap-2 text-slate-300">
                      <Server className="h-4 w-4 text-primary" />
                      <span>150+ integrated data sources</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-300">
                      <Globe className="h-4 w-4 text-primary" />
                      <span>Global threat coverage</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-300">
                      <Clock className="h-4 w-4 text-primary" />
                      <span>Sub-second query response</span>
                    </div>
                    <div className="flex items-center gap-2 text-slate-300">
                      <Database className="h-4 w-4 text-primary" />
                      <span>500M+ threat indicators</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </section>

      {/* Capabilities Section */}
      <section className="py-16 bg-slate-900/30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold mb-4">Platform Capabilities</h2>
            <p className="text-slate-400 max-w-2xl mx-auto">
              A comprehensive suite of tools designed for modern threat intelligence operations.
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-4 max-w-4xl mx-auto">
            {CAPABILITIES.map((capability, i) => (
              <div key={i} className="flex items-start gap-3 p-4 rounded-xl bg-slate-900/50 border border-slate-800/50">
                <CheckCircle2 className="h-5 w-5 text-primary flex-shrink-0 mt-0.5" />
                <span className="text-slate-300">{capability}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Values Section */}
      <section className="py-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold mb-4">Our Values</h2>
            <p className="text-slate-400">The principles that guide everything we build.</p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            {TEAM_VALUES.map((value, i) => (
              <Card key={i} className="bg-slate-900/50 border-slate-800/50 hover:border-primary/30 transition-all">
                <CardContent className="p-6 text-center">
                  <div className="p-3 rounded-xl bg-primary/10 w-fit mx-auto mb-4">
                    <value.icon className="h-6 w-6 text-primary" />
                  </div>
                  <h3 className="text-lg font-semibold mb-2">{value.title}</h3>
                  <p className="text-slate-400 text-sm">{value.description}</p>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Technology Section */}
      <section className="py-16 bg-slate-900/30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold mb-4">Built with Modern Technology</h2>
            <p className="text-slate-400 max-w-2xl mx-auto">
              Leveraging cutting-edge technologies to deliver a fast, secure, and reliable platform.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8 max-w-4xl mx-auto">
            <div className="text-center">
              <div className="p-4 rounded-2xl bg-slate-800/50 w-fit mx-auto mb-4">
                <Code className="h-8 w-8 text-cyan-400" />
              </div>
              <h3 className="font-semibold mb-2">React & TypeScript</h3>
              <p className="text-slate-400 text-sm">Type-safe, component-based architecture</p>
            </div>
            <div className="text-center">
              <div className="p-4 rounded-2xl bg-slate-800/50 w-fit mx-auto mb-4">
                <Database className="h-8 w-8 text-cyan-400" />
              </div>
              <h3 className="font-semibold mb-2">Cloud Backend</h3>
              <p className="text-slate-400 text-sm">Secure, scalable data persistence</p>
            </div>
            <div className="text-center">
              <div className="p-4 rounded-2xl bg-slate-800/50 w-fit mx-auto mb-4">
                <Zap className="h-8 w-8 text-cyan-400" />
              </div>
              <h3 className="font-semibold mb-2">Edge Functions</h3>
              <p className="text-slate-400 text-sm">Low-latency serverless compute</p>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <h2 className="text-3xl font-bold mb-4">
            Ready to get started?
          </h2>
          <p className="text-slate-400 mb-8">
            Join thousands of security professionals already using CIPHER OSINT.
          </p>
          <Link to="/auth">
            <Button size="lg" className="bg-gradient-to-r from-primary to-cyan-500 text-slate-900 font-semibold text-lg px-8">
              Create Free Account
              <ArrowRight className="ml-2 h-5 w-5" />
            </Button>
          </Link>
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
    </div>
  );
}
