# Phoenix OSINT Platform

<p align="center">
  <img src="https://imagizer.imageshack.com/img922/3923/c1TVGF.png" alt="Phoenix OSINT" width="200"/>
</p>

<p align="center">
  <strong>Enterprise-Grade Open Source Intelligence & Threat Analysis Platform</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#installation">Installation</a> •
  <a href="#api-integrations">APIs</a> •
  <a href="#components">Components</a> •
  <a href="#services">Services</a> •
  <a href="#database">Database</a>
</p>

---

## Overview

Phoenix OSINT is a comprehensive, real-time threat intelligence platform designed for security researchers, SOC analysts, and threat hunters. It aggregates data from **30+ global threat intelligence sources**, providing unified visibility into the cyber threat landscape through advanced visualization, LLM-powered analysis, and automated threat correlation.

### Key Highlights

- 🌐 **30+ Threat Intelligence Sources** - Unified feeds from abuse.ch, MITRE ATT&CK, CISA KEV, MalwareBazaar, and more
- 🔍 **Deep Dark Web Scanning** - Onion site crawling, Telegram channel monitoring, paste site analysis
- 🧠 **LLM-Powered Analysis** - Automated threat correlation, entity extraction, and intelligence reports
- 📊 **Real-Time Visualizations** - Interactive threat globe, attack graphs, and live dashboards
- 🛡️ **MITRE ATT&CK Mapping** - Automatic TTP identification and adversary attribution
- 🔔 **Continuous Monitoring** - 24/7 alerting with configurable thresholds
- 📱 **Multi-Platform Scraping** - LinkedIn, Google, GitHub, and social media OSINT
- 🗄️ **Auto-Scaling Database** - Intelligent cleanup at 75% capacity for optimal performance

---

## Features

### Intelligence Modules

| Module | Description |
|--------|-------------|
| **StealthMole Scanner** | Unified dark web intelligence with deep scanning across onion sites, Telegram, LinkedIn, and Google |
| **Malware Pipeline** | 8-stage processing: Ingestion → Classification → Infrastructure → Correlation → Exposure → Attribution → Detection → Monitoring |
| **CVE Explorer** | Real-time vulnerability tracking with CVSS scoring, KEV status, and PoC availability |
| **Domain Intelligence** | DNS enumeration, WHOIS, subdomain discovery, and certificate transparency analysis |
| **IP Analyzer** | Geolocation, ASN lookup, reputation scoring, and port intelligence |
| **Breach Checker** | Email and domain compromise detection across known breach databases |
| **Certificate Inspector** | SSL/TLS certificate analysis and chain validation |
| **Threat Globe** | 3D visualization of global attack patterns and C2 infrastructure |
| **Telegram Intelligence** | Channel scraping and message analysis for threat actor communications |
| **Crypto Abuse Scanner** | Bitcoin address investigation and wallet clustering |
| **Username Enumeration** | Cross-platform identity discovery and correlation |
| **News Intelligence** | Automated security news aggregation and threat trend analysis |

### Dashboard Capabilities

- **Real-Time Metrics**: Live threat counts, active monitors, and alert statistics
- **API Health Monitoring**: Status indicators for all integrated services
- **Activity Feed**: Chronological log of all intelligence operations
- **Interactive Charts**: Trend analysis with Recharts visualization
- **Crime Wall**: Visual investigation board for case management
- **Maltego-Style Graphs**: Entity relationship mapping and link analysis

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              PHOENIX OSINT PLATFORM                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐      │
│  │   React Frontend │    │  Edge Functions  │    │    Supabase DB   │      │
│  │   (Vite + TS)    │◄──►│   (Deno Runtime) │◄──►│   (PostgreSQL)   │      │
│  └────────┬─────────┘    └────────┬─────────┘    └────────┬─────────┘      │
│           │                       │                       │                 │
│  ┌────────▼─────────────────────▼─────────────────────▼────────┐           │
│  │                      SERVICE LAYER                           │           │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │           │
│  │  │ Threat Intel│  │ LLM Analysis│  │ Unified Pipeline    │  │           │
│  │  │ Services    │  │ Services    │  │ Service             │  │           │
│  │  └─────────────┘  └─────────────┘  └─────────────────────┘  │           │
│  └──────────────────────────────────────────────────────────────┘           │
│                                    │                                         │
│  ┌─────────────────────────────────▼────────────────────────────┐           │
│  │                    EXTERNAL DATA SOURCES                      │           │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐     │           │
│  │  │abuse.ch│ │ CISA   │ │ MITRE  │ │Firecrawl│ │VirusTotal│   │           │
│  │  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘     │           │
│  └──────────────────────────────────────────────────────────────┘           │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Technology Stack

| Layer | Technology |
|-------|------------|
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS |
| **UI Components** | shadcn/ui, Radix UI, Lucide Icons |
| **State Management** | TanStack Query, React Context |
| **Visualization** | Recharts, Custom WebGL Globe |
| **Backend** | Supabase Edge Functions (Deno) |
| **Database** | PostgreSQL with Row-Level Security |
| **Authentication** | Supabase Auth with OAuth support |
| **Real-Time** | Supabase Realtime subscriptions |

---

## Installation

### Prerequisites

- Node.js 18+ and npm
- Supabase account (for backend services)

### Setup

```bash
# Clone the repository
git clone <repository-url>
cd phoenix-osint

# Install dependencies
npm install

# Configure environment variables
cp .env.example .env

# Start development server
npm run dev
```

### Environment Variables

```env
# Supabase Configuration
VITE_SUPABASE_URL=your_supabase_url
VITE_SUPABASE_ANON_KEY=your_anon_key

# Threat Intelligence APIs
VITE_ABUSEIPDB_API_KEY=your_key
VITE_VIRUSTOTAL_API_KEY=your_key
VITE_NVD_API_KEY=your_key
VITE_GROQ_API_KEY=your_key
VITE_PERPLEXITY_API_KEY=your_key
```

---

## API Integrations

### Threat Intelligence Sources

| Source | Type | Data Provided |
|--------|------|---------------|
| **MalwareBazaar** | Malware Samples | SHA256 hashes, file signatures, malware families |
| **Feodo Tracker** | C2 Infrastructure | Botnet C2 IPs, associated malware families |
| **URLhaus** | Malicious URLs | URL blocklists, hosting infrastructure |
| **ThreatFox** | IOCs | IPs, domains, hashes linked to malware |
| **SSL Blacklist** | Certificates | Malicious SSL certificate fingerprints |
| **CISA KEV** | Vulnerabilities | Known exploited vulnerabilities catalog |
| **NVD** | CVE Database | Vulnerability details, CVSS scores |
| **MITRE ATT&CK** | TTPs | Tactics, techniques, and procedures |
| **Shodan** | Internet Scanning | Port data, service banners, device info |
| **VirusTotal** | Multi-AV | File/URL/IP reputation across 70+ engines |
| **AbuseIPDB** | IP Reputation | Abuse reports, confidence scores |
| **Firecrawl** | Web Scraping | LinkedIn, Google, and web content extraction |

### Edge Functions

| Function | Endpoint | Purpose |
|----------|----------|---------|
| `phoenix-chat` | `/phoenix-chat` | LLM-powered threat analysis chatbot |
| `phoenix-osint-analysis` | `/phoenix-osint-analysis` | Automated OSINT entity analysis |
| `threat-intel` | `/threat-intel` | Unified threat intelligence queries |
| `threat-sync` | `/threat-sync` | Background threat data synchronization |
| `firecrawl-search` | `/firecrawl-search` | Web and social media search |
| `firecrawl-scrape` | `/firecrawl-scrape` | Content extraction from URLs |
| `send-report` | `/send-report` | Intelligence report generation |
| `panic-alert` | `/panic-alert` | Emergency alert dispatch |

---

## Components

### Core OSINT Components

```
src/components/osint/
├── Dashboard.tsx              # Main metrics dashboard
├── StealthMoleScanner.tsx     # Unified dark web scanner (1600+ lines)
├── MalwarePipeline.tsx        # 8-stage malware analysis pipeline
├── ThreatVisualization.tsx    # Threat data visualization
├── ThreatGlobe.tsx            # 3D WebGL attack globe
├── CVEExplorer.tsx            # Vulnerability search and analysis
├── DomainIntelligence.tsx     # DNS/WHOIS/subdomain enumeration
├── IPAnalyzer.tsx             # IP geolocation and reputation
├── BreachChecker.tsx          # Credential compromise detection
├── CertificateInspector.tsx   # SSL/TLS certificate analysis
├── DarkWebScanner.tsx         # Onion site monitoring
├── TelegramIntelligence.tsx   # Telegram channel analysis
├── CryptoAbuseScanner.tsx     # Bitcoin address investigation
├── UsernameEnumeration.tsx    # Cross-platform identity lookup
├── NewsIntelligence.tsx       # Security news aggregation
├── LiveThreatFeed.tsx         # Real-time threat feed display
├── LiveThreatMap.tsx          # Geographic threat visualization
├── GraphVisualization.tsx     # Entity relationship graphs
├── MaltegoGraph.tsx           # Link analysis visualization
├── CrimeWall.tsx              # Investigation board
├── MonitoringDashboard.tsx    # Continuous monitoring interface
├── DataImporter.tsx           # Bulk data import tools
├── ThreatChatbot.tsx          # AI-powered analysis assistant
├── SearchInterface.tsx        # Universal search component
├── ThreatIntelSearch.tsx      # Threat-specific search
├── SearchHistoryPage.tsx      # Query history management
├── SettingsPage.tsx           # User preferences
├── RealTimeCharts.tsx         # Live chart components
├── OSINTSidebar.tsx           # Navigation sidebar
├── PanicButton.tsx            # Emergency alert trigger
├── ReportButton.tsx           # Report generation
├── StatCard.tsx               # Metric display cards
├── ThreatBadge.tsx            # Severity indicators
├── APIStatusIndicator.tsx     # Service health badges
└── DarkLookups.tsx            # Dark web search interface
```

---

## Services

### Service Architecture

```
src/services/
├── Threat Intelligence
│   ├── unifiedThreatPipelineService.ts    # Central aggregation engine
│   ├── threatIntelligenceDatabase.ts      # Database operations + auto-cleanup
│   ├── realTimeThreatFeedService.ts       # Live feed processing
│   ├── realTimeThreatService.ts           # Real-time event handling
│   ├── enhancedThreatService.ts           # Advanced threat enrichment
│   ├── supabaseThreatService.ts           # DB persistence layer
│   └── threatActorService.ts              # APT group tracking
│
├── Malware Analysis
│   ├── malwareBazaarService.ts            # MalwareBazaar API
│   ├── malwareTrackingService.ts          # Sample tracking
│   ├── feodoTrackerService.ts             # Feodo C2 tracking
│   ├── urlhausService.ts                  # URLhaus integration
│   └── mispFeedService.ts                 # MISP feed processing
│
├── Vulnerability Management
│   ├── cveService.ts                      # NVD + CISA KEV integration
│   └── victimExposureService.ts           # Exposure assessment
│
├── Network Intelligence
│   ├── dnsService.ts                      # DNS resolution
│   ├── ipService.ts                       # IP geolocation/reputation
│   ├── certService.ts                     # Certificate transparency
│   └── torService.ts                      # Tor node detection
│
├── Social & Dark Web
│   ├── telegramService.ts                 # Telegram monitoring
│   ├── advancedTelegramService.ts         # Enhanced Telegram OSINT
│   ├── darkWebForumService.ts             # Forum scraping
│   ├── socialScrapingService.ts           # LinkedIn/Google/Social
│   └── gitHubMalwareService.ts            # GitHub threat detection
│
├── AI & Analysis
│   ├── llmAnalysisService.ts              # LLM-powered analysis
│   ├── llmThreatProcessorService.ts       # AI threat processing
│   ├── entityDetectionService.ts          # Entity type detection
│   ├── detectionEngineService.ts          # Rule-based detection
│   └── firecrawlThreatService.ts          # AI web analysis
│
├── Correlation & Attribution
│   ├── campaignCorrelationService.ts      # Campaign linking
│   ├── openCtiCorrelationService.ts       # OpenCTI integration
│   ├── mitreAttackService.ts              # MITRE ATT&CK mapping
│   └── aptMapService.ts                   # APT geographic tracking
│
├── Investigation Tools
│   ├── bitcoinInvestigationService.ts     # Crypto forensics
│   ├── graphService.ts                    # Graph operations
│   └── osintIntegrationService.ts         # Multi-source OSINT
│
├── Monitoring & Reporting
│   ├── continuousMonitoringService.ts     # 24/7 monitoring
│   ├── newsService.ts                     # News aggregation
│   └── searchHistoryService.ts            # Query tracking
│
└── Utilities
    ├── userDataService.ts                 # User preferences
    ├── translationService.ts              # i18n support
    ├── advancedGeoLocationService.ts      # Enhanced geolocation
    └── virusTotalService.ts               # VT API wrapper
```

### Unified Threat Pipeline

The `UnifiedThreatPipelineService` is the core engine that:

1. **Aggregates** data from all threat sources in parallel
2. **Normalizes** different data formats into a unified schema
3. **Deduplicates** threats using intelligent hash matching
4. **Enriches** IOCs with additional context
5. **Stores** processed intelligence with confidence scoring
6. **Syncs** every 60 seconds for real-time updates

```typescript
// Pipeline execution flow
await Promise.allSettled([
  this.fetchAbuseChSources(),    // MalwareBazaar, Feodo, URLhaus, ThreatFox
  this.fetchAPTSources(),         // MITRE ATT&CK, APT groups
  this.fetchCVESources(),         // NVD, CISA KEV
  this.fetchRansomwareSources(),  // Ransomware.live, leak sites
  this.fetchAdditionalSources(),  // VirusTotal, custom feeds
]);
```

---

## Database

### Schema

```sql
-- Core threat intelligence table
CREATE TABLE threat_intelligence (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id TEXT NOT NULL,
  source_name TEXT NOT NULL,
  threat_type TEXT DEFAULT 'unknown',
  title TEXT DEFAULT 'Untitled Threat',
  description TEXT,
  severity_level TEXT DEFAULT 'medium',
  confidence_level INTEGER DEFAULT 50,
  indicators JSONB,           -- IOCs: IPs, domains, hashes
  ttps JSONB,                 -- MITRE ATT&CK techniques
  attribution JSONB,          -- Threat actor attribution
  targets JSONB,              -- Targeted industries/regions
  timeline JSONB,             -- Event timeline
  tags TEXT[],
  metadata JSONB,
  raw_data JSONB,
  status TEXT DEFAULT 'active',
  first_seen TIMESTAMPTZ DEFAULT now(),
  last_seen TIMESTAMPTZ DEFAULT now(),
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now(),
  user_id UUID REFERENCES auth.users
);

-- Auto-cleanup at 75% capacity (10,000 record limit)
CREATE FUNCTION cleanup_old_threats() RETURNS TRIGGER AS $$
BEGIN
  DELETE FROM threat_intelligence
  WHERE id IN (
    SELECT id FROM threat_intelligence
    ORDER BY created_at ASC
    LIMIT (SELECT COUNT(*) - 6000 FROM threat_intelligence)
  )
  WHERE (SELECT COUNT(*) FROM threat_intelligence) > 7500;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;
```

### Additional Tables

| Table | Purpose |
|-------|---------|
| `profiles` | User profile data and preferences |
| `search_history` | Query tracking and analytics |
| `saved_graphs` | Persisted investigation graphs |
| `monitoring_items` | Continuous monitoring configurations |
| `monitoring_alerts` | Alert records and notifications |
| `panic_alerts` | Emergency alert logs |
| `user_sessions` | Session management |

### Row-Level Security

All tables implement RLS policies ensuring users can only access their own data:

```sql
CREATE POLICY "Users can view own data"
  ON threat_intelligence FOR SELECT
  USING (auth.uid() = user_id OR user_id IS NULL);
```

---

## Performance Optimizations

### Auto-Cleanup System

The database implements intelligent auto-cleanup:

- **Threshold**: Triggers at 75% capacity (7,500 of 10,000 records)
- **Target**: Reduces to 60% capacity (6,000 records)
- **Method**: Deletes oldest records first (FIFO)
- **Frequency**: Checked every 30 seconds during write operations

### Rate Limit Management

- Parallel fetching with intelligent batching
- Exponential backoff for failed requests
- Source-specific rate limit tracking
- Fallback to cached data on API failures

### Real-Time Updates

- Supabase Realtime subscriptions for live data
- 30-second sync queue processing
- Optimistic UI updates with rollback

---

## Security

### Authentication

- Supabase Auth with email/password
- OAuth support (Google, GitHub)
- Session persistence with auto-refresh
- Protected routes with auth guards

### Data Protection

- Row-Level Security on all tables
- API key encryption at rest
- HTTPS-only communications
- XSS/CSRF protection built-in

### Privacy

- User data isolation
- No cross-user data access
- Configurable data retention
- GDPR-compliant design

---

## Deployment

### Production Build

```bash
# Build for production
npm run build

# Preview production build
npm run preview
```

### Edge Function Deployment

Edge functions auto-deploy on push. Manual deployment:

```bash
supabase functions deploy <function-name>
```

---

## Roadmap

- [ ] STIX/TAXII integration
- [ ] Automated threat hunting playbooks
- [ ] ML-based anomaly detection
- [ ] Custom feed support
- [ ] API access for external tools
- [ ] Mobile application
- [ ] Threat intelligence sharing (TLP support)
- [ ] Integration with SIEM platforms

---

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests for any enhancements.

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

<p align="center">
  <strong>Phoenix OSINT Platform</strong><br>
  Empowering Security Teams with Unified Threat Intelligence
</p>
