# SoTaNik OSINT Intelligence Hub

An advanced Open Source Intelligence (OSINT) platform featuring comprehensive threat analysis, malware intelligence, and real-time news monitoring capabilities.

## 🚀 New Features (v2.5)

### 4. Malware Intelligence Hub
- **Latest Malware Analysis**: Real-time tracking of new malware families, attack patterns, and origins
- **File/URL/Hash Analysis**: Comprehensive malware detection using multiple engines
- **Threat Family Classification**: Detailed information on active malware families and their tactics
- **IOC Extraction**: Automatic extraction and correlation of Indicators of Compromise

### 5. News Intelligence Scanner
- **Real-time News Monitoring**: Automated fetching of cybersecurity-related news articles
- **Sentiment Analysis**: AI-powered sentiment analysis of news content
- **Entity Recognition**: Extraction of key entities and topics from news articles
- **Alert System**: Customizable alerts for specific keywords and threat types
- **Trend Analysis**: Analysis of emerging threats and attack patterns

### 6. Enhanced Dashboard (Dark Theme)
- **Modern Dark UI**: Professional dark theme optimized for security operations
- **Expanded Metrics**: New metrics for malware detections, news alerts, and AI analysis
- **Enhanced Quick Actions**: Direct access to all new features from the dashboard
- **Real-time Status**: Live status indicators for all data sources including new services
- **AI-powered Insights**: Intelligent analysis and recommendations

### 🤖 Overall AI Features
- **AI Intelligence Assistant**: Interactive chat interface for threat analysis
- **Pattern Recognition**: Automated detection of threat patterns and anomalies
- **Risk Assessment**: AI-powered risk scoring and impact analysis
- **Correlation Engine**: Cross-reference indicators across multiple data sources
- **Predictive Analysis**: Threat forecasting and trend prediction

## 🎯 Core Features

### Intelligence Gathering
- **Domain Intelligence**: DNS analysis, subdomain enumeration, WHOIS data
- **IP Analysis**: Geolocation, ASN information, reputation checking
- **Certificate Inspection**: SSL/TLS certificate analysis and monitoring
- **Breach Checking**: Email breach lookup across multiple databases
- **Username OSINT**: Social media and platform enumeration (100+ platforms)

### Threat Analysis
- **CVE Explorer**: Vulnerability database with real-time updates
- **Live Threat Feeds**: Real-time threat intelligence from multiple sources
- **Dark Web Scanner**: Dark web monitoring and leak detection
- **Graph Visualization**: Maltego-style network analysis and mapping

### Data Management
- **Data Import/Export**: Support for multiple data formats
- **Local Database**: IndexedDB for offline data storage
- **Monitoring System**: Automated monitoring and alerting
- **Report Generation**: Comprehensive threat intelligence reports

## 🏗️ Architecture

### Frontend Stack
- **React 18** with TypeScript for type-safe development
- **Vite** for fast build and development
- **Tailwind CSS** for modern, responsive styling
- **shadcn/ui** components for consistent UI elements
- **Radix UI** primitives for accessibility

### Backend Integration
- **Supabase** for real-time database and authentication
- **Public APIs** integration for threat intelligence
- **CORS proxies** for cross-origin data fetching
- **Service workers** for offline capabilities

### AI & Analytics
- **Pattern analysis** algorithms
- **Sentiment analysis** for news intelligence
- **Entity recognition** for content analysis
- **Risk scoring** models

## 🚦 API Status

The platform integrates with multiple public and private APIs:

- ✅ **Google DNS API** - Domain resolution
- ✅ **IP Geolocation API** - Location services  
- ✅ **Shodan InternetDB** - Port and service scanning
- ✅ **Certificate Transparency** - SSL certificate monitoring
- ✅ **NVD Database** - CVE and vulnerability data
- ✅ **Malware Intelligence** - Threat detection services
- ✅ **News Feeds** - Real-time security news
- ✅ **Threat Feeds** - Live threat intelligence

## 🎨 UI/UX Features

- **Dark Theme Optimized**: Professional dark interface for security operations
- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **Real-time Updates**: Live data refresh and notifications
- **Keyboard Shortcuts**: Power user productivity features
- **Accessibility**: WCAG compliant design
- **Performance**: Optimized for large datasets and real-time analysis

## 📊 Dashboard Metrics

- **Total Records**: Comprehensive data tracking
- **Malware Detections**: Real-time malware analysis results
- **News Alerts**: Security-related news monitoring
- **AI Analyses**: Automated intelligence processing
- **Live Threats**: Active threat monitoring
- **Threat Score**: Dynamic risk assessment

## 🔧 Quick Start

```sh
# Step 1: Clone the repository using the project's Git URL.
git clone <YOUR_GIT_URL>

# Step 2: Navigate to the project directory.
cd <YOUR_PROJECT_NAME>

# Step 3: Install the necessary dependencies.
npm i

# Step 4: Start the development server with auto-reloading and an instant preview.
npm run dev
```

**Edit a file directly in GitHub**

- Navigate to the desired file(s).
- Click the "Edit" button (pencil icon) at the top right of the file view.
- Make your changes and commit the changes.

**Use GitHub Codespaces**

- Navigate to the main page of your repository.
- Click on the "Code" button (green button) near the top right.
- Select the "Codespaces" tab.
- Click on "New codespace" to launch a new Codespace environment.
- Edit files directly within the Codespace and commit and push your changes once you're done.

## What technologies are used for this project?

This project is built with:

- Vite
- TypeScript
- React
- shadcn-ui
- Tailwind CSS

## How can I deploy this project?

Simply open [Lovable](https://lovable.dev/projects/REPLACE_WITH_PROJECT_ID) and click on Share -> Publish.

## Can I connect a custom domain to my Lovable project?

Yes, you can!

To connect a domain, navigate to Project > Settings > Domains and click Connect Domain.

Read more here: [Setting up a custom domain](https://docs.lovable.dev/features/custom-domain#custom-domain)
