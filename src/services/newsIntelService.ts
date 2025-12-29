// News Intelligence Service
// Service for fetching and analyzing news related to cybersecurity and OSINT topics

export interface NewsArticle {
  id: string;
  title: string;
  description: string;
  url: string;
  source: string;
  publishedAt: Date;
  category?: string;
  sentiment?: 'positive' | 'negative' | 'neutral';
  relevanceScore?: number;
  entities?: string[];
}

export interface NewsAnalysis {
  sentiment: 'positive' | 'negative' | 'neutral';
  riskLevel: 'high' | 'medium' | 'low';
  confidence?: number;
  summary?: string;
  keyTopics?: string[];
  recommendations?: string[];
  trends?: {
    topic: string;
    trend: 'rising' | 'falling' | 'stable';
    confidence: number;
  }[];
}

interface NewsIntelligenceRequest {
  query: string;
  timeframe: string;
  sources?: string[];
  category?: string;
  analysis?: boolean;
}

// Mock news data for demonstration
const mockNewsArticles: NewsArticle[] = [
  {
    id: "1",
    title: "Major Healthcare System Hit by Ransomware Attack",
    description: "A large healthcare network experienced a sophisticated ransomware attack affecting patient care systems across multiple facilities.",
    url: "https://example.com/healthcare-ransomware",
    source: "CyberNews Today",
    publishedAt: new Date(Date.now() - 2 * 60 * 60 * 1000),
    category: "cybersecurity",
    sentiment: "negative",
    relevanceScore: 0.95,
    entities: ["Healthcare", "Ransomware", "Patient Data", "Critical Infrastructure"]
  },
  {
    id: "2",
    title: "New Zero-Day Vulnerability Discovered in Popular Software",
    description: "Security researchers have identified a critical zero-day vulnerability in widely-used enterprise software, prompting urgent patch releases.",
    url: "https://example.com/zero-day-discovery",
    source: "Security Research Weekly",
    publishedAt: new Date(Date.now() - 4 * 60 * 60 * 1000),
    category: "vulnerabilities",
    sentiment: "negative",
    relevanceScore: 0.88,
    entities: ["Zero-day", "Vulnerability", "Enterprise Software", "Patch"]
  },
  {
    id: "3",
    title: "AI-Powered Threat Detection Platform Stops Advanced Attack",
    description: "New artificial intelligence security platform successfully identifies and blocks sophisticated multi-stage attack campaign.",
    url: "https://example.com/ai-threat-detection",
    source: "Tech Security Journal",
    publishedAt: new Date(Date.now() - 6 * 60 * 60 * 1000),
    category: "technology",
    sentiment: "positive",
    relevanceScore: 0.82,
    entities: ["AI", "Threat Detection", "Machine Learning", "Cybersecurity"]
  },
  {
    id: "4",
    title: "International Cybercriminal Network Disrupted by Joint Operation",
    description: "Law enforcement agencies from multiple countries collaborate to take down major cybercriminal infrastructure.",
    url: "https://example.com/cybercriminal-takedown",
    source: "Global Security Report",
    publishedAt: new Date(Date.now() - 8 * 60 * 60 * 1000),
    category: "cybersecurity",
    sentiment: "positive",
    relevanceScore: 0.91,
    entities: ["Cybercrime", "Law Enforcement", "International", "Infrastructure"]
  },
  {
    id: "5",
    title: "Supply Chain Attack Targets Software Development Tools",
    description: "Attackers compromise popular development tools to inject malicious code into software build processes.",
    url: "https://example.com/supply-chain-attack",
    source: "Developer Security News",
    publishedAt: new Date(Date.now() - 12 * 60 * 60 * 1000),
    category: "breaches",
    sentiment: "negative",
    relevanceScore: 0.87,
    entities: ["Supply Chain", "Development Tools", "Malicious Code", "Build Process"]
  },
  {
    id: "6",
    title: "New Regulation Requires Enhanced Cyber Reporting",
    description: "Government introduces new cybersecurity incident reporting requirements for critical infrastructure organizations.",
    url: "https://example.com/cyber-regulation",
    source: "Policy & Compliance Today",
    publishedAt: new Date(Date.now() - 16 * 60 * 60 * 1000),
    category: "business",
    sentiment: "neutral",
    relevanceScore: 0.76,
    entities: ["Regulation", "Incident Reporting", "Critical Infrastructure", "Compliance"]
  },
  {
    id: "7",
    title: "Mobile Banking Apps Targeted by New Trojan Campaign",
    description: "Cybercriminals deploy sophisticated mobile malware targeting popular banking applications on Android devices.",
    url: "https://example.com/mobile-banking-trojan",
    source: "Mobile Security Alert",
    publishedAt: new Date(Date.now() - 18 * 60 * 60 * 1000),
    category: "malware",
    sentiment: "negative",
    relevanceScore: 0.84,
    entities: ["Mobile Banking", "Android", "Trojan", "Financial"]
  },
  {
    id: "8",
    title: "Security Researchers Unveil New Encryption Method",
    description: "Academic research team develops novel encryption approach that could enhance data protection for cloud services.",
    url: "https://example.com/new-encryption",
    source: "Academic Security Review",
    publishedAt: new Date(Date.now() - 24 * 60 * 60 * 1000),
    category: "technology",
    sentiment: "positive",
    relevanceScore: 0.73,
    entities: ["Encryption", "Research", "Cloud Security", "Data Protection"]
  }
];

const mockTopics = [
  "Ransomware",
  "Zero-day vulnerabilities",
  "AI Security",
  "Supply chain attacks",
  "Mobile threats",
  "Cloud security",
  "IoT vulnerabilities",
  "Threat hunting",
  "Incident response",
  "Compliance regulations"
];

export async function fetchNewsIntelligence(params: NewsIntelligenceRequest) {
  // Simulate API call delay
  await new Promise(resolve => setTimeout(resolve, 1500));

  // Filter articles based on query and timeframe
  let filteredArticles = mockNewsArticles.filter(article => {
    const matchesQuery = article.title.toLowerCase().includes(params.query.toLowerCase()) ||
                        article.description.toLowerCase().includes(params.query.toLowerCase()) ||
                        (article.entities && article.entities.some(entity => 
                          entity.toLowerCase().includes(params.query.toLowerCase())));

    // Apply timeframe filter
    const now = new Date();
    let cutoffTime: Date;
    
    switch (params.timeframe) {
      case '1h':
        cutoffTime = new Date(now.getTime() - 60 * 60 * 1000);
        break;
      case '24h':
        cutoffTime = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        break;
      case '7d':
        cutoffTime = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
        break;
      case '30d':
        cutoffTime = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        break;
      default:
        cutoffTime = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    }

    const withinTimeframe = article.publishedAt >= cutoffTime;

    return matchesQuery && withinTimeframe;
  });

  // Apply category filter if specified
  if (params.category && params.category !== 'all') {
    filteredArticles = filteredArticles.filter(article => article.category === params.category);
  }

  // Apply source filter if specified
  if (params.sources && params.sources.length > 0) {
    filteredArticles = filteredArticles.filter(article => 
      params.sources!.includes(article.source));
  }

  // Sort by relevance score and recency
  filteredArticles.sort((a, b) => {
    const scoreA = (a.relevanceScore || 0) * 0.7 + (a.publishedAt.getTime() / Date.now()) * 0.3;
    const scoreB = (b.relevanceScore || 0) * 0.7 + (b.publishedAt.getTime() / Date.now()) * 0.3;
    return scoreB - scoreA;
  });

  // Generate analysis if requested
  let analysis: NewsAnalysis | null = null;
  if (params.analysis || filteredArticles.length > 0) {
    analysis = generateNewsAnalysis(filteredArticles, params.query);
  }

  return {
    articles: filteredArticles,
    analysis,
    totalFound: filteredArticles.length
  };
}

function generateNewsAnalysis(articles: NewsArticle[], query: string): NewsAnalysis {
  // Calculate overall sentiment
  const sentiments = articles.filter(a => a.sentiment).map(a => a.sentiment!);
  const sentimentCounts = {
    positive: sentiments.filter(s => s === 'positive').length,
    negative: sentiments.filter(s => s === 'negative').length,
    neutral: sentiments.filter(s => s === 'neutral').length
  };

  let overallSentiment: 'positive' | 'negative' | 'neutral';
  if (sentimentCounts.negative > sentimentCounts.positive) {
    overallSentiment = 'negative';
  } else if (sentimentCounts.positive > sentimentCounts.negative) {
    overallSentiment = 'positive';
  } else {
    overallSentiment = 'neutral';
  }

  // Calculate risk level based on article content and sentiment
  let riskLevel: 'high' | 'medium' | 'low' = 'low';
  
  const riskKeywords = ['attack', 'breach', 'vulnerability', 'ransomware', 'malware', 'exploit'];
  const riskArticleCount = articles.filter(article => 
    riskKeywords.some(keyword => 
      article.title.toLowerCase().includes(keyword) ||
      article.description.toLowerCase().includes(keyword)
    )).length;

  const riskRatio = riskArticleCount / articles.length;
  if (riskRatio > 0.6) riskLevel = 'high';
  else if (riskRatio > 0.3) riskLevel = 'medium';

  // Extract key topics from entities
  const allEntities = articles.flatMap(a => a.entities || []);
  const entityCounts = allEntities.reduce((acc, entity) => {
    acc[entity] = (acc[entity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const keyTopics = Object.entries(entityCounts)
    .sort(([,a], [,b]) => b - a)
    .slice(0, 5)
    .map(([entity]) => entity);

  // Generate summary
  const summary = `Analysis of ${articles.length} articles related to "${query}". ` +
    `Overall sentiment is ${overallSentiment} with a ${riskLevel} risk level. ` +
    `Key topics include ${keyTopics.slice(0, 3).join(', ')}.`;

  // Generate recommendations
  const recommendations = [];
  if (riskLevel === 'high') {
    recommendations.push('Monitor threat indicators closely');
    recommendations.push('Review and update security policies');
    recommendations.push('Consider increased security alertness');
  }
  if (overallSentiment === 'negative') {
    recommendations.push('Investigate potential impact on your organization');
    recommendations.push('Prepare incident response procedures');
  }
  recommendations.push('Continue monitoring news developments');

  return {
    sentiment: overallSentiment,
    riskLevel,
    confidence: Math.random() * 0.3 + 0.7, // 0.7 - 1.0
    summary,
    keyTopics,
    recommendations
  };
}

export async function getNewsTopics(): Promise<string[]> {
  // Simulate API call delay
  await new Promise(resolve => setTimeout(resolve, 500));
  
  // In a real implementation, this would fetch trending topics from news APIs
  return mockTopics.sort(() => Math.random() - 0.5).slice(0, 8);
}

// Real-world integration placeholders
export async function fetchFromNewsAPI(query: string, timeframe: string) {
  // In a real implementation, this would integrate with NewsAPI.org
  // or similar news aggregation services
  return mockNewsArticles.filter(article => 
    article.title.toLowerCase().includes(query.toLowerCase()));
}

export async function fetchFromGoogleNews(query: string) {
  // In a real implementation, this would use Google News RSS feeds
  // or unofficial Google News API
  return mockNewsArticles.filter(article => 
    article.title.toLowerCase().includes(query.toLowerCase()));
}

export async function analyzeSentiment(text: string): Promise<'positive' | 'negative' | 'neutral'> {
  // In a real implementation, this would use sentiment analysis APIs
  // like Google Cloud Natural Language API, AWS Comprehend, or Azure Text Analytics
  const negativeWords = ['attack', 'breach', 'hack', 'steal', 'exploit', 'vulnerability'];
  const positiveWords = ['secure', 'protect', 'defense', 'prevent', 'improve', 'enhance'];
  
  const lowerText = text.toLowerCase();
  const negCount = negativeWords.filter(word => lowerText.includes(word)).length;
  const posCount = positiveWords.filter(word => lowerText.includes(word)).length;
  
  if (negCount > posCount) return 'negative';
  if (posCount > negCount) return 'positive';
  return 'neutral';
}

export async function extractEntities(text: string): Promise<string[]> {
  // In a real implementation, this would use NER (Named Entity Recognition)
  // services like spaCy, Stanford NER, or cloud NER APIs
  const commonEntities = ['Microsoft', 'Google', 'Apple', 'Amazon', 'Government', 'Healthcare', 'Banking'];
  return commonEntities.filter(entity => 
    text.toLowerCase().includes(entity.toLowerCase()));
}