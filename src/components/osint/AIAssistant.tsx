import { useState } from "react";
import { 
  Brain, 
  Send, 
  Loader2, 
  Bot, 
  User, 
  Lightbulb, 
  Search,
  FileText,
  TrendingUp,
  Shield,
  AlertTriangle,
  RefreshCw
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";

interface Message {
  id: string;
  type: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

interface AIInsight {
  id: string;
  title: string;
  type: 'threat' | 'opportunity' | 'recommendation' | 'analysis';
  confidence: number;
  content: string;
  timestamp: Date;
}

export function AIAssistant() {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: "1",
      type: 'assistant',
      content: "Hello! I'm your AI OSINT assistant. I can help you analyze threats, correlate intelligence data, and provide insights. What would you like to investigate today?",
      timestamp: new Date()
    }
  ]);
  const [inputMessage, setInputMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [insights, setInsights] = useState<AIInsight[]>([
    {
      id: "1",
      title: "Increased Malware Activity Detected",
      type: "threat",
      confidence: 0.87,
      content: "Pattern analysis indicates a 45% increase in malware submissions targeting financial institutions over the past 7 days.",
      timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000)
    },
    {
      id: "2",
      title: "CVE Correlation Opportunity",
      type: "opportunity",
      confidence: 0.92,
      content: "Recent vulnerability CVE-2024-1234 shows similar attack vectors to previous incidents in your monitored domains.",
      timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000)
    },
    {
      id: "3",
      title: "Update Security Monitoring Rules",
      type: "recommendation",
      confidence: 0.78,
      content: "Consider adding new indicators based on emerging threat patterns: suspicious domain patterns, unusual certificate requests.",
      timestamp: new Date(Date.now() - 6 * 60 * 60 * 1000)
    }
  ]);

  const quickActions = [
    { icon: Search, label: "Analyze Recent Threats", query: "Analyze the latest threat patterns in my environment" },
    { icon: Shield, label: "Security Posture", query: "Assess my current security posture and vulnerabilities" },
    { icon: TrendingUp, label: "Trend Analysis", query: "Show me trending attack vectors this week" },
    { icon: FileText, label: "Generate Report", query: "Create a threat intelligence summary report" },
  ];

  const handleSendMessage = async () => {
    if (!inputMessage.trim() || loading) return;

    const userMessage: Message = {
      id: Date.now().toString(),
      type: 'user',
      content: inputMessage,
      timestamp: new Date()
    };

    setMessages(prev => [...prev, userMessage]);
    setInputMessage("");
    setLoading(true);

    // Simulate AI response
    setTimeout(() => {
      const aiResponse = generateAIResponse(inputMessage);
      const assistantMessage: Message = {
        id: (Date.now() + 1).toString(),
        type: 'assistant',
        content: aiResponse,
        timestamp: new Date()
      };

      setMessages(prev => [...prev, assistantMessage]);
      setLoading(false);
    }, 2000);
  };

  const generateAIResponse = (query: string): string => {
    const lowerQuery = query.toLowerCase();
    
    if (lowerQuery.includes('threat') || lowerQuery.includes('malware')) {
      return "Based on my analysis of your threat landscape, I've identified several key patterns:\n\n• 3 new malware families detected in the last 24 hours\n• Ransomware activity increased by 23% this week\n• 7 domains flagged as potentially malicious\n\nWould you like me to investigate any specific threats or provide detailed analysis on these findings?";
    }
    
    if (lowerQuery.includes('vulnerability') || lowerQuery.includes('cve')) {
      return "I've analyzed recent CVE data and found:\n\n• 12 critical vulnerabilities published this week\n• 4 affect your monitored infrastructure\n• Exploit code available for 2 of them\n\nI recommend prioritizing patches for CVE-2024-1234 and CVE-2024-5678. Shall I provide detailed remediation steps?";
    }
    
    if (lowerQuery.includes('report') || lowerQuery.includes('summary')) {
      return "I can generate a comprehensive intelligence report including:\n\n• Threat landscape overview\n• Risk assessment findings\n• IOC analysis and attribution\n• Recommended actions\n\nWhat timeframe and focus areas would you like me to include in the report?";
    }
    
    if (lowerQuery.includes('analyze') || lowerQuery.includes('investigation')) {
      return "I'm ready to assist with your investigation. I can help you:\n\n• Correlate indicators across data sources\n• Identify patterns and anomalies\n• Provide threat actor attribution\n• Suggest additional collection requirements\n\nPlease provide the specific indicators or data you'd like me to analyze.";
    }

    return "I understand you're looking for intelligence analysis. I can help with threat hunting, IOC correlation, risk assessment, and generating actionable intelligence. Could you provide more specific details about what you'd like me to investigate?";
  };

  const handleQuickAction = (query: string) => {
    setInputMessage(query);
  };

  const getInsightIcon = (type: string) => {
    switch (type) {
      case 'threat': return AlertTriangle;
      case 'opportunity': return Lightbulb;
      case 'recommendation': return TrendingUp;
      case 'analysis': return Brain;
      default: return Brain;
    }
  };

  const getInsightColor = (type: string) => {
    switch (type) {
      case 'threat': return 'text-red-500 bg-red-500/10';
      case 'opportunity': return 'text-green-500 bg-green-500/10';
      case 'recommendation': return 'text-blue-500 bg-blue-500/10';
      case 'analysis': return 'text-purple-500 bg-purple-500/10';
      default: return 'text-gray-500 bg-gray-500/10';
    }
  };

  const formatTimeAgo = (date: Date) => {
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days}d ago`;
    if (hours > 0) return `${hours}h ago`;
    return 'Just now';
  };

  return (
    <div className="container mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground flex items-center gap-2">
            <Brain className="h-8 w-8 text-primary" />
            AI Intelligence Assistant
          </h1>
          <p className="text-muted-foreground text-sm mt-1">
            Advanced AI-powered threat analysis and intelligence correlation
          </p>
        </div>
        <Button variant="outline" size="sm">
          <RefreshCw className="h-4 w-4" />
          Refresh Insights
        </Button>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Chat Interface */}
        <div className="lg:col-span-2 space-y-6">
          {/* Quick Actions */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Lightbulb className="h-5 w-5" />
                Quick Actions
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-3">
                {quickActions.map((action, index) => (
                  <Button
                    key={index}
                    variant="outline"
                    className="flex items-center gap-2 h-auto p-4 text-left justify-start"
                    onClick={() => handleQuickAction(action.query)}
                  >
                    <action.icon className="h-4 w-4" />
                    <span>{action.label}</span>
                  </Button>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Chat Messages */}
          <Card className="h-[600px] flex flex-col">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Bot className="h-5 w-5" />
                Intelligence Analysis Chat
              </CardTitle>
            </CardHeader>
            <CardContent className="flex-1 flex flex-col p-0">
              {/* Messages */}
              <div className="flex-1 overflow-y-auto p-4 space-y-4">
                {messages.map((message) => (
                  <div
                    key={message.id}
                    className={cn(
                      "flex items-start gap-3",
                      message.type === 'user' ? "flex-row-reverse" : ""
                    )}
                  >
                    <div className={cn(
                      "p-2 rounded-lg",
                      message.type === 'user' 
                        ? "bg-primary/10 text-primary" 
                        : "bg-secondary text-secondary-foreground"
                    )}>
                      {message.type === 'user' ? (
                        <User className="h-4 w-4" />
                      ) : (
                        <Bot className="h-4 w-4" />
                      )}
                    </div>
                    <div
                      className={cn(
                        "max-w-[80%] p-3 rounded-lg",
                        message.type === 'user'
                          ? "bg-primary text-primary-foreground ml-auto"
                          : "bg-secondary"
                      )}
                    >
                      <p className="text-sm whitespace-pre-wrap">{message.content}</p>
                      <span className="text-xs opacity-60 mt-1 block">
                        {formatTimeAgo(message.timestamp)}
                      </span>
                    </div>
                  </div>
                ))}
                
                {loading && (
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-secondary">
                      <Bot className="h-4 w-4" />
                    </div>
                    <div className="bg-secondary p-3 rounded-lg">
                      <div className="flex items-center gap-2">
                        <Loader2 className="h-4 w-4 animate-spin" />
                        <span className="text-sm">Analyzing...</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Input */}
              <div className="p-4 border-t border-border">
                <div className="flex gap-2">
                  <Input
                    placeholder="Ask me about threats, IOCs, patterns, or request analysis..."
                    value={inputMessage}
                    onChange={(e) => setInputMessage(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleSendMessage()}
                    disabled={loading}
                  />
                  <Button 
                    onClick={handleSendMessage} 
                    disabled={loading || !inputMessage.trim()}
                  >
                    <Send className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* AI Insights Panel */}
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <TrendingUp className="h-5 w-5" />
                AI-Generated Insights
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {insights.map((insight) => {
                const Icon = getInsightIcon(insight.type);
                return (
                  <div key={insight.id} className="p-4 border border-border rounded-lg">
                    <div className="flex items-start gap-3">
                      <div className={cn("p-2 rounded-lg", getInsightColor(insight.type))}>
                        <Icon className="h-4 w-4" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <h4 className="font-medium text-sm text-foreground truncate">
                            {insight.title}
                          </h4>
                          <Badge variant="outline" className="text-xs">
                            {Math.round(insight.confidence * 100)}%
                          </Badge>
                        </div>
                        <p className="text-xs text-muted-foreground mb-2">
                          {insight.content}
                        </p>
                        <div className="flex items-center justify-between text-xs text-muted-foreground">
                          <span className="capitalize">{insight.type}</span>
                          <span>{formatTimeAgo(insight.timestamp)}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </CardContent>
          </Card>

          {/* AI Status */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Brain className="h-5 w-5" />
                AI Analysis Status
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-3">
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Active Models</span>
                  <span className="text-foreground">3/3 Online</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Processing Queue</span>
                  <span className="text-foreground">12 items</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Analysis Accuracy</span>
                  <span className="text-foreground">94.2%</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Data Sources</span>
                  <span className="text-foreground">8 Connected</span>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}