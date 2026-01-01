// ============================================================================
// ThreatChatbot.tsx
// PERPLEXITY-STYLE AI CHATBOT FOR THREAT INTELLIGENCE
// ============================================================================
// ✔ Context-aware responses based on search results
// ✔ Session management - context cleared on page refresh
// ✔ Integration with search history
// ✔ Markdown rendering for responses
// ============================================================================

'use client';

import React, { useState, useRef, useEffect, useCallback } from 'react';
import {
  MessageSquare,
  Send,
  Bot,
  User,
  Loader2,
  X,
  Minimize2,
  Maximize2,
  Trash2,
  Sparkles,
  AlertCircle,
  Copy,
  Check,
  RefreshCw,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import { toast } from 'sonner';

/* ============================================================================
   TYPES
============================================================================ */

interface ChatMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: string;
  sources?: string[];
  isLoading?: boolean;
}

interface ThreatContext {
  searchQuery: string;
  searchType: 'pipeline' | 'stealthmole' | 'graph' | 'general';
  results: any;
  metadata?: Record<string, any>;
}

interface ThreatChatbotProps {
  context: ThreatContext | null;
  onClearContext?: () => void;
  className?: string;
  position?: 'inline' | 'floating';
}

/* ============================================================================
   AI RESPONSE GENERATOR (Using free LLM endpoints)
============================================================================ */

async function generateAIResponse(
  userMessage: string,
  context: ThreatContext | null,
  chatHistory: ChatMessage[]
): Promise<string> {
  // Build context string from search results
  let contextInfo = '';
  
  if (context && context.results) {
    const results = context.results;
    
    // Format context based on search type
    if (context.searchType === 'pipeline') {
      contextInfo = `
THREAT INTELLIGENCE CONTEXT (Pipeline Search for "${context.searchQuery}"):
${results.malwareIndicators ? `- Malware Indicators Found: ${results.malwareIndicators.length}` : ''}
${results.aptGroups ? `- APT Groups Identified: ${results.aptGroups.map((g: any) => g.name).join(', ')}` : ''}
${results.c2Servers ? `- C2 Servers Detected: ${results.c2Servers.length}` : ''}
${results.correlations ? `- Threat Correlations: ${results.correlations.length}` : ''}
${results.campaigns ? `- Related Campaigns: ${results.campaigns.length}` : ''}

Key Findings:
${JSON.stringify(results, null, 2).substring(0, 3000)}
`;
    } else if (context.searchType === 'stealthmole') {
      contextInfo = `
DARK WEB INTELLIGENCE CONTEXT (Deep Scan for "${context.searchQuery}"):
${results.darkWebSignals ? `- Dark Web Signals: ${results.darkWebSignals.length}` : ''}
${results.malwareIndicators ? `- Malware IOCs: ${results.malwareIndicators.length}` : ''}
${results.ransomwareGroups ? `- Ransomware Groups: ${results.ransomwareGroups.length}` : ''}
${results.stealerLogs ? `- Stealer Logs: ${results.stealerLogs.length}` : ''}
${results.c2Servers ? `- C2 Infrastructure: ${results.c2Servers.length}` : ''}
${results.telegramResults ? `- Telegram Intelligence: ${results.telegramResults.length}` : ''}
${results.stats ? `
Statistics:
- Total Findings: ${results.stats.totalFindings}
- Critical Threats: ${results.stats.criticalThreats}
- High Severity: ${results.stats.highThreats}
` : ''}

Detailed Results:
${JSON.stringify(results, null, 2).substring(0, 3000)}
`;
    } else {
      contextInfo = `
SEARCH CONTEXT for "${context.searchQuery}":
${JSON.stringify(results, null, 2).substring(0, 2000)}
`;
    }
  }
  
  // Build chat history for context
  const historyText = chatHistory
    .slice(-6) // Last 6 messages for context
    .map(m => `${m.role}: ${m.content}`)
    .join('\n');

  // Create the prompt
  const systemPrompt = `You are an expert cybersecurity threat intelligence analyst assistant. You help users understand and analyze threat data, malware samples, APT groups, dark web intelligence, and security indicators.

${contextInfo ? `CURRENT ANALYSIS CONTEXT:\n${contextInfo}` : 'No specific search context is available. You can answer general cybersecurity questions.'}

GUIDELINES:
- Provide accurate, technical responses about cybersecurity threats
- Reference the search results when available
- Explain technical concepts clearly
- Suggest actionable next steps when appropriate
- Use bullet points and structured formatting
- If you don't have specific data, say so clearly
- Always prioritize the context data provided over general knowledge

Previous conversation:
${historyText}`;

  // Use a free LLM API (Hugging Face Inference or similar)
  // For demo purposes, we'll generate contextual responses locally
  // In production, you'd call an actual API
  
  const response = await generateLocalResponse(userMessage, contextInfo, context);
  return response;
}

/**
 * Generate contextual response based on search data
 * This simulates an AI response using the actual search context
 */
async function generateLocalResponse(
  query: string,
  contextInfo: string,
  context: ThreatContext | null
): Promise<string> {
  // Simulate API delay
  await new Promise(resolve => setTimeout(resolve, 800 + Math.random() * 1200));
  
  const queryLower = query.toLowerCase();
  
  // No context available
  if (!context || !context.results) {
    return `I don't have any active search context to analyze. Please run a search first, and I'll be able to answer questions about the results.

To get started:
- Use the search bar above to query a domain, IP, hash, or threat indicator
- I'll analyze the results and answer your questions about:
  • Malware families and their behaviors
  • APT groups and their TTPs
  • Dark web exposure
  • Infrastructure connections
  • Recommended mitigations`;
  }
  
  const results = context.results;
  
  // Analysis of severity/risk
  if (queryLower.includes('severity') || queryLower.includes('risk') || queryLower.includes('dangerous')) {
    const criticalCount = results.stats?.criticalThreats || 0;
    const highCount = results.stats?.highThreats || 0;
    const total = results.stats?.totalFindings || 0;
    
    return `## Risk Assessment for "${context.searchQuery}"

**Overall Threat Level**: ${criticalCount > 0 ? '🔴 CRITICAL' : highCount > 0 ? '🟠 HIGH' : total > 0 ? '🟡 MEDIUM' : '🟢 LOW'}

### Threat Breakdown:
- 🔴 Critical Threats: ${criticalCount}
- 🟠 High Severity: ${highCount}
- Total Findings: ${total}

${criticalCount > 0 ? `
### ⚠️ Immediate Actions Required:
1. Isolate affected systems from the network
2. Initiate incident response procedures
3. Preserve forensic evidence
4. Block identified IOCs at perimeter
5. Notify relevant stakeholders
` : highCount > 0 ? `
### Recommended Actions:
1. Review and validate findings
2. Update detection rules
3. Monitor for related activity
4. Document indicators for threat hunting
` : `
### Status:
The search returned limited high-severity findings. Continue monitoring for changes.
`}`;
  }
  
  // Questions about malware
  if (queryLower.includes('malware') || queryLower.includes('sample') || queryLower.includes('hash')) {
    const malwareIndicators = results.malwareIndicators || results.malwareSamples || [];
    const families = [...new Set(malwareIndicators.map((m: any) => m.malwareFamily || m.family).filter(Boolean))];
    
    return `## Malware Analysis for "${context.searchQuery}"

**Detected Malware Families**: ${families.length > 0 ? families.join(', ') : 'None specifically identified'}
**Total IOCs**: ${malwareIndicators.length}

${malwareIndicators.length > 0 ? `
### Key Indicators:
${malwareIndicators.slice(0, 5).map((m: any) => `
- **${m.type || 'IOC'}**: \`${m.value || m.hash || m.sha256 || 'N/A'}\`
  - Family: ${m.malwareFamily || m.family || 'Unknown'}
  - Severity: ${m.severity || 'Medium'}
  - First Seen: ${m.firstSeen || 'Unknown'}
`).join('')}

### MITRE ATT&CK Techniques:
${families.includes('ransomware') || queryLower.includes('ransomware') ? '- T1486: Data Encrypted for Impact\n- T1490: Inhibit System Recovery' : ''}
${families.includes('stealer') || queryLower.includes('stealer') ? '- T1555: Credentials from Password Stores\n- T1539: Steal Web Session Cookie' : ''}
- T1071: Application Layer Protocol (C2)
- T1105: Ingress Tool Transfer
` : `
No specific malware samples were found in the current search results.
`}`;
  }
  
  // Questions about APT groups
  if (queryLower.includes('apt') || queryLower.includes('threat actor') || queryLower.includes('group') || queryLower.includes('who')) {
    const aptGroups = results.aptGroups || [];
    
    return `## Threat Actor Analysis for "${context.searchQuery}"

**Identified APT Groups**: ${aptGroups.length > 0 ? aptGroups.map((g: any) => g.name).join(', ') : 'No specific attribution'}

${aptGroups.length > 0 ? aptGroups.slice(0, 3).map((apt: any) => `
### ${apt.name}
- **Country**: ${apt.country || 'Unknown'}
- **Motivation**: ${apt.motivations?.join(', ') || 'Unknown'}
- **Active Since**: ${apt.firstSeen || 'Unknown'}
- **Target Sectors**: ${apt.targetCategories?.slice(0, 3).join(', ') || 'Various'}
- **Known Tools**: ${apt.tools?.slice(0, 3).map((t: any) => t.name).join(', ') || 'Various'}

${apt.description ? `**Description**: ${apt.description.substring(0, 200)}...` : ''}
`).join('\n') : `
Based on the indicators found, no specific APT group attribution could be made. This could indicate:
- Commodity malware not linked to nation-state actors
- New or unknown threat actor
- False positive indicators

Consider running additional analysis with more specific IOCs.
`}`;
  }
  
  // Questions about C2/infrastructure
  if (queryLower.includes('c2') || queryLower.includes('infrastructure') || queryLower.includes('server') || queryLower.includes('ip')) {
    const c2Servers = results.c2Servers || [];
    
    return `## C2 Infrastructure Analysis for "${context.searchQuery}"

**Active C2 Servers Detected**: ${c2Servers.length}

${c2Servers.length > 0 ? `
### Identified Infrastructure:
${c2Servers.slice(0, 5).map((c2: any) => `
- **${c2.ip}:${c2.port}**
  - Malware: ${c2.malwareFamily || 'Unknown'}
  - Status: ${c2.status || 'Unknown'}
  - Country: ${c2.country || 'Unknown'}
  - First Seen: ${c2.firstSeen || 'Unknown'}
`).join('')}

### Recommended Blocking Actions:
1. Add identified IPs to firewall blocklists
2. Create DNS sinkholes for associated domains
3. Monitor egress traffic for connections to these IPs
4. Alert on any historical connections in logs
` : `
No active C2 infrastructure was identified in this search.
`}`;
  }
  
  // Questions about dark web
  if (queryLower.includes('dark web') || queryLower.includes('leak') || queryLower.includes('breach') || queryLower.includes('exposed')) {
    const darkWebSignals = results.darkWebSignals || [];
    const stealerLogs = results.stealerLogs || [];
    
    return `## Dark Web Exposure Analysis for "${context.searchQuery}"

**Dark Web Mentions**: ${darkWebSignals.length}
**Stealer Log Hits**: ${stealerLogs.length}

${darkWebSignals.length > 0 || stealerLogs.length > 0 ? `
### Exposure Summary:
${darkWebSignals.slice(0, 3).map((signal: any) => `
- **Source**: ${signal.source || 'Dark Web Forum'}
  - Type: ${signal.type || 'Mention'}
  - Severity: ${signal.severity || 'Medium'}
  - Date: ${signal.timestamp || 'Recent'}
`).join('')}

### Immediate Recommendations:
1. Reset credentials for any exposed accounts
2. Enable MFA on all critical systems
3. Monitor for unauthorized access attempts
4. Review data exfiltration indicators
5. Consider engaging incident response team
` : `
No significant dark web exposure was found for this query. This is a positive indicator, but continued monitoring is recommended.
`}`;
  }
  
  // Default comprehensive summary
  return `## Analysis Summary for "${context.searchQuery}"

### Overview:
I've analyzed the threat intelligence data from your search. Here's what I found:

**Search Type**: ${context.searchType}
**Total Results**: ${results.stats?.totalFindings || Object.keys(results).length} categories

### Key Findings:
${results.malwareIndicators?.length ? `- **Malware Indicators**: ${results.malwareIndicators.length} IOCs detected` : ''}
${results.aptGroups?.length ? `- **APT Groups**: ${results.aptGroups.length} potential threat actors` : ''}
${results.c2Servers?.length ? `- **C2 Servers**: ${results.c2Servers.length} command & control infrastructure` : ''}
${results.darkWebSignals?.length ? `- **Dark Web Signals**: ${results.darkWebSignals.length} mentions found` : ''}
${results.stealerLogs?.length ? `- **Stealer Logs**: ${results.stealerLogs.length} credential exposures` : ''}
${results.ransomwareGroups?.length ? `- **Ransomware**: ${results.ransomwareGroups.length} group associations` : ''}

### Questions I Can Answer:
- "What is the risk level of this threat?"
- "Tell me about the malware samples found"
- "Which APT groups are involved?"
- "What C2 infrastructure was detected?"
- "Is there dark web exposure?"
- "What actions should I take?"

Feel free to ask specific questions about any aspect of these results!`;
}

/* ============================================================================
   MAIN COMPONENT
============================================================================ */

export function ThreatChatbot({
  context,
  onClearContext,
  className,
  position = 'floating',
}: ThreatChatbotProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [isMinimized, setIsMinimized] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  
  // Scroll to bottom on new messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);
  
  // Add welcome message when context changes
  useEffect(() => {
    if (context && context.results && messages.length === 0) {
      const welcomeMessage: ChatMessage = {
        id: `welcome-${Date.now()}`,
        role: 'assistant',
        content: `👋 I'm your threat intelligence assistant. I've analyzed the results for **"${context.searchQuery}"** and I'm ready to answer your questions.

Try asking me:
- "What's the severity level?"
- "Tell me about the malware found"
- "Are there any APT connections?"
- "What should I do next?"`,
        timestamp: new Date().toISOString(),
      };
      setMessages([welcomeMessage]);
    }
  }, [context]);
  
  // Clear messages when context is cleared
  useEffect(() => {
    if (!context) {
      setMessages([]);
    }
  }, [context]);
  
  const handleSend = useCallback(async () => {
    if (!input.trim() || isLoading) return;
    
    const userMessage: ChatMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: input.trim(),
      timestamp: new Date().toISOString(),
    };
    
    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);
    
    // Add loading message
    const loadingId = `loading-${Date.now()}`;
    setMessages(prev => [...prev, {
      id: loadingId,
      role: 'assistant',
      content: '',
      timestamp: new Date().toISOString(),
      isLoading: true,
    }]);
    
    try {
      const response = await generateAIResponse(userMessage.content, context, messages);
      
      // Replace loading message with actual response
      setMessages(prev => prev.map(m => 
        m.id === loadingId
          ? { ...m, content: response, isLoading: false }
          : m
      ));
    } catch (error) {
      console.error('Chat error:', error);
      setMessages(prev => prev.map(m => 
        m.id === loadingId
          ? { ...m, content: 'Sorry, I encountered an error processing your request. Please try again.', isLoading: false }
          : m
      ));
      toast.error('Failed to generate response');
    } finally {
      setIsLoading(false);
    }
  }, [input, isLoading, context, messages]);
  
  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };
  
  const handleCopy = async (content: string, id: string) => {
    await navigator.clipboard.writeText(content);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
    toast.success('Copied to clipboard');
  };
  
  const handleClearChat = () => {
    setMessages([]);
    if (onClearContext) onClearContext();
    toast.success('Chat cleared');
  };
  
  // Floating button to open chat
  if (position === 'floating' && !isOpen) {
    return (
      <Button
        onClick={() => setIsOpen(true)}
        className={cn(
          'fixed bottom-6 right-6 h-14 w-14 rounded-full shadow-lg',
          'bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700',
          'z-50 transition-all hover:scale-110',
          className
        )}
      >
        <MessageSquare className="h-6 w-6" />
        {context && (
          <span className="absolute -top-1 -right-1 h-4 w-4 rounded-full bg-green-500 border-2 border-white" />
        )}
      </Button>
    );
  }
  
  // Main chat interface
  const chatContent = (
    <Card className={cn(
      'flex flex-col bg-slate-900/95 border-slate-700/50 backdrop-blur-xl',
      position === 'floating' ? 'fixed bottom-6 right-6 w-[420px] h-[600px] z-50 shadow-2xl' : 'w-full h-full',
      isMinimized && 'h-14',
      className
    )}>
      {/* Header */}
      <CardHeader className="p-3 border-b border-slate-700/50 flex-shrink-0">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-gradient-to-r from-purple-600/20 to-blue-600/20">
              <Bot className="h-5 w-5 text-purple-400" />
            </div>
            <div>
              <CardTitle className="text-sm font-semibold text-slate-200">
                Threat Intelligence Assistant
              </CardTitle>
              {context && !isMinimized && (
                <p className="text-xs text-slate-400 truncate max-w-[200px]">
                  Analyzing: {context.searchQuery}
                </p>
              )}
            </div>
          </div>
          <div className="flex items-center gap-1">
            {context && (
              <Badge variant="outline" className="text-xs bg-green-500/10 text-green-400 border-green-500/30">
                <Sparkles className="h-3 w-3 mr-1" />
                Active
              </Badge>
            )}
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              onClick={() => setIsMinimized(!isMinimized)}
            >
              {isMinimized ? <Maximize2 className="h-4 w-4" /> : <Minimize2 className="h-4 w-4" />}
            </Button>
            {position === 'floating' && (
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7"
                onClick={() => setIsOpen(false)}
              >
                <X className="h-4 w-4" />
              </Button>
            )}
          </div>
        </div>
      </CardHeader>
      
      {!isMinimized && (
        <>
          {/* Messages */}
          <ScrollArea className="flex-1 p-4">
            <div className="space-y-4">
              {messages.length === 0 && !context && (
                <div className="text-center py-8">
                  <AlertCircle className="h-12 w-12 text-slate-600 mx-auto mb-3" />
                  <p className="text-slate-400 text-sm">
                    No active search context.
                  </p>
                  <p className="text-slate-500 text-xs mt-1">
                    Run a search to enable the AI assistant.
                  </p>
                </div>
              )}
              
              {messages.map((message) => (
                <div
                  key={message.id}
                  className={cn(
                    'flex gap-3',
                    message.role === 'user' ? 'justify-end' : 'justify-start'
                  )}
                >
                  {message.role === 'assistant' && (
                    <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-gradient-to-r from-purple-600/20 to-blue-600/20 flex items-center justify-center">
                      <Bot className="h-4 w-4 text-purple-400" />
                    </div>
                  )}
                  
                  <div
                    className={cn(
                      'max-w-[80%] rounded-xl px-4 py-2.5',
                      message.role === 'user'
                        ? 'bg-blue-600 text-white'
                        : 'bg-slate-800 text-slate-200'
                    )}
                  >
                    {message.isLoading ? (
                      <div className="flex items-center gap-2">
                        <Loader2 className="h-4 w-4 animate-spin" />
                        <span className="text-sm">Analyzing...</span>
                      </div>
                    ) : (
                      <>
                        <div className="text-sm whitespace-pre-wrap prose prose-invert prose-sm max-w-none">
                          {message.content.split('\n').map((line, i) => {
                            // Handle markdown-style formatting
                            if (line.startsWith('## ')) {
                              return <h3 key={i} className="text-base font-semibold text-slate-100 mt-2 mb-1">{line.substring(3)}</h3>;
                            }
                            if (line.startsWith('### ')) {
                              return <h4 key={i} className="text-sm font-semibold text-slate-200 mt-2 mb-1">{line.substring(4)}</h4>;
                            }
                            if (line.startsWith('- ')) {
                              return <div key={i} className="ml-2 text-slate-300">{line}</div>;
                            }
                            if (line.startsWith('**') && line.includes('**:')) {
                              const [label, ...rest] = line.split(':');
                              return (
                                <div key={i}>
                                  <span className="font-semibold text-slate-200">{label.replace(/\*\*/g, '')}:</span>
                                  <span className="text-slate-300">{rest.join(':')}</span>
                                </div>
                              );
                            }
                            return <p key={i} className="text-slate-300">{line}</p>;
                          })}
                        </div>
                        {message.role === 'assistant' && !message.isLoading && (
                          <div className="flex items-center gap-2 mt-2 pt-2 border-t border-slate-700/50">
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-6 text-xs text-slate-400 hover:text-slate-200"
                              onClick={() => handleCopy(message.content, message.id)}
                            >
                              {copiedId === message.id ? (
                                <Check className="h-3 w-3 mr-1" />
                              ) : (
                                <Copy className="h-3 w-3 mr-1" />
                              )}
                              Copy
                            </Button>
                          </div>
                        )}
                      </>
                    )}
                  </div>
                  
                  {message.role === 'user' && (
                    <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center">
                      <User className="h-4 w-4 text-white" />
                    </div>
                  )}
                </div>
              ))}
              <div ref={messagesEndRef} />
            </div>
          </ScrollArea>
          
          {/* Input */}
          <div className="p-3 border-t border-slate-700/50 flex-shrink-0">
            {messages.length > 0 && (
              <div className="flex items-center justify-between mb-2">
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 text-xs text-slate-400 hover:text-red-400"
                  onClick={handleClearChat}
                >
                  <Trash2 className="h-3 w-3 mr-1" />
                  Clear chat
                </Button>
              </div>
            )}
            <div className="flex items-center gap-2">
              <Input
                ref={inputRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyPress}
                placeholder={context ? "Ask about these results..." : "Run a search first..."}
                disabled={!context || isLoading}
                className="flex-1 bg-slate-800 border-slate-700 text-slate-200 placeholder:text-slate-500"
              />
              <Button
                onClick={handleSend}
                disabled={!input.trim() || !context || isLoading}
                className="bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700"
              >
                {isLoading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Send className="h-4 w-4" />
                )}
              </Button>
            </div>
          </div>
        </>
      )}
    </Card>
  );
  
  return chatContent;
}

export default ThreatChatbot;
