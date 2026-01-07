import React, { useState } from 'react';
import { Search, TrendingUp, AlertTriangle, Shield, ExternalLink, Copy } from 'lucide-react';
import { scanCryptoAddress, getCryptoRiskColor, getCryptoRiskBgColor, type CryptoScanResult } from '../../services/cryptoScannerService';

const CryptoScanner: React.FC = () => {
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<CryptoScanResult | null>(null);
  const [error, setError] = useState('');

  const handleScan = async () => {
    if (!input.trim()) {
      setError('Please enter a cryptocurrency address');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const scanResult = await scanCryptoAddress(input.trim());
      setResult(scanResult);
      
      if (!scanResult.success && scanResult.flags.length > 0) {
        setError(scanResult.flags.join(', '));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Scan failed');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const formatBalance = (balance: number, blockchain: string) => {
    if (balance === 0) return '0';
    
    const symbols: Record<string, string> = {
      bitcoin: 'BTC',
      ethereum: 'ETH',
      litecoin: 'LTC',
      'bitcoin-cash': 'BCH',
      dogecoin: 'DOGE',
      monero: 'XMR',
    };
    
    return `${balance.toFixed(8)} ${symbols[blockchain] || blockchain.toUpperCase()}`;
  };

  const getRiskIcon = (level: string) => {
    switch (level) {
      case 'critical':
      case 'high':
        return <AlertTriangle className="w-4 h-4" />;
      case 'medium':
        return <TrendingUp className="w-4 h-4" />;
      default:
        return <Shield className="w-4 h-4" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="text-center">
        <h2 className="text-2xl font-bold text-white mb-2">Cryptocurrency Address Scanner</h2>
        <p className="text-gray-400">
          Analyze cryptocurrency addresses for risk, sanctions, and blockchain intelligence
        </p>
      </div>

      {/* Search Input */}
      <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700">
        <div className="flex gap-2">
          <div className="flex-1 relative">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Enter cryptocurrency address (Bitcoin, Ethereum, Litecoin, etc.)"
              className="w-full px-4 py-2 bg-gray-700 text-white border border-gray-600 rounded-md focus:outline-none focus:border-blue-500 font-mono text-sm"
              onKeyPress={(e) => e.key === 'Enter' && handleScan()}
            />
          </div>
          <button
            onClick={handleScan}
            disabled={loading}
            className="px-6 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 flex items-center gap-2"
          >
            {loading ? (
              <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            ) : (
              <Search className="w-4 h-4" />
            )}
            {loading ? 'Scanning...' : 'Scan'}
          </button>
        </div>
        
        {error && (
          <div className="mt-3 p-3 bg-red-500/20 border border-red-500 rounded text-red-400 text-sm">
            {error}
          </div>
        )}
      </div>

      {/* Results */}
      {result && (
        <div className="space-y-4">
          {/* Overview */}
          <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-semibold text-white">Address Overview</h3>
              <div className={`px-3 py-1 rounded-full border text-sm font-medium flex items-center gap-2 ${getCryptoRiskBgColor(result.risk)}`}>
                {getRiskIcon(result.risk)}
                <span className={getCryptoRiskColor(result.risk)}>
                  {result.risk.toUpperCase()} RISK
                </span>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-sm text-gray-400">Address</label>
                <div className="flex items-center gap-2 mt-1">
                  <code className="text-white font-mono text-sm bg-gray-700 px-2 py-1 rounded">
                    {result.address.slice(0, 20)}...{result.address.slice(-10)}
                  </code>
                  <button
                    onClick={() => copyToClipboard(result.address)}
                    className="text-gray-400 hover:text-white"
                  >
                    <Copy className="w-4 h-4" />
                  </button>
                </div>
              </div>

              <div>
                <label className="text-sm text-gray-400">Blockchain</label>
                <div className="text-white font-medium capitalize mt-1">
                  {result.blockchain.replace('-', ' ')}
                </div>
              </div>

              <div>
                <label className="text-sm text-gray-400">Balance</label>
                <div className="text-white font-medium mt-1">
                  {formatBalance(result.balance, result.blockchain)}
                </div>
              </div>

              <div>
                <label className="text-sm text-gray-400">Transactions</label>
                <div className="text-white font-medium mt-1">
                  {result.transactions.toLocaleString()}
                </div>
              </div>

              <div>
                <label className="text-sm text-gray-400">Risk Score</label>
                <div className="flex items-center gap-2 mt-1">
                  <div className="flex-1 bg-gray-700 rounded-full h-2">
                    <div
                      className={`h-2 rounded-full ${result.riskScore >= 80 ? 'bg-red-500' : 
                        result.riskScore >= 60 ? 'bg-orange-500' : 
                        result.riskScore >= 40 ? 'bg-yellow-500' : 
                        result.riskScore >= 20 ? 'bg-blue-500' : 'bg-green-500'}`}
                      style={{ width: `${result.riskScore}%` }}
                    />
                  </div>
                  <span className="text-white text-sm font-medium">{result.riskScore}/100</span>
                </div>
              </div>

              <div>
                <label className="text-sm text-gray-400">Last Updated</label>
                <div className="text-white text-sm mt-1">
                  {new Date(result.timestamp).toLocaleString()}
                </div>
              </div>
            </div>
          </div>

          {/* Risk Flags */}
          {result.flags.length > 0 && (
            <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700">
              <h3 className="text-lg font-semibold text-white mb-3 flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-orange-500" />
                Risk Flags
              </h3>
              <div className="space-y-2">
                {result.flags.map((flag, index) => (
                  <div key={index} className="flex items-center gap-2 text-orange-400 text-sm">
                    <div className="w-1 h-1 bg-orange-400 rounded-full" />
                    {flag}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Tags */}
          {result.tags.length > 0 && (
            <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700">
              <h3 className="text-lg font-semibold text-white mb-3">Tags</h3>
              <div className="flex flex-wrap gap-2">
                {result.tags.map((tag, index) => (
                  <span
                    key={index}
                    className="px-2 py-1 bg-blue-600/20 border border-blue-600 text-blue-400 text-xs rounded-md"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Exchange Info */}
          {result.exchangeInfo && (
            <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700">
              <h3 className="text-lg font-semibold text-white mb-3">Exchange Information</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-sm text-gray-400">Exchange Name</label>
                  <div className="text-white font-medium mt-1">{result.exchangeInfo.name}</div>
                </div>
                <div>
                  <label className="text-sm text-gray-400">Status</label>
                  <div className="text-green-400 font-medium mt-1">
                    {result.exchangeInfo.isKnown ? 'Known Exchange' : 'Unknown'}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Activity Timeline */}
          {(result.firstSeen || result.lastSeen) && (
            <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700">
              <h3 className="text-lg font-semibold text-white mb-3">Activity Timeline</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {result.firstSeen && (
                  <div>
                    <label className="text-sm text-gray-400">First Seen</label>
                    <div className="text-white font-medium mt-1">
                      {new Date(result.firstSeen).toLocaleDateString()}
                    </div>
                  </div>
                )}
                {result.lastSeen && (
                  <div>
                    <label className="text-sm text-gray-400">Last Seen</label>
                    <div className="text-white font-medium mt-1">
                      {new Date(result.lastSeen).toLocaleDateString()}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Sources */}
          <div className="bg-gray-800/50 rounded-lg p-6 border border-gray-700">
            <h3 className="text-lg font-semibold text-white mb-3">Data Sources</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {Object.entries(result.sources).map(([source, data]) => (
                <div key={source} className="bg-gray-700/50 rounded p-3">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-white capitalize">
                      {source.replace(/([A-Z])/g, ' $1').trim()}
                    </span>
                    <div className={`w-2 h-2 rounded-full ${
                      data.found !== false && !data.error ? 'bg-green-500' : 'bg-red-500'
                    }`} />
                  </div>
                  <div className="text-xs text-gray-400">
                    {data.error ? `Error: ${data.error}` : 
                     data.found === false ? 'No data found' : 'Data available'}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Info Panel */}
      <div className="bg-blue-900/20 border border-blue-500 rounded-lg p-4">
        <h3 className="text-lg font-semibold text-blue-400 mb-2">Supported Cryptocurrencies</h3>
        <p className="text-gray-300 text-sm mb-3">
          This scanner supports Bitcoin (BTC), Ethereum (ETH), Litecoin (LTC), Bitcoin Cash (BCH), 
          Dogecoin (DOGE), and Monero (XMR) addresses.
        </p>
        <div className="text-xs text-gray-400">
          <strong>Data Sources:</strong> BlockCypher, Blockchain.info, Etherscan, Crystal Blockchain, 
          OFAC Sanctions List, and Known Exchange databases.
        </div>
      </div>
    </div>
  );
};

export default CryptoScanner;
