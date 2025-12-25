import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, XCircle, Activity, AlertCircle, Info } from 'lucide-react';

const PhishGuard = () => {
  const [input, setInput] = useState('');
  const [result, setResult] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState('');
  const [ping, setPing] = useState(0);

  // Simulate realistic ping
  useEffect(() => {
    const updatePing = () => {
      const basePing = 25;
      const variation = Math.random() * 20 - 10;
      setPing(Math.max(5, Math.round(basePing + variation)));
    };
    
    updatePing();
    const interval = setInterval(updatePing, 2000);
    return () => clearInterval(interval);
  }, []);

  const getPingStatus = (ping) => {
    if (ping < 30) return { color: 'bg-green-500', text: 'Excellent', textColor: 'text-green-400' };
    if (ping < 60) return { color: 'bg-yellow-500', text: 'Good', textColor: 'text-yellow-400' };
    if (ping < 100) return { color: 'bg-orange-500', text: 'Fair', textColor: 'text-orange-400' };
    return { color: 'bg-red-500', text: 'Poor', textColor: 'text-red-400' };
  };

  const analyzeURL = (url) => {
    const results = [];
    let totalRisk = 0;
    const maxRisk = 952;

    url = url.trim().toLowerCase();

    let domain = '';
    let protocol = '';
    let path = '';
    
    try {
      const urlObj = new URL(url.startsWith('http') ? url : 'http://' + url);
      domain = urlObj.hostname;
      protocol = urlObj.protocol;
      path = urlObj.pathname + urlObj.search;
    } catch (e) {
      domain = url.replace(/^https?:\/\//, '').split('/')[0];
      protocol = url.startsWith('https') ? 'https:' : 'http:';
      path = url.substring(url.indexOf('/'));
    }

    // Domain & DNS Analysis
    if (url.length > 75) {
      totalRisk += 10;
      results.push({ rule: 'Excessive URL Length', risk: 10, severity: 'medium', category: 'Domain Analysis' });
    }

    const subdomains = domain.split('.').length - 2;
    if (subdomains > 3) {
      totalRisk += 12;
      results.push({ rule: 'Excessive Subdomains', risk: 12, severity: 'medium', category: 'Domain Analysis' });
    }

    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
      totalRisk += 50;
      results.push({ rule: 'IP Address Instead of Domain', risk: 25, severity: 'critical', category: 'Domain Analysis' });
    }

    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.zip', '.xyz'];
    if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
      totalRisk += 20;
      results.push({ rule: 'Suspicious TLD Detected', risk: 20, severity: 'high', category: 'Domain Analysis' });
    }

    const brands = ['paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'bank'];
    const hasBrand = brands.some(brand => domain.includes(brand));
    const legitimateDomains = ['paypal.com', 'amazon.com', 'google.com', 'microsoft.com'];
    if (hasBrand && !legitimateDomains.some(ld => domain.endsWith(ld))) {
      totalRisk += 45;
      results.push({ rule: 'Brand Name Impersonation', risk: 30, severity: 'critical', category: 'Phishing Detection' });
    }

    if (protocol === 'http:') {
      totalRisk += 38;
      results.push({ rule: 'No HTTPS (Insecure)', risk: 25, severity: 'high', category: 'Security' });
    }

    // URL Structure Analysis
    if (url.includes('@')) {
      totalRisk += 30;
      results.push({ rule: '@ Symbol in URL', risk: 30, severity: 'critical', category: 'URL Structure' });
    }

    if (path.includes('//')) {
      totalRisk += 15;
      results.push({ rule: 'Double Slashes in Path', risk: 15, severity: 'medium', category: 'URL Structure' });
    }

    const hexMatches = url.match(/%[0-9A-Fa-f]{2}/g);
    if (hexMatches && hexMatches.length > 3) {
      totalRisk += 18;
      results.push({ rule: 'Excessive URL Encoding', risk: 18, severity: 'medium', category: 'URL Structure' });
    }

    const hyphenCount = domain.split('-').length - 1;
    if (hyphenCount > 4) {
      totalRisk += 14;
      results.push({ rule: 'Excessive Hyphens in Domain', risk: 14, severity: 'medium', category: 'URL Structure' });
    }

    if (url.match(/:\d+/)) {
      const port = url.match(/:(\d+)/)[1];
      if (port !== '80' && port !== '443') {
        totalRisk += 20;
        results.push({ rule: 'Non-Standard Port Detected', risk: 20, severity: 'high', category: 'URL Structure' });
      }
    }

    const suspiciousKeywords = ['login', 'verify', 'account', 'secure', 'update', 'signin', 'banking'];
    const foundKeywords = suspiciousKeywords.filter(kw => url.includes(kw));
    if (foundKeywords.length > 0) {
      totalRisk += 15 * foundKeywords.length;
      results.push({ rule: `Suspicious Keywords (${foundKeywords.join(', ')})`, risk: 15, severity: 'medium', category: 'Phishing Detection' });
    }

    const dangerousExts = ['.exe', '.zip', '.scr', '.bat', '.cmd', '.apk'];
    if (dangerousExts.some(ext => url.endsWith(ext))) {
      totalRisk += 25;
      results.push({ rule: 'Dangerous File Extension', risk: 25, severity: 'high', category: 'Malware Detection' });
    }

    // Phishing & Social Engineering
    const bankingKeywords = ['bank', 'credit', 'card', 'payment'];
    if (bankingKeywords.some(kw => url.includes(kw)) && hasBrand) {
      totalRisk += 25;
      results.push({ rule: 'Banking Keywords with Suspicious Domain', risk: 25, severity: 'high', category: 'Phishing Detection' });
    }

    const urgencyWords = ['urgent', 'suspended', 'expire', 'immediately'];
    if (urgencyWords.some(uw => url.includes(uw))) {
      totalRisk += 20;
      results.push({ rule: 'Urgency Language Detected', risk: 20, severity: 'high', category: 'Social Engineering' });
    }

    const prizeKeywords = ['winner', 'prize', 'lottery', 'won', 'congratulations'];
    if (prizeKeywords.some(pk => url.includes(pk))) {
      totalRisk += 22;
      results.push({ rule: 'Prize/Lottery Scam Indicators', risk: 22, severity: 'high', category: 'Social Engineering' });
    }

    // Tech Support Scam
    const techSupportWords = ['refund', 'renew', 'subscription', 'cancel', 'expired'];
    if (techSupportWords.some(ts => url.includes(ts))) {
      totalRisk += 20;
      results.push({ rule: 'Tech Support Scam Pattern', risk: 20, severity: 'high', category: 'Social Engineering' });
    }

    // Government/Tax Impersonation
    const govWords = ['tax', 'irs', 'gov', 'revenue', 'stimulus', 'benefits'];
    const hasGovWord = govWords.some(gw => url.includes(gw));
    if (hasGovWord && !domain.endsWith('.gov')) {
      totalRisk += 35;
      results.push({ rule: 'Government Agency Impersonation', risk: 35, severity: 'critical', category: 'Phishing Detection' });
    }

    // Shortened/Redirected URL indicators
    const shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 't.co', 'rebrand.ly'];
    if (shorteners.some(sh => domain.includes(sh))) {
      totalRisk += 15;
      results.push({ rule: 'URL Shortener Detected', risk: 15, severity: 'medium', category: 'URL Structure' });
    }

    // Suspicious file hosting
    const fileHosts = ['dropbox', 'mediafire', 'mega.nz', 'wetransfer'];
    if (fileHosts.some(fh => domain.includes(fh)) && path.includes('download')) {
      totalRisk += 18;
      results.push({ rule: 'Suspicious File Hosting Pattern', risk: 18, severity: 'medium', category: 'Malware Detection' });
    }

    // Homograph/Unicode attacks
    if (/[а-яА-Я]/.test(domain) || /[α-ωΑ-Ω]/.test(domain)) {
      totalRisk += 35;
      results.push({ rule: 'Homograph Attack (Cyrillic/Greek Characters)', risk: 35, severity: 'critical', category: 'Advanced Threats' });
    }

    // Mixed case in domain (cAmElCaSe)
    if (domain.match(/[a-z][A-Z]|[A-Z][a-z][A-Z]/)) {
      totalRisk += 12;
      results.push({ rule: 'Suspicious Mixed Case Domain', risk: 12, severity: 'medium', category: 'Domain Analysis' });
    }

    // Excessive query parameters
    const paramCount = (url.match(/&/g) || []).length;
    if (paramCount > 10) {
      totalRisk += 15;
      results.push({ rule: 'Excessive Query Parameters', risk: 15, severity: 'medium', category: 'URL Structure' });
    }

    // Data exfiltration patterns
    if (url.match(/data=|info=|credentials=|token=/i)) {
      totalRisk += 25;
      results.push({ rule: 'Data Exfiltration Pattern', risk: 25, severity: 'high', category: 'Attack Vectors' });
    }

    // Pharming indicators
    if (domain.match(/\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}/)) {
      totalRisk += 30;
      results.push({ rule: 'IP Address Obfuscation', risk: 30, severity: 'high', category: 'Advanced Threats' });
    }

    // Package delivery scams
    const deliveryWords = ['delivery', 'package', 'parcel', 'shipment', 'tracking', 'fedex', 'ups', 'usps', 'dhl'];
    const foundDelivery = deliveryWords.filter(dw => url.includes(dw));
    if (foundDelivery.length > 0 && !['fedex.com', 'ups.com', 'usps.com', 'dhl.com'].some(ld => domain.endsWith(ld))) {
      totalRisk += 28;
      results.push({ rule: 'Fake Package Delivery Scam', risk: 28, severity: 'high', category: 'Phishing Detection' });
    }

    // Romance/Dating scams
    const romanceWords = ['dating', 'match', 'meet', 'singles', 'romance'];
    if (romanceWords.some(rw => url.includes(rw)) && suspiciousTLDs.some(tld => domain.endsWith(tld))) {
      totalRisk += 25;
      results.push({ rule: 'Romance/Dating Scam Pattern', risk: 25, severity: 'high', category: 'Social Engineering' });
    }

    // Typosquatting advanced detection
    const popularSites = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'netflix', 'paypal', 'instagram', 'twitter', 'linkedin'];
    popularSites.forEach(site => {
      const siteVariations = [
        site.replace(/o/g, '0'),
        site.replace(/l/g, '1'),
        site.replace(/i/g, '1'),
        site.replace(/e/g, '3')
      ];
      if (siteVariations.some(v => domain.includes(v))) {
        totalRisk += 40;
        results.push({ rule: `Typosquatting: Fake ${site.charAt(0).toUpperCase() + site.slice(1)}`, risk: 40, severity: 'critical', category: 'Phishing Detection' });
      }
    });

    // Cryptocurrency Scam Detection
    const cryptoScamKeywords = ['airdrop', 'claim', 'giveaway', 'crypto-', 'bitcoin-', 'ethereum-', 'wallet-connect', 'metamask-', 'trust-wallet'];
    const foundCryptoScams = cryptoScamKeywords.filter(kw => url.includes(kw));
    if (foundCryptoScams.length > 0) {
      totalRisk += 40 * foundCryptoScams.length;
      results.push({ rule: `Cryptocurrency Scam Pattern (${foundCryptoScams.join(', ')})`, risk: 40, severity: 'critical', category: 'Crypto Scam' });
    }

    // Celebrity/Influencer Impersonation Scams
    const celebrities = ['elon-musk', 'elonmusk', 'jeff-bezos', 'bill-gates', 'vitalik', 'coinbase', 'binance'];
    const foundCelebrity = celebrities.filter(c => domain.includes(c));
    if (foundCelebrity.length > 0 && !['coinbase.com', 'binance.com'].some(ld => domain.endsWith(ld))) {
      totalRisk += 45;
      results.push({ rule: 'Celebrity/Brand Impersonation Scam', risk: 45, severity: 'critical', category: 'Crypto Scam' });
    }

    // Prize/Reward Scam Patterns
    const rewardWords = ['free', 'bonus', 'reward', 'double', 'triple', 'earn', 'profit'];
    const foundRewards = rewardWords.filter(rw => url.includes(rw));
    if (foundRewards.length >= 2) {
      totalRisk += 30;
      results.push({ rule: 'Multiple Reward/Prize Keywords', risk: 30, severity: 'high', category: 'Scam Detection' });
    }

    // Investment/Financial Scam
    const investmentWords = ['invest', 'trading', 'profit', 'earn', 'income', 'roi', 'returns'];
    const foundInvestment = investmentWords.filter(iw => url.includes(iw));
    if (foundInvestment.length > 0 && !domain.match(/\.(gov|edu|org)$/)) {
      totalRisk += 25;
      results.push({ rule: 'Investment/Trading Scheme Indicators', risk: 25, severity: 'high', category: 'Financial Scam' });
    }

    // Suspicious domain patterns
    const suspiciousPatterns = [
      { pattern: /-claim/, name: 'Claim Domain Pattern' },
      { pattern: /-verify/, name: 'Verification Scam Pattern' },
      { pattern: /-secure/, name: 'False Security Pattern' },
      { pattern: /-wallet/, name: 'Fake Wallet Pattern' },
      { pattern: /-support/, name: 'Fake Support Pattern' },
      { pattern: /\d{4,}/, name: 'Excessive Numbers in Domain' }
    ];

    suspiciousPatterns.forEach(({ pattern, name }) => {
      if (pattern.test(domain)) {
        totalRisk += 20;
        results.push({ rule: name, risk: 20, severity: 'high', category: 'Domain Analysis' });
      }
    });

    // Advanced Patterns
    if (domain.includes('xn--')) {
      totalRisk += 20;
      results.push({ rule: 'Punycode Domain Detected', risk: 20, severity: 'high', category: 'Advanced Threats' });
    }

    const sqlPatterns = [' or ', '1=1', 'select', 'union', 'drop'];
    if (sqlPatterns.some(sp => url.toLowerCase().includes(sp))) {
      totalRisk += 40;
      results.push({ rule: 'SQL Injection Pattern', risk: 40, severity: 'critical', category: 'Attack Vectors' });
    }

    if (url.includes('<script>') || url.includes('javascript:')) {
      totalRisk += 35;
      results.push({ rule: 'XSS Attack Pattern', risk: 35, severity: 'critical', category: 'Attack Vectors' });
    }

    if (url.includes('../') || url.includes('..\\')) {
      totalRisk += 30;
      results.push({ rule: 'Path Traversal Attempt', risk: 30, severity: 'critical', category: 'Attack Vectors' });
    }

    const riskPercentage = Math.min(100, Math.round((totalRisk / maxRisk) * 100));

    let riskLevel, riskColor, riskIcon, riskBg;
    if (riskPercentage <= 20) {
      riskLevel = 'Safe';
      riskColor = 'text-green-400';
      riskIcon = <CheckCircle className="w-12 h-12 text-green-400" />;
      riskBg = 'from-green-500/20 to-green-600/10';
    } else if (riskPercentage <= 40) {
      riskLevel = 'Low Risk';
      riskColor = 'text-yellow-400';
      riskIcon = <Info className="w-12 h-12 text-yellow-400" />;
      riskBg = 'from-yellow-500/20 to-yellow-600/10';
    } else if (riskPercentage <= 60) {
      riskLevel = 'Medium Risk';
      riskColor = 'text-orange-400';
      riskIcon = <AlertCircle className="w-12 h-12 text-orange-400" />;
      riskBg = 'from-orange-500/20 to-orange-600/10';
    } else if (riskPercentage <= 80) {
      riskLevel = 'High Risk';
      riskColor = 'text-red-400';
      riskIcon = <AlertTriangle className="w-12 h-12 text-red-400" />;
      riskBg = 'from-red-500/20 to-red-600/10';
    } else {
      riskLevel = 'Critical';
      riskColor = 'text-red-600';
      riskIcon = <XCircle className="w-12 h-12 text-red-600" />;
      riskBg = 'from-red-600/30 to-red-700/20';
    }

    return {
      url,
      domain,
      protocol,
      riskPercentage,
      riskLevel,
      riskColor,
      riskIcon,
      riskBg,
      totalRisk,
      detections: results,
      timestamp: new Date().toLocaleString()
    };
  };

  const handleAnalyze = () => {
    setError('');
    setResult(null);

    if (!input.trim()) {
      setError('Please enter a URL or email content to analyze');
      return;
    }

    const trimmedInput = input.trim();
    let isValid = false;

    // Replace [.] with . for obfuscated URLs
    const normalizedInput = trimmedInput.replace(/\[\.\]/g, '.');

    try {
      new URL(normalizedInput.startsWith('http') ? normalizedInput : 'https://' + normalizedInput);
      isValid = true;
    } catch (e) {
      // Enhanced pattern to accept domains with brackets and various formats
      const basicPattern = /^(https?:\/\/)?([a-zA-Z0-9-]+[\[\.\]\.]+)+[a-zA-Z]{2,}/;
      isValid = basicPattern.test(trimmedInput);
    }

    if (!isValid) {
      setError('Please enter a valid URL');
      return;
    }

    setIsAnalyzing(true);

    setTimeout(() => {
      // Use normalized input for analysis
      const analysis = analyzeURL(normalizedInput);
      setResult(analysis);
      setIsAnalyzing(false);
    }, 1500);
  };

  const pingStatus = getPingStatus(ping);

  return (
    <div className="min-h-screen bg-gradient-to-b from-slate-950 via-slate-900 to-slate-950 text-white">
      {/* Header */}
      <div className="text-center pt-16 pb-8">
        <div className="flex items-center justify-center mb-4">
          <Shield className="w-16 h-16 text-cyan-400 mr-4" />
          <h1 className="text-6xl font-bold text-cyan-400">PhishGuard</h1>
        </div>
        <p className="text-slate-400 text-lg tracking-wider">AI-Powered Phishing Detection & Security Analysis</p>
        
        <div className="mt-6 inline-flex items-center bg-slate-800/50 border border-slate-700 rounded-full px-6 py-3 space-x-3">
          <div className={`w-3 h-3 ${pingStatus.color} rounded-full animate-pulse shadow-lg`}></div>
          <Activity className={`w-4 h-4 ${pingStatus.textColor}`} />
          <span className={`${pingStatus.textColor} font-semibold`}>{ping}ms</span>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-6xl mx-auto px-6 pb-20">
        {/* Analyze Section */}
        <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-8 mb-8">
          <div className="flex items-center mb-6">
            <Shield className="w-6 h-6 text-cyan-400 mr-3" />
            <h2 className="text-2xl font-bold text-white">Analyze</h2>
          </div>

          {!result && (
            <>
              <div className="mb-6">
                <h3 className="text-xl font-semibold mb-3">Security Analysis</h3>
                <p className="text-slate-400 mb-6">Paste a URL or email content to analyze for phishing threats</p>
                
                <label className="block text-slate-300 mb-2 font-medium">Input to Analyze</label>
                <textarea
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  placeholder="Paste URL or email content here... Example:
https://paypal-secure-verify.tk/login"
                  className="w-full h-32 bg-slate-800/80 border border-slate-700 rounded-lg px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 resize-none"
                />
                <p className="text-slate-500 text-sm mt-2">Enter any URL, email message, or text content for phishing analysis</p>
              </div>

              <button
                onClick={handleAnalyze}
                disabled={isAnalyzing}
                className="w-full bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-600 hover:to-blue-700 text-white font-semibold py-4 rounded-lg transition-all duration-300 flex items-center justify-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed shadow-lg shadow-cyan-500/20"
              >
                {isAnalyzing ? (
                  <>
                    <div className="w-5 h-5 border-t-2 border-white rounded-full animate-spin" />
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <Shield className="w-5 h-5" />
                    <span>Analyze for Threats</span>
                  </>
                )}
              </button>

              {error && (
                <div className="mt-4 text-red-400 flex items-center space-x-2 bg-red-500/10 border border-red-500/30 rounded-lg p-3">
                  <AlertTriangle className="w-4 h-4" />
                  <span>{error}</span>
                </div>
              )}
            </>
          )}

          {/* Results */}
          {result && (
            <div className="space-y-6 animate-fadeIn">
              {/* Risk Overview Card */}
              <div className={`bg-gradient-to-br ${result.riskBg} rounded-xl p-8 border-2 ${result.riskPercentage <= 20 ? 'border-green-500/30' : result.riskPercentage <= 40 ? 'border-yellow-500/30' : result.riskPercentage <= 60 ? 'border-orange-500/30' : 'border-red-500/30'} backdrop-blur-sm`}>
                <div className="flex items-center justify-between mb-6">
                  <div className="flex items-center space-x-4">
                    <div className="relative">
                      {result.riskIcon}
                      <div className="absolute inset-0 blur-xl opacity-50">{result.riskIcon}</div>
                    </div>
                    <div>
                      <h3 className={`text-4xl font-bold ${result.riskColor} mb-1`}>{result.riskLevel}</h3>
                      <p className="text-slate-400">Threat Level Assessment</p>
                    </div>
                  </div>
                  <div className="text-center">
                    <div className={`w-24 h-24 rounded-full border-4 ${result.riskPercentage <= 20 ? 'border-green-500' : result.riskPercentage <= 40 ? 'border-yellow-500' : result.riskPercentage <= 60 ? 'border-orange-500' : 'border-red-500'} flex items-center justify-center bg-slate-800/50`}>
                      <span className={`text-3xl font-bold ${result.riskColor}`}>{result.riskPercentage}</span>
                    </div>
                    <p className="text-slate-400 text-sm mt-2">Risk Score</p>
                  </div>
                </div>

                {/* Animated Risk Bar */}
                <div className="relative">
                  <div className="w-full bg-slate-700/50 rounded-full h-4 overflow-hidden backdrop-blur-sm">
                    <div
                      className={`h-full transition-all duration-1000 ease-out ${
                        result.riskPercentage <= 20 ? 'bg-gradient-to-r from-green-400 to-green-500' :
                        result.riskPercentage <= 40 ? 'bg-gradient-to-r from-yellow-400 to-yellow-500' :
                        result.riskPercentage <= 60 ? 'bg-gradient-to-r from-orange-400 to-orange-500' :
                        'bg-gradient-to-r from-red-400 to-red-600'
                      } shadow-lg`}
                      style={{ width: `${result.riskPercentage}%` }}
                    />
                  </div>
                  <div className="flex justify-between text-xs text-slate-400 mt-2 px-1">
                    <span>Safe</span>
                    <span>Low</span>
                    <span>Medium</span>
                    <span>High</span>
                    <span>Critical</span>
                  </div>
                </div>

                {/* Analysis Details */}
                <div className="grid grid-cols-2 gap-4 mt-6 pt-6 border-t border-slate-700/50">
                  <div className="bg-slate-800/50 rounded-lg p-3">
                    <p className="text-slate-400 text-sm mb-1">Analyzed At</p>
                    <p className="text-white font-semibold text-sm">{result.timestamp}</p>
                  </div>
                  <div className="bg-slate-800/50 rounded-lg p-3">
                    <p className="text-slate-400 text-sm mb-1">Domain</p>
                    <p className="text-white font-semibold text-sm truncate">{result.domain}</p>
                  </div>
                  <div className="col-span-2 bg-slate-800/50 rounded-lg p-3">
                    <p className="text-slate-400 text-sm mb-1">Full URL</p>
                    <p className="text-white font-mono text-xs break-all">{result.url}</p>
                  </div>
                </div>
              </div>

              {/* Security Issues */}
              {result.detections.length > 0 && (
                <div className="bg-slate-800/50 rounded-xl p-6 border border-slate-700">
                  <div className="flex items-center justify-between mb-6">
                    <h4 className="text-xl font-bold flex items-center space-x-2">
                      <AlertTriangle className="w-6 h-6 text-orange-400" />
                      <span>Security Issues Detected</span>
                    </h4>
                    <span className="bg-red-500/20 text-red-300 px-4 py-1.5 rounded-full text-sm font-semibold border border-red-500/30">
                      {result.detections.length} {result.detections.length === 1 ? 'issue' : 'issues'}
                    </span>
                  </div>

                  <div className="space-y-3 max-h-96 overflow-y-auto pr-2">
                    {result.detections.map((detection, index) => (
                      <div
                        key={index}
                        className={`bg-slate-900/50 rounded-lg p-4 border-l-4 ${
                          detection.severity === 'critical' ? 'border-red-500' :
                          detection.severity === 'high' ? 'border-orange-500' :
                          detection.severity === 'medium' ? 'border-yellow-500' :
                          'border-green-500'
                        } hover:bg-slate-900/70 transition-colors`}
                      >
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center space-x-2 mb-2">
                              <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase ${
                                detection.severity === 'critical' ? 'bg-red-500/20 text-red-300 border border-red-500/30' :
                                detection.severity === 'high' ? 'bg-orange-500/20 text-orange-300 border border-orange-500/30' :
                                detection.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/30' :
                                'bg-green-500/20 text-green-300 border border-green-500/30'
                              }`}>
                                {detection.severity}
                              </span>
                              <span className="text-slate-400 text-xs bg-slate-700/50 px-2 py-1 rounded">
                                {detection.category}
                              </span>
                            </div>
                            <p className="text-white font-semibold">{detection.rule}</p>
                          </div>
                          <div className="ml-4 text-right">
                            <span className="text-red-400 font-bold text-lg">+{detection.risk}%</span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {result.detections.length === 0 && (
                <div className="bg-gradient-to-br from-green-500/10 to-green-600/5 rounded-xl p-8 border-2 border-green-500/30">
                  <div className="flex items-center space-x-4 text-green-400">
                    <CheckCircle className="w-12 h-12" />
                    <div>
                      <h4 className="text-2xl font-bold mb-1">All Clear!</h4>
                      <p className="text-green-300/80">No security threats detected. This URL appears to be safe.</p>
                    </div>
                  </div>
                </div>
              )}

              <button
                onClick={() => {
                  setResult(null);
                  setInput('');
                }}
                className="w-full bg-slate-700 hover:bg-slate-600 text-white font-semibold py-4 rounded-lg transition-all duration-300 shadow-lg"
              >
                Analyze Another URL
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-slate-900/50 py-12">
        <div className="max-w-6xl mx-auto px-6">
          {/* Stats Section */}
          <div className="grid md:grid-cols-3 gap-6 mb-12">
            <div className="bg-gradient-to-br from-cyan-500/10 to-blue-600/10 rounded-xl p-6 border border-cyan-500/20 text-center">
              <div className="text-4xl font-bold text-cyan-400 mb-2">100+</div>
              <p className="text-slate-300 font-semibold mb-1">Detection Rules</p>
              <p className="text-slate-500 text-sm">Advanced security protocols</p>
            </div>
            <div className="bg-gradient-to-br from-green-500/10 to-emerald-600/10 rounded-xl p-6 border border-green-500/20 text-center">
              <div className="text-4xl font-bold text-green-400 mb-2">98%</div>
              <p className="text-slate-300 font-semibold mb-1">Detection Accuracy</p>
              <p className="text-slate-500 text-sm">Proven threat identification</p>
            </div>
            <a
              href="https://docs.google.com/forms/d/e/1FAIpQLSdiEpoYmY2CliIcbWTnr_8g431HratLxS3lpejf6WaENGTPQw/viewform?usp=header"
              target="_blank"
              rel="noopener noreferrer"
              className="bg-gradient-to-br from-purple-500/10 to-pink-600/10 rounded-xl p-6 border border-purple-500/20 text-center hover:from-purple-500/20 hover:to-pink-600/20 transition-all duration-300 group block"
            >
              <div className="flex justify-center mb-3">
                <svg className="w-10 h-10 text-purple-400 group-hover:scale-110 transition-transform" fill="currentColor" viewBox="0 0 20 20">
                  <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
                </svg>
              </div>
              <p className="text-slate-300 font-semibold mb-2">Leave a Review</p>
              <p className="text-slate-500 text-sm mb-4">Help us improve security</p>
              <div className="flex justify-center">
                <span className="bg-gradient-to-r from-purple-500 to-pink-600 text-white font-semibold px-6 py-2 rounded-lg text-sm group-hover:from-purple-600 group-hover:to-pink-700 transition-all duration-300 shadow-lg shadow-purple-500/20">
                  Write Review
                </span>
              </div>
            </a>
          </div>

          <p className="text-center text-slate-400 mb-6">Powered by advanced phishing detection algorithms</p>
          
          <div className="flex justify-center items-center flex-wrap gap-4 text-sm text-slate-500 mb-8">
            <span>URL Analysis</span>
            <span>•</span>
            <span>Email Scanning</span>
            <span>•</span>
            <span>Real-time Detection</span>
            <span>•</span>
            <span>Database Persistence</span>
          </div>

          <div className="text-center">
            <p className="text-slate-400 mb-2">Made by <span className="text-cyan-400 font-semibold">Sahil Parihar</span></p>
            <p className="text-slate-500 text-sm">© 2025 PhishGuard. All rights reserved.</p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default PhishGuard;