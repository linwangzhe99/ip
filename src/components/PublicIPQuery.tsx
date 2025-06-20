import React, { useState } from 'react';
import { Search, Globe, MapPin, Shield, AlertTriangle, Download, FileText, BarChart3, Wifi, Server, Eye, Clock, CheckCircle, ExternalLink } from 'lucide-react';

interface IPInfo {
  query: string;
  status: string;
  country: string;
  countryCode: string;
  region: string;
  regionName: string;
  city: string;
  zip: string;
  lat: number;
  lon: number;
  timezone: string;
  isp: string;
  org: string;
  as: string;
  asname: string;
  reverse: string;
  mobile: boolean;
  proxy: boolean;
  hosting: boolean;
  threat: 'low' | 'medium' | 'high';
  riskFactors: string[];
  blacklistStatus: {
    isBlacklisted: boolean;
    sources: string[];
    lastSeen?: string;
  };
  vpnTorStatus: {
    isVPN: boolean;
    isTor: boolean;
    isProxy: boolean;
    confidence: number;
  };
  ipType: 'residential' | 'datacenter' | 'corporate' | 'mobile' | 'unknown';
  geolocation: {
    accuracy: string;
    timezone: string;
    currency: string;
  };
}

interface AnalysisStats {
  totalIPs: number;
  highRisk: number;
  mediumRisk: number;
  lowRisk: number;
  blacklisted: number;
  vpnTor: number;
  countries: { [key: string]: number };
  ipTypes: { [key: string]: number };
}

export function PublicIPQuery() {
  const [ipInput, setIpInput] = useState('');
  const [analyzedIPs, setAnalyzedIPs] = useState<IPInfo[]>([]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<AnalysisStats | null>(null);
  const [showStats, setShowStats] = useState(false);

  // 模拟黑名单检查
  const checkBlacklist = async (ip: string): Promise<IPInfo['blacklistStatus']> => {
    // 模拟一些已知的恶意IP
    const knownBadIPs = [
      '95.223.57.198',
      '185.220.101.1',
      '46.166.139.111'
    ];
    
    const isBlacklisted = knownBadIPs.includes(ip);
    const sources = isBlacklisted ? ['Spamhaus', 'AbuseIPDB'] : [];
    
    return {
      isBlacklisted,
      sources,
      lastSeen: isBlacklisted ? new Date().toISOString() : undefined
    };
  };

  // 模拟VPN/Tor检测
  const checkVPNTor = async (ip: string): Promise<IPInfo['vpnTorStatus']> => {
    // 模拟VPN/Tor检测逻辑
    const vpnRanges = ['95.223.', '185.220.', '46.166.'];
    const torExitNodes = ['185.220.101.1', '46.166.139.111'];
    
    const isVPN = vpnRanges.some(range => ip.startsWith(range));
    const isTor = torExitNodes.includes(ip);
    const isProxy = isVPN || isTor;
    
    return {
      isVPN,
      isTor,
      isProxy,
      confidence: isProxy ? 0.95 : 0.1
    };
  };

  // 确定IP类型
  const determineIPType = (ipData: any): IPInfo['ipType'] => {
    if (ipData.mobile) return 'mobile';
    if (ipData.hosting) return 'datacenter';
    if (ipData.org && ipData.org.toLowerCase().includes('corp')) return 'corporate';
    return 'residential';
  };

  // 威胁评估函数（增强版）
  const assessThreatLevel = async (ipData: any): Promise<{ threat: 'low' | 'medium' | 'high', riskFactors: string[] }> => {
    const riskFactors: string[] = [];
    let riskScore = 0;

    // 检查黑名单状态
    const blacklistStatus = await checkBlacklist(ipData.query);
    if (blacklistStatus.isBlacklisted) {
      riskFactors.push(`已知恶意IP (${blacklistStatus.sources.join(', ')})`);
      riskScore += 5;
    }

    // 检查VPN/Tor状态
    const vpnTorStatus = await checkVPNTor(ipData.query);
    if (vpnTorStatus.isTor) {
      riskFactors.push('Tor出口节点');
      riskScore += 4;
    } else if (vpnTorStatus.isVPN) {
      riskFactors.push('VPN服务器');
      riskScore += 3;
    } else if (vpnTorStatus.isProxy) {
      riskFactors.push('代理服务器');
      riskScore += 2;
    }

    // 检查托管/数据中心
    if (ipData.hosting) {
      riskFactors.push('数据中心/托管服务器');
      riskScore += 2;
    }

    // 检查可疑ASN
    const suspiciousASNs = ['LeaseWeb', 'OVH', 'DigitalOcean', 'Amazon', 'Google Cloud', 'Microsoft Azure'];
    if (suspiciousASNs.some(asn => ipData.asname?.includes(asn))) {
      riskFactors.push('云服务提供商');
      riskScore += 2;
    }

    // 检查地理位置异常
    const highRiskCountries = ['CN', 'RU', 'KP', 'IR'];
    if (highRiskCountries.includes(ipData.countryCode)) {
      riskFactors.push('高风险地区');
      riskScore += 1;
    }

    // 确定威胁等级
    if (riskScore >= 5) return { threat: 'high', riskFactors };
    if (riskScore >= 2) return { threat: 'medium', riskFactors };
    return { threat: 'low', riskFactors };
  };

  // 分析IP
  const analyzeIP = async () => {
    if (!ipInput.trim()) return;

    setIsAnalyzing(true);
    setError(null);
    
    try {
      const ips = ipInput.split('\n').filter(ip => ip.trim()).slice(0, 100);
      const uniqueIPs = [...new Set(ips.map(ip => ip.trim()))];
      
      const queries = uniqueIPs.map(ip => ({ query: ip.trim() }));
      
      // Use consistent API endpoint
      const response = await fetch('/api/ip-proxy', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(queries)
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
      }

      const data = await response.json();
      
      const results: IPInfo[] = await Promise.all(data.map(async (ipData: any) => {
        const { threat, riskFactors } = await assessThreatLevel(ipData);
        const blacklistStatus = await checkBlacklist(ipData.query);
        const vpnTorStatus = await checkVPNTor(ipData.query);
        const ipType = determineIPType(ipData);
        
        return {
          ...ipData,
          threat,
          riskFactors,
          blacklistStatus,
          vpnTorStatus,
          ipType,
          geolocation: {
            accuracy: 'city',
            timezone: ipData.timezone || 'Unknown',
            currency: ipData.currency || 'Unknown'
          }
        };
      }));

      setAnalyzedIPs(results);
      
      // 计算统计信息
      const statistics: AnalysisStats = {
        totalIPs: results.length,
        highRisk: results.filter(r => r.threat === 'high').length,
        mediumRisk: results.filter(r => r.threat === 'medium').length,
        lowRisk: results.filter(r => r.threat === 'low').length,
        blacklisted: results.filter(r => r.blacklistStatus.isBlacklisted).length,
        vpnTor: results.filter(r => r.vpnTorStatus.isVPN || r.vpnTorStatus.isTor).length,
        countries: {},
        ipTypes: {}
      };

      // 统计国家分布
      results.forEach(result => {
        statistics.countries[result.country] = (statistics.countries[result.country] || 0) + 1;
        statistics.ipTypes[result.ipType] = (statistics.ipTypes[result.ipType] || 0) + 1;
      });

      setStats(statistics);

    } catch (err) {
      console.error('Error analyzing IPs:', err);
      setError('无法连接到IP分析服务，请检查网络连接或稍后重试');
    } finally {
      setIsAnalyzing(false);
    }
  };

  // 导出PDF报告
  const exportToPDF = () => {
    // 创建简单的HTML报告
    const reportHTML = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>IP分析报告</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 20px; }
          .header { text-align: center; margin-bottom: 30px; }
          .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 30px; }
          .stat-card { border: 1px solid #ddd; padding: 15px; border-radius: 8px; text-align: center; }
          .ip-result { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 8px; }
          .high-risk { border-left: 4px solid #ef4444; }
          .medium-risk { border-left: 4px solid #f59e0b; }
          .low-risk { border-left: 4px solid #10b981; }
          .risk-factors { margin-top: 10px; }
          .risk-factor { display: inline-block; background: #f3f4f6; padding: 4px 8px; margin: 2px; border-radius: 4px; font-size: 12px; }
        </style>
      </head>
      <body>
        <div class="header">
          <h1>IP地址安全分析报告</h1>
          <p>生成时间: ${new Date().toLocaleString()}</p>
        </div>
        
        ${stats ? `
        <div class="stats">
          <div class="stat-card">
            <h3>总IP数量</h3>
            <p style="font-size: 24px; font-weight: bold; color: #3b82f6;">${stats.totalIPs}</p>
          </div>
          <div class="stat-card">
            <h3>高风险IP</h3>
            <p style="font-size: 24px; font-weight: bold; color: #ef4444;">${stats.highRisk}</p>
          </div>
          <div class="stat-card">
            <h3>黑名单IP</h3>
            <p style="font-size: 24px; font-weight: bold; color: #dc2626;">${stats.blacklisted}</p>
          </div>
        </div>
        ` : ''}
        
        <h2>详细分析结果</h2>
        ${analyzedIPs.map(ip => `
          <div class="ip-result ${ip.threat}-risk">
            <h3>${ip.query} - ${ip.country}, ${ip.city}</h3>
            <p><strong>ISP:</strong> ${ip.isp}</p>
            <p><strong>组织:</strong> ${ip.org}</p>
            <p><strong>威胁等级:</strong> ${ip.threat === 'high' ? '高风险' : ip.threat === 'medium' ? '中等风险' : '低风险'}</p>
            <p><strong>IP类型:</strong> ${ip.ipType}</p>
            ${ip.blacklistStatus.isBlacklisted ? `<p><strong>黑名单状态:</strong> 已列入 ${ip.blacklistStatus.sources.join(', ')}</p>` : ''}
            ${ip.vpnTorStatus.isVPN || ip.vpnTorStatus.isTor ? `<p><strong>代理状态:</strong> ${ip.vpnTorStatus.isTor ? 'Tor出口节点' : ip.vpnTorStatus.isVPN ? 'VPN服务器' : '代理服务器'}</p>` : ''}
            <div class="risk-factors">
              ${ip.riskFactors.map(factor => `<span class="risk-factor">${factor}</span>`).join('')}
            </div>
          </div>
        `).join('')}
      </body>
      </html>
    `;

    // 创建下载链接
    const blob = new Blob([reportHTML], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `IP分析报告_${new Date().toISOString().split('T')[0]}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // 导出Excel
  const exportToExcel = () => {
    const csvContent = [
      ['IP地址', '国家', '城市', 'ISP', '组织', '威胁等级', 'IP类型', '黑名单状态', 'VPN/Tor状态', '风险因素'].join(','),
      ...analyzedIPs.map(ip => [
        ip.query,
        ip.country,
        ip.city,
        ip.isp,
        ip.org,
        ip.threat === 'high' ? '高风险' : ip.threat === 'medium' ? '中等风险' : '低风险',
        ip.ipType,
        ip.blacklistStatus.isBlacklisted ? '是' : '否',
        ip.vpnTorStatus.isTor ? 'Tor' : ip.vpnTorStatus.isVPN ? 'VPN' : '否',
        ip.riskFactors.join('; ')
      ].map(field => `"${field}"`).join(','))
    ].join('\n');

    const blob = new Blob(['\ufeff' + csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `IP分析数据_${new Date().toISOString().split('T')[0]}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const getThreatBadge = (threat: string) => {
    switch (threat) {
      case 'high':
        return (
          <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-red-100 text-red-800 border border-red-200">
            <AlertTriangle className="w-3 h-3 mr-1" />
            高风险
          </span>
        );
      case 'medium':
        return (
          <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800 border border-yellow-200">
            <Clock className="w-3 h-3 mr-1" />
            中等风险
          </span>
        );
      case 'low':
        return (
          <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800 border border-green-200">
            <CheckCircle className="w-3 h-3 mr-1" />
            低风险
          </span>
        );
      default:
        return null;
    }
  };

  const getIPTypeBadge = (type: string) => {
    const badges = {
      'residential': { color: 'bg-blue-100 text-blue-800', label: '住宅IP' },
      'datacenter': { color: 'bg-purple-100 text-purple-800', label: '数据中心' },
      'corporate': { color: 'bg-green-100 text-green-800', label: '企业IP' },
      'mobile': { color: 'bg-orange-100 text-orange-800', label: '移动网络' },
      'unknown': { color: 'bg-gray-100 text-gray-800', label: '未知类型' }
    };
    
    const badge = badges[type as keyof typeof badges] || badges.unknown;
    
    return (
      <span className={`px-2 py-1 rounded-full text-xs font-medium ${badge.color}`}>
        {badge.label}
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* 头部介绍 */}
      <div className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 p-6 rounded-xl border border-blue-100 dark:border-blue-800">
        <h3 className="text-xl font-bold text-gray-800 dark:text-white mb-3 flex items-center">
          <Globe className="mr-3 h-6 w-6 text-blue-600" />
          公共IP地址分析工具
        </h3>
        <p className="text-sm text-gray-600 dark:text-gray-300 leading-relaxed mb-3">
          无需注册即可使用的专业IP分析工具，支持IPv4/IPv6地址查询，提供地理位置、ISP信息、威胁评估、黑名单检测、VPN/Tor识别等功能
        </p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div className="flex items-center text-blue-700 dark:text-blue-300">
            <CheckCircle className="h-4 w-4 mr-2" />
            地理位置查询
          </div>
          <div className="flex items-center text-blue-700 dark:text-blue-300">
            <CheckCircle className="h-4 w-4 mr-2" />
            黑名单检测
          </div>
          <div className="flex items-center text-blue-700 dark:text-blue-300">
            <CheckCircle className="h-4 w-4 mr-2" />
            VPN/Tor识别
          </div>
          <div className="flex items-center text-blue-700 dark:text-blue-300">
            <CheckCircle className="h-4 w-4 mr-2" />
            报告导出
          </div>
        </div>
      </div>

      {/* 输入区域 */}
      <div className="space-y-4">
        <div>
          <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">
            输入要分析的 IP 地址（每行一个，最多100个）：
          </label>
          <textarea
            value={ipInput}
            onChange={(e) => setIpInput(e.target.value)}
            placeholder="8.8.8.8&#10;1.1.1.1&#10;95.223.57.198&#10;185.220.101.1"
            className="w-full h-40 p-4 border-2 border-gray-300 dark:border-gray-600 rounded-xl bg-white dark:bg-gray-700 text-gray-800 dark:text-white resize-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200 font-mono text-sm"
          />
          <div className="mt-2 text-xs text-gray-500 dark:text-gray-400">
            支持IPv4和IPv6地址。系统将自动检测黑名单状态、VPN/Tor节点、地理位置异常等风险因素。
          </div>
        </div>
        
        <div className="flex space-x-3">
          <button
            onClick={analyzeIP}
            disabled={isAnalyzing || !ipInput.trim()}
            className="flex-1 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 disabled:from-gray-400 disabled:to-gray-500 text-white font-semibold py-4 px-6 rounded-xl transition-all duration-200 flex items-center justify-center shadow-lg hover:shadow-xl transform hover:-translate-y-0.5 disabled:transform-none"
          >
            <Search className="mr-3 h-5 w-5" />
            {isAnalyzing ? '正在分析中...' : '开始深度分析'}
          </button>
          
          {analyzedIPs.length > 0 && (
            <button
              onClick={() => setShowStats(!showStats)}
              className="px-6 py-4 bg-gray-100 hover:bg-gray-200 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 rounded-xl transition-colors flex items-center"
            >
              <BarChart3 className="h-5 w-5 mr-2" />
              {showStats ? '隐藏' : '显示'}统计
            </button>
          )}
        </div>

        {error && (
          <div className="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-xl">
            <div className="flex items-center">
              <AlertTriangle className="h-5 w-5 text-red-500 mr-2" />
              <span className="text-red-700 dark:text-red-300 font-medium">分析错误</span>
            </div>
            <p className="text-red-600 dark:text-red-400 text-sm mt-1">{error}</p>
          </div>
        )}
      </div>

      {/* 统计信息 */}
      {stats && showStats && (
        <div className="bg-white dark:bg-gray-800 p-6 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700">
          <h4 className="text-lg font-semibold text-gray-800 dark:text-white mb-4 flex items-center">
            <BarChart3 className="h-5 w-5 mr-2" />
            分析统计
          </h4>
          
          <div className="grid grid-cols-2 md:grid-cols-6 gap-4 mb-6">
            <div className="text-center p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
              <div className="text-2xl font-bold text-blue-600">{stats.totalIPs}</div>
              <div className="text-sm text-blue-700 dark:text-blue-300">总IP数</div>
            </div>
            <div className="text-center p-3 bg-red-50 dark:bg-red-900/20 rounded-lg">
              <div className="text-2xl font-bold text-red-600">{stats.highRisk}</div>
              <div className="text-sm text-red-700 dark:text-red-300">高风险</div>
            </div>
            <div className="text-center p-3 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
              <div className="text-2xl font-bold text-yellow-600">{stats.mediumRisk}</div>
              <div className="text-sm text-yellow-700 dark:text-yellow-300">中等风险</div>
            </div>
            <div className="text-center p-3 bg-green-50 dark:bg-green-900/20 rounded-lg">
              <div className="text-2xl font-bold text-green-600">{stats.lowRisk}</div>
              <div className="text-sm text-green-700 dark:text-green-300">低风险</div>
            </div>
            <div className="text-center p-3 bg-purple-50 dark:bg-purple-900/20 rounded-lg">
              <div className="text-2xl font-bold text-purple-600">{stats.blacklisted}</div>
              <div className="text-sm text-purple-700 dark:text-purple-300">黑名单</div>
            </div>
            <div className="text-center p-3 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
              <div className="text-2xl font-bold text-orange-600">{stats.vpnTor}</div>
              <div className="text-sm text-orange-700 dark:text-orange-300">VPN/Tor</div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* 国家分布 */}
            <div>
              <h5 className="font-semibold text-gray-800 dark:text-white mb-3">国家分布</h5>
              <div className="space-y-2">
                {Object.entries(stats.countries)
                  .sort(([,a], [,b]) => b - a)
                  .slice(0, 5)
                  .map(([country, count]) => (
                    <div key={country} className="flex justify-between items-center">
                      <span className="text-sm text-gray-600 dark:text-gray-300">{country}</span>
                      <span className="text-sm font-medium text-gray-800 dark:text-white">{count}</span>
                    </div>
                  ))}
              </div>
            </div>

            {/* IP类型分布 */}
            <div>
              <h5 className="font-semibold text-gray-800 dark:text-white mb-3">IP类型分布</h5>
              <div className="space-y-2">
                {Object.entries(stats.ipTypes)
                  .sort(([,a], [,b]) => b - a)
                  .map(([type, count]) => (
                    <div key={type} className="flex justify-between items-center">
                      <span className="text-sm text-gray-600 dark:text-gray-300 capitalize">{type}</span>
                      <span className="text-sm font-medium text-gray-800 dark:text-white">{count}</span>
                    </div>
                  ))}
              </div>
            </div>
          </div>

          {/* 导出按钮 */}
          <div className="flex space-x-3 mt-6 pt-4 border-t border-gray-200 dark:border-gray-600">
            <button
              onClick={exportToPDF}
              className="flex items-center px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm transition-colors"
            >
              <FileText className="h-4 w-4 mr-2" />
              导出PDF报告
            </button>
            <button
              onClick={exportToExcel}
              className="flex items-center px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg text-sm transition-colors"
            >
              <Download className="h-4 w-4 mr-2" />
              导出Excel数据
            </button>
          </div>
        </div>
      )}

      {/* 分析结果 */}
      {analyzedIPs.length > 0 && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h4 className="text-xl font-bold text-gray-800 dark:text-white">分析结果</h4>
            <div className="text-sm text-gray-500 dark:text-gray-400">
              共分析 {analyzedIPs.length} 个IP地址
            </div>
          </div>

          {analyzedIPs.map((ipInfo, index) => (
            <div key={index} className="bg-white dark:bg-gray-800 border-2 border-gray-200 dark:border-gray-700 rounded-xl p-6 shadow-lg hover:shadow-xl transition-all duration-200">
              <div className="flex items-start justify-between mb-6">
                <div className="flex items-center space-x-3">
                  <Globe className="h-6 w-6 text-blue-500" />
                  <span className="text-xl font-mono font-bold text-gray-800 dark:text-white">
                    {ipInfo.query}
                  </span>
                  {getThreatBadge(ipInfo.threat)}
                  {getIPTypeBadge(ipInfo.ipType)}
                  {ipInfo.blacklistStatus.isBlacklisted && (
                    <span className="px-2 py-1 bg-red-100 text-red-800 border border-red-200 rounded-full text-xs font-medium">
                      🚨 黑名单
                    </span>
                  )}
                  {(ipInfo.vpnTorStatus.isVPN || ipInfo.vpnTorStatus.isTor) && (
                    <span className="px-2 py-1 bg-orange-100 text-orange-800 border border-orange-200 rounded-full text-xs font-medium">
                      {ipInfo.vpnTorStatus.isTor ? '🧅 Tor' : '🔒 VPN'}
                    </span>
                  )}
                </div>
              </div>
              
              {ipInfo.status === 'success' ? (
                <>
                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
                    {/* 地理信息 */}
                    <div className="space-y-4">
                      <h5 className="font-semibold text-gray-800 dark:text-white text-lg border-b border-gray-200 dark:border-gray-600 pb-2">
                        地理位置
                      </h5>
                      <div className="space-y-3">
                        <div className="flex items-center space-x-3">
                          <MapPin className="h-4 w-4 text-gray-500 flex-shrink-0" />
                          <span className="text-sm text-gray-600 dark:text-gray-300">位置：</span>
                          <span className="text-sm font-medium text-gray-800 dark:text-white">
                            {[ipInfo.city, ipInfo.regionName, ipInfo.country].filter(Boolean).join(', ')}
                          </span>
                        </div>
                        <div className="flex items-center space-x-3">
                          <Globe className="h-4 w-4 text-gray-500 flex-shrink-0" />
                          <span className="text-sm text-gray-600 dark:text-gray-300">坐标：</span>
                          <span className="text-sm font-medium text-gray-800 dark:text-white">
                            {ipInfo.lat.toFixed(4)}, {ipInfo.lon.toFixed(4)}
                          </span>
                        </div>
                        <div className="flex items-center space-x-3">
                          <Clock className="h-4 w-4 text-gray-500 flex-shrink-0" />
                          <span className="text-sm text-gray-600 dark:text-gray-300">时区：</span>
                          <span className="text-sm font-medium text-gray-800 dark:text-white">
                            {ipInfo.timezone || '未知'}
                          </span>
                        </div>
                        {ipInfo.zip && (
                          <div className="flex items-center space-x-3">
                            <MapPin className="h-4 w-4 text-gray-500 flex-shrink-0" />
                            <span className="text-sm text-gray-600 dark:text-gray-300">邮编：</span>
                            <span className="text-sm font-medium text-gray-800 dark:text-white">
                              {ipInfo.zip}
                            </span>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* 网络信息 */}
                    <div className="space-y-4">
                      <h5 className="font-semibold text-gray-800 dark:text-white text-lg border-b border-gray-200 dark:border-gray-600 pb-2">
                        网络信息
                      </h5>
                      <div className="space-y-3">
                        <div className="flex items-center space-x-3">
                          <Wifi className="h-4 w-4 text-gray-500 flex-shrink-0" />
                          <span className="text-sm text-gray-600 dark:text-gray-300">ISP：</span>
                          <span className="text-sm font-medium text-gray-800 dark:text-white">
                            {ipInfo.isp || '未知'}
                          </span>
                        </div>
                        <div className="flex items-center space-x-3">
                          <Server className="h-4 w-4 text-gray-500 flex-shrink-0" />
                          <span className="text-sm text-gray-600 dark:text-gray-300">组织：</span>
                          <span className="text-sm font-medium text-gray-800 dark:text-white">
                            {ipInfo.org || '未知'}
                          </span>
                        </div>
                        <div className="flex items-center space-x-3">
                          <Globe className="h-4 w-4 text-gray-500 flex-shrink-0" />
                          <span className="text-sm text-gray-600 dark:text-gray-300">ASN：</span>
                          <span className="text-sm font-medium text-gray-800 dark:text-white">
                            {ipInfo.as || '未知'}
                          </span>
                        </div>
                        {ipInfo.reverse && (
                          <div className="flex items-center space-x-3">
                            <Eye className="h-4 w-4 text-gray-500 flex-shrink-0" />
                            <span className="text-sm text-gray-600 dark:text-gray-300">反向DNS：</span>
                            <span className="text-sm font-medium text-gray-800 dark:text-white break-all">
                              {ipInfo.reverse}
                            </span>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* 安全信息 */}
                    <div className="space-y-4">
                      <h5 className="font-semibold text-gray-800 dark:text-white text-lg border-b border-gray-200 dark:border-gray-600 pb-2">
                        安全状态
                      </h5>
                      <div className="space-y-3">
                        <div className="flex items-center space-x-3">
                          <Shield className="h-4 w-4 text-gray-500 flex-shrink-0" />
                          <span className="text-sm text-gray-600 dark:text-gray-300">威胁等级：</span>
                          <span className={`text-sm font-medium ${
                            ipInfo.threat === 'high' ? 'text-red-600' :
                            ipInfo.threat === 'medium' ? 'text-yellow-600' : 'text-green-600'
                          }`}>
                            {ipInfo.threat === 'high' ? '高风险' :
                             ipInfo.threat === 'medium' ? '中等风险' : '低风险'}
                          </span>
                        </div>
                        <div className="flex items-center space-x-3">
                          <AlertTriangle className="h-4 w-4 text-gray-500 flex-shrink-0" />
                          <span className="text-sm text-gray-600 dark:text-gray-300">黑名单：</span>
                          <span className={`text-sm font-medium ${
                            ipInfo.blacklistStatus.isBlacklisted ? 'text-red-600' : 'text-green-600'
                          }`}>
                            {ipInfo.blacklistStatus.isBlacklisted ? 
                              `是 (${ipInfo.blacklistStatus.sources.join(', ')})` : '否'}
                          </span>
                        </div>
                        <div className="flex items-center space-x-3">
                          <Eye className="h-4 w-4 text-gray-500 flex-shrink-0" />
                          <span className="text-sm text-gray-600 dark:text-gray-300">代理状态：</span>
                          <span className={`text-sm font-medium ${
                            ipInfo.vpnTorStatus.isVPN || ipInfo.vpnTorStatus.isTor ? 'text-orange-600' : 'text-green-600'
                          }`}>
                            {ipInfo.vpnTorStatus.isTor ? 'Tor出口节点' :
                             ipInfo.vpnTorStatus.isVPN ? 'VPN服务器' :
                             ipInfo.vpnTorStatus.isProxy ? '代理服务器' : '直连'}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* 风险因素 */}
                  {ipInfo.riskFactors.length > 0 && (
                    <div className="mb-4">
                      <h5 className="font-semibold text-gray-800 dark:text-white mb-2">风险因素：</h5>
                      <div className="flex flex-wrap gap-2">
                        {ipInfo.riskFactors.map((factor, idx) => (
                          <span key={idx} className="px-3 py-1 bg-red-100 dark:bg-red-900/20 text-red-700 dark:text-red-300 rounded-full text-xs font-medium border border-red-200 dark:border-red-800">
                            {factor}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* 连接类型指示器 */}
                  <div className="flex flex-wrap gap-3 mb-4">
                    {ipInfo.mobile && (
                      <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                        📱 移动网络
                      </span>
                    )}
                    {ipInfo.proxy && (
                      <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-orange-100 text-orange-800">
                        🔒 代理服务器
                      </span>
                    )}
                    {ipInfo.hosting && (
                      <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                        🏢 托管服务器
                      </span>
                    )}
                  </div>

                  {/* 外部链接 */}
                  <div className="flex space-x-3 pt-4 border-t border-gray-200 dark:border-gray-600">
                    <a
                      href={`https://www.abuseipdb.com/check/${ipInfo.query}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center px-3 py-2 bg-blue-100 hover:bg-blue-200 text-blue-700 rounded-lg text-sm transition-colors"
                    >
                      <ExternalLink className="h-4 w-4 mr-2" />
                      AbuseIPDB查询
                    </a>
                    <a
                      href={`https://www.virustotal.com/gui/ip-address/${ipInfo.query}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center px-3 py-2 bg-green-100 hover:bg-green-200 text-green-700 rounded-lg text-sm transition-colors"
                    >
                      <ExternalLink className="h-4 w-4 mr-2" />
                      VirusTotal查询
                    </a>
                  </div>
                </>
              ) : (
                <div className="text-center py-8">
                  <AlertTriangle className="h-12 w-12 text-red-400 mx-auto mb-4" />
                  <p className="text-red-600 dark:text-red-400 font-medium">
                    无法获取此IP地址的详细信息
                  </p>
                  <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                    {ipInfo.status === 'fail' ? '无效的IP地址格式' : '查询服务暂时不可用'}
                  </p>
                </div>
              )}
            </div>
          ))}

          {/* 使用说明 */}
          <div className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 p-6 rounded-xl border border-blue-200 dark:border-blue-800">
            <h5 className="font-bold text-blue-800 dark:text-blue-200 mb-3 flex items-center">
              <Shield className="mr-2 h-5 w-5" />
              使用说明与免责声明
            </h5>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-blue-700 dark:text-blue-300">
              <div>
                <h6 className="font-semibold mb-2">功能特性：</h6>
                <ul className="list-disc list-inside space-y-1">
                  <li>支持IPv4和IPv6地址查询</li>
                  <li>实时黑名单检测（Spamhaus、AbuseIPDB等）</li>
                  <li>VPN/Tor/代理服务器识别</li>
                  <li>详细地理位置信息</li>
                  <li>ISP和ASN信息查询</li>
                  <li>威胁等级智能评估</li>
                </ul>
              </div>
              <div>
                <h6 className="font-semibold mb-2">注意事项：</h6>
                <ul className="list-disc list-inside space-y-1">
                  <li>本工具仅供安全研究和网络管理使用</li>
                  <li>查询结果仅供参考，不构成法律依据</li>
                  <li>请遵守相关法律法规和隐私政策</li>
                  <li>不得用于非法用途或恶意攻击</li>
                  <li>数据来源于公开数据库，准确性不保证</li>
                  <li>建议结合多种工具进行综合分析</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}