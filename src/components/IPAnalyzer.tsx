import React, { useState, useEffect } from 'react';
import { Search, MapPin, Globe, Shield, AlertTriangle, CheckCircle, Clock, Wifi, Server, Eye, Bell, History, Filter, Trash2, Download, RefreshCw } from 'lucide-react';
import { IPAnalysisDB } from '../lib/database';
import type { User } from '@supabase/supabase-js';
import type { IPAnalysisSession, IPAnalysisResult } from '../lib/supabase';

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
  isDuplicate?: boolean;
  lastSeen?: string;
}

interface IPAnalyzerProps {
  user: User;
}

export function IPAnalyzer({ user }: IPAnalyzerProps) {
  const [ipInput, setIpInput] = useState('');
  const [analyzedIPs, setAnalyzedIPs] = useState<IPInfo[]>([]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sessions, setSessions] = useState<IPAnalysisSession[]>([]);
  const [selectedSession, setSelectedSession] = useState<string | null>(null);
  const [showHistory, setShowHistory] = useState(false);
  const [alerts, setAlerts] = useState<string[]>([]);
  const [filterDuplicates, setFilterDuplicates] = useState(true);
  const [suspiciousIPs, setSuspiciousIPs] = useState<Set<string>>(new Set());

  // 可疑IP模式匹配
  const suspiciousPatterns = [
    /^95\.223\./, // 示例中的可疑网段
    /^185\./, // 常见的VPN/代理网段
    /^46\./, // 另一个常见的可疑网段
    /^109\./, // 可疑网段
  ];

  // 检查IP是否可疑
  const isSuspiciousIP = (ip: string): boolean => {
    return suspiciousPatterns.some(pattern => pattern.test(ip));
  };

  // 威胁评估函数
  const assessThreatLevel = (ipData: any): { threat: 'low' | 'medium' | 'high', riskFactors: string[] } => {
    const riskFactors: string[] = [];
    let riskScore = 0;

    // 检查是否为可疑IP段
    if (isSuspiciousIP(ipData.query)) {
      riskFactors.push('可疑IP网段');
      riskScore += 3;
    }

    // 检查托管/数据中心
    if (ipData.hosting) {
      riskFactors.push('数据中心/托管服务器');
      riskScore += 2;
    }

    // 检查代理
    if (ipData.proxy) {
      riskFactors.push('代理服务器');
      riskScore += 3;
    }

    // 检查移动网络
    if (ipData.mobile) {
      riskFactors.push('移动网络');
      riskScore += 1;
    }

    // 检查可疑ASN
    const suspiciousASNs = ['LeaseWeb', 'OVH', 'DigitalOcean', 'Amazon', 'Google Cloud', 'Microsoft Azure'];
    if (suspiciousASNs.some(asn => ipData.asname?.includes(asn))) {
      riskFactors.push('云服务提供商');
      riskScore += 2;
    }

    // 检查VPN/代理指示器
    const vpnIndicators = ['VPN', 'Proxy', 'Anonymous', 'Privacy'];
    if (vpnIndicators.some(indicator => ipData.isp?.includes(indicator) || ipData.org?.includes(indicator))) {
      riskFactors.push('VPN/匿名服务');
      riskScore += 3;
    }

    // 确定威胁等级
    if (riskScore >= 5) return { threat: 'high', riskFactors };
    if (riskScore >= 2) return { threat: 'medium', riskFactors };
    return { threat: 'low', riskFactors };
  };

  // 检查重复IP
  const checkDuplicates = async (ips: string[]): Promise<Map<string, string>> => {
    const duplicateMap = new Map<string, string>();
    
    try {
      // 从数据库获取历史记录
      const allSessions = await IPAnalysisDB.getUserSessions();
      const historicalIPs = new Set<string>();
      
      for (const session of allSessions) {
        const results = await IPAnalysisDB.getSessionResults(session.id);
        results.forEach(result => {
          if (ips.includes(result.ip_address)) {
            duplicateMap.set(result.ip_address, result.created_at);
            historicalIPs.add(result.ip_address);
          }
        });
      }
      
      return duplicateMap;
    } catch (error) {
      console.error('检查重复IP失败:', error);
      return duplicateMap;
    }
  };

  // 触发警报
  const triggerAlert = (message: string) => {
    setAlerts(prev => [...prev, message]);
    
    // 浏览器通知
    if (Notification.permission === 'granted') {
      new Notification('系统安全警报', {
        body: message,
        icon: '/favicon.ico'
      });
    }
    
    // 5秒后自动清除警报
    setTimeout(() => {
      setAlerts(prev => prev.filter(alert => alert !== message));
    }, 5000);
  };

  // 分析IP
  const analyzeIP = async () => {
    if (!ipInput.trim()) return;

    setIsAnalyzing(true);
    setError(null);
    
    try {
      const ips = ipInput.split('\n').filter(ip => ip.trim()).slice(0, 50);
      const uniqueIPs = [...new Set(ips.map(ip => ip.trim()))];
      
      // 检查重复
      const duplicates = await checkDuplicates(uniqueIPs);
      
      // 创建新的分析会话
      const session = await IPAnalysisDB.createSession(`IP分析 - ${new Date().toLocaleString()}`);
      if (!session) {
        throw new Error('创建分析会话失败');
      }

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
      
      const results: IPInfo[] = data.map((ipData: any) => {
        const { threat, riskFactors } = assessThreatLevel(ipData);
        const isDuplicate = duplicates.has(ipData.query);
        
        return {
          ...ipData,
          threat,
          riskFactors,
          isDuplicate,
          lastSeen: isDuplicate ? duplicates.get(ipData.query) : undefined
        };
      });

      // 检查可疑IP并触发警报
      const suspiciousResults = results.filter(result => 
        result.threat === 'high' || isSuspiciousIP(result.query)
      );
      
      if (suspiciousResults.length > 0) {
        const suspiciousIPs = suspiciousResults.map(r => r.query).join(', ');
        triggerAlert(`检测到 ${suspiciousResults.length} 个高风险IP: ${suspiciousIPs}`);
        
        // 更新可疑IP集合
        setSuspiciousIPs(prev => {
          const newSet = new Set(prev);
          suspiciousResults.forEach(result => newSet.add(result.query));
          return newSet;
        });
      }

      // 过滤重复项（如果启用）
      const finalResults = filterDuplicates 
        ? results.filter(result => !result.isDuplicate)
        : results;

      setAnalyzedIPs(finalResults);
      
      // 保存到数据库
      await IPAnalysisDB.saveResults(session.id, results);
      
      // 刷新会话列表
      loadSessions();

    } catch (err) {
      console.error('Error analyzing IPs:', err);
      setError('无法连接到IP分析服务，请检查网络连接或稍后重试');
    } finally {
      setIsAnalyzing(false);
    }
  };

  // 加载会话列表
  const loadSessions = async () => {
    try {
      const sessionList = await IPAnalysisDB.getUserSessions();
      setSessions(sessionList);
    } catch (error) {
      console.error('加载会话失败:', error);
    }
  };

  // 加载会话结果
  const loadSessionResults = async (sessionId: string) => {
    try {
      const results = await IPAnalysisDB.getSessionResults(sessionId);
      const formattedResults: IPInfo[] = results.map(result => ({
        query: result.ip_address,
        status: 'success',
        country: result.country || '未知',
        countryCode: result.country_code || 'XX',
        region: result.region || 'XX',
        regionName: result.region || '未知',
        city: result.city || '未知',
        zip: '',
        lat: 0,
        lon: 0,
        timezone: '',
        isp: result.isp || '未知ISP',
        org: result.organization || '未知组织',
        as: '',
        asname: result.organization || '未知ASN',
        reverse: '',
        mobile: result.is_mobile,
        proxy: result.is_proxy,
        hosting: result.is_hosting,
        threat: result.threat_level as 'low' | 'medium' | 'high',
        riskFactors: result.risk_factors || []
      }));
      
      setAnalyzedIPs(formattedResults);
      setSelectedSession(sessionId);
    } catch (error) {
      console.error('加载会话结果失败:', error);
    }
  };

  // 删除会话
  const deleteSession = async (sessionId: string) => {
    if (confirm('确定要删除这个分析会话吗？')) {
      const success = await IPAnalysisDB.deleteSession(sessionId);
      if (success) {
        loadSessions();
        if (selectedSession === sessionId) {
          setSelectedSession(null);
          setAnalyzedIPs([]);
        }
      }
    }
  };

  // 请求通知权限
  useEffect(() => {
    if (Notification.permission === 'default') {
      Notification.requestPermission();
    }
  }, []);

  // 初始加载
  useEffect(() => {
    loadSessions();
  }, []);

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

  const getLocationString = (ipInfo: IPInfo) => {
    const parts = [ipInfo.city, ipInfo.regionName, ipInfo.country].filter(Boolean);
    return parts.join(', ') || '未知位置';
  };

  const getThreatColor = (threat: string) => {
    switch (threat) {
      case 'high': return 'border-red-500';
      case 'medium': return 'border-yellow-500';
      case 'low': return 'border-green-500';
      default: return 'border-gray-300';
    }
  };

  return (
    <div className="space-y-6">
      {/* 警报区域 */}
      {alerts.length > 0 && (
        <div className="space-y-2">
          {alerts.map((alert, index) => (
            <div key={index} className="bg-red-50 dark:bg-red-900/20 border-l-4 border-red-500 p-4 rounded-r-lg animate-pulse">
              <div className="flex items-center">
                <Bell className="h-5 w-5 text-red-500 mr-2" />
                <span className="font-semibold text-red-700 dark:text-red-300">安全警报</span>
              </div>
              <p className="text-red-600 dark:text-red-400 text-sm mt-1">{alert}</p>
            </div>
          ))}
        </div>
      )}

      <div className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 p-6 rounded-xl border border-blue-100 dark:border-blue-800">
        <h3 className="text-xl font-bold text-gray-800 dark:text-white mb-3 flex items-center">
          <Shield className="mr-3 h-6 w-6 text-blue-600" />
          高级 IP 地址安全分析器
        </h3>
        <p className="text-sm text-gray-600 dark:text-gray-300 leading-relaxed">
          使用实时地理位置数据库进行详细的IP地址分析，包括威胁评估、重复检测、地理位置、ISP信息和安全风险因素识别
        </p>
      </div>

      {/* 控制面板 */}
      <div className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700">
        <div className="flex flex-wrap items-center gap-4 mb-4">
          <button
            onClick={() => setShowHistory(!showHistory)}
            className="flex items-center px-3 py-2 bg-gray-100 hover:bg-gray-200 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 rounded-lg text-sm transition-colors"
          >
            <History className="h-4 w-4 mr-2" />
            {showHistory ? '隐藏历史' : '显示历史'}
          </button>
          
          <label className="flex items-center space-x-2">
            <input
              type="checkbox"
              checked={filterDuplicates}
              onChange={(e) => setFilterDuplicates(e.target.checked)}
              className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            />
            <span className="text-sm text-gray-700 dark:text-gray-300">过滤重复IP</span>
          </label>

          <div className="text-sm text-gray-500 dark:text-gray-400">
            可疑IP: {suspiciousIPs.size} 个
          </div>
        </div>

        {/* 历史会话 */}
        {showHistory && (
          <div className="mb-4 p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
            <h4 className="font-semibold text-gray-800 dark:text-white mb-3">分析历史</h4>
            <div className="space-y-2 max-h-40 overflow-y-auto">
              {sessions.map((session) => (
                <div key={session.id} className="flex items-center justify-between p-2 bg-white dark:bg-gray-800 rounded border">
                  <div className="flex-1">
                    <div className="font-medium text-sm">{session.session_name}</div>
                    <div className="text-xs text-gray-500">
                      {session.total_ips} 个IP | 高风险: {session.high_risk_count} | 
                      {new Date(session.created_at).toLocaleString()}
                    </div>
                  </div>
                  <div className="flex space-x-2">
                    <button
                      onClick={() => loadSessionResults(session.id)}
                      className="px-2 py-1 bg-blue-100 hover:bg-blue-200 text-blue-700 rounded text-xs"
                    >
                      查看
                    </button>
                    <button
                      onClick={() => deleteSession(session.id)}
                      className="px-2 py-1 bg-red-100 hover:bg-red-200 text-red-700 rounded text-xs"
                    >
                      <Trash2 className="h-3 w-3" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">
            输入要分析的 IP 地址（每行一个，最多50个）：
          </label>
          <textarea
            value={ipInput}
            onChange={(e) => setIpInput(e.target.value)}
            placeholder="77.11.6.121&#10;89.245.16.215&#10;109.42.49.1&#10;95.223.57.198"
            className="w-full h-40 p-4 border-2 border-gray-300 dark:border-gray-600 rounded-xl bg-white dark:bg-gray-700 text-gray-800 dark:text-white resize-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition-all duration-200 font-mono text-sm"
          />
          <div className="mt-2 text-xs text-gray-500 dark:text-gray-400">
            支持IPv4地址，每行一个。系统会自动检测重复IP和可疑网段，并触发安全警报。
          </div>
        </div>
        
        <button
          onClick={analyzeIP}
          disabled={isAnalyzing || !ipInput.trim()}
          className="w-full bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 disabled:from-gray-400 disabled:to-gray-500 text-white font-semibold py-4 px-6 rounded-xl transition-all duration-200 flex items-center justify-center shadow-lg hover:shadow-xl transform hover:-translate-y-0.5 disabled:transform-none"
        >
          <Search className="mr-3 h-5 w-5" />
          {isAnalyzing ? '正在分析中...' : '开始深度分析'}
        </button>

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

      {analyzedIPs.length > 0 && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h4 className="text-xl font-bold text-gray-800 dark:text-white">分析结果</h4>
            <div className="text-sm text-gray-500 dark:text-gray-400">
              共分析 {analyzedIPs.length} 个IP地址
            </div>
          </div>

          {/* 统计摘要 */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-red-50 dark:bg-red-900/20 p-4 rounded-xl border border-red-200 dark:border-red-800">
              <div className="flex items-center">
                <AlertTriangle className="h-5 w-5 text-red-500 mr-2" />
                <span className="font-semibold text-red-700 dark:text-red-300">高风险</span>
              </div>
              <div className="text-2xl font-bold text-red-600 dark:text-red-400 mt-1">
                {analyzedIPs.filter(ip => ip.threat === 'high').length}
              </div>
            </div>
            <div className="bg-yellow-50 dark:bg-yellow-900/20 p-4 rounded-xl border border-yellow-200 dark:border-yellow-800">
              <div className="flex items-center">
                <Clock className="h-5 w-5 text-yellow-500 mr-2" />
                <span className="font-semibold text-yellow-700 dark:text-yellow-300">中等风险</span>
              </div>
              <div className="text-2xl font-bold text-yellow-600 dark:text-yellow-400 mt-1">
                {analyzedIPs.filter(ip => ip.threat === 'medium').length}
              </div>
            </div>
            <div className="bg-green-50 dark:bg-green-900/20 p-4 rounded-xl border border-green-200 dark:border-green-800">
              <div className="flex items-center">
                <CheckCircle className="h-5 w-5 text-green-500 mr-2" />
                <span className="font-semibold text-green-700 dark:text-green-300">低风险</span>
              </div>
              <div className="text-2xl font-bold text-green-600 dark:text-green-400 mt-1">
                {analyzedIPs.filter(ip => ip.threat === 'low').length}
              </div>
            </div>
            <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-xl border border-blue-200 dark:border-blue-800">
              <div className="flex items-center">
                <Filter className="h-5 w-5 text-blue-500 mr-2" />
                <span className="font-semibold text-blue-700 dark:text-blue-300">可疑网段</span>
              </div>
              <div className="text-2xl font-bold text-blue-600 dark:text-blue-400 mt-1">
                {analyzedIPs.filter(ip => isSuspiciousIP(ip.query)).length}
              </div>
            </div>
          </div>

          {analyzedIPs.map((ipInfo, index) => (
            <div key={index} className={`bg-white dark:bg-gray-800 border-2 ${getThreatColor(ipInfo.threat)} rounded-xl p-6 shadow-lg hover:shadow-xl transition-all duration-200 ${isSuspiciousIP(ipInfo.query) ? 'ring-2 ring-red-300' : ''}`}>
              <div className="flex items-start justify-between mb-6">
                <div className="flex items-center space-x-3">
                  <Globe className="h-6 w-6 text-blue-500" />
                  <span className="text-xl font-mono font-bold text-gray-800 dark:text-white">
                    {ipInfo.query}
                  </span>
                  {isSuspiciousIP(ipInfo.query) && (
                    <span className="px-2 py-1 bg-red-100 text-red-800 border border-red-200 rounded-full text-xs font-medium">
                      🚨 可疑网段
                    </span>
                  )}
                  {ipInfo.isDuplicate && (
                    <span className="px-2 py-1 bg-orange-100 text-orange-800 border border-orange-200 rounded-full text-xs font-medium">
                      🔄 重复IP
                    </span>
                  )}
                  {ipInfo.status !== 'success' && (
                    <span className="text-sm text-red-500 font-medium">(查询失败)</span>
                  )}
                </div>
                {getThreatBadge(ipInfo.threat)}
              </div>
              
              {ipInfo.status === 'success' ? (
                <>
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                    <div className="space-y-4">
                      <h5 className="font-semibold text-gray-800 dark:text-white text-lg border-b border-gray-200 dark:border-gray-600 pb-2">
                        地理信息
                      </h5>
                      <div className="space-y-3">
                        <div className="flex items-center space-x-3">
                          <MapPin className="h-4 w-4 text-gray-500 flex-shrink-0" />
                          <span className="text-sm text-gray-600 dark:text-gray-300 min-w-0">位置：</span>
                          <span className="text-sm font-medium text-gray-800 dark:text-white">
                            {getLocationString(ipInfo)}
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
                        <div className="flex items-center space-x-3">
                          <Globe className="h-4 w-4 text-gray-500 flex-shrink-0" />
                          <span className="text-sm text-gray-600 dark:text-gray-300">时区：</span>
                          <span className="text-sm font-medium text-gray-800 dark:text-white">
                            {ipInfo.timezone || '未知'}
                          </span>
                        </div>
                      </div>
                    </div>

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
                            {ipInfo.asname || '未知'}
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
                  </div>

                  {/* 重复信息 */}
                  {ipInfo.isDuplicate && ipInfo.lastSeen && (
                    <div className="mb-4 p-3 bg-orange-50 dark:bg-orange-900/20 rounded-lg border-l-4 border-orange-500">
                      <div className="flex items-center mb-1">
                        <RefreshCw className="h-4 w-4 text-orange-500 mr-2" />
                        <span className="font-semibold text-orange-700 dark:text-orange-300">重复检测</span>
                      </div>
                      <p className="text-sm text-orange-700 dark:text-orange-300">
                        此IP在 {new Date(ipInfo.lastSeen).toLocaleString()} 已被分析过
                      </p>
                    </div>
                  )}

                  {/* 风险因素 */}
                  {ipInfo.riskFactors.length > 0 && (
                    <div className="mb-4">
                      <h5 className="font-semibold text-gray-800 dark:text-white mb-2">风险因素：</h5>
                      <div className="flex flex-wrap gap-2">
                        {ipInfo.riskFactors.map((factor, idx) => (
                          <span key={idx} className="px-3 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-full text-xs font-medium">
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

              {/* 安全建议 */}
              {(ipInfo.threat === 'high' || isSuspiciousIP(ipInfo.query)) && (
                <div className="mt-6 p-4 bg-red-50 dark:bg-red-900/20 rounded-xl border-l-4 border-red-500">
                  <div className="flex items-center mb-2">
                    <AlertTriangle className="h-5 w-5 text-red-500 mr-2" />
                    <span className="font-semibold text-red-700 dark:text-red-300">高风险警告</span>
                  </div>
                  <p className="text-sm text-red-700 dark:text-red-300 mb-2">
                    此IP地址存在多个安全风险因素，建议立即采取以下防护措施：
                  </p>
                  <ul className="text-sm text-red-600 dark:text-red-400 list-disc list-inside space-y-1">
                    <li>立即阻止来自此IP的连接</li>
                    <li>检查防火墙日志中的相关活动</li>
                    <li>运行全面的安全扫描</li>
                    <li>监控系统是否有异常行为</li>
                  </ul>
                </div>
              )}

              {ipInfo.threat === 'medium' && (
                <div className="mt-6 p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-xl border-l-4 border-yellow-500">
                  <div className="flex items-center mb-2">
                    <Clock className="h-5 w-5 text-yellow-500 mr-2" />
                    <span className="font-semibold text-yellow-700 dark:text-yellow-300">中等风险提醒</span>
                  </div>
                  <p className="text-sm text-yellow-700 dark:text-yellow-300">
                    此IP地址需要关注，建议监控相关网络活动并保持警惕。
                  </p>
                </div>
              )}
            </div>
          ))}

          <div className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 p-6 rounded-xl border border-blue-200 dark:border-blue-800">
            <h5 className="font-bold text-blue-800 dark:text-blue-200 mb-3 flex items-center">
              <Shield className="mr-2 h-5 w-5" />
              综合安全建议
            </h5>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <ul className="list-disc list-inside text-sm text-blue-700 dark:text-blue-300 space-y-2">
                <li>定期监控网络连接和防火墙日志</li>
                <li>对来自数据中心和代理的连接保持警惕</li>
                <li>使用入侵检测系统(IDS)监控异常流量</li>
                <li>及时更新系统和安全软件</li>
              </ul>
              <ul className="list-disc list-inside text-sm text-blue-700 dark:text-blue-300 space-y-2">
                <li>考虑使用地理位置阻断功能</li>
                <li>建立IP地址白名单和黑名单</li>
                <li>定期进行安全审计和渗透测试</li>
                <li>保持对新兴威胁的关注和学习</li>
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}