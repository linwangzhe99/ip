import React, { useState, useEffect } from 'react';
import { 
  Link, 
  Eye, 
  AlertTriangle, 
  Globe, 
  MapPin, 
  Clock, 
  Shield, 
  Plus,
  Copy,
  ExternalLink,
  BarChart3,
  Users,
  Activity,
  Trash2,
  Edit,
  Settings,
  Download,
  RefreshCw
} from 'lucide-react';
import { VisitorTrackingDB } from '../lib/visitorTracking';
import type { User } from '@supabase/supabase-js';
import type { 
  TrackingLink, 
  VisitorIPLog, 
  VisitorSession, 
  IPAnomalyDetection,
  VisitorAnalytics 
} from '../lib/visitorTracking';

interface VisitorTrackingProps {
  user: User;
}

export function VisitorTracking({ user }: VisitorTrackingProps) {
  const [trackingLinks, setTrackingLinks] = useState<TrackingLink[]>([]);
  const [selectedLink, setSelectedLink] = useState<TrackingLink | null>(null);
  const [visitorLogs, setVisitorLogs] = useState<VisitorIPLog[]>([]);
  const [visitorSessions, setVisitorSessions] = useState<VisitorSession[]>([]);
  const [anomalies, setAnomalies] = useState<IPAnomalyDetection[]>([]);
  const [analytics, setAnalytics] = useState<VisitorAnalytics | null>(null);
  const [activeTab, setActiveTab] = useState<'links' | 'logs' | 'sessions' | 'anomalies' | 'analytics'>('links');
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  // 创建链接表单状态
  const [newLink, setNewLink] = useState({
    link_name: '',
    description: '',
    target_url: '',
    collect_user_agent: true,
    collect_referrer: true,
    alert_on_suspicious: true,
    max_visits: '',
    expires_at: ''
  });

  // 加载跟踪链接
  const loadTrackingLinks = async () => {
    setIsLoading(true);
    try {
      const links = await VisitorTrackingDB.getUserTrackingLinks();
      setTrackingLinks(links);
    } catch (error) {
      console.error('加载跟踪链接失败:', error);
    } finally {
      setIsLoading(false);
    }
  };

  // 加载选中链接的数据
  const loadLinkData = async (link: TrackingLink) => {
    setIsLoading(true);
    try {
      const [logs, sessions, anomalyData, analyticsData] = await Promise.all([
        VisitorTrackingDB.getVisitorLogs(link.id),
        VisitorTrackingDB.getVisitorSessions(link.id),
        VisitorTrackingDB.getAnomalyDetections(link.id),
        VisitorTrackingDB.getVisitorAnalytics(link.id)
      ]);

      setVisitorLogs(logs);
      setVisitorSessions(sessions);
      setAnomalies(anomalyData);
      setAnalytics(analyticsData);
    } catch (error) {
      console.error('加载链接数据失败:', error);
    } finally {
      setIsLoading(false);
    }
  };

  // 创建跟踪链接
  const createTrackingLink = async () => {
    if (!newLink.link_name.trim()) return;

    try {
      const link = await VisitorTrackingDB.createTrackingLink(
        newLink.link_name,
        newLink.description || undefined,
        newLink.target_url || undefined,
        {
          collect_user_agent: newLink.collect_user_agent,
          collect_referrer: newLink.collect_referrer,
          alert_on_suspicious: newLink.alert_on_suspicious,
          max_visits: newLink.max_visits ? parseInt(newLink.max_visits) : undefined,
          expires_at: newLink.expires_at || undefined
        }
      );

      if (link) {
        setTrackingLinks(prev => [link, ...prev]);
        setShowCreateForm(false);
        setNewLink({
          link_name: '',
          description: '',
          target_url: '',
          collect_user_agent: true,
          collect_referrer: true,
          alert_on_suspicious: true,
          max_visits: '',
          expires_at: ''
        });
      }
    } catch (error) {
      console.error('创建跟踪链接失败:', error);
    }
  };

  // 复制链接到剪贴板
  const copyTrackingLink = (linkCode: string) => {
    const fullUrl = `${window.location.origin}/track/${linkCode}`;
    navigator.clipboard.writeText(fullUrl);
    // 这里可以添加成功提示
  };

  // 删除跟踪链接
  const deleteTrackingLink = async (linkId: string) => {
    if (!confirm('确定要删除这个跟踪链接吗？这将删除所有相关的访问记录。')) return;

    const success = await VisitorTrackingDB.deleteTrackingLink(linkId);
    if (success) {
      setTrackingLinks(prev => prev.filter(link => link.id !== linkId));
      if (selectedLink?.id === linkId) {
        setSelectedLink(null);
      }
    }
  };

  // 获取威胁等级颜色
  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'high': return 'text-red-600 bg-red-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-green-600 bg-green-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  // 获取异常严重程度颜色
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-700 bg-red-200';
      case 'high': return 'text-red-600 bg-red-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'low': return 'text-blue-600 bg-blue-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  useEffect(() => {
    loadTrackingLinks();
  }, []);

  useEffect(() => {
    if (selectedLink) {
      loadLinkData(selectedLink);
    }
  }, [selectedLink]);

  return (
    <div className="space-y-6">
      {/* 头部 */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-xl font-bold text-gray-800 dark:text-white">访问者IP跟踪</h3>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            创建跟踪链接，自动记录访问者IP并检测异常行为
          </p>
        </div>
        <button
          onClick={() => setShowCreateForm(true)}
          className="flex items-center px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
        >
          <Plus className="h-4 w-4 mr-2" />
          创建跟踪链接
        </button>
      </div>

      {/* 创建链接表单 */}
      {showCreateForm && (
        <div className="bg-white dark:bg-gray-800 p-6 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700">
          <h4 className="font-semibold text-gray-800 dark:text-white mb-4">创建新的跟踪链接</h4>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                链接名称 *
              </label>
              <input
                type="text"
                value={newLink.link_name}
                onChange={(e) => setNewLink(prev => ({ ...prev, link_name: e.target.value }))}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder="例如：产品页面跟踪"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                重定向URL（可选）
              </label>
              <input
                type="url"
                value={newLink.target_url}
                onChange={(e) => setNewLink(prev => ({ ...prev, target_url: e.target.value }))}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder="https://example.com"
              />
            </div>
          </div>

          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              描述（可选）
            </label>
            <textarea
              value={newLink.description}
              onChange={(e) => setNewLink(prev => ({ ...prev, description: e.target.value }))}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              rows={3}
              placeholder="描述这个跟踪链接的用途..."
            />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div className="space-y-3">
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={newLink.collect_user_agent}
                  onChange={(e) => setNewLink(prev => ({ ...prev, collect_user_agent: e.target.checked }))}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-gray-700 dark:text-gray-300">收集User-Agent</span>
              </label>
              
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={newLink.collect_referrer}
                  onChange={(e) => setNewLink(prev => ({ ...prev, collect_referrer: e.target.checked }))}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-gray-700 dark:text-gray-300">收集Referrer</span>
              </label>
              
              <label className="flex items-center">
                <input
                  type="checkbox"
                  checked={newLink.alert_on_suspicious}
                  onChange={(e) => setNewLink(prev => ({ ...prev, alert_on_suspicious: e.target.checked }))}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
                <span className="ml-2 text-sm text-gray-700 dark:text-gray-300">可疑访问警报</span>
              </label>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                最大访问次数
              </label>
              <input
                type="number"
                value={newLink.max_visits}
                onChange={(e) => setNewLink(prev => ({ ...prev, max_visits: e.target.value }))}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder="无限制"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                过期时间
              </label>
              <input
                type="datetime-local"
                value={newLink.expires_at}
                onChange={(e) => setNewLink(prev => ({ ...prev, expires_at: e.target.value }))}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
          </div>

          <div className="flex space-x-3">
            <button
              onClick={createTrackingLink}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
            >
              创建链接
            </button>
            <button
              onClick={() => setShowCreateForm(false)}
              className="px-4 py-2 bg-gray-300 hover:bg-gray-400 text-gray-700 rounded-lg transition-colors"
            >
              取消
            </button>
          </div>
        </div>
      )}

      {/* 跟踪链接列表 */}
      {!selectedLink && (
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700">
          <div className="p-6 border-b border-gray-200 dark:border-gray-600">
            <h4 className="font-semibold text-gray-800 dark:text-white">我的跟踪链接</h4>
          </div>
          
          <div className="p-6">
            {isLoading ? (
              <div className="flex items-center justify-center py-8">
                <RefreshCw className="h-6 w-6 animate-spin text-blue-500 mr-2" />
                <span className="text-gray-600 dark:text-gray-300">加载中...</span>
              </div>
            ) : trackingLinks.length === 0 ? (
              <div className="text-center py-8">
                <Link className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-500 dark:text-gray-400">还没有创建任何跟踪链接</p>
                <button
                  onClick={() => setShowCreateForm(true)}
                  className="mt-4 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                >
                  创建第一个链接
                </button>
              </div>
            ) : (
              <div className="space-y-4">
                {trackingLinks.map((link) => (
                  <div key={link.id} className="border border-gray-200 dark:border-gray-600 rounded-lg p-4">
                    <div className="flex items-start justify-between mb-3">
                      <div className="flex-1">
                        <h5 className="font-semibold text-gray-800 dark:text-white">{link.link_name}</h5>
                        {link.description && (
                          <p className="text-sm text-gray-600 dark:text-gray-300 mt-1">{link.description}</p>
                        )}
                        <div className="flex items-center space-x-4 mt-2 text-xs text-gray-500">
                          <span>创建时间: {new Date(link.created_at).toLocaleString()}</span>
                          {link.expires_at && (
                            <span>过期时间: {new Date(link.expires_at).toLocaleString()}</span>
                          )}
                          <span className={`px-2 py-1 rounded ${link.is_active ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
                            {link.is_active ? '活跃' : '已停用'}
                          </span>
                        </div>
                      </div>
                      
                      <div className="flex space-x-2">
                        <button
                          onClick={() => copyTrackingLink(link.link_code)}
                          className="p-2 text-gray-500 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
                          title="复制链接"
                        >
                          <Copy className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => setSelectedLink(link)}
                          className="p-2 text-gray-500 hover:text-green-600 hover:bg-green-50 rounded-lg transition-colors"
                          title="查看详情"
                        >
                          <Eye className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => deleteTrackingLink(link.id)}
                          className="p-2 text-gray-500 hover:text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                          title="删除链接"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                    
                    <div className="bg-gray-50 dark:bg-gray-700 p-3 rounded-lg">
                      <div className="flex items-center justify-between">
                        <code className="text-sm font-mono text-blue-600 dark:text-blue-400">
                          {window.location.origin}/track/{link.link_code}
                        </code>
                        <a
                          href={`${window.location.origin}/track/${link.link_code}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-600 hover:text-blue-700"
                        >
                          <ExternalLink className="h-4 w-4" />
                        </a>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* 链接详情页面 */}
      {selectedLink && (
        <div className="space-y-6">
          {/* 返回按钮和链接信息 */}
          <div className="flex items-center justify-between">
            <button
              onClick={() => setSelectedLink(null)}
              className="flex items-center text-blue-600 hover:text-blue-700"
            >
              ← 返回链接列表
            </button>
            <div className="text-right">
              <h4 className="font-semibold text-gray-800 dark:text-white">{selectedLink.link_name}</h4>
              <code className="text-sm text-gray-500">
                {window.location.origin}/track/{selectedLink.link_code}
              </code>
            </div>
          </div>

          {/* 统计概览 */}
          {analytics && (
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow border border-gray-200 dark:border-gray-700">
                <div className="flex items-center">
                  <Eye className="h-5 w-5 text-blue-500 mr-2" />
                  <span className="font-semibold text-gray-800 dark:text-white">总访问量</span>
                </div>
                <div className="text-2xl font-bold text-blue-600 mt-1">{analytics.totalVisits}</div>
              </div>
              
              <div className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow border border-gray-200 dark:border-gray-700">
                <div className="flex items-center">
                  <Users className="h-5 w-5 text-green-500 mr-2" />
                  <span className="font-semibold text-gray-800 dark:text-white">独立访客</span>
                </div>
                <div className="text-2xl font-bold text-green-600 mt-1">{analytics.uniqueVisitors}</div>
              </div>
              
              <div className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow border border-gray-200 dark:border-gray-700">
                <div className="flex items-center">
                  <AlertTriangle className="h-5 w-5 text-red-500 mr-2" />
                  <span className="font-semibold text-gray-800 dark:text-white">可疑访问</span>
                </div>
                <div className="text-2xl font-bold text-red-600 mt-1">{analytics.suspiciousVisits}</div>
              </div>
              
              <div className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow border border-gray-200 dark:border-gray-700">
                <div className="flex items-center">
                  <Activity className="h-5 w-5 text-purple-500 mr-2" />
                  <span className="font-semibold text-gray-800 dark:text-white">异常检测</span>
                </div>
                <div className="text-2xl font-bold text-purple-600 mt-1">{anomalies.length}</div>
              </div>
            </div>
          )}

          {/* Tab 导航 */}
          <div className="flex space-x-1 bg-gray-100 dark:bg-gray-700 rounded-lg p-1">
            {[
              { key: 'logs', label: '访问记录', icon: Eye },
              { key: 'sessions', label: '访问会话', icon: Users },
              { key: 'anomalies', label: '异常检测', icon: AlertTriangle },
              { key: 'analytics', label: '数据分析', icon: BarChart3 }
            ].map(({ key, label, icon: Icon }) => (
              <button
                key={key}
                onClick={() => setActiveTab(key as any)}
                className={`flex-1 py-2 px-4 rounded-md font-medium transition-colors text-sm ${
                  activeTab === key
                    ? 'bg-white dark:bg-gray-800 text-blue-600 dark:text-blue-400 shadow-sm'
                    : 'text-gray-600 dark:text-gray-300 hover:text-gray-800 dark:hover:text-white'
                }`}
              >
                <Icon className="inline mr-1 h-4 w-4" />
                {label}
              </button>
            ))}
          </div>

          {/* Tab 内容 */}
          <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700">
            {activeTab === 'logs' && (
              <div className="p-6">
                <h5 className="font-semibold text-gray-800 dark:text-white mb-4">访问记录</h5>
                {visitorLogs.length === 0 ? (
                  <p className="text-gray-500 dark:text-gray-400 text-center py-8">暂无访问记录</p>
                ) : (
                  <div className="space-y-4">
                    {visitorLogs.map((log) => (
                      <div key={log.id} className="border border-gray-200 dark:border-gray-600 rounded-lg p-4">
                        <div className="flex items-start justify-between mb-3">
                          <div className="flex items-center space-x-3">
                            <Globe className="h-5 w-5 text-blue-500" />
                            <div>
                              <span className="font-mono font-semibold text-gray-800 dark:text-white">
                                {log.ip_address}
                              </span>
                              <div className="text-sm text-gray-600 dark:text-gray-300">
                                {log.city}, {log.country} | {log.isp}
                              </div>
                            </div>
                          </div>
                          
                          <div className="flex items-center space-x-2">
                            <span className={`px-2 py-1 rounded-full text-xs font-medium ${getThreatLevelColor(log.threat_level)}`}>
                              {log.threat_level === 'high' ? '高风险' : 
                               log.threat_level === 'medium' ? '中等风险' : 
                               log.threat_level === 'low' ? '低风险' : '未知'}
                            </span>
                            {log.is_suspicious && (
                              <span className="px-2 py-1 bg-red-100 text-red-700 rounded-full text-xs font-medium">
                                可疑
                              </span>
                            )}
                          </div>
                        </div>
                        
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                          <div>
                            <span className="text-gray-500">访问时间:</span>
                            <div className="font-medium">{new Date(log.created_at).toLocaleString()}</div>
                          </div>
                          <div>
                            <span className="text-gray-500">异常评分:</span>
                            <div className="font-medium">{log.anomaly_score}/100</div>
                          </div>
                          <div>
                            <span className="text-gray-500">页面浏览:</span>
                            <div className="font-medium">{log.page_views}</div>
                          </div>
                          <div>
                            <span className="text-gray-500">会话ID:</span>
                            <div className="font-mono text-xs">{log.session_id}</div>
                          </div>
                        </div>
                        
                        {log.risk_factors.length > 0 && (
                          <div className="mt-3">
                            <span className="text-sm text-gray-500">风险因素:</span>
                            <div className="flex flex-wrap gap-1 mt-1">
                              {log.risk_factors.map((factor, idx) => (
                                <span key={idx} className="px-2 py-1 bg-red-100 text-red-700 rounded text-xs">
                                  {factor}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {activeTab === 'sessions' && (
              <div className="p-6">
                <h5 className="font-semibold text-gray-800 dark:text-white mb-4">访问会话</h5>
                {visitorSessions.length === 0 ? (
                  <p className="text-gray-500 dark:text-gray-400 text-center py-8">暂无会话记录</p>
                ) : (
                  <div className="space-y-4">
                    {visitorSessions.map((session) => (
                      <div key={session.id} className="border border-gray-200 dark:border-gray-600 rounded-lg p-4">
                        <div className="flex items-start justify-between mb-3">
                          <div>
                            <span className="font-mono font-semibold text-gray-800 dark:text-white">
                              {session.ip_address}
                            </span>
                            <div className="text-sm text-gray-600 dark:text-gray-300">
                              会话ID: {session.session_id}
                            </div>
                          </div>
                          
                          {session.is_suspicious && (
                            <span className="px-2 py-1 bg-red-100 text-red-700 rounded-full text-xs font-medium">
                              可疑会话
                            </span>
                          )}
                        </div>
                        
                        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 text-sm">
                          <div>
                            <span className="text-gray-500">首次访问:</span>
                            <div className="font-medium">{new Date(session.first_visit).toLocaleString()}</div>
                          </div>
                          <div>
                            <span className="text-gray-500">最后访问:</span>
                            <div className="font-medium">{new Date(session.last_visit).toLocaleString()}</div>
                          </div>
                          <div>
                            <span className="text-gray-500">访问次数:</span>
                            <div className="font-medium">{session.total_visits}</div>
                          </div>
                          <div>
                            <span className="text-gray-500">页面浏览:</span>
                            <div className="font-medium">{session.total_page_views}</div>
                          </div>
                          <div>
                            <span className="text-gray-500">使用IP数:</span>
                            <div className="font-medium">{session.unique_ips.length}</div>
                          </div>
                        </div>
                        
                        <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                          <div>
                            <span className="text-gray-500">访问国家:</span>
                            <div className="font-medium">{session.countries.join(', ')}</div>
                          </div>
                          <div>
                            <span className="text-gray-500">使用IP:</span>
                            <div className="font-mono text-xs">{session.unique_ips.join(', ')}</div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {activeTab === 'anomalies' && (
              <div className="p-6">
                <h5 className="font-semibold text-gray-800 dark:text-white mb-4">异常检测结果</h5>
                {anomalies.length === 0 ? (
                  <p className="text-gray-500 dark:text-gray-400 text-center py-8">暂无异常检测结果</p>
                ) : (
                  <div className="space-y-4">
                    {anomalies.map((anomaly) => (
                      <div key={anomaly.id} className="border border-gray-200 dark:border-gray-600 rounded-lg p-4">
                        <div className="flex items-start justify-between mb-3">
                          <div>
                            <h6 className="font-semibold text-gray-800 dark:text-white">{anomaly.description}</h6>
                            <div className="text-sm text-gray-600 dark:text-gray-300">
                              类型: {anomaly.anomaly_type} | 置信度: {anomaly.confidence_score}%
                            </div>
                          </div>
                          
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(anomaly.severity)}`}>
                            {anomaly.severity === 'critical' ? '严重' :
                             anomaly.severity === 'high' ? '高' :
                             anomaly.severity === 'medium' ? '中' : '低'}
                          </span>
                        </div>
                        
                        <div className="text-sm text-gray-600 dark:text-gray-300">
                          检测时间: {new Date(anomaly.created_at).toLocaleString()}
                        </div>
                        
                        {anomaly.evidence && Object.keys(anomaly.evidence).length > 0 && (
                          <div className="mt-3 p-3 bg-gray-50 dark:bg-gray-700 rounded">
                            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">证据:</span>
                            <pre className="text-xs mt-1 text-gray-600 dark:text-gray-400">
                              {JSON.stringify(anomaly.evidence, null, 2)}
                            </pre>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {activeTab === 'analytics' && analytics && (
              <div className="p-6 space-y-6">
                <h5 className="font-semibold text-gray-800 dark:text-white">数据分析</h5>
                
                {/* 国家分布 */}
                <div>
                  <h6 className="font-medium text-gray-800 dark:text-white mb-3">访问国家分布</h6>
                  <div className="space-y-2">
                    {analytics.topCountries.slice(0, 10).map((country, idx) => (
                      <div key={idx} className="flex items-center justify-between">
                        <span className="text-sm text-gray-600 dark:text-gray-300">{country.country}</span>
                        <div className="flex items-center space-x-2">
                          <div className="w-32 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                            <div 
                              className="bg-blue-500 h-2 rounded-full"
                              style={{ width: `${(country.count / analytics.totalVisits) * 100}%` }}
                            ></div>
                          </div>
                          <span className="text-sm font-medium text-gray-800 dark:text-white w-8">
                            {country.count}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* ISP分布 */}
                <div>
                  <h6 className="font-medium text-gray-800 dark:text-white mb-3">ISP分布</h6>
                  <div className="space-y-2">
                    {analytics.topISPs.slice(0, 5).map((isp, idx) => (
                      <div key={idx} className="flex items-center justify-between">
                        <span className="text-sm text-gray-600 dark:text-gray-300 truncate">{isp.isp}</span>
                        <div className="flex items-center space-x-2">
                          <div className="w-24 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                            <div 
                              className="bg-green-500 h-2 rounded-full"
                              style={{ width: `${(isp.count / analytics.totalVisits) * 100}%` }}
                            ></div>
                          </div>
                          <span className="text-sm font-medium text-gray-800 dark:text-white w-8">
                            {isp.count}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* 威胁等级分布 */}
                <div>
                  <h6 className="font-medium text-gray-800 dark:text-white mb-3">威胁等级分布</h6>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {Object.entries(analytics.threatLevelDistribution).map(([level, count]) => (
                      <div key={level} className="text-center p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                        <div className={`text-2xl font-bold ${getThreatLevelColor(level).split(' ')[0]}`}>
                          {count}
                        </div>
                        <div className="text-sm text-gray-600 dark:text-gray-300">
                          {level === 'high' ? '高风险' : 
                           level === 'medium' ? '中等风险' : 
                           level === 'low' ? '低风险' : '未知'}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}