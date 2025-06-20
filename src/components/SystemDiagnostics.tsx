import React, { useState } from 'react';
import { Search, AlertTriangle, CheckCircle, Info, Globe, Cpu, Mouse, Shield, Activity, Package, ExternalLink, Link as LinkIcon, Users, BarChart3 } from 'lucide-react';
import { IPAnalyzer } from './IPAnalyzer';
import { PerformanceDiagnostics } from './PerformanceDiagnostics';
import { ProgramAnalyzer } from './ProgramAnalyzer';
import { PublicIPQuery } from './PublicIPQuery';
import { VisitorTracking } from './VisitorTracking';
import type { User } from '@supabase/supabase-js';

interface SystemDiagnosticsProps {
  user: User;
}

interface SystemIssue {
  id: string;
  type: 'performance' | 'security' | 'hardware' | 'software';
  severity: 'low' | 'medium' | 'high';
  title: string;
  description: string;
  solution: string;
  detected: boolean;
}

export function SystemDiagnostics({ user }: SystemDiagnosticsProps) {
  const [ipAddresses, setIpAddresses] = useState('95.223.57.198\n95.223.70.174\n95.223.45.216');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [activeTab, setActiveTab] = useState<'public' | 'tracking' | 'ip' | 'performance' | 'programs' | 'ipanalyzer'>('public');

  const systemIssues: SystemIssue[] = [
    {
      id: '1',
      type: 'hardware',
      severity: 'high',
      title: '鼠标自动移动问题',
      description: '鼠标指针自动移动可能由以下原因造成：',
      solution: '1. 清洁鼠标传感器\n2. 更换鼠标垫\n3. 检查USB接口\n4. 更新鼠标驱动\n5. 检查是否存在恶意软件',
      detected: true
    },
    {
      id: '2',
      type: 'performance',
      severity: 'high',
      title: '系统卡顿问题',
      description: '系统卡顿经常出现的原因：',
      solution: '1. 内存不足 - 关闭不必要的程序\n2. 硬盘空间不足 - 清理垃圾文件\n3. 后台程序过多 - 禁用启动项\n4. 病毒感染 - 全盘杀毒\n5. 硬件老化 - 考虑升级',
      detected: true
    },
    {
      id: '3',
      type: 'security',
      severity: 'medium',
      title: '可疑网络连接',
      description: '检测到可疑IP连接，建议进行安全检查',
      solution: '1. 运行杀毒软件全盘扫描\n2. 检查防火墙设置\n3. 更新系统补丁\n4. 监控网络流量',
      detected: true
    }
  ];

  const analyzeIPs = async () => {
    setIsAnalyzing(true);
    await new Promise(resolve => setTimeout(resolve, 2000));
    setIsAnalyzing(false);
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'high':
        return <AlertTriangle className="h-5 w-5 text-red-500" />;
      case 'medium':
        return <Info className="h-5 w-5 text-yellow-500" />;
      case 'low':
        return <CheckCircle className="h-5 w-5 text-green-500" />;
      default:
        return <Info className="h-5 w-5 text-gray-500" />;
    }
  };

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow-lg">
      <h2 className="text-2xl font-bold text-gray-800 dark:text-white mb-4 flex items-center">
        <Search className="mr-2" />
        智能系统诊断
      </h2>

      {/* Tab 导航 */}
      <div className="flex space-x-1 bg-gray-100 dark:bg-gray-700 rounded-lg p-1 mb-6 overflow-x-auto">
        <button
          onClick={() => setActiveTab('public')}
          className={`flex-shrink-0 py-2 px-4 rounded-md font-medium transition-colors text-sm ${
            activeTab === 'public'
              ? 'bg-white dark:bg-gray-800 text-blue-600 dark:text-blue-400 shadow-sm'
              : 'text-gray-600 dark:text-gray-300 hover:text-gray-800 dark:hover:text-white'
          }`}
        >
          <Globe className="inline mr-1 h-4 w-4" />
          免费IP查询
        </button>
        <button
          onClick={() => setActiveTab('tracking')}
          className={`flex-shrink-0 py-2 px-4 rounded-md font-medium transition-colors text-sm ${
            activeTab === 'tracking'
              ? 'bg-white dark:bg-gray-800 text-blue-600 dark:text-blue-400 shadow-sm'
              : 'text-gray-600 dark:text-gray-300 hover:text-gray-800 dark:hover:text-white'
          }`}
        >
          <Users className="inline mr-1 h-4 w-4" />
          访客IP跟踪
        </button>
        <button
          onClick={() => setActiveTab('ip')}
          className={`flex-shrink-0 py-2 px-4 rounded-md font-medium transition-colors text-sm ${
            activeTab === 'ip'
              ? 'bg-white dark:bg-gray-800 text-blue-600 dark:text-blue-400 shadow-sm'
              : 'text-gray-600 dark:text-gray-300 hover:text-gray-800 dark:hover:text-white'
          }`}
        >
          <BarChart3 className="inline mr-1 h-4 w-4" />
          批量IP分析
        </button>
        <button
          onClick={() => setActiveTab('performance')}
          className={`flex-shrink-0 py-2 px-4 rounded-md font-medium transition-colors text-sm ${
            activeTab === 'performance'
              ? 'bg-white dark:bg-gray-800 text-blue-600 dark:text-blue-400 shadow-sm'
              : 'text-gray-600 dark:text-gray-300 hover:text-gray-800 dark:hover:text-white'
          }`}
        >
          <Activity className="inline mr-1 h-4 w-4" />
          性能诊断
        </button>
        <button
          onClick={() => setActiveTab('programs')}
          className={`flex-shrink-0 py-2 px-4 rounded-md font-medium transition-colors text-sm ${
            activeTab === 'programs'
              ? 'bg-white dark:bg-gray-800 text-blue-600 dark:text-blue-400 shadow-sm'
              : 'text-gray-600 dark:text-gray-300 hover:text-gray-800 dark:hover:text-white'
          }`}
        >
          <Package className="inline mr-1 h-4 w-4" />
          程序分析
        </button>
        <button
          onClick={() => setActiveTab('ipanalyzer')}
          className={`flex-shrink-0 py-2 px-4 rounded-md font-medium transition-colors text-sm ${
            activeTab === 'ipanalyzer'
              ? 'bg-white dark:bg-gray-800 text-blue-600 dark:text-blue-400 shadow-sm'
              : 'text-gray-600 dark:text-gray-300 hover:text-gray-800 dark:hover:text-white'
          }`}
        >
          <Shield className="inline mr-1 h-4 w-4" />
          高级IP分析
        </button>
      </div>

      {/* 功能说明 */}
      <div className="mb-6 p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
        <h3 className="font-semibold text-blue-800 dark:text-blue-200 mb-2">功能说明</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 text-sm text-blue-700 dark:text-blue-300">
          <div className="flex items-start space-x-2">
            <Globe className="h-4 w-4 mt-0.5 flex-shrink-0" />
            <div>
              <span className="font-medium">免费IP查询：</span>
              <span className="block text-xs">无需登录，快速查询单个或多个IP地址信息</span>
            </div>
          </div>
          <div className="flex items-start space-x-2">
            <Users className="h-4 w-4 mt-0.5 flex-shrink-0" />
            <div>
              <span className="font-medium">访客IP跟踪：</span>
              <span className="block text-xs">创建跟踪链接，自动记录访问者IP和行为</span>
            </div>
          </div>
          <div className="flex items-start space-x-2">
            <BarChart3 className="h-4 w-4 mt-0.5 flex-shrink-0" />
            <div>
              <span className="font-medium">批量IP分析：</span>
              <span className="block text-xs">简单的批量IP查询和基础威胁评估</span>
            </div>
          </div>
          <div className="flex items-start space-x-2">
            <Activity className="h-4 w-4 mt-0.5 flex-shrink-0" />
            <div>
              <span className="font-medium">性能诊断：</span>
              <span className="block text-xs">检测系统性能问题和硬件状态</span>
            </div>
          </div>
          <div className="flex items-start space-x-2">
            <Package className="h-4 w-4 mt-0.5 flex-shrink-0" />
            <div>
              <span className="font-medium">程序分析：</span>
              <span className="block text-xs">分析已安装程序的安全性和必要性</span>
            </div>
          </div>
          <div className="flex items-start space-x-2">
            <Shield className="h-4 w-4 mt-0.5 flex-shrink-0" />
            <div>
              <span className="font-medium">高级IP分析：</span>
              <span className="block text-xs">深度IP分析，包含历史记录和高级威胁检测</span>
            </div>
          </div>
        </div>
      </div>

      {/* 免费IP查询选项卡 */}
      {activeTab === 'public' && <PublicIPQuery />}

      {/* 访客IP跟踪选项卡 */}
      {activeTab === 'tracking' && <VisitorTracking user={user} />}

      {/* 批量IP分析选项卡 */}
      {activeTab === 'ip' && (
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              输入要分析的 IP 地址（每行一个）：
            </label>
            <textarea
              value={ipAddresses}
              onChange={(e) => setIpAddresses(e.target.value)}
              placeholder="95.223.57.198&#10;95.223.70.174&#10;95.223.45.216"
              className="w-full h-24 p-3 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-white"
            />
          </div>
          <button
            onClick={analyzeIPs}
            disabled={isAnalyzing || !ipAddresses.trim()}
            className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white font-bold py-2 px-4 rounded-lg transition-colors"
          >
            {isAnalyzing ? '分析中...' : '开始分析'}
          </button>
          <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
            <h4 className="font-semibold text-blue-800 dark:text-blue-200 mb-2">IP关联性分析：</h4>
            <p className="text-sm text-blue-700 dark:text-blue-300">
              检测到的IP地址都属于95.223.xx网段，这表明它们可能来自同一个ISP或地理区域。建议进行以下操作：
            </p>
            <ul className="list-disc list-inside text-sm text-blue-700 dark:text-blue-300 mt-2">
              <li>检查防火墙日志确认连接来源</li>
              <li>运行杀毒软件全盘扫描</li>
              <li>监控网络流量是否异常</li>
              <li>考虑临时阻止这些IP段</li>
            </ul>
          </div>
        </div>
      )}

      {/* 性能诊断选项卡 */}
      {activeTab === 'performance' && <PerformanceDiagnostics user={user} />}

      {/* 程序分析选项卡 */}
      {activeTab === 'programs' && <ProgramAnalyzer user={user} />}

      {/* 高级IP分析器选项卡 */}
      {activeTab === 'ipanalyzer' && <IPAnalyzer user={user} />}
    </div>
  );
}