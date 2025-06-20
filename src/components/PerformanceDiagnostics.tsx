import React, { useState, useEffect } from 'react';
import { Cpu, HardDrive, MemoryStick as Memory, Wifi, Battery, Thermometer, AlertTriangle, CheckCircle, Info, RefreshCw, Monitor, Zap, Activity, Clock, TrendingUp, Settings, History, Trash2 } from 'lucide-react';
import { PerformanceDB } from '../lib/database';
import type { User } from '@supabase/supabase-js';
import type { PerformanceDiagnostic } from '../lib/supabase';

interface SystemMetrics {
  cpu: {
    usage: number;
    temperature: number;
    cores: number;
    frequency: number;
  };
  memory: {
    total: number;
    used: number;
    available: number;
    usage: number;
  };
  disk: {
    total: number;
    used: number;
    free: number;
    usage: number;
  };
  network: {
    downloadSpeed: number;
    uploadSpeed: number;
    latency: number;
    packetsLost: number;
  };
  battery?: {
    level: number;
    charging: boolean;
    timeRemaining: number;
  };
}

interface PerformanceIssue {
  id: string;
  type: 'critical' | 'warning' | 'info';
  category: 'cpu' | 'memory' | 'disk' | 'network' | 'system';
  title: string;
  description: string;
  impact: string;
  solutions: string[];
  autoFixAvailable: boolean;
}

interface PerformanceDiagnosticsProps {
  user: User;
}

export function PerformanceDiagnostics({ user }: PerformanceDiagnosticsProps) {
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [issues, setIssues] = useState<PerformanceIssue[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [lastScanTime, setLastScanTime] = useState<Date | null>(null);
  const [diagnosticHistory, setDiagnosticHistory] = useState<PerformanceDiagnostic[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [trends, setTrends] = useState<PerformanceDiagnostic[]>([]);

  // 模拟系统指标获取
  const getSystemMetrics = async (): Promise<SystemMetrics> => {
    // 模拟API调用延迟
    await new Promise(resolve => setTimeout(resolve, 1500));
    
    return {
      cpu: {
        usage: Math.random() * 100,
        temperature: 45 + Math.random() * 30,
        cores: 8,
        frequency: 2.4 + Math.random() * 1.6
      },
      memory: {
        total: 16384,
        used: 8192 + Math.random() * 4096,
        available: 8192 - Math.random() * 4096,
        usage: 50 + Math.random() * 40
      },
      disk: {
        total: 512000,
        used: 256000 + Math.random() * 128000,
        free: 256000 - Math.random() * 128000,
        usage: 50 + Math.random() * 30
      },
      network: {
        downloadSpeed: 50 + Math.random() * 100,
        uploadSpeed: 10 + Math.random() * 50,
        latency: 10 + Math.random() * 40,
        packetsLost: Math.random() * 2
      },
      battery: Math.random() > 0.5 ? {
        level: Math.random() * 100,
        charging: Math.random() > 0.5,
        timeRemaining: Math.random() * 480
      } : undefined
    };
  };

  // 分析性能问题
  const analyzePerformanceIssues = (metrics: SystemMetrics): PerformanceIssue[] => {
    const issues: PerformanceIssue[] = [];

    // CPU 相关问题
    if (metrics.cpu.usage > 80) {
      issues.push({
        id: 'high-cpu',
        type: 'critical',
        category: 'cpu',
        title: 'CPU使用率过高',
        description: `CPU使用率达到 ${metrics.cpu.usage.toFixed(1)}%，可能导致系统卡顿`,
        impact: '系统响应缓慢，程序启动延迟，可能出现卡死现象',
        solutions: [
          '打开任务管理器，结束占用CPU最高的进程',
          '禁用不必要的启动项',
          '运行磁盘清理工具',
          '检查是否有病毒或恶意软件',
          '考虑升级CPU或增加散热'
        ],
        autoFixAvailable: true
      });
    }

    if (metrics.cpu.temperature > 70) {
      issues.push({
        id: 'high-temp',
        type: 'warning',
        category: 'cpu',
        title: 'CPU温度过高',
        description: `CPU温度达到 ${metrics.cpu.temperature.toFixed(1)}°C，可能影响性能`,
        impact: 'CPU可能降频运行，系统性能下降，长期高温可能损坏硬件',
        solutions: [
          '清理CPU散热器灰尘',
          '检查散热风扇是否正常工作',
          '重新涂抹导热硅脂',
          '改善机箱通风',
          '降低CPU超频设置'
        ],
        autoFixAvailable: false
      });
    }

    // 内存相关问题
    if (metrics.memory.usage > 85) {
      issues.push({
        id: 'high-memory',
        type: 'critical',
        category: 'memory',
        title: '内存使用率过高',
        description: `内存使用率达到 ${metrics.memory.usage.toFixed(1)}%，系统可能开始使用虚拟内存`,
        impact: '系统运行缓慢，程序可能崩溃或无响应',
        solutions: [
          '关闭不必要的程序和浏览器标签页',
          '重启系统释放内存',
          '禁用内存占用大的启动项',
          '运行内存诊断工具',
          '考虑增加物理内存'
        ],
        autoFixAvailable: true
      });
    }

    // 磁盘相关问题
    if (metrics.disk.usage > 90) {
      issues.push({
        id: 'disk-full',
        type: 'critical',
        category: 'disk',
        title: '磁盘空间不足',
        description: `磁盘使用率达到 ${metrics.disk.usage.toFixed(1)}%，可能影响系统性能`,
        impact: '系统运行缓慢，无法安装新程序，可能导致系统崩溃',
        solutions: [
          '运行磁盘清理工具删除临时文件',
          '卸载不需要的程序',
          '清空回收站',
          '移动大文件到外部存储',
          '使用存储感知功能自动清理'
        ],
        autoFixAvailable: true
      });
    }

    // 网络相关问题
    if (metrics.network.latency > 100) {
      issues.push({
        id: 'high-latency',
        type: 'warning',
        category: 'network',
        title: '网络延迟过高',
        description: `网络延迟达到 ${metrics.network.latency.toFixed(0)}ms，可能影响网络体验`,
        impact: '网页加载缓慢，在线游戏卡顿，视频通话质量差',
        solutions: [
          '重启路由器和调制解调器',
          '检查网络电缆连接',
          '更新网络驱动程序',
          '关闭占用带宽的程序',
          '联系网络服务提供商'
        ],
        autoFixAvailable: false
      });
    }

    if (metrics.network.packetsLost > 1) {
      issues.push({
        id: 'packet-loss',
        type: 'warning',
        category: 'network',
        title: '网络丢包严重',
        description: `网络丢包率达到 ${metrics.network.packetsLost.toFixed(1)}%`,
        impact: '网络连接不稳定，数据传输可能中断',
        solutions: [
          '检查网络电缆是否损坏',
          '重启网络设备',
          '更新网络驱动程序',
          '检查网络设备是否过热',
          '联系网络服务提供商检查线路'
        ],
        autoFixAvailable: false
      });
    }

    return issues;
  };

  const runDiagnostics = async () => {
    setIsScanning(true);
    try {
      const systemMetrics = await getSystemMetrics();
      const detectedIssues = analyzePerformanceIssues(systemMetrics);
      
      setMetrics(systemMetrics);
      setIssues(detectedIssues);
      setLastScanTime(new Date());

      // 保存到数据库
      const scanName = `性能扫描 - ${new Date().toLocaleString()}`;
      await PerformanceDB.saveDiagnostic(scanName, systemMetrics, detectedIssues, user.id);
      
      // 刷新历史记录
      loadDiagnosticHistory();
    } catch (error) {
      console.error('诊断失败:', error);
    } finally {
      setIsScanning(false);
    }
  };

  // 加载诊断历史
  const loadDiagnosticHistory = async () => {
    try {
      const history = await PerformanceDB.getUserDiagnostics();
      setDiagnosticHistory(history);
    } catch (error) {
      console.error('加载诊断历史失败:', error);
    }
  };

  // 加载性能趋势
  const loadPerformanceTrends = async () => {
    try {
      const trendData = await PerformanceDB.getPerformanceTrends(30);
      setTrends(trendData);
    } catch (error) {
      console.error('加载性能趋势失败:', error);
    }
  };

  // 删除历史记录
  const deleteHistoryRecord = async (recordId: string) => {
    // 这里需要在数据库类中添加删除方法
    // 暂时从本地状态中移除
    setDiagnosticHistory(prev => prev.filter(record => record.id !== recordId));
  };

  const getIssueIcon = (type: string) => {
    switch (type) {
      case 'critical':
        return <AlertTriangle className="h-5 w-5 text-red-500" />;
      case 'warning':
        return <Info className="h-5 w-5 text-yellow-500" />;
      case 'info':
        return <CheckCircle className="h-5 w-5 text-blue-500" />;
      default:
        return <Info className="h-5 w-5 text-gray-500" />;
    }
  };

  const getUsageColor = (usage: number) => {
    if (usage > 90) return 'bg-red-500';
    if (usage > 70) return 'bg-yellow-500';
    return 'bg-green-500';
  };

  const formatBytes = (bytes: number) => {
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    if (bytes === 0) return '0 B';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
  };

  const formatTime = (minutes: number) => {
    const hours = Math.floor(minutes / 60);
    const mins = Math.floor(minutes % 60);
    return `${hours}小时${mins}分钟`;
  };

  useEffect(() => {
    runDiagnostics();
    loadDiagnosticHistory();
    loadPerformanceTrends();
  }, []);

  return (
    <div className="space-y-6">
      {/* 扫描控制 */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-xl font-bold text-gray-800 dark:text-white">系统性能诊断</h3>
          {lastScanTime && (
            <p className="text-sm text-gray-500 dark:text-gray-400">
              上次扫描: {lastScanTime.toLocaleString()}
            </p>
          )}
        </div>
        <div className="flex space-x-2">
          <button
            onClick={() => setShowHistory(!showHistory)}
            className="flex items-center px-3 py-2 bg-gray-100 hover:bg-gray-200 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 rounded-lg text-sm transition-colors"
          >
            <History className="h-4 w-4 mr-2" />
            {showHistory ? '隐藏历史' : '显示历史'}
          </button>
          <button
            onClick={runDiagnostics}
            disabled={isScanning}
            className="flex items-center px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white rounded-lg transition-colors"
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${isScanning ? 'animate-spin' : ''}`} />
            {isScanning ? '扫描中...' : '重新扫描'}
          </button>
        </div>
      </div>

      {/* 历史记录 */}
      {showHistory && (
        <div className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700">
          <h4 className="font-semibold text-gray-800 dark:text-white mb-3">诊断历史</h4>
          <div className="space-y-2 max-h-60 overflow-y-auto">
            {diagnosticHistory.map((record) => (
              <div key={record.id} className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded border">
                <div className="flex-1">
                  <div className="font-medium text-sm">{record.scan_name}</div>
                  <div className="text-xs text-gray-500 space-x-4">
                    <span>CPU: {record.cpu_usage?.toFixed(1)}%</span>
                    <span>内存: {record.memory_usage?.toFixed(1)}%</span>
                    <span>磁盘: {record.disk_usage?.toFixed(1)}%</span>
                    <span>问题: {record.issues_count}</span>
                    <span>{new Date(record.created_at).toLocaleString()}</span>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  {record.critical_issues > 0 && (
                    <span className="px-2 py-1 bg-red-100 text-red-700 rounded text-xs">
                      {record.critical_issues} 严重
                    </span>
                  )}
                  {record.warning_issues > 0 && (
                    <span className="px-2 py-1 bg-yellow-100 text-yellow-700 rounded text-xs">
                      {record.warning_issues} 警告
                    </span>
                  )}
                  <button
                    onClick={() => deleteHistoryRecord(record.id)}
                    className="p-1 text-red-500 hover:bg-red-100 rounded"
                  >
                    <Trash2 className="h-3 w-3" />
                  </button>
                </div>
              </div>
            ))}
            {diagnosticHistory.length === 0 && (
              <div className="text-center py-4 text-gray-500">暂无诊断历史</div>
            )}
          </div>
        </div>
      )}

      {/* 性能趋势图表 */}
      {trends.length > 0 && (
        <div className="bg-white dark:bg-gray-800 p-6 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700">
          <h4 className="font-semibold text-gray-800 dark:text-white mb-4 flex items-center">
            <TrendingUp className="h-5 w-5 mr-2" />
            30天性能趋势
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-600">
                {trends.reduce((sum, t) => sum + (t.cpu_usage || 0), 0) / trends.length}%
              </div>
              <div className="text-sm text-gray-500">平均CPU使用率</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-green-600">
                {trends.reduce((sum, t) => sum + (t.memory_usage || 0), 0) / trends.length}%
              </div>
              <div className="text-sm text-gray-500">平均内存使用率</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-purple-600">
                {trends.reduce((sum, t) => sum + (t.issues_count || 0), 0)}
              </div>
              <div className="text-sm text-gray-500">总检测问题数</div>
            </div>
          </div>
        </div>
      )}

      {/* 系统指标概览 */}
      {metrics && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* CPU */}
          <div className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center">
                <Cpu className="h-5 w-5 text-blue-500 mr-2" />
                <span className="font-semibold text-gray-800 dark:text-white">CPU</span>
              </div>
              <span className="text-sm text-gray-500">{metrics.cpu.cores}核</span>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span className="text-gray-600 dark:text-gray-300">使用率</span>
                <span className="font-medium">{metrics.cpu.usage.toFixed(1)}%</span>
              </div>
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                <div 
                  className={`h-2 rounded-full ${getUsageColor(metrics.cpu.usage)}`}
                  style={{ width: `${metrics.cpu.usage}%` }}
                ></div>
              </div>
              <div className="flex justify-between text-xs text-gray-500">
                <span>温度: {metrics.cpu.temperature.toFixed(0)}°C</span>
                <span>频率: {metrics.cpu.frequency.toFixed(1)}GHz</span>
              </div>
            </div>
          </div>

          {/* 内存 */}
          <div className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center">
                <Memory className="h-5 w-5 text-green-500 mr-2" />
                <span className="font-semibold text-gray-800 dark:text-white">内存</span>
              </div>
              <span className="text-sm text-gray-500">{formatBytes(metrics.memory.total * 1024 * 1024)}</span>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span className="text-gray-600 dark:text-gray-300">使用率</span>
                <span className="font-medium">{metrics.memory.usage.toFixed(1)}%</span>
              </div>
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                <div 
                  className={`h-2 rounded-full ${getUsageColor(metrics.memory.usage)}`}
                  style={{ width: `${metrics.memory.usage}%` }}
                ></div>
              </div>
              <div className="flex justify-between text-xs text-gray-500">
                <span>已用: {formatBytes(metrics.memory.used * 1024 * 1024)}</span>
                <span>可用: {formatBytes(metrics.memory.available * 1024 * 1024)}</span>
              </div>
            </div>
          </div>

          {/* 磁盘 */}
          <div className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center">
                <HardDrive className="h-5 w-5 text-purple-500 mr-2" />
                <span className="font-semibold text-gray-800 dark:text-white">磁盘</span>
              </div>
              <span className="text-sm text-gray-500">{formatBytes(metrics.disk.total * 1024 * 1024)}</span>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span className="text-gray-600 dark:text-gray-300">使用率</span>
                <span className="font-medium">{metrics.disk.usage.toFixed(1)}%</span>
              </div>
              <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                <div 
                  className={`h-2 rounded-full ${getUsageColor(metrics.disk.usage)}`}
                  style={{ width: `${metrics.disk.usage}%` }}
                ></div>
              </div>
              <div className="flex justify-between text-xs text-gray-500">
                <span>已用: {formatBytes(metrics.disk.used * 1024 * 1024)}</span>
                <span>可用: {formatBytes(metrics.disk.free * 1024 * 1024)}</span>
              </div>
            </div>
          </div>

          {/* 网络 */}
          <div className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center">
                <Wifi className="h-5 w-5 text-orange-500 mr-2" />
                <span className="font-semibold text-gray-800 dark:text-white">网络</span>
              </div>
              <span className="text-sm text-gray-500">{metrics.network.latency.toFixed(0)}ms</span>
            </div>
            <div className="space-y-2">
              <div className="flex justify-between text-xs text-gray-500">
                <span>下载: {metrics.network.downloadSpeed.toFixed(1)} Mbps</span>
                <span>上传: {metrics.network.uploadSpeed.toFixed(1)} Mbps</span>
              </div>
              <div className="flex justify-between text-xs text-gray-500">
                <span>延迟: {metrics.network.latency.toFixed(0)}ms</span>
                <span>丢包: {metrics.network.packetsLost.toFixed(1)}%</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 电池信息（如果有） */}
      {metrics?.battery && (
        <div className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center">
              <Battery className="h-5 w-5 text-green-500 mr-2" />
              <span className="font-semibold text-gray-800 dark:text-white">电池状态</span>
            </div>
            <span className={`text-sm px-2 py-1 rounded ${metrics.battery.charging ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}`}>
              {metrics.battery.charging ? '充电中' : '使用电池'}
            </span>
          </div>
          <div className="grid grid-cols-3 gap-4 text-sm">
            <div>
              <span className="text-gray-600 dark:text-gray-300">电量</span>
              <div className="font-medium">{metrics.battery.level.toFixed(0)}%</div>
            </div>
            <div>
              <span className="text-gray-600 dark:text-gray-300">剩余时间</span>
              <div className="font-medium">{formatTime(metrics.battery.timeRemaining)}</div>
            </div>
            <div>
              <span className="text-gray-600 dark:text-gray-300">状态</span>
              <div className="font-medium">{metrics.battery.charging ? '充电' : '放电'}</div>
            </div>
          </div>
        </div>
      )}

      {/* 问题列表 */}
      {issues.length > 0 ? (
        <div className="space-y-4">
          <h4 className="text-lg font-semibold text-gray-800 dark:text-white flex items-center">
            <AlertTriangle className="h-5 w-5 text-red-500 mr-2" />
            检测到 {issues.length} 个性能问题
          </h4>
          
          {issues.map((issue) => (
            <div key={issue.id} className="bg-white dark:bg-gray-800 p-6 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700">
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center space-x-3">
                  {getIssueIcon(issue.type)}
                  <div>
                    <h5 className="font-semibold text-gray-800 dark:text-white">{issue.title}</h5>
                    <p className="text-sm text-gray-600 dark:text-gray-300">{issue.description}</p>
                  </div>
                </div>
                {issue.autoFixAvailable && (
                  <button className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors">
                    自动修复
                  </button>
                )}
              </div>
              
              <div className="mb-4 p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                <h6 className="font-medium text-gray-800 dark:text-white mb-1">影响:</h6>
                <p className="text-sm text-gray-600 dark:text-gray-300">{issue.impact}</p>
              </div>
              
              <div>
                <h6 className="font-medium text-gray-800 dark:text-white mb-2">解决方案:</h6>
                <ul className="space-y-1">
                  {issue.solutions.map((solution, index) => (
                    <li key={index} className="flex items-start text-sm text-gray-600 dark:text-gray-300">
                      <span className="inline-block w-2 h-2 bg-blue-500 rounded-full mt-2 mr-3 flex-shrink-0"></span>
                      {solution}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          ))}
        </div>
      ) : metrics ? (
        <div className="bg-green-50 dark:bg-green-900/20 p-6 rounded-xl border border-green-200 dark:border-green-800">
          <div className="flex items-center">
            <CheckCircle className="h-6 w-6 text-green-500 mr-3" />
            <div>
              <h4 className="font-semibold text-green-800 dark:text-green-200">系统运行良好</h4>
              <p className="text-sm text-green-700 dark:text-green-300">未检测到严重的性能问题，系统运行状态正常。</p>
            </div>
          </div>
        </div>
      ) : null}

      {/* 性能优化建议 */}
      <div className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 p-6 rounded-xl border border-blue-200 dark:border-blue-800">
        <h4 className="font-bold text-blue-800 dark:text-blue-200 mb-3 flex items-center">
          <TrendingUp className="mr-2 h-5 w-5" />
          性能优化建议
        </h4>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <h5 className="font-semibold text-blue-700 dark:text-blue-300 mb-2">日常维护</h5>
            <ul className="list-disc list-inside text-sm text-blue-700 dark:text-blue-300 space-y-1">
              <li>定期重启系统释放内存</li>
              <li>清理临时文件和垃圾文件</li>
              <li>更新系统和驱动程序</li>
              <li>运行磁盘碎片整理</li>
            </ul>
          </div>
          <div>
            <h5 className="font-semibold text-blue-700 dark:text-blue-300 mb-2">硬件优化</h5>
            <ul className="list-disc list-inside text-sm text-blue-700 dark:text-blue-300 space-y-1">
              <li>清理机箱内部灰尘</li>
              <li>检查硬盘健康状态</li>
              <li>监控系统温度</li>
              <li>考虑升级内存或SSD</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}