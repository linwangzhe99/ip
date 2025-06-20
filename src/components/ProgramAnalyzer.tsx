import React, { useState, useEffect } from 'react';
import { 
  Package, 
  Trash2, 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Info, 
  Search,
  Filter,
  Download,
  Clock,
  HardDrive,
  Zap,
  Eye,
  Settings,
  RefreshCw,
  History,
  BarChart3
} from 'lucide-react';
import { ProgramAnalysisDB } from '../lib/database';
import type { User } from '@supabase/supabase-js';
import type { ProgramAnalysisRecord } from '../lib/supabase';

interface InstalledProgram {
  id: string;
  name: string;
  version: string;
  publisher: string;
  installDate: string;
  size: number;
  category: 'system' | 'productivity' | 'gaming' | 'media' | 'development' | 'utility' | 'unknown';
  riskLevel: 'safe' | 'caution' | 'risky' | 'unknown';
  recommendation: 'keep' | 'optional' | 'remove' | 'update';
  description: string;
  usageFrequency: 'high' | 'medium' | 'low' | 'never';
  lastUsed: string;
  autoStart: boolean;
  systemImpact: 'low' | 'medium' | 'high';
  reasons: string[];
  isDuplicate?: boolean;
  lastScanDate?: string;
}

interface ProgramCategory {
  name: string;
  count: number;
  totalSize: number;
  riskCount: number;
}

interface ProgramAnalyzerProps {
  user: User;
}

export function ProgramAnalyzer({ user }: ProgramAnalyzerProps) {
  const [programs, setPrograms] = useState<InstalledProgram[]>([]);
  const [filteredPrograms, setFilteredPrograms] = useState<InstalledProgram[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterCategory, setFilterCategory] = useState<string>('all');
  const [filterRisk, setFilterRisk] = useState<string>('all');
  const [sortBy, setSortBy] = useState<'name' | 'size' | 'date' | 'risk'>('name');
  const [categories, setCategories] = useState<ProgramCategory[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [analysisHistory, setAnalysisHistory] = useState<ProgramAnalysisRecord[]>([]);
  const [filterDuplicates, setFilterDuplicates] = useState(true);
  const [duplicatePrograms, setDuplicatePrograms] = useState<Set<string>>(new Set());

  // 模拟程序数据
  const mockPrograms: InstalledProgram[] = [
    {
      id: '1',
      name: 'ASUS Aura Sync',
      version: '1.07.84',
      publisher: 'ASUSTeK Computer Inc.',
      installDate: '2024-01-15',
      size: 245760, // KB
      category: 'utility',
      riskLevel: 'safe',
      recommendation: 'optional',
      description: 'RGB灯效控制软件，用于控制华硕主板和显卡的RGB灯效',
      usageFrequency: 'low',
      lastUsed: '2024-01-20',
      autoStart: true,
      systemImpact: 'low',
      reasons: ['占用系统资源较少', '如不使用RGB功能可以卸载', '开机自启动']
    },
    {
      id: '2',
      name: 'GameSDK Service',
      version: '2.1.0',
      publisher: 'Unknown Publisher',
      installDate: '2024-02-01',
      size: 512000,
      category: 'gaming',
      riskLevel: 'caution',
      recommendation: 'remove',
      description: '游戏SDK服务，可能与某些游戏相关',
      usageFrequency: 'never',
      lastUsed: '从未使用',
      autoStart: true,
      systemImpact: 'medium',
      reasons: ['未知发布者', '占用系统资源', '开机自启动', '可能不必要']
    },
    {
      id: '3',
      name: 'Microsoft Visual C++ 2019 Redistributable',
      version: '14.29.30133',
      publisher: 'Microsoft Corporation',
      installDate: '2024-01-10',
      size: 25600,
      category: 'system',
      riskLevel: 'safe',
      recommendation: 'keep',
      description: 'Microsoft Visual C++ 运行库，许多程序需要此组件',
      usageFrequency: 'high',
      lastUsed: '系统组件',
      autoStart: false,
      systemImpact: 'low',
      reasons: ['系统必需组件', '多个程序依赖', '来自可信发布者']
    },
    {
      id: '4',
      name: 'CCleaner',
      version: '6.09.10300',
      publisher: 'Piriform Ltd',
      installDate: '2024-01-25',
      size: 102400,
      category: 'utility',
      riskLevel: 'caution',
      recommendation: 'update',
      description: '系统清理工具，可清理垃圾文件和注册表',
      usageFrequency: 'medium',
      lastUsed: '2024-01-30',
      autoStart: false,
      systemImpact: 'low',
      reasons: ['版本较旧', '建议更新到最新版本', '有用的清理工具']
    },
    {
      id: '5',
      name: 'Suspicious Optimizer Pro',
      version: '1.0.0',
      publisher: 'Unknown',
      installDate: '2024-02-10',
      size: 1024000,
      category: 'utility',
      riskLevel: 'risky',
      recommendation: 'remove',
      description: '可疑的系统优化软件',
      usageFrequency: 'low',
      lastUsed: '2024-02-10',
      autoStart: true,
      systemImpact: 'high',
      reasons: ['未知发布者', '可能是恶意软件', '占用大量系统资源', '强烈建议删除']
    },
    {
      id: '6',
      name: 'Google Chrome',
      version: '120.0.6099.129',
      publisher: 'Google LLC',
      installDate: '2024-01-05',
      size: 307200,
      category: 'productivity',
      riskLevel: 'safe',
      recommendation: 'keep',
      description: 'Google Chrome 网络浏览器',
      usageFrequency: 'high',
      lastUsed: '2024-02-15',
      autoStart: false,
      systemImpact: 'medium',
      reasons: ['常用浏览器', '来自可信发布者', '定期更新']
    },
    {
      id: '7',
      name: 'Adobe Flash Player',
      version: '32.0.0.465',
      publisher: 'Adobe Inc.',
      installDate: '2023-12-01',
      size: 51200,
      category: 'media',
      riskLevel: 'risky',
      recommendation: 'remove',
      description: 'Adobe Flash Player 插件（已停止支持）',
      usageFrequency: 'never',
      lastUsed: '2023-12-01',
      autoStart: false,
      systemImpact: 'low',
      reasons: ['已停止安全更新', '存在安全风险', '现代浏览器不再支持', '建议立即卸载']
    },
    {
      id: '8',
      name: 'Steam',
      version: '3.4.1.0',
      publisher: 'Valve Corporation',
      installDate: '2024-01-12',
      size: 2048000,
      category: 'gaming',
      riskLevel: 'safe',
      recommendation: 'keep',
      description: 'Steam 游戏平台客户端',
      usageFrequency: 'high',
      lastUsed: '2024-02-14',
      autoStart: true,
      systemImpact: 'medium',
      reasons: ['游戏平台', '来自可信发布者', '经常使用']
    },
    // 添加一些重复程序用于测试
    {
      id: '9',
      name: 'Google Chrome',
      version: '119.0.6045.199',
      publisher: 'Google LLC',
      installDate: '2023-12-15',
      size: 295000,
      category: 'productivity',
      riskLevel: 'safe',
      recommendation: 'remove',
      description: 'Google Chrome 网络浏览器（旧版本）',
      usageFrequency: 'never',
      lastUsed: '2023-12-20',
      autoStart: false,
      systemImpact: 'low',
      reasons: ['重复安装', '版本过旧', '建议卸载保留最新版本'],
      isDuplicate: true
    }
  ];

  // 检查重复程序
  const checkDuplicates = async (programs: InstalledProgram[]): Promise<InstalledProgram[]> => {
    const duplicates = new Set<string>();
    const programNames = new Map<string, InstalledProgram[]>();
    
    // 按程序名分组
    programs.forEach(program => {
      const name = program.name.toLowerCase();
      if (!programNames.has(name)) {
        programNames.set(name, []);
      }
      programNames.get(name)!.push(program);
    });
    
    // 标记重复程序
    const result = programs.map(program => {
      const name = program.name.toLowerCase();
      const sameNamePrograms = programNames.get(name) || [];
      
      if (sameNamePrograms.length > 1) {
        // 如果有多个相同名称的程序，标记除了最新版本外的其他版本为重复
        const sortedByDate = sameNamePrograms.sort((a, b) => 
          new Date(b.installDate).getTime() - new Date(a.installDate).getTime()
        );
        
        if (program.id !== sortedByDate[0].id) {
          duplicates.add(program.name);
          return { ...program, isDuplicate: true };
        }
      }
      
      return program;
    });
    
    setDuplicatePrograms(duplicates);
    return result;
  };

  const scanPrograms = async () => {
    setIsScanning(true);
    // 模拟扫描延迟
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // 检查重复程序
    const programsWithDuplicates = await checkDuplicates(mockPrograms);
    
    setPrograms(programsWithDuplicates);
    setFilteredPrograms(programsWithDuplicates);
    
    // 计算分类统计
    const categoryStats: { [key: string]: ProgramCategory } = {};
    programsWithDuplicates.forEach(program => {
      if (!categoryStats[program.category]) {
        categoryStats[program.category] = {
          name: program.category,
          count: 0,
          totalSize: 0,
          riskCount: 0
        };
      }
      categoryStats[program.category].count++;
      categoryStats[program.category].totalSize += program.size;
      if (program.riskLevel === 'risky' || program.riskLevel === 'caution') {
        categoryStats[program.category].riskCount++;
      }
    });
    
    setCategories(Object.values(categoryStats));
    
    // 保存到数据库
    try {
      await ProgramAnalysisDB.saveAnalysis(programsWithDuplicates, user.id);
      loadAnalysisHistory();
    } catch (error) {
      console.error('保存程序分析失败:', error);
    }
    
    setIsScanning(false);
  };

  // 加载分析历史
  const loadAnalysisHistory = async () => {
    try {
      const history = await ProgramAnalysisDB.getUserAnalysis();
      setAnalysisHistory(history);
    } catch (error) {
      console.error('加载分析历史失败:', error);
    }
  };

  const filterPrograms = () => {
    let filtered = programs;

    // 过滤重复程序
    if (filterDuplicates) {
      filtered = filtered.filter(program => !program.isDuplicate);
    }

    // 搜索过滤
    if (searchTerm) {
      filtered = filtered.filter(program => 
        program.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        program.publisher.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    // 分类过滤
    if (filterCategory !== 'all') {
      filtered = filtered.filter(program => program.category === filterCategory);
    }

    // 风险等级过滤
    if (filterRisk !== 'all') {
      filtered = filtered.filter(program => program.riskLevel === filterRisk);
    }

    // 排序
    filtered.sort((a, b) => {
      switch (sortBy) {
        case 'size':
          return b.size - a.size;
        case 'date':
          return new Date(b.installDate).getTime() - new Date(a.installDate).getTime();
        case 'risk':
          const riskOrder = { 'risky': 3, 'caution': 2, 'unknown': 1, 'safe': 0 };
          return riskOrder[b.riskLevel] - riskOrder[a.riskLevel];
        default:
          return a.name.localeCompare(b.name);
      }
    });

    setFilteredPrograms(filtered);
  };

  useEffect(() => {
    filterPrograms();
  }, [searchTerm, filterCategory, filterRisk, sortBy, programs, filterDuplicates]);

  useEffect(() => {
    scanPrograms();
    loadAnalysisHistory();
  }, []);

  const getRiskIcon = (riskLevel: string) => {
    switch (riskLevel) {
      case 'risky':
        return <AlertTriangle className="h-4 w-4 text-red-500" />;
      case 'caution':
        return <Info className="h-4 w-4 text-yellow-500" />;
      case 'safe':
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      default:
        return <Shield className="h-4 w-4 text-gray-500" />;
    }
  };

  const getRecommendationBadge = (recommendation: string) => {
    const badges = {
      'keep': 'bg-green-100 text-green-800 border-green-200',
      'optional': 'bg-blue-100 text-blue-800 border-blue-200',
      'remove': 'bg-red-100 text-red-800 border-red-200',
      'update': 'bg-yellow-100 text-yellow-800 border-yellow-200'
    };
    
    const labels = {
      'keep': '保留',
      'optional': '可选',
      'remove': '删除',
      'update': '更新'
    };

    return (
      <span className={`px-2 py-1 rounded-full text-xs font-medium border ${badges[recommendation as keyof typeof badges]}`}>
        {labels[recommendation as keyof typeof labels]}
      </span>
    );
  };

  const formatSize = (sizeKB: number) => {
    if (sizeKB < 1024) return `${sizeKB} KB`;
    if (sizeKB < 1024 * 1024) return `${(sizeKB / 1024).toFixed(1)} MB`;
    return `${(sizeKB / (1024 * 1024)).toFixed(1)} GB`;
  };

  const getCategoryName = (category: string) => {
    const names = {
      'system': '系统组件',
      'productivity': '生产力工具',
      'gaming': '游戏相关',
      'media': '媒体播放',
      'development': '开发工具',
      'utility': '实用工具',
      'unknown': '未知类别'
    };
    return names[category as keyof typeof names] || category;
  };

  return (
    <div className="space-y-6">
      {/* 扫描控制和统计 */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-xl font-bold text-gray-800 dark:text-white">程序分析管理</h3>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            分析已安装程序，识别不必要、重复或有风险的软件
          </p>
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
            onClick={scanPrograms}
            disabled={isScanning}
            className="flex items-center px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white rounded-lg transition-colors"
          >
            <RefreshCw className={`h-4 w-4 mr-2 ${isScanning ? 'animate-spin' : ''}`} />
            {isScanning ? '扫描中...' : '重新扫描'}
          </button>
        </div>
      </div>

      {/* 分析历史 */}
      {showHistory && (
        <div className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700">
          <h4 className="font-semibold text-gray-800 dark:text-white mb-3 flex items-center">
            <BarChart3 className="h-5 w-5 mr-2" />
            分析历史统计
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div className="text-center p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
              <div className="text-2xl font-bold text-blue-600">{analysisHistory.length}</div>
              <div className="text-sm text-blue-700 dark:text-blue-300">总扫描次数</div>
            </div>
            <div className="text-center p-3 bg-red-50 dark:bg-red-900/20 rounded-lg">
              <div className="text-2xl font-bold text-red-600">
                {analysisHistory.filter(p => p.risk_level === 'risky').length}
              </div>
              <div className="text-sm text-red-700 dark:text-red-300">高风险程序</div>
            </div>
            <div className="text-center p-3 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
              <div className="text-2xl font-bold text-orange-600">{duplicatePrograms.size}</div>
              <div className="text-sm text-orange-700 dark:text-orange-300">重复程序</div>
            </div>
          </div>
          
          <div className="space-y-2 max-h-40 overflow-y-auto">
            {analysisHistory.slice(0, 10).map((record) => (
              <div key={record.id} className="flex items-center justify-between p-2 bg-gray-50 dark:bg-gray-700 rounded border text-sm">
                <div className="flex-1">
                  <span className="font-medium">{record.program_name}</span>
                  <span className="text-gray-500 ml-2">v{record.version}</span>
                </div>
                <div className="flex items-center space-x-2">
                  {getRiskIcon(record.risk_level)}
                  {getRecommendationBadge(record.recommendation)}
                  <span className="text-xs text-gray-500">
                    {new Date(record.created_at).toLocaleDateString()}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 统计概览 */}
      {programs.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <div className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700">
            <div className="flex items-center">
              <Package className="h-5 w-5 text-blue-500 mr-2" />
              <span className="font-semibold text-gray-800 dark:text-white">总程序数</span>
            </div>
            <div className="text-2xl font-bold text-blue-600 dark:text-blue-400 mt-1">
              {programs.length}
            </div>
          </div>
          <div className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700">
            <div className="flex items-center">
              <AlertTriangle className="h-5 w-5 text-red-500 mr-2" />
              <span className="font-semibold text-gray-800 dark:text-white">高风险</span>
            </div>
            <div className="text-2xl font-bold text-red-600 dark:text-red-400 mt-1">
              {programs.filter(p => p.riskLevel === 'risky').length}
            </div>
          </div>
          <div className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700">
            <div className="flex items-center">
              <Trash2 className="h-5 w-5 text-orange-500 mr-2" />
              <span className="font-semibold text-gray-800 dark:text-white">建议删除</span>
            </div>
            <div className="text-2xl font-bold text-orange-600 dark:text-orange-400 mt-1">
              {programs.filter(p => p.recommendation === 'remove').length}
            </div>
          </div>
          <div className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700">
            <div className="flex items-center">
              <RefreshCw className="h-5 w-5 text-purple-500 mr-2" />
              <span className="font-semibold text-gray-800 dark:text-white">重复程序</span>
            </div>
            <div className="text-2xl font-bold text-purple-600 dark:text-purple-400 mt-1">
              {programs.filter(p => p.isDuplicate).length}
            </div>
          </div>
          <div className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700">
            <div className="flex items-center">
              <HardDrive className="h-5 w-5 text-green-500 mr-2" />
              <span className="font-semibold text-gray-800 dark:text-white">总占用</span>
            </div>
            <div className="text-2xl font-bold text-green-600 dark:text-green-400 mt-1">
              {formatSize(programs.reduce((sum, p) => sum + p.size, 0))}
            </div>
          </div>
        </div>
      )}

      {/* 搜索和过滤 */}
      <div className="bg-white dark:bg-gray-800 p-4 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700">
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
            <input
              type="text"
              placeholder="搜索程序名称或发布者..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
          
          <select
            value={filterCategory}
            onChange={(e) => setFilterCategory(e.target.value)}
            className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          >
            <option value="all">所有分类</option>
            <option value="system">系统组件</option>
            <option value="productivity">生产力工具</option>
            <option value="gaming">游戏相关</option>
            <option value="media">媒体播放</option>
            <option value="development">开发工具</option>
            <option value="utility">实用工具</option>
            <option value="unknown">未知类别</option>
          </select>
          
          <select
            value={filterRisk}
            onChange={(e) => setFilterRisk(e.target.value)}
            className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          >
            <option value="all">所有风险等级</option>
            <option value="safe">安全</option>
            <option value="caution">注意</option>
            <option value="risky">高风险</option>
            <option value="unknown">未知</option>
          </select>
          
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as any)}
            className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          >
            <option value="name">按名称排序</option>
            <option value="size">按大小排序</option>
            <option value="date">按安装日期排序</option>
            <option value="risk">按风险等级排序</option>
          </select>

          <label className="flex items-center space-x-2">
            <input
              type="checkbox"
              checked={filterDuplicates}
              onChange={(e) => setFilterDuplicates(e.target.checked)}
              className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            />
            <span className="text-sm text-gray-700 dark:text-gray-300">过滤重复</span>
          </label>
        </div>
      </div>

      {/* 程序列表 */}
      {isScanning ? (
        <div className="flex items-center justify-center py-12">
          <RefreshCw className="h-8 w-8 animate-spin text-blue-500 mr-3" />
          <span className="text-lg text-gray-600 dark:text-gray-300">正在扫描已安装程序...</span>
        </div>
      ) : (
        <div className="space-y-4">
          {filteredPrograms.map((program) => (
            <div key={program.id} className={`bg-white dark:bg-gray-800 p-6 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700 ${program.isDuplicate ? 'ring-2 ring-orange-300' : ''}`}>
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-start space-x-4">
                  <div className="flex-shrink-0">
                    {getRiskIcon(program.riskLevel)}
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center space-x-3 mb-2">
                      <h4 className="font-semibold text-gray-800 dark:text-white text-lg">{program.name}</h4>
                      {getRecommendationBadge(program.recommendation)}
                      {program.autoStart && (
                        <span className="px-2 py-1 bg-orange-100 text-orange-800 border border-orange-200 rounded-full text-xs font-medium">
                          开机启动
                        </span>
                      )}
                      {program.isDuplicate && (
                        <span className="px-2 py-1 bg-red-100 text-red-800 border border-red-200 rounded-full text-xs font-medium">
                          🔄 重复程序
                        </span>
                      )}
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm text-gray-600 dark:text-gray-300 mb-3">
                      <div>
                        <span className="font-medium">版本:</span> {program.version}
                      </div>
                      <div>
                        <span className="font-medium">发布者:</span> {program.publisher}
                      </div>
                      <div>
                        <span className="font-medium">大小:</span> {formatSize(program.size)}
                      </div>
                      <div>
                        <span className="font-medium">安装日期:</span> {program.installDate}
                      </div>
                    </div>
                    <p className="text-sm text-gray-600 dark:text-gray-300 mb-3">{program.description}</p>
                  </div>
                </div>
                <div className="flex space-x-2">
                  <button className="px-3 py-1 bg-gray-100 hover:bg-gray-200 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 rounded-lg text-sm transition-colors">
                    详情
                  </button>
                  {program.recommendation === 'remove' && (
                    <button className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm transition-colors">
                      卸载
                    </button>
                  )}
                  {program.recommendation === 'update' && (
                    <button className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm transition-colors">
                      更新
                    </button>
                  )}
                </div>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                <div className="flex items-center text-sm">
                  <Eye className="h-4 w-4 text-gray-400 mr-2" />
                  <span className="text-gray-600 dark:text-gray-300">使用频率:</span>
                  <span className="ml-2 font-medium">{
                    program.usageFrequency === 'high' ? '经常' :
                    program.usageFrequency === 'medium' ? '偶尔' :
                    program.usageFrequency === 'low' ? '很少' : '从未'
                  }</span>
                </div>
                <div className="flex items-center text-sm">
                  <Clock className="h-4 w-4 text-gray-400 mr-2" />
                  <span className="text-gray-600 dark:text-gray-300">最后使用:</span>
                  <span className="ml-2 font-medium">{program.lastUsed}</span>
                </div>
                <div className="flex items-center text-sm">
                  <Zap className="h-4 w-4 text-gray-400 mr-2" />
                  <span className="text-gray-600 dark:text-gray-300">系统影响:</span>
                  <span className={`ml-2 font-medium ${
                    program.systemImpact === 'high' ? 'text-red-600' :
                    program.systemImpact === 'medium' ? 'text-yellow-600' : 'text-green-600'
                  }`}>
                    {program.systemImpact === 'high' ? '高' :
                     program.systemImpact === 'medium' ? '中' : '低'}
                  </span>
                </div>
              </div>
              
              {program.reasons.length > 0 && (
                <div className="bg-gray-50 dark:bg-gray-700 p-3 rounded-lg">
                  <h5 className="font-medium text-gray-800 dark:text-white mb-2">分析原因:</h5>
                  <ul className="space-y-1">
                    {program.reasons.map((reason, index) => (
                      <li key={index} className="flex items-start text-sm text-gray-600 dark:text-gray-300">
                        <span className="inline-block w-1.5 h-1.5 bg-blue-500 rounded-full mt-2 mr-2 flex-shrink-0"></span>
                        {reason}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ))}
          
          {filteredPrograms.length === 0 && !isScanning && (
            <div className="text-center py-12">
              <Package className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-500 dark:text-gray-400">没有找到匹配的程序</p>
            </div>
          )}
        </div>
      )}

      {/* 批量操作建议 */}
      {programs.length > 0 && (
        <div className="bg-gradient-to-r from-orange-50 to-red-50 dark:from-orange-900/20 dark:to-red-900/20 p-6 rounded-xl border border-orange-200 dark:border-orange-800">
          <h4 className="font-bold text-orange-800 dark:text-orange-200 mb-3 flex items-center">
            <AlertTriangle className="mr-2 h-5 w-5" />
            智能清理建议
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <h5 className="font-semibold text-orange-700 dark:text-orange-300 mb-2">立即删除</h5>
              <ul className="list-disc list-inside text-sm text-orange-700 dark:text-orange-300 space-y-1">
                {programs.filter(p => p.recommendation === 'remove').slice(0, 3).map(p => (
                  <li key={p.id}>{p.name} - {p.reasons[0]}</li>
                ))}
                {programs.filter(p => p.recommendation === 'remove').length > 3 && (
                  <li>还有 {programs.filter(p => p.recommendation === 'remove').length - 3} 个程序...</li>
                )}
              </ul>
            </div>
            <div>
              <h5 className="font-semibold text-orange-700 dark:text-orange-300 mb-2">重复程序</h5>
              <ul className="list-disc list-inside text-sm text-orange-700 dark:text-orange-300 space-y-1">
                {programs.filter(p => p.isDuplicate).slice(0, 3).map(p => (
                  <li key={p.id}>{p.name} - 重复安装</li>
                ))}
                {programs.filter(p => p.isDuplicate).length > 3 && (
                  <li>还有 {programs.filter(p => p.isDuplicate).length - 3} 个重复程序...</li>
                )}
              </ul>
            </div>
            <div>
              <h5 className="font-semibold text-orange-700 dark:text-orange-300 mb-2">需要更新</h5>
              <ul className="list-disc list-inside text-sm text-orange-700 dark:text-orange-300 space-y-1">
                {programs.filter(p => p.recommendation === 'update').slice(0, 3).map(p => (
                  <li key={p.id}>{p.name} - 版本过旧</li>
                ))}
                {programs.filter(p => p.recommendation === 'update').length > 3 && (
                  <li>还有 {programs.filter(p => p.recommendation === 'update').length - 3} 个程序...</li>
                )}
              </ul>
            </div>
          </div>
          <div className="mt-4 flex flex-wrap gap-3">
            <button className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm transition-colors">
              批量卸载危险程序 ({programs.filter(p => p.recommendation === 'remove').length})
            </button>
            <button className="px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded-lg text-sm transition-colors">
              清理重复程序 ({programs.filter(p => p.isDuplicate).length})
            </button>
            <button className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm transition-colors">
              批量更新过期程序 ({programs.filter(p => p.recommendation === 'update').length})
            </button>
          </div>
          
          <div className="mt-4 p-3 bg-white dark:bg-gray-800 rounded-lg">
            <h6 className="font-semibold text-gray-800 dark:text-white mb-2">预计释放空间:</h6>
            <div className="text-2xl font-bold text-green-600">
              {formatSize(
                programs
                  .filter(p => p.recommendation === 'remove' || p.isDuplicate)
                  .reduce((sum, p) => sum + p.size, 0)
              )}
            </div>
            <p className="text-sm text-gray-600 dark:text-gray-300 mt-1">
              通过清理不必要和重复的程序可释放的磁盘空间
            </p>
          </div>
        </div>
      )}
    </div>
  );
}