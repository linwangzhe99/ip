import { supabase } from './supabase';
import type { 
  IPAnalysisSession, 
  IPAnalysisResult, 
  PerformanceDiagnostic, 
  ProgramAnalysisRecord,
  DiagnosticSession 
} from './supabase';

// IP分析相关数据库操作
export class IPAnalysisDB {
  // 创建新的IP分析会话
  static async createSession(sessionName: string = '未命名会话'): Promise<IPAnalysisSession | null> {
    const { data, error } = await supabase
      .from('ip_analysis_sessions')
      .insert([{ session_name: sessionName }])
      .select()
      .single();

    if (error) {
      console.error('创建IP分析会话失败:', error);
      return null;
    }
    return data;
  }

  // 保存IP分析结果
  static async saveResults(sessionId: string, results: any[]): Promise<boolean> {
    const formattedResults = results.map(result => ({
      session_id: sessionId,
      ip_address: result.query,
      country: result.country,
      country_code: result.countryCode,
      region: result.regionName,
      city: result.city,
      isp: result.isp,
      organization: result.org,
      threat_level: result.threat,
      risk_factors: result.riskFactors || [],
      is_proxy: result.proxy || false,
      is_hosting: result.hosting || false,
      is_mobile: result.mobile || false,
      analysis_data: result
    }));

    const { error } = await supabase
      .from('ip_analysis_results')
      .insert(formattedResults);

    if (error) {
      console.error('保存IP分析结果失败:', error);
      return false;
    }

    // 更新会话统计
    const threatCounts = results.reduce((acc, result) => {
      acc[result.threat] = (acc[result.threat] || 0) + 1;
      return acc;
    }, {});

    await supabase
      .from('ip_analysis_sessions')
      .update({
        total_ips: results.length,
        high_risk_count: threatCounts.high || 0,
        medium_risk_count: threatCounts.medium || 0,
        low_risk_count: threatCounts.low || 0,
        updated_at: new Date().toISOString()
      })
      .eq('id', sessionId);

    return true;
  }

  // 获取所有IP分析会话列表（全局共享）
  static async getAllSessions(): Promise<IPAnalysisSession[]> {
    const { data, error } = await supabase
      .from('ip_analysis_sessions')
      .select(`
        *,
        user:auth.users(email)
      `)
      .order('created_at', { ascending: false })
      .limit(100);

    if (error) {
      console.error('获取IP分析会话失败:', error);
      return [];
    }
    return data || [];
  }

  // 获取用户自己的IP分析会话列表
  static async getUserSessions(): Promise<IPAnalysisSession[]> {
    const { data, error } = await supabase
      .from('ip_analysis_sessions')
      .select('*')
      .eq('user_id', (await supabase.auth.getUser()).data.user?.id)
      .order('created_at', { ascending: false });

    if (error) {
      console.error('获取用户IP分析会话失败:', error);
      return [];
    }
    return data || [];
  }

  // 获取会话的分析结果
  static async getSessionResults(sessionId: string): Promise<IPAnalysisResult[]> {
    const { data, error } = await supabase
      .from('ip_analysis_results')
      .select('*')
      .eq('session_id', sessionId)
      .order('created_at', { ascending: false });

    if (error) {
      console.error('获取IP分析结果失败:', error);
      return [];
    }
    return data || [];
  }

  // 删除会话及其结果（仅限创建者）
  static async deleteSession(sessionId: string): Promise<boolean> {
    const { error } = await supabase
      .from('ip_analysis_sessions')
      .delete()
      .eq('id', sessionId)
      .eq('user_id', (await supabase.auth.getUser()).data.user?.id);

    if (error) {
      console.error('删除IP分析会话失败:', error);
      return false;
    }
    return true;
  }
}

// 性能诊断相关数据库操作
export class PerformanceDB {
  // 保存性能诊断结果
  static async saveDiagnostic(
    scanName: string,
    metrics: any,
    issues: any[],
    userId: string
  ): Promise<PerformanceDiagnostic | null> {
    const criticalIssues = issues.filter(issue => issue.type === 'critical').length;
    const warningIssues = issues.filter(issue => issue.type === 'warning').length;

    const { data, error } = await supabase
      .from('performance_diagnostics')
      .insert([{
        user_id: userId,
        scan_name: scanName,
        cpu_usage: metrics.cpu?.usage,
        cpu_temperature: metrics.cpu?.temperature,
        memory_usage: metrics.memory?.usage,
        memory_total_mb: metrics.memory?.total,
        disk_usage: metrics.disk?.usage,
        disk_total_gb: Math.round(metrics.disk?.total / 1024),
        network_latency: metrics.network?.latency,
        network_download_speed: metrics.network?.downloadSpeed,
        network_upload_speed: metrics.network?.uploadSpeed,
        issues_count: issues.length,
        critical_issues: criticalIssues,
        warning_issues: warningIssues,
        issues_detected: issues,
        system_metrics: metrics,
        recommendations: [] // 可以添加推荐建议
      }])
      .select()
      .single();

    if (error) {
      console.error('保存性能诊断失败:', error);
      return null;
    }
    return data;
  }

  // 获取所有性能诊断历史（全局共享）
  static async getAllDiagnostics(): Promise<PerformanceDiagnostic[]> {
    const { data, error } = await supabase
      .from('performance_diagnostics')
      .select(`
        *,
        user:auth.users(email)
      `)
      .order('created_at', { ascending: false })
      .limit(100);

    if (error) {
      console.error('获取性能诊断历史失败:', error);
      return [];
    }
    return data || [];
  }

  // 获取用户的性能诊断历史
  static async getUserDiagnostics(): Promise<PerformanceDiagnostic[]> {
    const { data, error } = await supabase
      .from('performance_diagnostics')
      .select('*')
      .eq('user_id', (await supabase.auth.getUser()).data.user?.id)
      .order('created_at', { ascending: false })
      .limit(50);

    if (error) {
      console.error('获取性能诊断历史失败:', error);
      return [];
    }
    return data || [];
  }

  // 获取性能趋势数据
  static async getPerformanceTrends(days: number = 30): Promise<PerformanceDiagnostic[]> {
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const { data, error } = await supabase
      .from('performance_diagnostics')
      .select('*')
      .gte('created_at', startDate.toISOString())
      .order('created_at', { ascending: true });

    if (error) {
      console.error('获取性能趋势失败:', error);
      return [];
    }
    return data || [];
  }
}

// 程序分析相关数据库操作
export class ProgramAnalysisDB {
  // 保存程序分析结果
  static async saveAnalysis(programs: any[], userId: string, scanSessionId?: string): Promise<boolean> {
    const sessionId = scanSessionId || crypto.randomUUID();
    
    const formattedPrograms = programs.map(program => ({
      user_id: userId,
      scan_session_id: sessionId,
      program_name: program.name,
      version: program.version,
      publisher: program.publisher,
      install_date: program.installDate,
      size_kb: program.size,
      category: program.category,
      risk_level: program.riskLevel,
      recommendation: program.recommendation,
      usage_frequency: program.usageFrequency,
      last_used: program.lastUsed,
      auto_start: program.autoStart,
      system_impact: program.systemImpact,
      analysis_reasons: program.reasons || [],
      program_details: {
        description: program.description,
        usageFrequency: program.usageFrequency,
        lastUsed: program.lastUsed
      }
    }));

    const { error } = await supabase
      .from('program_analysis')
      .insert(formattedPrograms);

    if (error) {
      console.error('保存程序分析失败:', error);
      return false;
    }
    return true;
  }

  // 获取所有程序分析记录（全局共享）
  static async getAllAnalysis(): Promise<ProgramAnalysisRecord[]> {
    const { data, error } = await supabase
      .from('program_analysis')
      .select(`
        *,
        user:auth.users(email)
      `)
      .order('created_at', { ascending: false })
      .limit(500);

    if (error) {
      console.error('获取程序分析记录失败:', error);
      return [];
    }
    return data || [];
  }

  // 获取用户的程序分析记录
  static async getUserAnalysis(): Promise<ProgramAnalysisRecord[]> {
    const { data, error } = await supabase
      .from('program_analysis')
      .select('*')
      .eq('user_id', (await supabase.auth.getUser()).data.user?.id)
      .order('created_at', { ascending: false });

    if (error) {
      console.error('获取程序分析记录失败:', error);
      return [];
    }
    return data || [];
  }

  // 获取特定扫描会话的程序
  static async getSessionPrograms(scanSessionId: string): Promise<ProgramAnalysisRecord[]> {
    const { data, error } = await supabase
      .from('program_analysis')
      .select('*')
      .eq('scan_session_id', scanSessionId)
      .order('program_name');

    if (error) {
      console.error('获取会话程序失败:', error);
      return [];
    }
    return data || [];
  }

  // 获取风险程序统计
  static async getRiskStatistics(): Promise<any> {
    const { data, error } = await supabase
      .from('program_analysis')
      .select('risk_level, recommendation')
      .order('created_at', { ascending: false })
      .limit(1000);

    if (error) {
      console.error('获取风险统计失败:', error);
      return null;
    }

    const stats = data.reduce((acc, program) => {
      acc.riskLevels[program.risk_level] = (acc.riskLevels[program.risk_level] || 0) + 1;
      acc.recommendations[program.recommendation] = (acc.recommendations[program.recommendation] || 0) + 1;
      return acc;
    }, { riskLevels: {}, recommendations: {} });

    return stats;
  }

  // 更新程序状态（仅限创建者）
  static async updateProgramStatus(programId: string, updates: Partial<ProgramAnalysisRecord>): Promise<boolean> {
    const { error } = await supabase
      .from('program_analysis')
      .update(updates)
      .eq('id', programId)
      .eq('user_id', (await supabase.auth.getUser()).data.user?.id);

    if (error) {
      console.error('更新程序状态失败:', error);
      return false;
    }
    return true;
  }
}

// 诊断会话管理
export class DiagnosticSessionDB {
  // 创建诊断会话
  static async createSession(
    sessionType: DiagnosticSession['session_type'],
    sessionName: string
  ): Promise<DiagnosticSession | null> {
    const { data, error } = await supabase
      .from('diagnostic_sessions')
      .insert([{
        session_type: sessionType,
        session_name: sessionName,
        status: 'running'
      }])
      .select()
      .single();

    if (error) {
      console.error('创建诊断会话失败:', error);
      return null;
    }
    return data;
  }

  // 完成诊断会话
  static async completeSession(
    sessionId: string,
    summary: any,
    totalIssues: number = 0,
    criticalIssues: number = 0
  ): Promise<boolean> {
    const { error } = await supabase
      .from('diagnostic_sessions')
      .update({
        status: 'completed',
        completed_at: new Date().toISOString(),
        total_issues: totalIssues,
        critical_issues: criticalIssues,
        session_summary: summary
      })
      .eq('id', sessionId);

    if (error) {
      console.error('完成诊断会话失败:', error);
      return false;
    }
    return true;
  }

  // 获取所有诊断会话历史（全局共享）
  static async getAllSessions(): Promise<DiagnosticSession[]> {
    const { data, error } = await supabase
      .from('diagnostic_sessions')
      .select(`
        *,
        user:auth.users(email)
      `)
      .order('created_at', { ascending: false })
      .limit(100);

    if (error) {
      console.error('获取诊断会话历史失败:', error);
      return [];
    }
    return data || [];
  }

  // 获取用户的诊断会话历史
  static async getUserSessions(): Promise<DiagnosticSession[]> {
    const { data, error } = await supabase
      .from('diagnostic_sessions')
      .select('*')
      .eq('user_id', (await supabase.auth.getUser()).data.user?.id)
      .order('created_at', { ascending: false })
      .limit(100);

    if (error) {
      console.error('获取诊断会话历史失败:', error);
      return [];
    }
    return data || [];
  }
}