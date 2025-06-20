import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseAnonKey) {
  throw new Error('Missing Supabase environment variables');
}

export const supabase = createClient(supabaseUrl, supabaseAnonKey);

// 数据库类型定义
export interface IPAnalysisSession {
  id: string;
  user_id: string;
  session_name: string;
  total_ips: number;
  high_risk_count: number;
  medium_risk_count: number;
  low_risk_count: number;
  created_at: string;
  updated_at: string;
}

export interface IPAnalysisResult {
  id: string;
  session_id: string;
  ip_address: string;
  country?: string;
  country_code?: string;
  region?: string;
  city?: string;
  isp?: string;
  organization?: string;
  threat_level: 'low' | 'medium' | 'high' | 'unknown';
  risk_factors: string[];
  is_proxy: boolean;
  is_hosting: boolean;
  is_mobile: boolean;
  analysis_data: any;
  created_at: string;
}

export interface PerformanceDiagnostic {
  id: string;
  user_id: string;
  scan_name: string;
  cpu_usage?: number;
  cpu_temperature?: number;
  memory_usage?: number;
  memory_total_mb?: number;
  disk_usage?: number;
  disk_total_gb?: number;
  network_latency?: number;
  network_download_speed?: number;
  network_upload_speed?: number;
  issues_count: number;
  critical_issues: number;
  warning_issues: number;
  issues_detected: any[];
  system_metrics: any;
  recommendations: any[];
  created_at: string;
}

export interface ProgramAnalysisRecord {
  id: string;
  user_id: string;
  scan_session_id: string;
  program_name: string;
  version?: string;
  publisher?: string;
  install_date?: string;
  size_kb: number;
  category: 'system' | 'productivity' | 'gaming' | 'media' | 'development' | 'utility' | 'unknown';
  risk_level: 'safe' | 'caution' | 'risky' | 'unknown';
  recommendation: 'keep' | 'optional' | 'remove' | 'update';
  usage_frequency: 'high' | 'medium' | 'low' | 'never';
  last_used?: string;
  auto_start: boolean;
  system_impact: 'low' | 'medium' | 'high';
  analysis_reasons: string[];
  program_details: any;
  created_at: string;
  updated_at: string;
}

export interface DiagnosticSession {
  id: string;
  user_id: string;
  session_type: 'full_scan' | 'ip_analysis' | 'performance_check' | 'program_audit';
  session_name: string;
  status: 'running' | 'completed' | 'failed';
  total_issues: number;
  critical_issues: number;
  resolved_issues: number;
  session_summary: any;
  started_at: string;
  completed_at?: string;
  created_at: string;
}