/*
  # 系统诊断中心数据库架构

  1. 新建表
    - `ip_analysis_sessions` - IP分析会话记录
      - `id` (uuid, 主键)
      - `user_id` (uuid, 外键到auth.users)
      - `session_name` (text, 会话名称)
      - `created_at` (timestamp)
      - `updated_at` (timestamp)
    
    - `ip_analysis_results` - IP分析结果
      - `id` (uuid, 主键)
      - `session_id` (uuid, 外键到ip_analysis_sessions)
      - `ip_address` (text, IP地址)
      - `country` (text, 国家)
      - `city` (text, 城市)
      - `isp` (text, ISP信息)
      - `threat_level` (text, 威胁等级)
      - `risk_factors` (jsonb, 风险因素)
      - `analysis_data` (jsonb, 完整分析数据)
      - `created_at` (timestamp)
    
    - `performance_diagnostics` - 性能诊断记录
      - `id` (uuid, 主键)
      - `user_id` (uuid, 外键到auth.users)
      - `cpu_usage` (numeric, CPU使用率)
      - `memory_usage` (numeric, 内存使用率)
      - `disk_usage` (numeric, 磁盘使用率)
      - `network_latency` (numeric, 网络延迟)
      - `issues_detected` (jsonb, 检测到的问题)
      - `system_metrics` (jsonb, 完整系统指标)
      - `created_at` (timestamp)
    
    - `program_analysis` - 程序分析记录
      - `id` (uuid, 主键)
      - `user_id` (uuid, 外键到auth.users)
      - `program_name` (text, 程序名称)
      - `version` (text, 版本)
      - `publisher` (text, 发布者)
      - `size_kb` (bigint, 程序大小KB)
      - `risk_level` (text, 风险等级)
      - `recommendation` (text, 建议操作)
      - `analysis_reasons` (jsonb, 分析原因)
      - `created_at` (timestamp)
      - `updated_at` (timestamp)

  2. 安全设置
    - 为所有表启用行级安全(RLS)
    - 添加用户只能访问自己数据的策略
*/

-- IP分析会话表
CREATE TABLE IF NOT EXISTS ip_analysis_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE,
  session_name text NOT NULL DEFAULT '未命名会话',
  total_ips integer DEFAULT 0,
  high_risk_count integer DEFAULT 0,
  medium_risk_count integer DEFAULT 0,
  low_risk_count integer DEFAULT 0,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

-- IP分析结果表
CREATE TABLE IF NOT EXISTS ip_analysis_results (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id uuid REFERENCES ip_analysis_sessions(id) ON DELETE CASCADE,
  ip_address text NOT NULL,
  country text,
  country_code text,
  region text,
  city text,
  isp text,
  organization text,
  threat_level text CHECK (threat_level IN ('low', 'medium', 'high', 'unknown')) DEFAULT 'unknown',
  risk_factors jsonb DEFAULT '[]'::jsonb,
  is_proxy boolean DEFAULT false,
  is_hosting boolean DEFAULT false,
  is_mobile boolean DEFAULT false,
  analysis_data jsonb DEFAULT '{}'::jsonb,
  created_at timestamptz DEFAULT now()
);

-- 性能诊断记录表
CREATE TABLE IF NOT EXISTS performance_diagnostics (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE,
  scan_name text DEFAULT '性能扫描',
  cpu_usage numeric(5,2),
  cpu_temperature numeric(5,2),
  memory_usage numeric(5,2),
  memory_total_mb bigint,
  disk_usage numeric(5,2),
  disk_total_gb bigint,
  network_latency numeric(8,2),
  network_download_speed numeric(10,2),
  network_upload_speed numeric(10,2),
  issues_count integer DEFAULT 0,
  critical_issues integer DEFAULT 0,
  warning_issues integer DEFAULT 0,
  issues_detected jsonb DEFAULT '[]'::jsonb,
  system_metrics jsonb DEFAULT '{}'::jsonb,
  recommendations jsonb DEFAULT '[]'::jsonb,
  created_at timestamptz DEFAULT now()
);

-- 程序分析记录表
CREATE TABLE IF NOT EXISTS program_analysis (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE,
  scan_session_id uuid DEFAULT gen_random_uuid(),
  program_name text NOT NULL,
  version text,
  publisher text,
  install_date date,
  size_kb bigint DEFAULT 0,
  category text CHECK (category IN ('system', 'productivity', 'gaming', 'media', 'development', 'utility', 'unknown')) DEFAULT 'unknown',
  risk_level text CHECK (risk_level IN ('safe', 'caution', 'risky', 'unknown')) DEFAULT 'unknown',
  recommendation text CHECK (recommendation IN ('keep', 'optional', 'remove', 'update')) DEFAULT 'keep',
  usage_frequency text CHECK (usage_frequency IN ('high', 'medium', 'low', 'never')) DEFAULT 'unknown',
  last_used text,
  auto_start boolean DEFAULT false,
  system_impact text CHECK (system_impact IN ('low', 'medium', 'high')) DEFAULT 'low',
  analysis_reasons jsonb DEFAULT '[]'::jsonb,
  program_details jsonb DEFAULT '{}'::jsonb,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

-- 系统诊断历史汇总表
CREATE TABLE IF NOT EXISTS diagnostic_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE,
  session_type text CHECK (session_type IN ('full_scan', 'ip_analysis', 'performance_check', 'program_audit')) NOT NULL,
  session_name text NOT NULL,
  status text CHECK (status IN ('running', 'completed', 'failed')) DEFAULT 'running',
  total_issues integer DEFAULT 0,
  critical_issues integer DEFAULT 0,
  resolved_issues integer DEFAULT 0,
  session_summary jsonb DEFAULT '{}'::jsonb,
  started_at timestamptz DEFAULT now(),
  completed_at timestamptz,
  created_at timestamptz DEFAULT now()
);

-- 启用行级安全
ALTER TABLE ip_analysis_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ip_analysis_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE performance_diagnostics ENABLE ROW LEVEL SECURITY;
ALTER TABLE program_analysis ENABLE ROW LEVEL SECURITY;
ALTER TABLE diagnostic_sessions ENABLE ROW LEVEL SECURITY;

-- IP分析会话策略
CREATE POLICY "用户只能访问自己的IP分析会话"
  ON ip_analysis_sessions
  FOR ALL
  TO authenticated
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- IP分析结果策略
CREATE POLICY "用户只能访问自己的IP分析结果"
  ON ip_analysis_results
  FOR ALL
  TO authenticated
  USING (
    session_id IN (
      SELECT id FROM ip_analysis_sessions 
      WHERE user_id = auth.uid()
    )
  );

-- 性能诊断策略
CREATE POLICY "用户只能访问自己的性能诊断记录"
  ON performance_diagnostics
  FOR ALL
  TO authenticated
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- 程序分析策略
CREATE POLICY "用户只能访问自己的程序分析记录"
  ON program_analysis
  FOR ALL
  TO authenticated
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- 诊断会话策略
CREATE POLICY "用户只能访问自己的诊断会话"
  ON diagnostic_sessions
  FOR ALL
  TO authenticated
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- 创建索引以提高查询性能
CREATE INDEX IF NOT EXISTS idx_ip_sessions_user_id ON ip_analysis_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_ip_sessions_created_at ON ip_analysis_sessions(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ip_results_session_id ON ip_analysis_results(session_id);
CREATE INDEX IF NOT EXISTS idx_ip_results_threat_level ON ip_analysis_results(threat_level);
CREATE INDEX IF NOT EXISTS idx_ip_results_created_at ON ip_analysis_results(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_performance_user_id ON performance_diagnostics(user_id);
CREATE INDEX IF NOT EXISTS idx_performance_created_at ON performance_diagnostics(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_program_user_id ON program_analysis(user_id);
CREATE INDEX IF NOT EXISTS idx_program_scan_session ON program_analysis(scan_session_id);
CREATE INDEX IF NOT EXISTS idx_program_risk_level ON program_analysis(risk_level);
CREATE INDEX IF NOT EXISTS idx_program_recommendation ON program_analysis(recommendation);

CREATE INDEX IF NOT EXISTS idx_diagnostic_sessions_user_id ON diagnostic_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_diagnostic_sessions_type ON diagnostic_sessions(session_type);
CREATE INDEX IF NOT EXISTS idx_diagnostic_sessions_created_at ON diagnostic_sessions(created_at DESC);

-- 创建更新时间触发器函数
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- 为需要的表添加更新时间触发器
CREATE TRIGGER update_ip_sessions_updated_at 
  BEFORE UPDATE ON ip_analysis_sessions 
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_program_analysis_updated_at 
  BEFORE UPDATE ON program_analysis 
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();