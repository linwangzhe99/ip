/*
  # 重复检测和警报系统增强

  1. 新增表
    - `ip_blacklist` - IP黑名单表
    - `suspicious_patterns` - 可疑模式表
    - `alert_notifications` - 警报通知表
    - `duplicate_detection_cache` - 重复检测缓存表

  2. 安全
    - 启用RLS
    - 添加用户访问策略

  3. 索引
    - 优化查询性能
*/

-- IP黑名单表
CREATE TABLE IF NOT EXISTS ip_blacklist (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE,
  ip_address text NOT NULL,
  reason text NOT NULL,
  threat_level text CHECK (threat_level IN ('low', 'medium', 'high')) DEFAULT 'medium',
  auto_added boolean DEFAULT false,
  is_active boolean DEFAULT true,
  added_at timestamptz DEFAULT now(),
  last_seen timestamptz DEFAULT now(),
  detection_count integer DEFAULT 1
);

-- 可疑模式表
CREATE TABLE IF NOT EXISTS suspicious_patterns (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE,
  pattern_type text CHECK (pattern_type IN ('ip_range', 'asn', 'country', 'isp')) NOT NULL,
  pattern_value text NOT NULL,
  description text,
  threat_level text CHECK (threat_level IN ('low', 'medium', 'high')) DEFAULT 'medium',
  is_active boolean DEFAULT true,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

-- 警报通知表
CREATE TABLE IF NOT EXISTS alert_notifications (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE,
  alert_type text CHECK (alert_type IN ('suspicious_ip', 'high_risk_program', 'performance_critical', 'duplicate_detected')) NOT NULL,
  title text NOT NULL,
  message text NOT NULL,
  severity text CHECK (severity IN ('info', 'warning', 'critical')) DEFAULT 'warning',
  is_read boolean DEFAULT false,
  related_data jsonb DEFAULT '{}'::jsonb,
  created_at timestamptz DEFAULT now(),
  expires_at timestamptz DEFAULT (now() + interval '7 days')
);

-- 重复检测缓存表
CREATE TABLE IF NOT EXISTS duplicate_detection_cache (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE,
  item_type text CHECK (item_type IN ('ip_address', 'program_name')) NOT NULL,
  item_identifier text NOT NULL,
  first_seen timestamptz DEFAULT now(),
  last_seen timestamptz DEFAULT now(),
  occurrence_count integer DEFAULT 1,
  related_sessions jsonb DEFAULT '[]'::jsonb,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

-- 启用行级安全
ALTER TABLE ip_blacklist ENABLE ROW LEVEL SECURITY;
ALTER TABLE suspicious_patterns ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE duplicate_detection_cache ENABLE ROW LEVEL SECURITY;

-- IP黑名单策略
CREATE POLICY "用户只能访问自己的IP黑名单"
  ON ip_blacklist
  FOR ALL
  TO authenticated
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- 可疑模式策略
CREATE POLICY "用户只能访问自己的可疑模式"
  ON suspicious_patterns
  FOR ALL
  TO authenticated
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- 警报通知策略
CREATE POLICY "用户只能访问自己的警报通知"
  ON alert_notifications
  FOR ALL
  TO authenticated
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- 重复检测缓存策略
CREATE POLICY "用户只能访问自己的重复检测缓存"
  ON duplicate_detection_cache
  FOR ALL
  TO authenticated
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_ip_blacklist_user_id ON ip_blacklist(user_id);
CREATE INDEX IF NOT EXISTS idx_ip_blacklist_ip_address ON ip_blacklist(ip_address);
CREATE INDEX IF NOT EXISTS idx_ip_blacklist_active ON ip_blacklist(is_active) WHERE is_active = true;

CREATE INDEX IF NOT EXISTS idx_suspicious_patterns_user_id ON suspicious_patterns(user_id);
CREATE INDEX IF NOT EXISTS idx_suspicious_patterns_type ON suspicious_patterns(pattern_type);
CREATE INDEX IF NOT EXISTS idx_suspicious_patterns_active ON suspicious_patterns(is_active) WHERE is_active = true;

CREATE INDEX IF NOT EXISTS idx_alert_notifications_user_id ON alert_notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_alert_notifications_unread ON alert_notifications(is_read) WHERE is_read = false;
CREATE INDEX IF NOT EXISTS idx_alert_notifications_created_at ON alert_notifications(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_duplicate_cache_user_id ON duplicate_detection_cache(user_id);
CREATE INDEX IF NOT EXISTS idx_duplicate_cache_type_identifier ON duplicate_detection_cache(item_type, item_identifier);
CREATE INDEX IF NOT EXISTS idx_duplicate_cache_updated_at ON duplicate_detection_cache(updated_at DESC);

-- 添加更新时间触发器
CREATE TRIGGER update_suspicious_patterns_updated_at 
  BEFORE UPDATE ON suspicious_patterns 
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_duplicate_cache_updated_at 
  BEFORE UPDATE ON duplicate_detection_cache 
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- 插入默认可疑模式
INSERT INTO suspicious_patterns (user_id, pattern_type, pattern_value, description, threat_level) 
SELECT 
  auth.uid(),
  'ip_range',
  '95.223.0.0/16',
  '可疑IP网段 - 经常出现恶意活动',
  'high'
WHERE auth.uid() IS NOT NULL
ON CONFLICT DO NOTHING;

INSERT INTO suspicious_patterns (user_id, pattern_type, pattern_value, description, threat_level) 
SELECT 
  auth.uid(),
  'ip_range',
  '185.0.0.0/8',
  'VPN/代理常用网段',
  'medium'
WHERE auth.uid() IS NOT NULL
ON CONFLICT DO NOTHING;