/*
  # 访问者IP跟踪和异常检测系统

  1. 新增表
    - `visitor_ip_logs` - 访问者IP记录表
    - `ip_tracking_links` - IP跟踪链接表
    - `visitor_sessions` - 访问者会话表
    - `ip_anomaly_detection` - IP异常检测结果表

  2. 安全
    - 启用RLS
    - 添加访问策略

  3. 功能
    - 自动记录访问者IP
    - 异常行为检测
    - 地理位置跟踪
    - 访问统计分析
*/

-- IP跟踪链接表
CREATE TABLE IF NOT EXISTS ip_tracking_links (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE,
  link_name text NOT NULL,
  link_code text UNIQUE NOT NULL DEFAULT encode(gen_random_bytes(8), 'hex'),
  description text,
  target_url text, -- 可选的重定向URL
  is_active boolean DEFAULT true,
  collect_user_agent boolean DEFAULT true,
  collect_referrer boolean DEFAULT true,
  alert_on_suspicious boolean DEFAULT true,
  max_visits integer, -- 最大访问次数限制
  expires_at timestamptz,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

-- 访问者IP记录表
CREATE TABLE IF NOT EXISTS visitor_ip_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tracking_link_id uuid REFERENCES ip_tracking_links(id) ON DELETE CASCADE,
  ip_address inet NOT NULL,
  user_agent text,
  referrer text,
  country text,
  country_code text,
  region text,
  city text,
  latitude numeric(10,8),
  longitude numeric(11,8),
  timezone text,
  isp text,
  organization text,
  asn text,
  is_mobile boolean DEFAULT false,
  is_proxy boolean DEFAULT false,
  is_hosting boolean DEFAULT false,
  is_tor boolean DEFAULT false,
  is_vpn boolean DEFAULT false,
  threat_level text CHECK (threat_level IN ('low', 'medium', 'high', 'unknown')) DEFAULT 'unknown',
  risk_factors jsonb DEFAULT '[]'::jsonb,
  session_id text, -- 浏览器会话ID
  visit_duration integer, -- 访问时长（秒）
  page_views integer DEFAULT 1,
  is_suspicious boolean DEFAULT false,
  anomaly_score numeric(5,2) DEFAULT 0,
  created_at timestamptz DEFAULT now()
);

-- 访问者会话表
CREATE TABLE IF NOT EXISTS visitor_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tracking_link_id uuid REFERENCES ip_tracking_links(id) ON DELETE CASCADE,
  session_id text NOT NULL,
  ip_address inet NOT NULL,
  first_visit timestamptz DEFAULT now(),
  last_visit timestamptz DEFAULT now(),
  total_visits integer DEFAULT 1,
  total_page_views integer DEFAULT 1,
  total_duration integer DEFAULT 0,
  unique_ips text[] DEFAULT '{}',
  countries text[] DEFAULT '{}',
  user_agents text[] DEFAULT '{}',
  is_suspicious boolean DEFAULT false,
  anomaly_flags jsonb DEFAULT '[]'::jsonb,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

-- IP异常检测结果表
CREATE TABLE IF NOT EXISTS ip_anomaly_detection (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  visitor_log_id uuid REFERENCES visitor_ip_logs(id) ON DELETE CASCADE,
  tracking_link_id uuid REFERENCES ip_tracking_links(id) ON DELETE CASCADE,
  anomaly_type text CHECK (anomaly_type IN (
    'rapid_location_change', 'suspicious_ip_range', 'tor_usage', 
    'vpn_usage', 'datacenter_ip', 'blacklisted_ip', 'unusual_user_agent',
    'high_frequency_access', 'geographic_anomaly', 'time_anomaly'
  )) NOT NULL,
  severity text CHECK (severity IN ('low', 'medium', 'high', 'critical')) DEFAULT 'medium',
  description text NOT NULL,
  confidence_score numeric(5,2) DEFAULT 0,
  evidence jsonb DEFAULT '{}'::jsonb,
  auto_detected boolean DEFAULT true,
  is_false_positive boolean DEFAULT false,
  created_at timestamptz DEFAULT now()
);

-- 启用行级安全
ALTER TABLE ip_tracking_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE visitor_ip_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE visitor_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ip_anomaly_detection ENABLE ROW LEVEL SECURITY;

-- IP跟踪链接策略
CREATE POLICY "用户只能管理自己的跟踪链接"
  ON ip_tracking_links
  FOR ALL
  TO authenticated
  USING (auth.uid() = user_id)
  WITH CHECK (auth.uid() = user_id);

-- 访问者IP记录策略（链接创建者可查看）
CREATE POLICY "链接创建者可以查看访问记录"
  ON visitor_ip_logs
  FOR SELECT
  TO authenticated
  USING (
    tracking_link_id IN (
      SELECT id FROM ip_tracking_links 
      WHERE user_id = auth.uid()
    )
  );

-- 允许匿名用户插入访问记录
CREATE POLICY "允许匿名访问记录"
  ON visitor_ip_logs
  FOR INSERT
  TO anon
  WITH CHECK (true);

-- 访问者会话策略
CREATE POLICY "链接创建者可以查看会话"
  ON visitor_sessions
  FOR SELECT
  TO authenticated
  USING (
    tracking_link_id IN (
      SELECT id FROM ip_tracking_links 
      WHERE user_id = auth.uid()
    )
  );

CREATE POLICY "允许匿名会话记录"
  ON visitor_sessions
  FOR ALL
  TO anon
  USING (true)
  WITH CHECK (true);

-- 异常检测策略
CREATE POLICY "链接创建者可以查看异常检测"
  ON ip_anomaly_detection
  FOR SELECT
  TO authenticated
  USING (
    tracking_link_id IN (
      SELECT id FROM ip_tracking_links 
      WHERE user_id = auth.uid()
    )
  );

CREATE POLICY "允许系统插入异常检测结果"
  ON ip_anomaly_detection
  FOR INSERT
  TO anon
  WITH CHECK (true);

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_ip_tracking_links_code ON ip_tracking_links(link_code);
CREATE INDEX IF NOT EXISTS idx_ip_tracking_links_user_id ON ip_tracking_links(user_id);
CREATE INDEX IF NOT EXISTS idx_ip_tracking_links_active ON ip_tracking_links(is_active) WHERE is_active = true;

CREATE INDEX IF NOT EXISTS idx_visitor_ip_logs_tracking_link ON visitor_ip_logs(tracking_link_id);
CREATE INDEX IF NOT EXISTS idx_visitor_ip_logs_ip ON visitor_ip_logs(ip_address);
CREATE INDEX IF NOT EXISTS idx_visitor_ip_logs_created_at ON visitor_ip_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_visitor_ip_logs_suspicious ON visitor_ip_logs(is_suspicious) WHERE is_suspicious = true;

CREATE INDEX IF NOT EXISTS idx_visitor_sessions_tracking_link ON visitor_sessions(tracking_link_id);
CREATE INDEX IF NOT EXISTS idx_visitor_sessions_session_id ON visitor_sessions(session_id);
CREATE INDEX IF NOT EXISTS idx_visitor_sessions_ip ON visitor_sessions(ip_address);
CREATE INDEX IF NOT EXISTS idx_visitor_sessions_suspicious ON visitor_sessions(is_suspicious) WHERE is_suspicious = true;

CREATE INDEX IF NOT EXISTS idx_anomaly_detection_tracking_link ON ip_anomaly_detection(tracking_link_id);
CREATE INDEX IF NOT EXISTS idx_anomaly_detection_type ON ip_anomaly_detection(anomaly_type);
CREATE INDEX IF NOT EXISTS idx_anomaly_detection_severity ON ip_anomaly_detection(severity);
CREATE INDEX IF NOT EXISTS idx_anomaly_detection_created_at ON ip_anomaly_detection(created_at DESC);

-- 添加更新时间触发器
CREATE TRIGGER update_ip_tracking_links_updated_at 
  BEFORE UPDATE ON ip_tracking_links 
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_visitor_sessions_updated_at 
  BEFORE UPDATE ON visitor_sessions 
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- 创建自动异常检测函数
CREATE OR REPLACE FUNCTION detect_ip_anomalies()
RETURNS TRIGGER AS $$
DECLARE
  anomaly_count integer := 0;
  prev_visit record;
  time_diff interval;
  distance_km numeric;
BEGIN
  -- 检查是否为Tor节点
  IF NEW.is_tor = true THEN
    INSERT INTO ip_anomaly_detection (
      visitor_log_id, tracking_link_id, anomaly_type, severity, 
      description, confidence_score, evidence
    ) VALUES (
      NEW.id, NEW.tracking_link_id, 'tor_usage', 'high',
      'Tor出口节点访问', 0.95,
      jsonb_build_object('ip', NEW.ip_address, 'tor_detected', true)
    );
    anomaly_count := anomaly_count + 1;
  END IF;

  -- 检查是否为VPN
  IF NEW.is_vpn = true THEN
    INSERT INTO ip_anomaly_detection (
      visitor_log_id, tracking_link_id, anomaly_type, severity, 
      description, confidence_score, evidence
    ) VALUES (
      NEW.id, NEW.tracking_link_id, 'vpn_usage', 'medium',
      'VPN服务器访问', 0.85,
      jsonb_build_object('ip', NEW.ip_address, 'vpn_detected', true)
    );
    anomaly_count := anomaly_count + 1;
  END IF;

  -- 检查是否为数据中心IP
  IF NEW.is_hosting = true THEN
    INSERT INTO ip_anomaly_detection (
      visitor_log_id, tracking_link_id, anomaly_type, severity, 
      description, confidence_score, evidence
    ) VALUES (
      NEW.id, NEW.tracking_link_id, 'datacenter_ip', 'medium',
      '数据中心IP访问', 0.80,
      jsonb_build_object('ip', NEW.ip_address, 'hosting_detected', true)
    );
    anomaly_count := anomaly_count + 1;
  END IF;

  -- 检查快速地理位置变化
  SELECT * INTO prev_visit 
  FROM visitor_ip_logs 
  WHERE tracking_link_id = NEW.tracking_link_id 
    AND session_id = NEW.session_id 
    AND id != NEW.id
    AND latitude IS NOT NULL 
    AND longitude IS NOT NULL
  ORDER BY created_at DESC 
  LIMIT 1;

  IF prev_visit.id IS NOT NULL AND NEW.latitude IS NOT NULL AND NEW.longitude IS NOT NULL THEN
    time_diff := NEW.created_at - prev_visit.created_at;
    
    -- 计算距离（简化的球面距离公式）
    distance_km := 6371 * acos(
      cos(radians(prev_visit.latitude)) * cos(radians(NEW.latitude)) * 
      cos(radians(NEW.longitude) - radians(prev_visit.longitude)) + 
      sin(radians(prev_visit.latitude)) * sin(radians(NEW.latitude))
    );

    -- 如果在1小时内移动超过500公里，标记为异常
    IF time_diff < interval '1 hour' AND distance_km > 500 THEN
      INSERT INTO ip_anomaly_detection (
        visitor_log_id, tracking_link_id, anomaly_type, severity, 
        description, confidence_score, evidence
      ) VALUES (
        NEW.id, NEW.tracking_link_id, 'rapid_location_change', 'high',
        format('快速地理位置变化: %s公里在%s内', round(distance_km), time_diff),
        0.90,
        jsonb_build_object(
          'distance_km', distance_km,
          'time_diff_minutes', extract(epoch from time_diff)/60,
          'prev_location', format('%s, %s', prev_visit.city, prev_visit.country),
          'new_location', format('%s, %s', NEW.city, NEW.country)
        )
      );
      anomaly_count := anomaly_count + 1;
    END IF;
  END IF;

  -- 更新异常评分
  NEW.anomaly_score := LEAST(anomaly_count * 25.0, 100.0);
  NEW.is_suspicious := anomaly_count > 0;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 创建触发器
CREATE TRIGGER trigger_detect_ip_anomalies
  BEFORE INSERT ON visitor_ip_logs
  FOR EACH ROW
  EXECUTE FUNCTION detect_ip_anomalies();

-- 创建会话更新函数
CREATE OR REPLACE FUNCTION update_visitor_session()
RETURNS TRIGGER AS $$
DECLARE
  session_record record;
BEGIN
  -- 查找或创建会话记录
  SELECT * INTO session_record
  FROM visitor_sessions
  WHERE tracking_link_id = NEW.tracking_link_id 
    AND session_id = NEW.session_id;

  IF session_record.id IS NOT NULL THEN
    -- 更新现有会话
    UPDATE visitor_sessions SET
      last_visit = NEW.created_at,
      total_visits = total_visits + 1,
      total_page_views = total_page_views + NEW.page_views,
      unique_ips = array_append(
        CASE WHEN NEW.ip_address::text = ANY(unique_ips) 
        THEN unique_ips 
        ELSE array_append(unique_ips, NEW.ip_address::text) 
        END, 
        NULL
      ),
      countries = array_append(
        CASE WHEN NEW.country = ANY(countries) 
        THEN countries 
        ELSE array_append(countries, NEW.country) 
        END, 
        NULL
      ),
      user_agents = array_append(
        CASE WHEN NEW.user_agent = ANY(user_agents) 
        THEN user_agents 
        ELSE array_append(user_agents, NEW.user_agent) 
        END, 
        NULL
      ),
      is_suspicious = is_suspicious OR NEW.is_suspicious,
      updated_at = now()
    WHERE id = session_record.id;
  ELSE
    -- 创建新会话
    INSERT INTO visitor_sessions (
      tracking_link_id, session_id, ip_address, first_visit, last_visit,
      total_visits, total_page_views, unique_ips, countries, user_agents,
      is_suspicious
    ) VALUES (
      NEW.tracking_link_id, NEW.session_id, NEW.ip_address, NEW.created_at, NEW.created_at,
      1, NEW.page_views, ARRAY[NEW.ip_address::text], ARRAY[NEW.country], ARRAY[NEW.user_agent],
      NEW.is_suspicious
    );
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 创建会话更新触发器
CREATE TRIGGER trigger_update_visitor_session
  AFTER INSERT ON visitor_ip_logs
  FOR EACH ROW
  EXECUTE FUNCTION update_visitor_session();