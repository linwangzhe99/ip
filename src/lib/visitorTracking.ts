import { supabase } from './supabase';

export interface TrackingLink {
  id: string;
  user_id: string;
  link_name: string;
  link_code: string;
  description?: string;
  target_url?: string;
  is_active: boolean;
  collect_user_agent: boolean;
  collect_referrer: boolean;
  alert_on_suspicious: boolean;
  max_visits?: number;
  expires_at?: string;
  created_at: string;
  updated_at: string;
}

export interface VisitorIPLog {
  id: string;
  tracking_link_id: string;
  ip_address: string;
  user_agent?: string;
  referrer?: string;
  country?: string;
  country_code?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  timezone?: string;
  isp?: string;
  organization?: string;
  asn?: string;
  is_mobile: boolean;
  is_proxy: boolean;
  is_hosting: boolean;
  is_tor: boolean;
  is_vpn: boolean;
  threat_level: 'low' | 'medium' | 'high' | 'unknown';
  risk_factors: string[];
  session_id?: string;
  visit_duration?: number;
  page_views: number;
  is_suspicious: boolean;
  anomaly_score: number;
  created_at: string;
}

export interface VisitorSession {
  id: string;
  tracking_link_id: string;
  session_id: string;
  ip_address: string;
  first_visit: string;
  last_visit: string;
  total_visits: number;
  total_page_views: number;
  total_duration: number;
  unique_ips: string[];
  countries: string[];
  user_agents: string[];
  is_suspicious: boolean;
  anomaly_flags: any[];
  created_at: string;
  updated_at: string;
}

export interface IPAnomalyDetection {
  id: string;
  visitor_log_id: string;
  tracking_link_id: string;
  anomaly_type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  confidence_score: number;
  evidence: any;
  auto_detected: boolean;
  is_false_positive: boolean;
  created_at: string;
}

export interface VisitorAnalytics {
  totalVisits: number;
  uniqueVisitors: number;
  suspiciousVisits: number;
  topCountries: Array<{ country: string; count: number }>;
  topISPs: Array<{ isp: string; count: number }>;
  threatLevelDistribution: { [key: string]: number };
  anomalyTypes: { [key: string]: number };
  timelineData: Array<{ date: string; visits: number; suspicious: number }>;
  geographicData: Array<{ 
    country: string; 
    latitude: number; 
    longitude: number; 
    count: number; 
    suspicious: number 
  }>;
}

export class VisitorTrackingDB {
  // 创建跟踪链接
  static async createTrackingLink(
    linkName: string,
    description?: string,
    targetUrl?: string,
    options: Partial<TrackingLink> = {}
  ): Promise<TrackingLink | null> {
    try {
      // Get the authenticated user
      const { data: { user }, error: userError } = await supabase.auth.getUser();
      
      if (userError || !user) {
        throw new Error('用户未认证');
      }

      const { data, error } = await supabase
        .from('ip_tracking_links')
        .insert([{
          user_id: user.id,
          link_name: linkName,
          description,
          target_url: targetUrl,
          collect_user_agent: options.collect_user_agent ?? true,
          collect_referrer: options.collect_referrer ?? true,
          alert_on_suspicious: options.alert_on_suspicious ?? true,
          max_visits: options.max_visits,
          expires_at: options.expires_at
        }])
        .select()
        .single();

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('创建跟踪链接失败:', error);
      return null;
    }
  }

  // 获取用户的跟踪链接
  static async getUserTrackingLinks(): Promise<TrackingLink[]> {
    try {
      const { data, error } = await supabase
        .from('ip_tracking_links')
        .select('*')
        .order('created_at', { ascending: false });

      if (error) throw error;
      return data || [];
    } catch (error) {
      console.error('获取跟踪链接失败:', error);
      return [];
    }
  }

  // 通过链接代码获取跟踪链接
  static async getTrackingLinkByCode(linkCode: string): Promise<TrackingLink | null> {
    try {
      const { data, error } = await supabase
        .from('ip_tracking_links')
        .select('*')
        .eq('link_code', linkCode)
        .eq('is_active', true)
        .single();

      if (error && error.code !== 'PGRST116') throw error;
      return data;
    } catch (error) {
      console.error('获取跟踪链接失败:', error);
      return null;
    }
  }

  // 记录访问者IP
  static async logVisitorIP(
    trackingLinkId: string,
    ipData: {
      ip_address: string;
      user_agent?: string;
      referrer?: string;
      session_id?: string;
    }
  ): Promise<VisitorIPLog | null> {
    try {
      // 首先分析IP地址
      const ipAnalysis = await this.analyzeIPAddress(ipData.ip_address);
      
      const { data, error } = await supabase
        .from('visitor_ip_logs')
        .insert([{
          tracking_link_id: trackingLinkId,
          ip_address: ipData.ip_address,
          user_agent: ipData.user_agent,
          referrer: ipData.referrer,
          session_id: ipData.session_id || this.generateSessionId(),
          ...ipAnalysis
        }])
        .select()
        .single();

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('记录访问者IP失败:', error);
      return null;
    }
  }

  // 分析IP地址
  static async analyzeIPAddress(ipAddress: string): Promise<Partial<VisitorIPLog>> {
    try {
      // 使用IP分析API
      const response = await fetch('/.netlify/functions/ip-proxy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify([{ query: ipAddress }])
      });

      if (!response.ok) throw new Error('IP分析失败');
      
      const [ipData] = await response.json();
      
      if (ipData.status !== 'success') {
        return { threat_level: 'unknown' };
      }

      // 威胁评估
      const { threat, riskFactors } = this.assessThreatLevel(ipData);
      
      return {
        country: ipData.country,
        country_code: ipData.countryCode,
        region: ipData.regionName,
        city: ipData.city,
        latitude: ipData.lat,
        longitude: ipData.lon,
        timezone: ipData.timezone,
        isp: ipData.isp,
        organization: ipData.org,
        asn: ipData.as,
        is_mobile: ipData.mobile || false,
        is_proxy: ipData.proxy || false,
        is_hosting: ipData.hosting || false,
        is_tor: this.isTorExitNode(ipAddress),
        is_vpn: this.isVPNServer(ipAddress),
        threat_level: threat,
        risk_factors: riskFactors
      };
    } catch (error) {
      console.error('IP分析失败:', error);
      return { threat_level: 'unknown' };
    }
  }

  // 威胁等级评估
  private static assessThreatLevel(ipData: any): { threat: 'low' | 'medium' | 'high', riskFactors: string[] } {
    const riskFactors: string[] = [];
    let riskScore = 0;

    // 检查是否为可疑IP段
    if (this.isSuspiciousRange(ipData.query)) {
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

    // 检查Tor
    if (this.isTorExitNode(ipData.query)) {
      riskFactors.push('Tor出口节点');
      riskScore += 4;
    }

    // 检查VPN
    if (this.isVPNServer(ipData.query)) {
      riskFactors.push('VPN服务器');
      riskScore += 3;
    }

    // 确定威胁等级
    if (riskScore >= 5) return { threat: 'high', riskFactors };
    if (riskScore >= 2) return { threat: 'medium', riskFactors };
    return { threat: 'low', riskFactors };
  }

  // 检查是否为可疑IP段
  private static isSuspiciousRange(ip: string): boolean {
    const suspiciousRanges = ['95.223.', '185.220.', '46.166.'];
    return suspiciousRanges.some(range => ip.startsWith(range));
  }

  // 检查是否为Tor出口节点
  private static isTorExitNode(ip: string): boolean {
    const torExitNodes = ['185.220.101.1', '46.166.139.111', '95.223.57.198'];
    return torExitNodes.includes(ip);
  }

  // 检查是否为VPN服务器
  private static isVPNServer(ip: string): boolean {
    const vpnRanges = ['95.223.', '185.220.', '46.166.'];
    return vpnRanges.some(range => ip.startsWith(range));
  }

  // 生成会话ID
  private static generateSessionId(): string {
    return Math.random().toString(36).substring(2) + Date.now().toString(36);
  }

  // 获取跟踪链接的访问记录
  static async getVisitorLogs(trackingLinkId: string): Promise<VisitorIPLog[]> {
    try {
      const { data, error } = await supabase
        .from('visitor_ip_logs')
        .select('*')
        .eq('tracking_link_id', trackingLinkId)
        .order('created_at', { ascending: false });

      if (error) throw error;
      return data || [];
    } catch (error) {
      console.error('获取访问记录失败:', error);
      return [];
    }
  }

  // 获取访问者会话
  static async getVisitorSessions(trackingLinkId: string): Promise<VisitorSession[]> {
    try {
      const { data, error } = await supabase
        .from('visitor_sessions')
        .select('*')
        .eq('tracking_link_id', trackingLinkId)
        .order('last_visit', { ascending: false });

      if (error) throw error;
      return data || [];
    } catch (error) {
      console.error('获取访问会话失败:', error);
      return [];
    }
  }

  // 获取异常检测结果
  static async getAnomalyDetections(trackingLinkId: string): Promise<IPAnomalyDetection[]> {
    try {
      const { data, error } = await supabase
        .from('ip_anomaly_detection')
        .select('*')
        .eq('tracking_link_id', trackingLinkId)
        .order('created_at', { ascending: false });

      if (error) throw error;
      return data || [];
    } catch (error) {
      console.error('获取异常检测结果失败:', error);
      return [];
    }
  }

  // 获取访问分析数据
  static async getVisitorAnalytics(trackingLinkId: string): Promise<VisitorAnalytics> {
    try {
      const logs = await this.getVisitorLogs(trackingLinkId);
      const sessions = await this.getVisitorSessions(trackingLinkId);
      const anomalies = await this.getAnomalyDetections(trackingLinkId);

      // 计算基础统计
      const totalVisits = logs.length;
      const uniqueVisitors = new Set(logs.map(log => log.ip_address)).size;
      const suspiciousVisits = logs.filter(log => log.is_suspicious).length;

      // 国家分布
      const countryCount = new Map<string, number>();
      logs.forEach(log => {
        if (log.country) {
          countryCount.set(log.country, (countryCount.get(log.country) || 0) + 1);
        }
      });
      const topCountries = Array.from(countryCount.entries())
        .map(([country, count]) => ({ country, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10);

      // ISP分布
      const ispCount = new Map<string, number>();
      logs.forEach(log => {
        if (log.isp) {
          ispCount.set(log.isp, (ispCount.get(log.isp) || 0) + 1);
        }
      });
      const topISPs = Array.from(ispCount.entries())
        .map(([isp, count]) => ({ isp, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10);

      // 威胁等级分布
      const threatLevelDistribution: { [key: string]: number } = {};
      logs.forEach(log => {
        threatLevelDistribution[log.threat_level] = 
          (threatLevelDistribution[log.threat_level] || 0) + 1;
      });

      // 异常类型分布
      const anomalyTypes: { [key: string]: number } = {};
      anomalies.forEach(anomaly => {
        anomalyTypes[anomaly.anomaly_type] = 
          (anomalyTypes[anomaly.anomaly_type] || 0) + 1;
      });

      // 时间线数据（按天统计）
      const timelineMap = new Map<string, { visits: number; suspicious: number }>();
      logs.forEach(log => {
        const date = new Date(log.created_at).toISOString().split('T')[0];
        const current = timelineMap.get(date) || { visits: 0, suspicious: 0 };
        current.visits++;
        if (log.is_suspicious) current.suspicious++;
        timelineMap.set(date, current);
      });
      const timelineData = Array.from(timelineMap.entries())
        .map(([date, data]) => ({ date, ...data }))
        .sort((a, b) => a.date.localeCompare(b.date));

      // 地理数据
      const geoMap = new Map<string, { 
        latitude: number; 
        longitude: number; 
        count: number; 
        suspicious: number 
      }>();
      logs.forEach(log => {
        if (log.country && log.latitude && log.longitude) {
          const current = geoMap.get(log.country) || {
            latitude: log.latitude,
            longitude: log.longitude,
            count: 0,
            suspicious: 0
          };
          current.count++;
          if (log.is_suspicious) current.suspicious++;
          geoMap.set(log.country, current);
        }
      });
      const geographicData = Array.from(geoMap.entries())
        .map(([country, data]) => ({ country, ...data }));

      return {
        totalVisits,
        uniqueVisitors,
        suspiciousVisits,
        topCountries,
        topISPs,
        threatLevelDistribution,
        anomalyTypes,
        timelineData,
        geographicData
      };
    } catch (error) {
      console.error('获取访问分析失败:', error);
      return {
        totalVisits: 0,
        uniqueVisitors: 0,
        suspiciousVisits: 0,
        topCountries: [],
        topISPs: [],
        threatLevelDistribution: {},
        anomalyTypes: {},
        timelineData: [],
        geographicData: []
      };
    }
  }

  // 更新跟踪链接
  static async updateTrackingLink(
    linkId: string, 
    updates: Partial<TrackingLink>
  ): Promise<boolean> {
    try {
      const { error } = await supabase
        .from('ip_tracking_links')
        .update(updates)
        .eq('id', linkId);

      if (error) throw error;
      return true;
    } catch (error) {
      console.error('更新跟踪链接失败:', error);
      return false;
    }
  }

  // 删除跟踪链接
  static async deleteTrackingLink(linkId: string): Promise<boolean> {
    try {
      const { error } = await supabase
        .from('ip_tracking_links')
        .delete()
        .eq('id', linkId);

      if (error) throw error;
      return true;
    } catch (error) {
      console.error('删除跟踪链接失败:', error);
      return false;
    }
  }
}