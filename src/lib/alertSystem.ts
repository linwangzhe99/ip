import { supabase } from './supabase';

export interface AlertNotification {
  id: string;
  user_id: string;
  alert_type: 'suspicious_ip' | 'high_risk_program' | 'performance_critical' | 'duplicate_detected';
  title: string;
  message: string;
  severity: 'info' | 'warning' | 'critical';
  is_read: boolean;
  related_data: any;
  created_at: string;
  expires_at: string;
}

export interface SuspiciousPattern {
  id: string;
  user_id: string;
  pattern_type: 'ip_range' | 'asn' | 'country' | 'isp';
  pattern_value: string;
  description: string;
  threat_level: 'low' | 'medium' | 'high';
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface IPBlacklistEntry {
  id: string;
  user_id: string;
  ip_address: string;
  reason: string;
  threat_level: 'low' | 'medium' | 'high';
  auto_added: boolean;
  is_active: boolean;
  added_at: string;
  last_seen: string;
  detection_count: number;
}

export class AlertSystem {
  // 创建警报通知
  static async createAlert(
    alertType: AlertNotification['alert_type'],
    title: string,
    message: string,
    severity: AlertNotification['severity'] = 'warning',
    relatedData: any = {}
  ): Promise<AlertNotification | null> {
    try {
      const { data, error } = await supabase
        .from('alert_notifications')
        .insert([{
          alert_type: alertType,
          title,
          message,
          severity,
          related_data: relatedData
        }])
        .select()
        .single();

      if (error) throw error;
      return data;
    } catch (error) {
      console.error('创建警报失败:', error);
      return null;
    }
  }

  // 获取用户的未读警报
  static async getUnreadAlerts(): Promise<AlertNotification[]> {
    try {
      const { data, error } = await supabase
        .from('alert_notifications')
        .select('*')
        .eq('is_read', false)
        .lt('expires_at', new Date().toISOString())
        .order('created_at', { ascending: false });

      if (error) throw error;
      return data || [];
    } catch (error) {
      console.error('获取未读警报失败:', error);
      return [];
    }
  }

  // 标记警报为已读
  static async markAlertAsRead(alertId: string): Promise<boolean> {
    try {
      const { error } = await supabase
        .from('alert_notifications')
        .update({ is_read: true })
        .eq('id', alertId);

      if (error) throw error;
      return true;
    } catch (error) {
      console.error('标记警报已读失败:', error);
      return false;
    }
  }

  // 检查IP是否在黑名单中
  static async checkIPBlacklist(ipAddress: string): Promise<IPBlacklistEntry | null> {
    try {
      const { data, error } = await supabase
        .from('ip_blacklist')
        .select('*')
        .eq('ip_address', ipAddress)
        .eq('is_active', true)
        .single();

      if (error && error.code !== 'PGRST116') throw error;
      return data;
    } catch (error) {
      console.error('检查IP黑名单失败:', error);
      return null;
    }
  }

  // 添加IP到黑名单
  static async addToBlacklist(
    ipAddress: string,
    reason: string,
    threatLevel: 'low' | 'medium' | 'high' = 'medium',
    autoAdded: boolean = false
  ): Promise<boolean> {
    try {
      // 检查是否已存在
      const existing = await this.checkIPBlacklist(ipAddress);
      
      if (existing) {
        // 更新检测次数和最后发现时间
        const { error } = await supabase
          .from('ip_blacklist')
          .update({
            detection_count: existing.detection_count + 1,
            last_seen: new Date().toISOString(),
            threat_level: threatLevel
          })
          .eq('id', existing.id);

        if (error) throw error;
      } else {
        // 添加新条目
        const { error } = await supabase
          .from('ip_blacklist')
          .insert([{
            ip_address: ipAddress,
            reason,
            threat_level: threatLevel,
            auto_added: autoAdded
          }]);

        if (error) throw error;
      }

      return true;
    } catch (error) {
      console.error('添加IP到黑名单失败:', error);
      return false;
    }
  }

  // 获取可疑模式
  static async getSuspiciousPatterns(): Promise<Suspicious Pattern[]> {
    try {
      const { data, error } = await supabase
        .from('suspicious_patterns')
        .select('*')
        .eq('is_active', true)
        .order('threat_level', { ascending: false });

      if (error) throw error;
      return data || [];
    } catch (error) {
      console.error('获取可疑模式失败:', error);
      return [];
    }
  }

  // 检查IP是否匹配可疑模式
  static async checkSuspiciousPatterns(ipAddress: string): Promise<SuspiciousPattern[]> {
    try {
      const patterns = await this.getSuspiciousPatterns();
      const matchedPatterns: SuspiciousPattern[] = [];

      for (const pattern of patterns) {
        if (pattern.pattern_type === 'ip_range') {
          // 简单的IP范围检查（实际应用中需要更复杂的CIDR匹配）
          if (ipAddress.startsWith(pattern.pattern_value.split('/')[0].slice(0, -2))) {
            matchedPatterns.push(pattern);
          }
        }
      }

      return matchedPatterns;
    } catch (error) {
      console.error('检查可疑模式失败:', error);
      return [];
    }
  }

  // 触发可疑IP警报
  static async triggerSuspiciousIPAlert(
    ipAddress: string,
    threatLevel: 'low' | 'medium' | 'high',
    riskFactors: string[]
  ): Promise<void> {
    try {
      // 检查是否匹配可疑模式
      const matchedPatterns = await this.checkSuspiciousPatterns(ipAddress);
      
      if (matchedPatterns.length > 0 || threatLevel === 'high') {
        // 添加到黑名单
        await this.addToBlacklist(
          ipAddress,
          `自动检测: ${riskFactors.join(', ')}`,
          threatLevel,
          true
        );

        // 创建警报
        await this.createAlert(
          'suspicious_ip',
          '检测到可疑IP地址',
          `IP地址 ${ipAddress} 被标记为${threatLevel === 'high' ? '高风险' : '可疑'}。风险因素: ${riskFactors.join(', ')}`,
          threatLevel === 'high' ? 'critical' : 'warning',
          {
            ip_address: ipAddress,
            threat_level: threatLevel,
            risk_factors: riskFactors,
            matched_patterns: matchedPatterns.map(p => p.description)
          }
        );

        // 浏览器通知
        if (Notification.permission === 'granted') {
          new Notification('安全警报', {
            body: `检测到可疑IP: ${ipAddress}`,
            icon: '/favicon.ico'
          });
        }
      }
    } catch (error) {
      console.error('触发可疑IP警报失败:', error);
    }
  }

  // 触发重复检测警报
  static async triggerDuplicateAlert(
    itemType: 'ip_address' | 'program_name',
    itemIdentifier: string,
    duplicateCount: number
  ): Promise<void> {
    try {
      await this.createAlert(
        'duplicate_detected',
        '检测到重复项',
        `${itemType === 'ip_address' ? 'IP地址' : '程序'} "${itemIdentifier}" 出现重复，共检测到 ${duplicateCount} 次`,
        'info',
        {
          item_type: itemType,
          item_identifier: itemIdentifier,
          duplicate_count: duplicateCount
        }
      );
    } catch (error) {
      console.error('触发重复检测警报失败:', error);
    }
  }

  // 清理过期警报
  static async cleanupExpiredAlerts(): Promise<void> {
    try {
      const { error } = await supabase
        .from('alert_notifications')
        .delete()
        .lt('expires_at', new Date().toISOString());

      if (error) throw error;
    } catch (error) {
      console.error('清理过期警报失败:', error);
    }
  }
}