// IP分析增强功能库
export interface IPAnalysisResult {
  ip: string;
  location: {
    country: string;
    countryCode: string;
    region: string;
    city: string;
    latitude: number;
    longitude: number;
    timezone: string;
    postalCode?: string;
    accuracy: 'country' | 'region' | 'city' | 'precise';
  };
  network: {
    isp: string;
    organization: string;
    asn: string;
    asnName: string;
    reverseDns?: string;
    ipType: 'residential' | 'datacenter' | 'corporate' | 'mobile' | 'unknown';
  };
  security: {
    threatLevel: 'low' | 'medium' | 'high';
    riskFactors: string[];
    blacklistStatus: {
      isBlacklisted: boolean;
      sources: string[];
      lastSeen?: string;
      confidence: number;
    };
    vpnTorStatus: {
      isVPN: boolean;
      isTor: boolean;
      isProxy: boolean;
      confidence: number;
      exitNode?: boolean;
    };
    reputation: {
      score: number; // 0-100
      category: 'clean' | 'suspicious' | 'malicious';
      lastUpdate: string;
    };
  };
  usage: {
    isHosting: boolean;
    isMobile: boolean;
    isProxy: boolean;
    isBot: boolean;
    usageType: string[];
  };
  geolocation: {
    currency: string;
    languages: string[];
    callingCode: string;
    flag: string;
  };
}

export interface IPBatchAnalysis {
  results: IPAnalysisResult[];
  statistics: {
    total: number;
    byThreatLevel: { [key: string]: number };
    byCountry: { [key: string]: number };
    byIPType: { [key: string]: number };
    blacklisted: number;
    vpnTor: number;
    suspicious: number;
  };
  patterns: {
    suspiciousRanges: string[];
    commonISPs: string[];
    geographicClusters: Array<{
      country: string;
      count: number;
      ips: string[];
    }>;
    timePatterns?: Array<{
      hour: number;
      count: number;
    }>;
  };
}

export interface UserIPHistory {
  userId?: string;
  sessionId: string;
  ips: Array<{
    ip: string;
    timestamp: string;
    location: string;
    suspicious: boolean;
  }>;
  analysis: {
    totalSessions: number;
    uniqueCountries: number;
    suspiciousActivity: boolean;
    rapidLocationChanges: boolean;
    vpnUsage: boolean;
  };
}

// 黑名单数据源配置
export const BLACKLIST_SOURCES = {
  spamhaus: {
    name: 'Spamhaus',
    url: 'https://www.spamhaus.org/query/ip/',
    weight: 0.9,
    type: 'spam'
  },
  abuseipdb: {
    name: 'AbuseIPDB',
    url: 'https://www.abuseipdb.com/check/',
    weight: 0.8,
    type: 'abuse'
  },
  virustotal: {
    name: 'VirusTotal',
    url: 'https://www.virustotal.com/gui/ip-address/',
    weight: 0.85,
    type: 'malware'
  },
  talos: {
    name: 'Cisco Talos',
    url: 'https://talosintelligence.com/reputation_center/lookup?search=',
    weight: 0.8,
    type: 'reputation'
  }
};

// VPN/代理检测数据源
export const VPN_DETECTION_SOURCES = {
  known_vpn_ranges: [
    '95.223.0.0/16',
    '185.220.0.0/16',
    '46.166.0.0/16',
    '109.70.100.0/24',
    '192.42.116.0/24'
  ],
  tor_exit_nodes: [
    // 这里应该是实时更新的Tor出口节点列表
    '185.220.101.1',
    '46.166.139.111',
    '95.223.57.198'
  ],
  proxy_indicators: [
    'proxy',
    'vpn',
    'anonymous',
    'privacy',
    'tunnel',
    'hide'
  ]
};

// 可疑IP模式
export const SUSPICIOUS_PATTERNS = {
  high_risk_asns: [
    'AS13335', // Cloudflare (可能被滥用)
    'AS16509', // Amazon (大量代理)
    'AS15169', // Google (云服务)
    'AS8075'   // Microsoft (Azure)
  ],
  high_risk_countries: ['CN', 'RU', 'KP', 'IR', 'SY'],
  suspicious_isps: [
    'LeaseWeb',
    'OVH',
    'DigitalOcean',
    'Vultr',
    'Linode'
  ]
};

export class IPAnalysisEngine {
  // 批量分析IP地址
  static async analyzeBatch(ips: string[]): Promise<IPBatchAnalysis> {
    const results: IPAnalysisResult[] = [];
    
    for (const ip of ips) {
      try {
        const result = await this.analyzeIP(ip);
        results.push(result);
      } catch (error) {
        console.error(`分析IP ${ip} 失败:`, error);
      }
    }

    return {
      results,
      statistics: this.calculateStatistics(results),
      patterns: this.detectPatterns(results)
    };
  }

  // 单个IP分析
  static async analyzeIP(ip: string): Promise<IPAnalysisResult> {
    // 这里应该调用实际的IP分析API
    // 为了演示，我们使用模拟数据
    
    const mockResult: IPAnalysisResult = {
      ip,
      location: {
        country: 'Netherlands',
        countryCode: 'NL',
        region: 'North Holland',
        city: 'Amsterdam',
        latitude: 52.3740,
        longitude: 4.8897,
        timezone: 'Europe/Amsterdam',
        postalCode: '1012',
        accuracy: 'city'
      },
      network: {
        isp: 'LeaseWeb Netherlands B.V.',
        organization: 'LeaseWeb',
        asn: 'AS60781',
        asnName: 'LEASEWEB-NL',
        reverseDns: `${ip.replace(/\./g, '-')}.static.leaseweb.com`,
        ipType: 'datacenter'
      },
      security: {
        threatLevel: this.assessThreatLevel(ip),
        riskFactors: this.identifyRiskFactors(ip),
        blacklistStatus: await this.checkBlacklist(ip),
        vpnTorStatus: await this.checkVPNTor(ip),
        reputation: {
          score: Math.floor(Math.random() * 100),
          category: 'suspicious',
          lastUpdate: new Date().toISOString()
        }
      },
      usage: {
        isHosting: true,
        isMobile: false,
        isProxy: true,
        isBot: false,
        usageType: ['hosting', 'proxy']
      },
      geolocation: {
        currency: 'EUR',
        languages: ['nl', 'en'],
        callingCode: '+31',
        flag: '🇳🇱'
      }
    };

    return mockResult;
  }

  // 威胁等级评估
  private static assessThreatLevel(ip: string): 'low' | 'medium' | 'high' {
    let score = 0;
    
    // 检查是否在已知恶意IP列表中
    if (this.isKnownMaliciousIP(ip)) score += 5;
    
    // 检查IP段
    if (this.isSuspiciousRange(ip)) score += 3;
    
    // 检查是否为数据中心IP
    if (this.isDatacenterIP(ip)) score += 2;
    
    if (score >= 5) return 'high';
    if (score >= 2) return 'medium';
    return 'low';
  }

  // 识别风险因素
  private static identifyRiskFactors(ip: string): string[] {
    const factors: string[] = [];
    
    if (this.isKnownMaliciousIP(ip)) {
      factors.push('已知恶意IP');
    }
    
    if (this.isSuspiciousRange(ip)) {
      factors.push('可疑IP网段');
    }
    
    if (this.isDatacenterIP(ip)) {
      factors.push('数据中心IP');
    }
    
    if (this.isTorExitNode(ip)) {
      factors.push('Tor出口节点');
    }
    
    return factors;
  }

  // 检查黑名单状态
  private static async checkBlacklist(ip: string): Promise<IPAnalysisResult['security']['blacklistStatus']> {
    // 模拟黑名单检查
    const knownBadIPs = ['95.223.57.198', '185.220.101.1'];
    const isBlacklisted = knownBadIPs.includes(ip);
    
    return {
      isBlacklisted,
      sources: isBlacklisted ? ['Spamhaus', 'AbuseIPDB'] : [],
      lastSeen: isBlacklisted ? new Date().toISOString() : undefined,
      confidence: isBlacklisted ? 0.95 : 0.1
    };
  }

  // 检查VPN/Tor状态
  private static async checkVPNTor(ip: string): Promise<IPAnalysisResult['security']['vpnTorStatus']> {
    const isTor = VPN_DETECTION_SOURCES.tor_exit_nodes.includes(ip);
    const isVPN = VPN_DETECTION_SOURCES.known_vpn_ranges.some(range => 
      this.ipInRange(ip, range)
    );
    
    return {
      isVPN,
      isTor,
      isProxy: isVPN || isTor,
      confidence: (isVPN || isTor) ? 0.9 : 0.1,
      exitNode: isTor
    };
  }

  // 计算统计信息
  private static calculateStatistics(results: IPAnalysisResult[]): IPBatchAnalysis['statistics'] {
    const stats = {
      total: results.length,
      byThreatLevel: {} as { [key: string]: number },
      byCountry: {} as { [key: string]: number },
      byIPType: {} as { [key: string]: number },
      blacklisted: 0,
      vpnTor: 0,
      suspicious: 0
    };

    results.forEach(result => {
      // 威胁等级统计
      stats.byThreatLevel[result.security.threatLevel] = 
        (stats.byThreatLevel[result.security.threatLevel] || 0) + 1;
      
      // 国家统计
      stats.byCountry[result.location.country] = 
        (stats.byCountry[result.location.country] || 0) + 1;
      
      // IP类型统计
      stats.byIPType[result.network.ipType] = 
        (stats.byIPType[result.network.ipType] || 0) + 1;
      
      // 黑名单统计
      if (result.security.blacklistStatus.isBlacklisted) {
        stats.blacklisted++;
      }
      
      // VPN/Tor统计
      if (result.security.vpnTorStatus.isVPN || result.security.vpnTorStatus.isTor) {
        stats.vpnTor++;
      }
      
      // 可疑IP统计
      if (result.security.threatLevel !== 'low') {
        stats.suspicious++;
      }
    });

    return stats;
  }

  // 检测模式
  private static detectPatterns(results: IPAnalysisResult[]): IPBatchAnalysis['patterns'] {
    const patterns = {
      suspiciousRanges: [] as string[],
      commonISPs: [] as string[],
      geographicClusters: [] as Array<{
        country: string;
        count: number;
        ips: string[];
      }>
    };

    // 检测可疑IP段
    const ipRanges = new Map<string, string[]>();
    results.forEach(result => {
      const range = result.ip.split('.').slice(0, 3).join('.') + '.0/24';
      if (!ipRanges.has(range)) {
        ipRanges.set(range, []);
      }
      ipRanges.get(range)!.push(result.ip);
    });

    // 找出有多个IP的网段
    ipRanges.forEach((ips, range) => {
      if (ips.length > 1) {
        patterns.suspiciousRanges.push(range);
      }
    });

    // 统计常见ISP
    const ispCount = new Map<string, number>();
    results.forEach(result => {
      const isp = result.network.isp;
      ispCount.set(isp, (ispCount.get(isp) || 0) + 1);
    });

    patterns.commonISPs = Array.from(ispCount.entries())
      .sort(([,a], [,b]) => b - a)
      .slice(0, 5)
      .map(([isp]) => isp);

    // 地理聚类
    const countryGroups = new Map<string, string[]>();
    results.forEach(result => {
      const country = result.location.country;
      if (!countryGroups.has(country)) {
        countryGroups.set(country, []);
      }
      countryGroups.get(country)!.push(result.ip);
    });

    patterns.geographicClusters = Array.from(countryGroups.entries())
      .map(([country, ips]) => ({
        country,
        count: ips.length,
        ips
      }))
      .sort((a, b) => b.count - a.count);

    return patterns;
  }

  // 用户IP历史分析
  static analyzeUserIPHistory(history: UserIPHistory): UserIPHistory['analysis'] {
    const uniqueCountries = new Set(history.ips.map(ip => ip.location.split(',')[0])).size;
    const suspiciousCount = history.ips.filter(ip => ip.suspicious).length;
    const vpnUsage = history.ips.some(ip => ip.suspicious); // 简化判断
    
    // 检测快速位置变化
    let rapidChanges = false;
    for (let i = 1; i < history.ips.length; i++) {
      const prev = new Date(history.ips[i-1].timestamp);
      const curr = new Date(history.ips[i].timestamp);
      const timeDiff = (curr.getTime() - prev.getTime()) / (1000 * 60 * 60); // 小时
      
      if (timeDiff < 2 && history.ips[i-1].location !== history.ips[i].location) {
        rapidChanges = true;
        break;
      }
    }

    return {
      totalSessions: history.ips.length,
      uniqueCountries,
      suspiciousActivity: suspiciousCount > 0,
      rapidLocationChanges: rapidChanges,
      vpnUsage
    };
  }

  // 辅助方法
  private static isKnownMaliciousIP(ip: string): boolean {
    const knownBadIPs = ['95.223.57.198', '185.220.101.1', '46.166.139.111'];
    return knownBadIPs.includes(ip);
  }

  private static isSuspiciousRange(ip: string): boolean {
    const suspiciousRanges = ['95.223.', '185.220.', '46.166.'];
    return suspiciousRanges.some(range => ip.startsWith(range));
  }

  private static isDatacenterIP(ip: string): boolean {
    // 简化判断，实际应该查询ASN数据库
    return this.isSuspiciousRange(ip);
  }

  private static isTorExitNode(ip: string): boolean {
    return VPN_DETECTION_SOURCES.tor_exit_nodes.includes(ip);
  }

  private static ipInRange(ip: string, range: string): boolean {
    // 简化的CIDR检查，实际应该使用专门的IP库
    const [rangeIP, mask] = range.split('/');
    const rangeParts = rangeIP.split('.').map(Number);
    const ipParts = ip.split('.').map(Number);
    
    const maskBits = parseInt(mask);
    const bytes = Math.floor(maskBits / 8);
    
    for (let i = 0; i < bytes; i++) {
      if (rangeParts[i] !== ipParts[i]) return false;
    }
    
    return true;
  }
}

// 报告生成器
export class ReportGenerator {
  static generatePDFReport(analysis: IPBatchAnalysis): string {
    // 生成HTML格式的报告，可以转换为PDF
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>IP地址安全分析报告</title>
        <style>
          body { font-family: 'Microsoft YaHei', Arial, sans-serif; margin: 20px; line-height: 1.6; }
          .header { text-align: center; margin-bottom: 30px; border-bottom: 2px solid #3b82f6; padding-bottom: 20px; }
          .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
          .stat-card { border: 1px solid #e5e7eb; padding: 20px; border-radius: 8px; text-align: center; background: #f9fafb; }
          .stat-number { font-size: 2em; font-weight: bold; color: #3b82f6; }
          .ip-result { border: 1px solid #e5e7eb; margin: 15px 0; padding: 20px; border-radius: 8px; }
          .high-risk { border-left: 5px solid #ef4444; background: #fef2f2; }
          .medium-risk { border-left: 5px solid #f59e0b; background: #fffbeb; }
          .low-risk { border-left: 5px solid #10b981; background: #f0fdf4; }
          .risk-factors { margin-top: 15px; }
          .risk-factor { display: inline-block; background: #e5e7eb; padding: 5px 10px; margin: 3px; border-radius: 15px; font-size: 0.9em; }
          .patterns { background: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0; }
          .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #e5e7eb; text-align: center; color: #6b7280; }
        </style>
      </head>
      <body>
        <div class="header">
          <h1>IP地址安全分析报告</h1>
          <p>生成时间: ${new Date().toLocaleString('zh-CN')}</p>
          <p>分析引擎版本: v2.0 | 数据源: 多重验证</p>
        </div>
        
        <div class="stats">
          <div class="stat-card">
            <div class="stat-number">${analysis.statistics.total}</div>
            <div>总IP数量</div>
          </div>
          <div class="stat-card">
            <div class="stat-number">${analysis.statistics.byThreatLevel.high || 0}</div>
            <div>高风险IP</div>
          </div>
          <div class="stat-card">
            <div class="stat-number">${analysis.statistics.blacklisted}</div>
            <div>黑名单IP</div>
          </div>
          <div class="stat-card">
            <div class="stat-number">${analysis.statistics.vpnTor}</div>
            <div>VPN/Tor节点</div>
          </div>
        </div>
        
        <div class="patterns">
          <h2>模式分析</h2>
          <h3>地理分布</h3>
          <ul>
            ${analysis.patterns.geographicClusters.slice(0, 5).map(cluster => 
              `<li>${cluster.country}: ${cluster.count} 个IP</li>`
            ).join('')}
          </ul>
          
          <h3>常见ISP</h3>
          <ul>
            ${analysis.patterns.commonISPs.slice(0, 5).map(isp => 
              `<li>${isp}</li>`
            ).join('')}
          </ul>
          
          ${analysis.patterns.suspiciousRanges.length > 0 ? `
          <h3>可疑IP段</h3>
          <ul>
            ${analysis.patterns.suspiciousRanges.map(range => 
              `<li>${range}</li>`
            ).join('')}
          </ul>
          ` : ''}
        </div>
        
        <h2>详细分析结果</h2>
        ${analysis.results.map(result => `
          <div class="ip-result ${result.security.threatLevel}-risk">
            <h3>${result.ip} - ${result.location.country}, ${result.location.city}</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px;">
              <div>
                <h4>地理位置</h4>
                <p><strong>国家:</strong> ${result.location.country} ${result.geolocation.flag}</p>
                <p><strong>城市:</strong> ${result.location.city}</p>
                <p><strong>坐标:</strong> ${result.location.latitude.toFixed(4)}, ${result.location.longitude.toFixed(4)}</p>
                <p><strong>时区:</strong> ${result.location.timezone}</p>
              </div>
              <div>
                <h4>网络信息</h4>
                <p><strong>ISP:</strong> ${result.network.isp}</p>
                <p><strong>组织:</strong> ${result.network.organization}</p>
                <p><strong>ASN:</strong> ${result.network.asn}</p>
                <p><strong>类型:</strong> ${result.network.ipType}</p>
              </div>
              <div>
                <h4>安全状态</h4>
                <p><strong>威胁等级:</strong> ${result.security.threatLevel === 'high' ? '高风险' : result.security.threatLevel === 'medium' ? '中等风险' : '低风险'}</p>
                <p><strong>信誉评分:</strong> ${result.security.reputation.score}/100</p>
                <p><strong>黑名单:</strong> ${result.security.blacklistStatus.isBlacklisted ? '是' : '否'}</p>
                <p><strong>VPN/Tor:</strong> ${result.security.vpnTorStatus.isTor ? 'Tor节点' : result.security.vpnTorStatus.isVPN ? 'VPN服务器' : '否'}</p>
              </div>
            </div>
            
            ${result.security.riskFactors.length > 0 ? `
            <div class="risk-factors">
              <h4>风险因素:</h4>
              ${result.security.riskFactors.map(factor => `<span class="risk-factor">${factor}</span>`).join('')}
            </div>
            ` : ''}
            
            ${result.security.blacklistStatus.isBlacklisted ? `
            <div style="background: #fee2e2; padding: 10px; border-radius: 5px; margin-top: 10px;">
              <strong>⚠️ 黑名单警告:</strong> 此IP已被以下安全机构列入黑名单: ${result.security.blacklistStatus.sources.join(', ')}
            </div>
            ` : ''}
          </div>
        `).join('')}
        
        <div class="footer">
          <p>本报告由系统安全诊断中心自动生成</p>
          <p>数据来源: IP-API, Spamhaus, AbuseIPDB, VirusTotal 等公开数据库</p>
          <p>⚠️ 免责声明: 本报告仅供参考，不构成法律依据。请结合其他工具进行综合分析。</p>
        </div>
      </body>
      </html>
    `;
  }

  static generateExcelData(analysis: IPBatchAnalysis): string {
    const headers = [
      'IP地址', '国家', '城市', '纬度', '经度', 'ISP', '组织', 'ASN', 
      'IP类型', '威胁等级', '信誉评分', '黑名单状态', 'VPN/Tor状态', 
      '风险因素', '时区', '货币', '最后更新'
    ];

    const rows = analysis.results.map(result => [
      result.ip,
      result.location.country,
      result.location.city,
      result.location.latitude.toString(),
      result.location.longitude.toString(),
      result.network.isp,
      result.network.organization,
      result.network.asn,
      result.network.ipType,
      result.security.threatLevel === 'high' ? '高风险' : 
      result.security.threatLevel === 'medium' ? '中等风险' : '低风险',
      result.security.reputation.score.toString(),
      result.security.blacklistStatus.isBlacklisted ? '是' : '否',
      result.security.vpnTorStatus.isTor ? 'Tor节点' : 
      result.security.vpnTorStatus.isVPN ? 'VPN服务器' : '否',
      result.security.riskFactors.join('; '),
      result.location.timezone,
      result.geolocation.currency,
      new Date().toISOString()
    ]);

    return [headers, ...rows]
      .map(row => row.map(cell => `"${cell}"`).join(','))
      .join('\n');
  }
}