import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { VisitorTrackingDB } from '../lib/visitorTracking';
import { Globe, MapPin, Clock, Shield, AlertTriangle } from 'lucide-react';

export function TrackingPage() {
  const { linkCode } = useParams<{ linkCode: string }>();
  const navigate = useNavigate();
  const [isLoading, setIsLoading] = useState(true);
  const [trackingLink, setTrackingLink] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const trackVisit = async () => {
      if (!linkCode) {
        setError('无效的跟踪链接');
        setIsLoading(false);
        return;
      }

      try {
        // 获取跟踪链接信息
        const link = await VisitorTrackingDB.getTrackingLinkByCode(linkCode);
        
        if (!link) {
          setError('跟踪链接不存在或已过期');
          setIsLoading(false);
          return;
        }

        setTrackingLink(link);

        // 检查是否过期
        if (link.expires_at && new Date(link.expires_at) < new Date()) {
          setError('跟踪链接已过期');
          setIsLoading(false);
          return;
        }

        // 获取访问者信息
        const userAgent = navigator.userAgent;
        const referrer = document.referrer;
        
        // 获取访问者IP（通过第三方服务）
        let visitorIP = '';
        try {
          const ipResponse = await fetch('https://api.ipify.org?format=json');
          const ipData = await ipResponse.json();
          visitorIP = ipData.ip;
        } catch (ipError) {
          console.error('获取IP失败:', ipError);
          // 使用备用方法或默认值
          visitorIP = '0.0.0.0';
        }

        // 生成会话ID
        const sessionId = sessionStorage.getItem('visitor_session_id') || 
          Math.random().toString(36).substring(2) + Date.now().toString(36);
        sessionStorage.setItem('visitor_session_id', sessionId);

        // 记录访问
        await VisitorTrackingDB.logVisitorIP(link.id, {
          ip_address: visitorIP,
          user_agent: link.collect_user_agent ? userAgent : undefined,
          referrer: link.collect_referrer ? referrer : undefined,
          session_id: sessionId
        });

        // 如果有重定向URL，则重定向
        if (link.target_url) {
          setTimeout(() => {
            window.location.href = link.target_url;
          }, 2000); // 2秒后重定向
        }

      } catch (err) {
        console.error('跟踪访问失败:', err);
        setError('记录访问信息时出错');
      } finally {
        setIsLoading(false);
      }
    };

    trackVisit();
  }, [linkCode]);

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center">
        <div className="bg-white p-8 rounded-xl shadow-lg border border-gray-200 max-w-md w-full mx-4">
          <div className="text-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
            <h2 className="text-xl font-semibold text-gray-800 mb-2">正在加载...</h2>
            <p className="text-gray-600">正在处理您的访问请求</p>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-red-50 to-pink-100 flex items-center justify-center">
        <div className="bg-white p-8 rounded-xl shadow-lg border border-red-200 max-w-md w-full mx-4">
          <div className="text-center">
            <AlertTriangle className="h-12 w-12 text-red-500 mx-auto mb-4" />
            <h2 className="text-xl font-semibold text-red-800 mb-2">访问错误</h2>
            <p className="text-red-600 mb-4">{error}</p>
            <button
              onClick={() => navigate('/')}
              className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors"
            >
              返回首页
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-green-50 to-blue-100 flex items-center justify-center">
      <div className="bg-white p-8 rounded-xl shadow-lg border border-gray-200 max-w-md w-full mx-4">
        <div className="text-center">
          <Shield className="h-12 w-12 text-green-500 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-gray-800 mb-2">访问已记录</h2>
          <p className="text-gray-600 mb-4">
            您的访问信息已被安全记录用于分析目的
          </p>
          
          {trackingLink && (
            <div className="bg-gray-50 p-4 rounded-lg mb-4 text-left">
              <h3 className="font-semibold text-gray-800 mb-2">{trackingLink.link_name}</h3>
              {trackingLink.description && (
                <p className="text-sm text-gray-600 mb-2">{trackingLink.description}</p>
              )}
              
              <div className="space-y-2 text-xs text-gray-500">
                <div className="flex items-center">
                  <Globe className="h-3 w-3 mr-1" />
                  <span>IP地址和地理位置信息已记录</span>
                </div>
                {trackingLink.collect_user_agent && (
                  <div className="flex items-center">
                    <MapPin className="h-3 w-3 mr-1" />
                    <span>浏览器信息已记录</span>
                  </div>
                )}
                {trackingLink.collect_referrer && (
                  <div className="flex items-center">
                    <Clock className="h-3 w-3 mr-1" />
                    <span>来源页面已记录</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {trackingLink?.target_url ? (
            <div className="space-y-3">
              <p className="text-sm text-blue-600">
                正在重定向到目标页面...
              </p>
              <div className="w-full bg-blue-200 rounded-full h-2">
                <div className="bg-blue-600 h-2 rounded-full animate-pulse" style={{ width: '100%' }}></div>
              </div>
              <a
                href={trackingLink.target_url}
                className="inline-block px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
              >
                立即跳转
              </a>
            </div>
          ) : (
            <button
              onClick={() => navigate('/')}
              className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg transition-colors"
            >
              返回首页
            </button>
          )}
          
          <div className="mt-6 p-3 bg-blue-50 rounded-lg">
            <p className="text-xs text-blue-700">
              <Shield className="h-3 w-3 inline mr-1" />
              您的隐私受到保护。收集的信息仅用于安全分析和统计目的。
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}