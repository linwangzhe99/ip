import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { SystemDiagnostics } from './components/SystemDiagnostics';
import { Auth } from './components/Auth';
import { TrackingPage } from './components/TrackingPage';
import { supabase } from './lib/supabase';
import type { User } from '@supabase/supabase-js';

function App() {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // 获取当前用户会话
    supabase.auth.getSession().then(({ data: { session } }) => {
      setUser(session?.user ?? null);
      setLoading(false);
    });

    // 监听认证状态变化
    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      (event, session) => {
        setUser(session?.user ?? null);
      }
    );

    return () => subscription.unsubscribe();
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800 flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <Router>
      <Routes>
        {/* 访问跟踪页面 - 无需登录 */}
        <Route path="/track/:linkCode" element={<TrackingPage />} />
        
        {/* 主应用页面 */}
        <Route path="/*" element={
          <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800 p-4">
            <div className="max-w-6xl mx-auto">
              <div className="text-center mb-8">
                <h1 className="text-4xl font-bold text-gray-900 dark:text-white mb-2">
                  系统安全诊断中心
                </h1>
                <p className="text-lg text-gray-600 dark:text-gray-300">
                  专业的系统安全分析和IP地址威胁检测工具
                </p>
              </div>

              {user ? (
                <>
                  <div className="mb-6 flex justify-end">
                    <Auth user={user} onAuthChange={setUser} />
                  </div>
                  <SystemDiagnostics user={user} />
                </>
              ) : (
                <div className="max-w-md mx-auto">
                  <Auth user={user} onAuthChange={setUser} />
                </div>
              )}
            </div>
          </div>
        } />
      </Routes>
    </Router>
  );
}

export default App;