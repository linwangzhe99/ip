import React, { useState, useEffect } from 'react';
import { supabase } from '../lib/supabase';
import { User, LogIn, UserPlus, LogOut, Shield, Mail, RefreshCw, AlertCircle, CheckCircle } from 'lucide-react';
import type { User as SupabaseUser } from '@supabase/supabase-js';

interface AuthProps {
  user: SupabaseUser | null;
  onAuthChange: (user: SupabaseUser | null) => void;
}

export function Auth({ user, onAuthChange }: AuthProps) {
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [resendLoading, setResendLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [messageType, setMessageType] = useState<'success' | 'error' | 'warning' | 'info'>('info');
  const [showResendOption, setShowResendOption] = useState(false);

  useEffect(() => {
    // 监听认证状态变化
    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      (event, session) => {
        onAuthChange(session?.user ?? null);
        if (event === 'SIGNED_IN') {
          setMessage('登录成功！');
          setMessageType('success');
          setShowResendOption(false);
        } else if (event === 'SIGNED_OUT') {
          setMessage('已退出登录');
          setMessageType('info');
          setShowResendOption(false);
        }
      }
    );

    return () => subscription.unsubscribe();
  }, [onAuthChange]);

  const handleAuth = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');
    setShowResendOption(false);

    try {
      if (isLogin) {
        const { error } = await supabase.auth.signInWithPassword({
          email,
          password,
        });
        if (error) throw error;
      } else {
        const { error } = await supabase.auth.signUp({
          email,
          password,
        });
        if (error) throw error;
        setMessage('注册成功！请检查邮箱确认链接。');
        setMessageType('success');
      }
    } catch (error: any) {
      console.error('Auth error:', error);
      
      // 检查是否为邮箱未确认错误
      if (error.message?.includes('Email not confirmed') || 
          error.code === 'email_not_confirmed' ||
          error.message?.includes('email_not_confirmed')) {
        setMessage('邮箱尚未确认。请检查您的邮箱（包括垃圾邮件文件夹）并点击确认链接，或点击下方按钮重新发送确认邮件。');
        setMessageType('warning');
        setShowResendOption(true);
      } else if (error.message?.includes('Invalid login credentials')) {
        setMessage('邮箱或密码错误，请检查后重试。');
        setMessageType('error');
      } else if (error.message?.includes('User already registered')) {
        setMessage('该邮箱已注册，请直接登录。');
        setMessageType('warning');
        setIsLogin(true);
      } else {
        setMessage(error.message || '操作失败，请稍后重试。');
        setMessageType('error');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleResendConfirmation = async () => {
    if (!email) {
      setMessage('请先输入邮箱地址');
      setMessageType('warning');
      return;
    }

    setResendLoading(true);
    try {
      const { error } = await supabase.auth.resend({
        type: 'signup',
        email: email,
      });
      
      if (error) throw error;
      setMessage('确认邮件已重新发送！请检查您的邮箱（包括垃圾邮件文件夹）。');
      setMessageType('success');
      setShowResendOption(false);
    } catch (error: any) {
      console.error('Resend error:', error);
      setMessage(error.message || '重发邮件失败，请稍后重试。');
      setMessageType('error');
    } finally {
      setResendLoading(false);
    }
  };

  const handleSignOut = async () => {
    const { error } = await supabase.auth.signOut();
    if (error) {
      setMessage('退出登录失败');
      setMessageType('error');
    }
  };

  const getMessageIcon = () => {
    switch (messageType) {
      case 'success':
        return <CheckCircle className="h-4 w-4" />;
      case 'warning':
        return <AlertCircle className="h-4 w-4" />;
      case 'error':
        return <AlertCircle className="h-4 w-4" />;
      default:
        return <AlertCircle className="h-4 w-4" />;
    }
  };

  const getMessageStyles = () => {
    switch (messageType) {
      case 'success':
        return 'bg-green-100 text-green-700 border-green-200 dark:bg-green-900/20 dark:text-green-300 dark:border-green-800';
      case 'warning':
        return 'bg-yellow-100 text-yellow-700 border-yellow-200 dark:bg-yellow-900/20 dark:text-yellow-300 dark:border-yellow-800';
      case 'error':
        return 'bg-red-100 text-red-700 border-red-200 dark:bg-red-900/20 dark:text-red-300 dark:border-red-800';
      default:
        return 'bg-blue-100 text-blue-700 border-blue-200 dark:bg-blue-900/20 dark:text-blue-300 dark:border-blue-800';
    }
  };

  if (user) {
    return (
      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-2 text-sm text-gray-600 dark:text-gray-300">
          <User className="h-4 w-4" />
          <span>{user.email}</span>
        </div>
        <button
          onClick={handleSignOut}
          className="flex items-center space-x-1 px-3 py-1 text-sm bg-red-100 hover:bg-red-200 dark:bg-red-900/20 dark:hover:bg-red-900/30 text-red-700 dark:text-red-300 rounded-lg transition-colors"
        >
          <LogOut className="h-4 w-4" />
          <span>退出</span>
        </button>
      </div>
    );
  }

  return (
    <div className="bg-white dark:bg-gray-800 p-6 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700 max-w-md mx-auto">
      <div className="flex items-center justify-center mb-6">
        <Shield className="h-8 w-8 text-blue-600 mr-3" />
        <h2 className="text-2xl font-bold text-gray-800 dark:text-white">
          {isLogin ? '登录账户' : '注册账户'}
        </h2>
      </div>

      <form onSubmit={handleAuth} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
            邮箱地址
          </label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            placeholder="your@email.com"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
            密码
          </label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={6}
            className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-800 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            placeholder="至少6位密码"
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full flex items-center justify-center space-x-2 py-3 px-4 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white font-semibold rounded-lg transition-colors"
        >
          {loading ? (
            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
          ) : (
            <>
              {isLogin ? <LogIn className="h-4 w-4" /> : <UserPlus className="h-4 w-4" />}
              <span>{isLogin ? '登录' : '注册'}</span>
            </>
          )}
        </button>
      </form>

      {showResendOption && (
        <div className="mt-4">
          <button
            onClick={handleResendConfirmation}
            disabled={resendLoading}
            className="w-full flex items-center justify-center space-x-2 py-2 px-4 bg-orange-600 hover:bg-orange-700 disabled:bg-gray-400 text-white font-medium rounded-lg transition-colors"
          >
            {resendLoading ? (
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
            ) : (
              <>
                <RefreshCw className="h-4 w-4" />
                <span>重新发送确认邮件</span>
              </>
            )}
          </button>
        </div>
      )}

      <div className="mt-4 text-center">
        <button
          onClick={() => {
            setIsLogin(!isLogin);
            setMessage('');
            setShowResendOption(false);
          }}
          className="text-sm text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
        >
          {isLogin ? '没有账户？点击注册' : '已有账户？点击登录'}
        </button>
      </div>

      {message && (
        <div className={`mt-4 p-3 rounded-lg border text-sm flex items-start space-x-2 ${getMessageStyles()}`}>
          {getMessageIcon()}
          <span className="flex-1">{message}</span>
        </div>
      )}

      <div className="mt-6 p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
        <h3 className="font-semibold text-blue-800 dark:text-blue-200 mb-2">为什么需要注册？</h3>
        <ul className="text-sm text-blue-700 dark:text-blue-300 space-y-1">
          <li>• 保存您的诊断历史记录</li>
          <li>• 跟踪系统性能趋势</li>
          <li>• 管理IP分析会话</li>
          <li>• 获得个性化建议</li>
        </ul>
      </div>

      {showResendOption && (
        <div className="mt-4 p-3 bg-amber-50 dark:bg-amber-900/20 rounded-lg border border-amber-200 dark:border-amber-800">
          <div className="flex items-start space-x-2">
            <Mail className="h-4 w-4 text-amber-600 dark:text-amber-400 mt-0.5 flex-shrink-0" />
            <div className="text-sm text-amber-700 dark:text-amber-300">
              <p className="font-medium mb-1">邮箱确认提示：</p>
              <ul className="space-y-1 text-xs">
                <li>• 请检查您的邮箱收件箱</li>
                <li>• 如未收到，请检查垃圾邮件文件夹</li>
                <li>• 确认邮件可能需要几分钟才能到达</li>
                <li>• 点击邮件中的链接完成确认</li>
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}