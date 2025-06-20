/*
  # 移除团队协作功能，实现全局数据共享

  1. 删除团队相关表
    - teams
    - team_members  
    - team_shared_data
    - team_invitations

  2. 移除现有表中的team_id字段

  3. 更新RLS策略为全局共享
*/

-- 删除团队相关表
DROP TABLE IF EXISTS team_invitations CASCADE;
DROP TABLE IF EXISTS team_shared_data CASCADE;
DROP TABLE IF EXISTS team_members CASCADE;
DROP TABLE IF EXISTS teams CASCADE;

-- 移除现有表中的team_id字段
ALTER TABLE ip_analysis_sessions DROP COLUMN IF EXISTS team_id;
ALTER TABLE performance_diagnostics DROP COLUMN IF EXISTS team_id;
ALTER TABLE program_analysis DROP COLUMN IF EXISTS team_id;

-- 更新RLS策略为全局共享
DROP POLICY IF EXISTS "用户可以访问自己的或团队的IP分析会话" ON ip_analysis_sessions;
CREATE POLICY "所有用户可以访问IP分析会话"
  ON ip_analysis_sessions
  FOR ALL
  TO authenticated
  USING (true)
  WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "用户可以访问自己的或团队的性能诊断记录" ON performance_diagnostics;
CREATE POLICY "所有用户可以访问性能诊断记录"
  ON performance_diagnostics
  FOR ALL
  TO authenticated
  USING (true)
  WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "用户可以访问自己的或团队的程序分析记录" ON program_analysis;
CREATE POLICY "所有用户可以访问程序分析记录"
  ON program_analysis
  FOR ALL
  TO authenticated
  USING (true)
  WITH CHECK (auth.uid() = user_id);

-- IP分析结果也改为全局可见
DROP POLICY IF EXISTS "用户只能访问自己的IP分析结果" ON ip_analysis_results;
CREATE POLICY "所有用户可以访问IP分析结果"
  ON ip_analysis_results
  FOR ALL
  TO authenticated
  USING (true);

-- 诊断会话也改为全局可见
DROP POLICY IF EXISTS "用户只能访问自己的诊断会话" ON diagnostic_sessions;
CREATE POLICY "所有用户可以访问诊断会话"
  ON diagnostic_sessions
  FOR ALL
  TO authenticated
  USING (true)
  WITH CHECK (auth.uid() = user_id);