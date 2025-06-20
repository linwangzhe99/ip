/*
  # 团队协作功能

  1. 新建表
    - `teams` - 团队表
    - `team_members` - 团队成员表
    - `team_shared_data` - 团队共享数据表

  2. 安全
    - 启用RLS
    - 添加团队成员访问策略

  3. 功能
    - 团队创建和管理
    - 成员邀请和权限管理
    - 数据共享和协作查询
*/

-- 团队表
CREATE TABLE IF NOT EXISTS teams (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  description text,
  owner_id uuid REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  invite_code text UNIQUE DEFAULT encode(gen_random_bytes(8), 'hex'),
  is_active boolean DEFAULT true,
  max_members integer DEFAULT 10,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

-- 团队成员表
CREATE TABLE IF NOT EXISTS team_members (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid REFERENCES teams(id) ON DELETE CASCADE NOT NULL,
  user_id uuid REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  role text CHECK (role IN ('owner', 'admin', 'member', 'viewer')) DEFAULT 'member',
  permissions jsonb DEFAULT '{"read": true, "write": false, "delete": false, "invite": false}'::jsonb,
  joined_at timestamptz DEFAULT now(),
  invited_by uuid REFERENCES auth.users(id),
  is_active boolean DEFAULT true,
  UNIQUE(team_id, user_id)
);

-- 团队共享数据表
CREATE TABLE IF NOT EXISTS team_shared_data (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid REFERENCES teams(id) ON DELETE CASCADE NOT NULL,
  shared_by uuid REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  data_type text CHECK (data_type IN ('ip_analysis', 'performance_diagnostic', 'program_analysis')) NOT NULL,
  data_id uuid NOT NULL, -- 指向具体数据表的ID
  title text NOT NULL,
  description text,
  tags text[] DEFAULT '{}',
  is_public boolean DEFAULT false, -- 是否对团队外公开
  view_count integer DEFAULT 0,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

-- 团队邀请表
CREATE TABLE IF NOT EXISTS team_invitations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id uuid REFERENCES teams(id) ON DELETE CASCADE NOT NULL,
  invited_email text NOT NULL,
  invited_by uuid REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  role text CHECK (role IN ('admin', 'member', 'viewer')) DEFAULT 'member',
  invite_token text UNIQUE DEFAULT encode(gen_random_bytes(16), 'hex'),
  expires_at timestamptz DEFAULT (now() + interval '7 days'),
  accepted_at timestamptz,
  is_used boolean DEFAULT false,
  created_at timestamptz DEFAULT now()
);

-- 启用行级安全
ALTER TABLE teams ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_shared_data ENABLE ROW LEVEL SECURITY;
ALTER TABLE team_invitations ENABLE ROW LEVEL SECURITY;

-- 团队策略
CREATE POLICY "用户可以查看自己所在的团队"
  ON teams
  FOR SELECT
  TO authenticated
  USING (
    id IN (
      SELECT team_id FROM team_members 
      WHERE user_id = auth.uid() AND is_active = true
    )
  );

CREATE POLICY "团队所有者可以管理团队"
  ON teams
  FOR ALL
  TO authenticated
  USING (owner_id = auth.uid())
  WITH CHECK (owner_id = auth.uid());

-- 团队成员策略
CREATE POLICY "团队成员可以查看同团队成员"
  ON team_members
  FOR SELECT
  TO authenticated
  USING (
    team_id IN (
      SELECT team_id FROM team_members 
      WHERE user_id = auth.uid() AND is_active = true
    )
  );

CREATE POLICY "团队管理员可以管理成员"
  ON team_members
  FOR ALL
  TO authenticated
  USING (
    team_id IN (
      SELECT tm.team_id FROM team_members tm
      JOIN teams t ON tm.team_id = t.id
      WHERE tm.user_id = auth.uid() 
      AND tm.is_active = true
      AND (tm.role IN ('owner', 'admin') OR t.owner_id = auth.uid())
    )
  );

-- 团队共享数据策略
CREATE POLICY "团队成员可以查看共享数据"
  ON team_shared_data
  FOR SELECT
  TO authenticated
  USING (
    team_id IN (
      SELECT team_id FROM team_members 
      WHERE user_id = auth.uid() AND is_active = true
    )
    OR is_public = true
  );

CREATE POLICY "团队成员可以分享数据"
  ON team_shared_data
  FOR INSERT
  TO authenticated
  WITH CHECK (
    team_id IN (
      SELECT tm.team_id FROM team_members tm
      WHERE tm.user_id = auth.uid() 
      AND tm.is_active = true
      AND (tm.permissions->>'write')::boolean = true
    )
    AND shared_by = auth.uid()
  );

CREATE POLICY "数据分享者可以管理自己的分享"
  ON team_shared_data
  FOR ALL
  TO authenticated
  USING (shared_by = auth.uid());

-- 团队邀请策略
CREATE POLICY "团队管理员可以管理邀请"
  ON team_invitations
  FOR ALL
  TO authenticated
  USING (
    team_id IN (
      SELECT tm.team_id FROM team_members tm
      WHERE tm.user_id = auth.uid() 
      AND tm.is_active = true
      AND (tm.role IN ('owner', 'admin') OR (tm.permissions->>'invite')::boolean = true)
    )
    OR invited_by = auth.uid()
  );

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_teams_owner_id ON teams(owner_id);
CREATE INDEX IF NOT EXISTS idx_teams_invite_code ON teams(invite_code);

CREATE INDEX IF NOT EXISTS idx_team_members_team_id ON team_members(team_id);
CREATE INDEX IF NOT EXISTS idx_team_members_user_id ON team_members(user_id);
CREATE INDEX IF NOT EXISTS idx_team_members_active ON team_members(is_active) WHERE is_active = true;

CREATE INDEX IF NOT EXISTS idx_team_shared_data_team_id ON team_shared_data(team_id);
CREATE INDEX IF NOT EXISTS idx_team_shared_data_shared_by ON team_shared_data(shared_by);
CREATE INDEX IF NOT EXISTS idx_team_shared_data_type ON team_shared_data(data_type);
CREATE INDEX IF NOT EXISTS idx_team_shared_data_public ON team_shared_data(is_public) WHERE is_public = true;

CREATE INDEX IF NOT EXISTS idx_team_invitations_team_id ON team_invitations(team_id);
CREATE INDEX IF NOT EXISTS idx_team_invitations_token ON team_invitations(invite_token);
CREATE INDEX IF NOT EXISTS idx_team_invitations_email ON team_invitations(invited_email);

-- 添加更新时间触发器
CREATE TRIGGER update_teams_updated_at 
  BEFORE UPDATE ON teams 
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_team_shared_data_updated_at 
  BEFORE UPDATE ON team_shared_data 
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- 修改现有表以支持团队共享
ALTER TABLE ip_analysis_sessions ADD COLUMN IF NOT EXISTS team_id uuid REFERENCES teams(id) ON DELETE SET NULL;
ALTER TABLE performance_diagnostics ADD COLUMN IF NOT EXISTS team_id uuid REFERENCES teams(id) ON DELETE SET NULL;
ALTER TABLE program_analysis ADD COLUMN IF NOT EXISTS team_id uuid REFERENCES teams(id) ON DELETE SET NULL;

-- 更新现有策略以支持团队访问
DROP POLICY IF EXISTS "用户只能访问自己的IP分析会话" ON ip_analysis_sessions;
CREATE POLICY "用户可以访问自己的或团队的IP分析会话"
  ON ip_analysis_sessions
  FOR ALL
  TO authenticated
  USING (
    auth.uid() = user_id 
    OR team_id IN (
      SELECT team_id FROM team_members 
      WHERE user_id = auth.uid() AND is_active = true
    )
  )
  WITH CHECK (
    auth.uid() = user_id 
    OR team_id IN (
      SELECT tm.team_id FROM team_members tm
      WHERE tm.user_id = auth.uid() 
      AND tm.is_active = true
      AND (tm.permissions->>'write')::boolean = true
    )
  );

DROP POLICY IF EXISTS "用户只能访问自己的性能诊断记录" ON performance_diagnostics;
CREATE POLICY "用户可以访问自己的或团队的性能诊断记录"
  ON performance_diagnostics
  FOR ALL
  TO authenticated
  USING (
    auth.uid() = user_id 
    OR team_id IN (
      SELECT team_id FROM team_members 
      WHERE user_id = auth.uid() AND is_active = true
    )
  )
  WITH CHECK (
    auth.uid() = user_id 
    OR team_id IN (
      SELECT tm.team_id FROM team_members tm
      WHERE tm.user_id = auth.uid() 
      AND tm.is_active = true
      AND (tm.permissions->>'write')::boolean = true
    )
  );

DROP POLICY IF EXISTS "用户只能访问自己的程序分析记录" ON program_analysis;
CREATE POLICY "用户可以访问自己的或团队的程序分析记录"
  ON program_analysis
  FOR ALL
  TO authenticated
  USING (
    auth.uid() = user_id 
    OR team_id IN (
      SELECT team_id FROM team_members 
      WHERE user_id = auth.uid() AND is_active = true
    )
  )
  WITH CHECK (
    auth.uid() = user_id 
    OR team_id IN (
      SELECT tm.team_id FROM team_members tm
      WHERE tm.user_id = auth.uid() 
      AND tm.is_active = true
      AND (tm.permissions->>'write')::boolean = true
    )
  );