# 系统安全诊断中心

专业的系统安全分析和IP地址威胁检测工具，提供全面的系统诊断服务。

## 功能特性

- **IP地址安全分析**: 批量分析IP地址的地理位置、ISP信息和安全威胁等级
- **系统性能诊断**: 检测系统卡顿、硬件问题等常见问题
- **程序使用分析**: 分析已安装程序的必要性和安全性
- **实时威胁评估**: 基于多种风险因素进行智能威胁等级评估

## 技术栈

- **前端**: React 18 + TypeScript + Tailwind CSS
- **图标**: Lucide React
- **构建工具**: Vite
- **部署**: Netlify + Netlify Functions

## 本地开发

```bash
# 安装依赖
npm install

# 启动开发服务器
npm run dev

# 构建生产版本
npm run build
```

## 部署到 Netlify

1. 将代码推送到 Git 仓库
2. 在 Netlify 中连接您的仓库
3. 构建设置会自动从 `netlify.toml` 读取
4. Netlify Functions 会自动部署到 `/.netlify/functions/` 路径

### 环境变量

在 Netlify 控制台中设置以下环境变量（如果需要）：

- `NODE_VERSION`: 18 (推荐)

## API 端点

- `/.netlify/functions/ip-proxy`: IP地址分析代理服务

## 安全特性

- CORS 头部配置
- 请求速率限制
- 输入验证和清理
- 安全头部设置

## 许可证

MIT License