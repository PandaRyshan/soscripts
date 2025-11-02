# soscripts - 系统安全与网络管理工具集

## 主要功能

- **IP/端口白名单/黑名单管理** - 使用 nftables 管理入站流量
- **端口转发管理** - 支持 TCP/UDP 端口转发
- **TCP 连接监控** - 实时监控连接数，支持邮件预警
- **fail2ban 集成** - 自动安装配置 fail2ban 防护

## 🚀 一键安装

使用以下命令一键安装所有组件（需要 bash、curl、systemd 环境）：

```bash
curl -fsSL https://github.com/PandaRyshan/soscripts/raw/refs/heads/main/setup.sh | bash
```

或者下载脚本后执行：

```bash
# 下载安装脚本
curl -fsSL https://github.com/PandaRyshan/soscripts/raw/refs/heads/main/setup.sh -o setup.sh

# 赋予执行权限并运行
chmod +x setup.sh
sudo ./setup.sh
```

安装完成后，可直接使用以下命令：
- `nft-mgmt` - nftables 管理工具
- `conn-monitor` - 连接监控工具
- `fail2ban-client` - fail2ban 客户端

## 📋 安装内容

该命令会：
- 下载脚本到 `/usr/share/scripts/` 并赋予执行权限
- 在 `/usr/local/bin/` 创建软链接（去掉 `.sh` 后缀作为命令名）
- 下载并安装 systemd 服务单元
- 安装并配置 fail2ban 及其配置文件
- 刷新 systemd 缓存并启用开机自启

## 🔧 conn-monitor 服务环境变量

conn-monitor 服务支持以下环境变量配置：

### 邮件配置（必需）
```bash
MAIL_SERVER="smtp.yourmail.com"      # SMTP 服务器地址
MAIL_PORT="587"                      # SMTP 端口（通常 587 或 465）
MAIL_USERNAME="your_username"        # 发件邮箱用户名
MAIL_PASSWORD="your_password"        # 发件邮箱密码或应用专用密码
MAIL_TO="recipient1@example.com recipient2@example.com"  # 收件人邮箱（空格分隔）
```

### 监控配置（可选）
```bash
LOCAL_IP_OVERRIDE="192.168.1.100"    # 指定本机 IP（默认自动获取公网 IP）
INTERVAL="10"                        # 监控间隔（秒，默认 10）
THRESHOLD="2000"                     # 连接数预警阈值（默认 2000）
COOLDOWN_PERIOD="300"                # 邮件冷却时间（秒，默认 300）
```

### 在 systemd 服务文件中配置示例：
```ini
[Service]
Environment="MAIL_SERVER=smtp.gmail.com"
Environment="MAIL_PORT=587"
Environment="MAIL_USERNAME=your.email@gmail.com"
Environment="MAIL_PASSWORD=your_app_password"
Environment="MAIL_TO=admin@example.com alert@example.com"
Environment="LOCAL_IP_OVERRIDE=192.168.1.100"
```

## 🛡️ nft-mgmt 命令帮助

### 基本用法
```bash
nft-mgmt [command] [arguments]
```

### 命令列表

#### 白名单管理
```bash
nft-mgmt wl-add <IP/CIDR>      # 添加白名单 IP
nft-mgmt wl-del <IP/CIDR>      # 删除白名单 IP  
nft-mgmt wl-clear              # 清空白名单
```

#### 黑名单管理
```bash
nft-mgmt bl-add <IP/CIDR>      # 添加黑名单 IP
nft-mgmt bl-del <IP/CIDR>      # 删除黑名单 IP
nft-mgmt bl-clear              # 清空黑名单
```

#### 端口转发管理
```bash
nft-mgmt forward-add           # 交互式添加端口转发
nft-mgmt forward-del           # 交互式删除端口转发
nft-mgmt forward-list          # 列出所有端口转发规则
```

#### 系统管理
```bash
nft-mgmt --ensure-struct        # 确保 nftables 结构存在
nft-mgmt load                   # 加载配置
```

### 示例
```bash
# 添加白名单
nft-mgmt wl-add 192.168.1.0/24
nft-mgmt wl-add 2001:db8::/32

# 添加黑名单
nft-mgmt bl-add 203.0.113.5
nft-mgmt bl-add 198.51.100.0/24

# 管理端口转发
nft-mgmt forward-add
nft-mgmt forward-list
```