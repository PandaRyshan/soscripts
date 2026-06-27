# soscripts - 个人防火墙脚本合集

## 主要功能

- **IP/端口白名单/黑名单管理** - 使用 nftables 管理入站流量(对 docker 有效)
- **端口转发管理** - 支持 TCP/UDP 端口转发
- **TCP 连接监控** - 实时监控连接数，支持邮件预警
- **fail2ban 集成** - 自动安装配置 fail2ban 防护
- **智能带宽限制** - 主动监控流量，滑动窗口检测高占用，自动降级避免触发云厂商惩罚

## 🚀 一键安装

使用以下命令一键安装所有组件（需要 bash、curl、systemd 环境）：

```bash
curl -fsSL https://github.com/PandaRyshan/soscripts/raw/refs/heads/main/setup.sh | bash
```

安装完成后，可直接使用以下命令：
- `nft-mgmt` - nftables 管理工具
- `conn-monitor` - 连接监控工具
- `fail2ban-client` - fail2ban 客户端
- `tc_limit` - 智能带宽限制

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
nft-mgmt wl add <IP/CIDR>      # 添加白名单 IP
nft-mgmt wl del <IP/CIDR>      # 删除白名单 IP  
nft-mgmt wl clear              # 清空白名单
```

#### 黑名单管理
```bash
nft-mgmt bl add <IP/CIDR>      # 添加黑名单 IP
nft-mgmt bl del <IP/CIDR>      # 删除黑名单 IP
nft-mgmt bl clear              # 清空黑名单
```

#### 端口转发管理
```bash
nft-mgmt pf list          # 列出所有端口转发规则
nft-mgmt pf add           # 交互式添加端口转发菜单
nft-mgmt pf del           # 交互式删除端口转发菜单
nft-mgmt pf add <protocol> <src_ip> <src_port> <dst_ip> <dst_port>  # 添加端口转发规则
nft-mgmt pf del <protocol> <src_ip> <src_port> <dst_ip> <dst_port>  # 删除端口转发规则
nft-mgmt pfm <on/off>       # 启用/禁用 masquerade
```

#### 系统管理
```bash
nft-mgmt status                # 打印所有规则
nft-mgmt status <wl/bl/pf>     # 打印白名单/黑名单/端口转发规则
nft-mgmt init                  # 初始化 nftables 结构
nft-mgmt save                  # 保存规则表
nft-mgmt load                  # 加载规则表
```

## 🚦 tc_limit 智能带宽限制

tc_limit 是一个守护进程，通过主动监控网卡流量并动态调整 tc 限速，在触发云厂商带宽惩罚之前主动降级，冷却后自动恢复。

### 工作原理

```
常态 (150M) ──监控窗口累计流量──▶ 超警戒线 ──▶ 主动降级 (110M)
                                                    │
                                          cooldown 结束
                                                    │
                                                    ▼
                                              恢复常态 (150M)
```

- 每 10 秒采样一次网卡 tx/rx 字节计数器
- 维护一个 19 分钟的滑动窗口（114 个采样点）
- 窗口内累计数据量超过 `threshold × window` 时，说明持续高负载接近云厂商惩罚线，主动降级
- 降级后等待 cooldown 冷却期结束，自动恢复到常态限速

### 基本用法

```bash
# 启动 daemon（使用默认参数）
tc_limit --on

# 自定义参数
tc_limit --on -H 200 -L 100 -T 150 -W 20 -I 10 -C 5

# 查看运行状态
tc_limit --status

# 停止 daemon
tc_limit --off

# 仅监控不修改 tc（测试参数用）
tc_limit --on --dry-run
```

### 参数说明

| 参数 | 短标志 | 默认值 | 说明 |
|---|---|---|---|
| `--higher-limit` | `-H` | 150 | 常态带宽上限 (Mbps) |
| `--lower-limit`  | `-L` | 110 | 降级后带宽上限 (Mbps) |
| `--threshold`    | `-T` | 120 | 流量警戒线 (Mbps) |
| `--window`       | `-W` | 19  | 滑动窗口大小 (分钟) |
| `--interval`     | `-I` | 10  | 采样间隔 (秒) |
| `--cooldown`     | `-C` | 5   | 降级后冷却时间 (分钟) |
| `--iface`        |      | 自动 | 网卡接口名 |
| `--dry-run`      |      |      | 只监控不修改 tc 规则 |

### systemd 服务

```bash
# 启动
systemctl start tc-limit

# 开机自启
systemctl enable tc-limit

# 查看日志
journalctl -u tc-limit -f

# 自定义参数（创建 override 文件）
systemctl edit tc-limit
# 在 override 文件中加入：
# [Service]
# ExecStart=
# ExecStart=/usr/local/bin/tc_limit --on -H 200 -L 100
```
