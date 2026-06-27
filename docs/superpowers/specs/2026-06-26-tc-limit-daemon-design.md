# Design Spec: tc_limit 智能带宽限制 Daemon

> **日期**: 2026-06-26
> **状态**: 设计完成，待审核
> **相关文件**: `scripts/tc_limit.sh`, `services/tc-limit.service`

## 1. 背景与目标

当前 `tc_limit.sh` 是一个简单的固定带宽限制脚本：`--on` 设置固定值，`--off` 清除规则。问题是它无法感知网络实际使用状况，在低负载时浪费了可用带宽，在高负载时又无法主动防御云厂商的降级惩罚。

**目标**：将脚本扩展为 daemon，主动监控一段时间内的流量，模仿云厂商的惩罚策略做**主动自限**——在触发云厂商惩罚之前先自行降级，冷却后再恢复，最大化利用带宽同时最小化触发惩罚的概率。

### 云厂商惩罚规则（已知）

- **瞬时惩罚**：带宽达到 200M → 立即限速 1M，持续约 5 分钟
- **持续惩罚**：带宽持续超过 120M 达 20 分钟 → 限速 20M，持续约 5 分钟

（不同厂商规则不同，这些数值通过参数化来适配）

## 2. 设计概览

### 核心策略

```
常态 → 监控实时流量(滑动窗口) → 触发警戒 → 主动降级 → 冷却恢复 → 常态
```

### 状态机

```
          ┌──────────────┐
          │    NORMAL     │  tc = higher_limit (默认 150M)
          │   (常态运行)   │
          └──┬────────┬───┘
             │        │
             │        │ 滑动窗口累计字节 > threshold × window
             │        ▼
             │  ┌──────────────┐
             │  │   LIMITED     │  tc = lower_limit (默认 110M)
             │  │  (主动降级)    │
             │  └──────┬───────┘
             │         │
             │         │ cooldown 倒计时到期
             │         │ 清空缓冲区，从零重新采样
             │         ▼
             └──────── 恢复到 NORMAL
```

**恢复决策**：只用 cooldown 时间判断，不二次检查窗口累计量。原因：lower_limit(110M) 本身低于 threshold(120M)，在降级期间窗口累计只会下降，不会持续超标，引入二次窗口检查是多余的。

## 3. 参数设计

| 参数 | 短标志 | 默认值 | 单位 | 说明 |
|---|---|---|---|---|
| `--higher-limit` | `-H` | 150 | Mbps | 常态带宽上限 |
| `--lower-limit` | `-L` | 110 | Mbps | 降级后带宽上限 |
| `--threshold` | `-T` | 120 | Mbps | 流量警戒线，对标云厂商 sustained penalty 阈值 |
| `--window` | `-W` | 19 | 分钟 | 滑动窗口大小，用于计算警戒数据量上限 |
| `--interval` | `-I` | 10 | 秒 | 采样间隔，同时决定环形缓冲区槽位数 |
| `--cooldown` | `-C` | 5 | 分钟 | 降级后冷却时间 |
| `--iface` | 无 | 自动探测 | — | 网卡接口名 |
| `--dry-run` | 无 | false | — | 只监控不修改 tc 规则 |
| `--log-file` | 无 | — | — | 日志文件路径（默认 stdout/journal） |

### 设计约束

- `higher_limit > threshold > lower_limit`（被限制到 lower_limit 时必定低于警戒线）
- `higher_limit < 云厂商瞬时惩罚阈值`（避免瞬间触发惩罚）
- `threshold ≤ 云厂商 sustained 惩罚阈值`（在云厂商惩罚前主动干预）
- 滑动窗口槽位数 = `window × 60 / interval`，默认 114 槽位

## 4. 命令行接口

```bash
# 启动 daemon（使用所有默认值）
tc_limit --on

# 自定义参数启动
tc_limit --on -H 200 -L 100 -T 150 -W 19 -I 10 -C 5

# 停止 daemon 并清除所有 tc 规则
tc_limit --off

# 查看 daemon 运行状态
tc_limit --status

# 查看帮助
tc_limit -h
```

`--on` 启动时：
- 解析和校验参数
- 初始化 tc（应用 higher_limit）
- 初始化环形缓冲区
- 进入主循环（后台运行，由 systemd 管理生命周期）

`--status` 输出内容：
- 当前状态（NORMAL / LIMITED）
- 当前 tc 限速值
- 窗口累计数据量及平均带宽
- 如果在 LIMITED 状态，显示距离恢复剩余时间
- 最近一次状态变更时间和原因

## 5. 监控机制

### 数据源

`/sys/class/net/$IFACE/statistics/{tx_bytes,rx_bytes}`

- 内核级计数器，64 位，单调递增，不会因 tc 规则重建而归零
- 本机为代理专用服务器，回环流量可忽略，物理网卡统计基本等于代理流量
- 读取开销极低：一次 `cat` 拿到两个数字

### 采样与滑动窗口

```
采样间隔: 10 秒（可配置）
环形缓冲区: window × 60 / interval = 114 槽位
每个槽位: 该采样周期内 (tx_bytes + rx_bytes) 的增量
窗口累计: 缓冲区所有槽位之和
```

daemon 主循环每 interval 秒：
1. 读取当前字节计数器
2. 与上一次读数做差，得到本周期字节增量
3. 写入环形缓冲区（覆盖最旧槽位，维护当前写入位置指针）
4. 求和得到窗口累计值
5. 触发判断：`窗口累计字节 / window_seconds > threshold * 1000000 / 8`（转为 byte/s 比对）

## 6. tc 规则管理

### 初始化（启动时）

沿用现有逻辑：创建 IFB、设置 egress HTB + ingress 重定向到 IFB + IFB HTB。初始使用 higher_limit。

### 状态切换（运行时）

使用 `tc class change` 直接修改 rate/ceil，**不删不重建**，避免：
- 流量中断
- 计数器归零
- 规则引用丢失

```bash
# 切换到新速率（同时作用于 egress 和 IFB ingress）
tc class change dev $IFACE parent 1: classid 1:10 htb rate ${RATE}mbit ceil ${RATE}mbit burst ${BURST}kbit cburst ${BURST}kbit
tc class change dev $IFB   parent 2: classid 2:20 htb rate ${RATE}mbit ceil ${RATE}mbit burst ${BURST}kbit cburst ${BURST}kbit
```

burst/cburst 值沿用现有逻辑或根据新速率按比例计算。

### 清理（停止时）

删除所有 tc qdisc，关闭 IFB 设备，同现有 `cleanup()` 逻辑。

## 7. 持久化

### 文件

`/run/tc_limit.state`

### 内容

```
STATE=NORMAL
```
或
```
STATE=LIMITED
COOLDOWN_START=1719360000
```

### 行为

- **启动时**：如果 state 文件存在且有效，恢复状态。如果状态为 LIMITED 且剩余 cooldown > 0，继续在 LIMITED 状态运行，剩余冷却时间 = cooldown - (当前时间 - COOLDOWN_START)。如果冷却已过期，直接进入 NORMAL。
- **状态变更时**：写入 state 文件（原子写入：先写临时文件再 mv）
- **缓冲区不持久化**：重启后冷启动，最多损失一个窗口周期（默认 15 分钟）的监控数据。对于小概率重启事件可接受。

## 8. systemd 集成

### Service 文件变更

```ini
[Unit]
Description=Smart Bandwidth Limit Daemon (tc)
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=exec
ExecStart=/usr/local/bin/tc_limit --on
ExecStop=/usr/local/bin/tc_limit --off
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

- `Type=oneshot` → `Type=exec`：daemon 进程由 systemd 直接管理
- `ExecStart` 使用默认参数，用户可通过 `systemctl edit tc-limit` 的 override 文件或 `Environment=` 传递自定义参数
- `Restart=always`：daemon 异常退出时自动重启

### 日志

输出到 journal，包含：
- 启动信息（参数、接口、初始速率）
- 每次状态变更（原因、触发时的窗口平均带宽）
- 每 N 次采样的统计摘要（可选，避免刷屏）
- 错误（系统调用失败、tc 命令失败等）

## 9. 信号处理

| 信号 | 行为 |
|---|---|
| SIGTERM / SIGINT | 执行 cleanup（删除 tc 规则、IFB 设备），删除 state 文件，退出 0 |
| SIGUSR1 | 输出当前状态摘要到日志（同 `--status` 但在线输出） |

## 10. 错误处理

| 场景 | 处理 |
|---|---|
| 网卡不存在 | 启动时报错退出，exit 1 |
| tc 命令执行失败 | 记录错误日志，不退出（可能只是规则已存在） |
| /sys 读取失败 | 记录错误，跳过本次采样，下一个循环重试 |
| 连续 3 次采样失败 | 退出，让 systemd 重启（避免静默失效） |
| 参数校验失败 | 启动时报错退出，exit 1 |
| 已有 daemon 运行 | 检测 lock 文件或 pid 文件，拒绝重复启动 |

## 11. 文件变更清单

| 文件 | 变更 |
|---|---|
| `scripts/tc_limit.sh` | 完全重写：daemon 逻辑 + CLI 接口 |
| `services/tc-limit.service` | 修改 Type 和 ExecStart |
| `README.md` | 新增 tc_limit daemon 使用说明 |
| `/run/tc_limit.state` | 运行时状态文件（由脚本自动创建） |
| `docs/superpowers/specs/2026-06-26-tc-limit-daemon-design.md` | 本 spec 文件 |

## 12. 非功能需求

- **零外部依赖**：纯 bash，仅依赖 tc + ip 命令（已有）
- **向后兼容**：`tc_limit --off` 和 `tc_limit --status` 保持可用
- **低资源消耗**：每 10 秒一次文件读取 + 简单整数运算，CPU/内存几乎不可感知
- **优雅降级**：如果 `/run` 不可写（非 systemd 环境），跳过持久化，功能不受影响
