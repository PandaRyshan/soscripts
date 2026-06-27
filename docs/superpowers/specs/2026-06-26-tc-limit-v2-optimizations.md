# Design Spec: tc_limit v1→v2 优化

> **日期**: 2026-06-26
> **状态**: 待审阅
> **依赖**: v1 已验收通过（状态机、滑动窗口、tc 切换全部正常）
> **相关文件**: `scripts/tc_limit.sh`, `services/tc-limit.service`

## 1. 背景

v1 的基础功能（滑动窗口监控 + 状态机 + tc 热切换）已通过 iperf3 实测验证。本文档整理 7 个优化点中的可行方案，不考虑的和远期方案明确标注。

## 2. 优化清单总览

| # | 项目 | 决定 | 理由 |
|---|---|---|---|
| 1 | EWMA 指数滑动平均 | ❌ 不做 | 云厂商用精确 sliding window，EWMA 建模不对，徒增调参复杂度 |
| 2 | Hysteresis | ❌ 不做 | cooldown 已经防止振荡，lower_limit < threshold 保证窗口平均只降不升 |
| 3 | 结构化日志 + -v/-q | ✅ v2 | 投入产出比高 |
| 4 | STATE_FILE 富化 | ✅ 立即 | 一行文件写入，让 `--status` 即时可用 |
| 5 | 配置文件 + reload | ✅ v2 | 方便多机管理；reload 限于限速/阈值参数 |
| 6 | Token bucket | 🔵 v3 | 替代算法，需独立设计文档 |
| 7 | PID cmdline 校验 | ✅ 立即 | 一行改动消除安全隐患 |

## 3. 立即落地（本文档审阅通过后）

### 3.1 PID cmdline 校验（#7）

**问题**：当前 `proc_running()` 只检查 `/proc/$pid` 目录是否存在。PID 可能被内核复用。

**方案**：

```bash
# 当前
proc_running() { [[ -d "/proc/$1" ]]; }

# 改为
proc_running() {
    [[ -d "/proc/$1" ]] && grep -qF "tc_limit" "/proc/$1/cmdline" 2>/dev/null
}
```

影响面：仅 `proc_running` 一处定义，`stop_daemon` 和 `show_status` 自动受益。

### 3.2 STATE_FILE 富化（#4）

**问题**：当前 `/run/tc_limit.state` 只有 `STATE` 和 `COOLDOWN_START`，`--status` 每次要解析 tc 输出，daemon 不在时看不到任何历史信息。

**方案**：扩展 state 文件字段。

```
STATE=NORMAL
RATE=150
WINDOW_AVG=0.0
THRESHOLD=120
```

或 LIMITED 状态：

```
STATE=LIMITED
RATE=110
COOLDOWN_START=1719360000
WINDOW_AVG=35.5
THRESHOLD=120
```

字段说明：

| 字段 | 类型 | 说明 |
|---|---|---|
| `STATE` | enum | `NORMAL` 或 `LIMITED` |
| `RATE` | int | 当前 tc 限速 (Mbps) |
| `COOLDOWN_START` | epoch | 仅在 LIMITED 时出现 |
| `WINDOW_AVG` | float | 最近一次窗口平均值 (Mbps)，用于 `--status` 展示 |
| `THRESHOLD` | int | 当前使用的警戒线 (Mbps)，用于 `--status` 展示 |

变更影响：

- `save_state()`：写入新字段
- `load_state()`：无需读回（这些字段仅用于展示，恢复状态只用 STATE 和 COOLDOWN_START）
- `show_status()`：直接 source state 文件展示，无需解析 tc
- daemon 主循环：每次 periodic summary 时调用 `save_state()` 同步 WINDOW_AVG 和 RATE

**向后兼容**：旧格式 state 文件（缺少字段）被 `source` 时，`${RATE:-}` 和 `${WINDOW_AVG:-}` 通过默认值兜底，不会出错。

## 4. v2 规划（下个迭代）

### 4.1 结构化日志（#3）

**设计**：

```bash
# 日志级别定义
LOG_LEVEL=1          # 0=ERROR, 1=INFO, 2=WARN, 3=DEBUG

log_error() { (( LOG_LEVEL >= 0 )) && echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR $*" >&2; }
log_warn()  { (( LOG_LEVEL >= 2 )) && echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARN  $*" >&2; }
log_info()  { (( LOG_LEVEL >= 1 )) && echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO  $*" >&2; }
log_debug() { (( LOG_LEVEL >= 3 )) && echo "[$(date '+%Y-%m-%d %H:%M:%S')] DEBUG $*" >&2; }
```

CLI 控制：

```bash
tc_limit --on           # 默认 INFO（状态变更 + 周期 summary + 错误）
tc_limit --on -v        # DEBUG（额外：每次采样 delta、窗口累计值）
tc_limit --on -q        # ERROR only（生产静默运行，仅异常时输出）
```

映射：

| 标志 | LOG_LEVEL | 输出内容 |
|---|---|---|
| `-q` | 0 | 仅 FATAL 错误 |
| 无标志（默认） | 1 | + 状态变更、周期 summary |
| `-v` | 3 | + 每次采样详情 |

DEBUG 级别新增日志示例：

```
[2026-06-26 10:10:01] DEBUG sample #7: delta_bytes=49152000 window_sum=3774873600 threshold=3240000000
[2026-06-26 10:10:01] DEBUG decision: NORMAL → LIMITED
```

### 4.2 配置文件 + reload（#5）

**配置文件格式**（`/etc/tc_limit/tc_limit.conf`）：

```ini
# tc_limit daemon configuration
HIGHER_LIMIT=150
LOWER_LIMIT=110
THRESHOLD=120
WINDOW=19
INTERVAL=10
COOLDOWN=5
```

**加载优先级**：

```
命令行参数 > --config 指定的文件 > /etc/tc_limit/tc_limit.conf > 代码内置默认值
```

**实现方式**：bash `source` 逐行加载，与当前变量名一一对应，无需额外解析。

**CLI 扩展**：

```bash
tc_limit --on -c /etc/tc_limit/tc_limit.conf    # 指定配置文件
tc_limit --on --config /etc/tc_limit/tc_limit.conf
tc_limit --reload                                # 发送 SIGHUP 让 daemon 重新加载
```

**Reload 机制**：

- daemon 收到 `SIGHUP` 后重新读取配置文件
- 可热加载（立即生效）：`HIGHER_LIMIT`, `LOWER_LIMIT`, `THRESHOLD`, `COOLDOWN`
- 需 restart（跳过）：`WINDOW`, `INTERVAL`（会改变 BUF_SIZE 破坏环形缓冲区）
- 对于需 restart 的参数，reload 时记录 warn 日志提示

```bash
on_sighup() {
    log_info "Reloading configuration from ${CONFIG_FILE}"
    source "$CONFIG_FILE"
    validate_args
    if [[ "$STATE" == "NORMAL" ]]; then
        tc_change_rate "$HIGHER_LIMIT"
    fi
    save_state  # 更新 THRESHOLD 等展示字段
}
```

## 5. v3 方向（远期）

### 5.1 Token bucket 替代算法（#6）

作为可选的替代算法（`--algorithm=token`），而非替换当前 window 方案。

核心思路：

- 维护一个 burst token bucket：最大容量 = `(higher_limit - lower_limit) × window_seconds / 8` 字节
- 在 NORMAL 状态以 `(higher_limit - threshold)` 速率填充
- 每采样周期消耗 = `max(0, 实际流量 - threshold × interval_seconds / 8)`
- bucket 耗尽 → 进入 LIMITED
- 在 LIMITED 中以 cooldown 速率回充

区别于 window 算法：

| 维度 | Window | Token bucket |
|---|---|---|
| 低负载恢复 | 必须等满 window 周期 | 低负载时 token 快速回充 |
| 短时尖峰响应 | 被 window 稀释 | 快速消耗 token 更敏感 |
| 调参 | threshold + window | bucket_size + fill_rate + drain_rate |

此方案需要独立的设计文档和测试，v3 再议。

## 6. 实施计划

| 阶段 | 内容 | 变更文件 |
|---|---|---|
| 立即 | #7 PID cmdline 校验 | `proc_running()` 一处改动 |
| 立即 | #4 STATE_FILE 富化 | `save_state()`, `show_status()`, daemon 主循环 |
| v2 | #3 结构化日志 | 新增 log_* 函数族，CLI 新增 `-v`/`-q` |
| v2 | #5 配置文件 + reload | `parse_args` 扩展 `-c`，新增 `--reload` 子命令，SIGHUP handler |
| v3 | #6 Token bucket | 独立设计文档 |
