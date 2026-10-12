# Design Spec: nft-mgmt masquerade 持久化

> **日期**: 2026-10-12
> **状态**: 设计完成，待审核
> **相关文件**: `scripts/nft-mgmt.sh`, `scripts/tests/nft-mgmt-test.sh`（新增）, `services/nft-mgmt.service`

## 1. 背景与问题

### 现象

通过 `pfm on`、masquerade 菜单或 `pf add` 的自动启用所建立的 masquerade 规则，在 `nft-mgmt save` 之后不会被持久化；重启后 masquerade 丢失，端口转发虽被恢复却无法出网。

### 根因

1. `save_rules()`（`scripts/nft-mgmt.sh:935-941`）只导出 `table inet filter` 到 `/etc/nftables.d/nftrules.nft`，而 masquerade 规则位于 `ip nat` 表的 `POSTROUTING` 链，因此完全未被写入。
2. `load_rules()`（`scripts/nft-mgmt.sh:943-972`）只 `nft -f` 上述文件，随后仅从 `forward.csv` 恢复 DNAT 规则，**没有任何 masquerade 恢复逻辑**。因此开机后 masquerade 必然丢失；`pf add` 时调用的 `auto_enable_masquerade_default_eth0` 只覆盖 `eth0/enp3s0/ens33`，且仅在 `pf add` 路径上触发。
3. `save_forward_rules()`（`scripts/nft-mgmt.sh:532-538`）会把整个 ruleset 写入 `/etc/nftables.d/rules.nft`，但**没有任何子命令调用它**，属死代码，且其语义与 `save_rules()` 冲突。

### 目标

- `nft-mgmt save` 持久化脚本所管理的 masquerade 接口。
- `nft-mgmt load`（以及 `nft-mgmt.service` 开机路径）按持久化记录恢复 masquerade。
- 提供可重复、不污染宿主机的端到端测试。

### 非目标

- 不重写为 Python，不做 `nft -j` 解析层改造。
- 不改动黑/白名单、`udp off`、DNAT 的既有拦截逻辑。
- 不改 `pf clear` 与 masquerade 的关系（`pf clear` 仍只清 DNAT 及其 FORWARD accept）。
- 不更新 README。

## 2. 设计概览

### 不变量

**`ip nat` 表 `POSTROUTING` 链是唯一事实来源**；`masquerade.csv` 只持久化"哪些接口由本脚本启用"这一意图，绝不作为比内核状态更权威的数据。

```
启用路径                                禁用路径
pfm on / 菜单 / pf add 自动                pfm off / 菜单
        │                                       │
        ▼                                       ▼
  nft add rule (POSTROUTING)            nft delete rule (by handle)
        │                                       │
        ▼                                       ▼
  masq_registry_add <iface>            masq_registry_del <iface>
        │                                       │
        └──────────────┬────────────────────────┘
                       ▼
             /etc/nftables.d/masquerade.csv

save:  nft POSTROUTING ──masq_live_ifaces──► 覆盖写入 masquerade.csv（纠正漂移）
load:  masquerade.csv ──校验接口存在──► nft add rule (缺失则补下发)
```

### 关键决策

| 决策 | 选择 | 理由 |
|---|---|---|
| 持久化边界 | 仅记录本脚本启用的接口 | Docker 亦经 iptables-nft 在 `ip nat POSTROUTING` 写入 masquerade，若整体收录会在重启后下发陈旧规则 |
| 存储形态 | 独立注册表文件 `masquerade.csv` | 与既有 `forward.csv` 同目录同风格；DNAT 与 SNAT 生命周期互不干扰 |
| 事实来源 | live nft 状态 | `save` 以 live 覆盖注册表，手工 `nft delete` 造成的漂移会被自动纠正 |
| 接口缺失处理 | warn 并跳过 | 避免留下永不匹配的残留规则 |

## 3. 文件格式与判定规则

### 注册表

路径 `/etc/nftables.d/masquerade.csv`（复用已定义的 `RULES_DIR`），一行一个接口名，无表头：

```
eth0
ens33
```

读取时忽略空行与前导 `#` 注释行，写入时去重并规范化（去除首尾空白）。

### "自家规则"判定

Docker 生成的规则形如：

```
ip saddr 172.17.0.0/16 oifname != "docker0" masquerade
```

而本脚本生成的规则恒为：

```
oifname "eth0" masquerade # handle 2
```

因此从 `nft -a list chain ip nat POSTROUTING` 输出中逐行判定，**同时满足**：

- 含 `masquerade`
- 含 `oifname`，且 `oifname` 后接的是带引号的接口名（不是 `!=`）

**且不同时包含**任一排除项：`ip saddr`、`ip6 saddr`、`!=`、`fib`。

该条件集中于单一函数 `masq_parse_live`，是全脚本唯一解析 masquerade 的位置。

## 4. 函数边界

### 新增

| 函数 | 职责 |
|---|---|
| `masq_parse_live [--all]` | 解析 `POSTROUTING`，输出 `iface,handle` 行；默认仅自家规则，`--all` 输出全部 masquerade 规则（供 `list_masquerade` 展示用） |
| `masq_iface_has_rule <iface>` | 该接口是否已有自家 masquerade 规则 |
| `masq_live_ifaces` | 自家规则的接口名列表（去重），供 `save` 使用 |
| `masq_registry_add <iface>` | 幂等追加注册表条目 |
| `masq_registry_del <iface>` | 移除注册表条目 |
| `masq_registry_list` | 输出注册表中的接口名（过滤空行/注释/重复） |
| `sync_masq_registry` | 用 `masq_live_ifaces` 覆盖写入 `$MASQ_REG` |
| `apply_masquerade_from_registry` | `load` 路径：逐接口用 `list_net_ifaces` 校验存在性并补下发，单接口失败不中断 |
| `pfm_add_iface_from_args <iface>` | 非交互启用指定接口的 masquerade；先用 `list_net_ifaces` 校验接口存在，不存在则 `err` 返回 |
| `pfm_del_iface_from_args <iface>` | 非交互禁用指定接口：无论规则是否存在，都移除注册表条目；规则存在时按句柄删除 |

新增变量：`MASQ_REG="$RULES_DIR/masquerade.csv"`。

### 修改

| 位置 | 改动 |
|---|---|
| `enable_masquerade` | 下发成功后写注册表；**修正既有缺陷**：当前为 `nft add ... \|\| true` 后无条件打印"已启用"，改为失败即 `err` 返回且不入库（否则注册表会记录从未生效的接口） |
| `auto_enable_masquerade_default_eth0` | 成功下发后写注册表 |
| `disable_masquerade` | 删除成功后从注册表移除 |
| `list_masquerade` | 改用 `masq_parse_live --all`，删除内联 awk |
| `is_masquerade_enabled` | 改用 `masq_parse_live`，在其结果上过滤默认候选接口 |
| `save_rules` | 保存 `inet filter` 后调用 `sync_masq_registry`，并打印 `masquerade 已记录接口: ...`（无则打印未启用） |
| `load_rules` | 在 `apply_forward_from_csv` 之后调用 `apply_masquerade_from_registry` |
| `main` 的 `pfm` 分支 | 增加 `on <iface>` / `off <iface>` 非交互形式，无参数保持现有行为 |
| `usage()` | 补充 `pfm on\|off [iface]` 说明 |
| 删除 | `save_forward_rules()` 与 `RULES_FILE`（含 `rules.nft` 语义），因其无调用点且与 `save_rules` 语义冲突 |

### 相邻缺陷修正

以下三处在"普通用户 + sudo"模式下会以非 root 身份写 `/etc/nftables.d`，属既有缺陷；由于新增的注册表写入会经过同一目录，本次一并修正为 `$SUDO_CMD`：

- `scripts/nft-mgmt.sh:473` `touch "$FORWARD_REG"`
- `scripts/nft-mgmt.sh:563` `: > "$FORWARD_REG"`
- `scripts/nft-mgmt.sh:600` `touch "$FORWARD_REG"`

## 5. 命令行为

| 命令 | 行为 |
|---|---|
| `pfm on` | 默认候选接口中第一个可用者；找不到则 warn（保持现状） |
| `pfm on <iface>` | 直接启用指定接口；接口不在 `list_net_ifaces` 结果中则 err 返回 |
| `pfm off` | 保留交互式编号选择（保持现状） |
| `pfm off <iface>` | 直接删除该接口的 masquerade 规则并移除注册表条目；规则本就不存在时仍移除条目且不报错 |
| `pfm` | 进入 masquerade 交互菜单（保持现状） |
| `save` | 保存 `inet filter` 后刷新注册表并输出记录到的接口 |
| `load` | 加载规则文件 → 结构校验 → 从 CSV 恢复 DNAT → **恢复 masquerade** → 同步白名单控制 |

### 幂等性

任何路径重复启用同一接口都不会产生第二条规则：下发前一律经 `masq_iface_has_rule` 判定；注册表写入去重。

### 容错

- 注册表中的接口在当前系统链路中不存在 → `warn "接口 <iface> 不存在，跳过 masquerade 恢复"`，不下发规则、不中断 `load`。
- 单个接口下发失败 → 记录警告并继续处理其余接口，返回码不影响 `load` 整体成败（与既有 `apply_forward_from_csv` 风格一致）。
- 注册表文件不存在 → 视为未启用任何 masquerade，静默跳过（首次运行的正常状态）。

## 6. 测试交付物

新增 `scripts/tests/nft-mgmt-test.sh`，自包含、可重复、不污染宿主机。该目录不在 `setup.sh` 的 `SCRIPTS` 白名单内，因此不会被部署到目标机。

### 运行环境

- 自举：检测到未处于私有 netns 时，用 `unshare -rmn` 重新执行自身。
- 隔离手段：`/etc` 挂 tmpfs 覆盖层并创建 `/etc/nftables.d`；创建 `dummy0` 虚拟网卡并置 up。
- 净效果：netns 内 `id -u` 为 0，故 `SUDO_CMD` 为空，脚本直接读写 `/etc/nftables.d` 与真实 `nft`，等价于目标机的运行条件。
- 前置条件缺失（宿主禁用 unprivileged userns、缺少 `nft`/`unshare`/`ip`）时明确报错退出，**不静默跳过**。
- 测试不依赖网络与 DNS：转发相关场景统一使用字面 IP。

### 断言集

**场景隔离**：每个场景开始前执行 `nft flush chain ip nat POSTROUTING` 并清空 `masquerade.csv`，保证场景之间互不影响。

| # | 场景 | 断言 |
|---|---|---|
| 1 | 往返 | `pfm on dummy0` → `save` → `masquerade.csv` 含 `dummy0` → `flush chain ip nat POSTROUTING` 模拟重启 → `load` → 规则恢复且恰好 1 条 |
| 2 | 排除外部规则 | 预先手工插入 `ip saddr 172.17.0.0/16 oifname != "docker0" masquerade`，`save` 后断言注册表**不含** `docker0`；且该规则在 `load` 后仍原样存在 |
| 3 | 幂等 | 连续两次 `pfm on dummy0`，`POSTROUTING` 中该接口规则数为 1 |
| 4 | 容错 | 手工向注册表写入不存在的 `ens9`，`load` 后断言出现 warn 且未下发该规则 |
| 5 | 禁用 | `pfm off dummy0` 后断言规则与注册表条目均消失 |
| 6 | 未启用状态 | 无任何 masquerade 时 `save` 不报错，且注册表为空 |
| 7 | 默认候选接口路径 | 在 netns 内创建 dummy `eth0`，无参数 `pfm on` 应选中 `eth0` 并写入注册表；`is_masquerade_enabled` 判定为"开启"；另有 `dummy0` 规则时 `status` 的 masquerade 段仍按默认候选接口判定 |

### 退出码

全部通过返回 0；任一断言失败返回非 0，并打印失败项名称、期望值与实际值。

## 7. 风险与权衡

| 风险 | 影响 | 缓解 |
|---|---|---|
| 接口改名或换机器后注册表失效 | masquerade 不恢复，机器无法出网 | `load` 打印明确 warn；配合"跳过"策略，用户可重新 `pfm on <新接口>` 并 `save` |
| 注册表与内核状态漂移 | 记录与现状不一致 | `save` 一律以 live 状态覆盖；`load` 下发前查重 |
| 统一解析函数改动既有 `list_masquerade` / `is_masquerade_enabled` | 可能改变展示或判定行为 | 判定条件与既有一致（`oifname` + 引号接口名 + 排除 `!=`），断言集覆盖默认候选接口判定 |
| 宿主禁用 unprivileged userns | 测试无法运行 | 测试脚本显式报错并给出原因，不伪装成通过 |
| `pfm off` 无参数仍为交互式 | 脚本化场景无法使用 | 已提供 `pfm off <iface>` |

## 8. 验收标准

1. `bash -n scripts/nft-mgmt.sh` 与 `shellcheck scripts/nft-mgmt.sh` 无新增告警。
2. `bash scripts/tests/nft-mgmt-test.sh` 全绿（断言集 1–7）。
3. 真实主机验收：`nft-mgmt pfm on eth0` → `nft-mgmt save` → 重启 → `nft-mgmt status` 显示 masquerade 开启，`nft list chain ip nat POSTROUTING` 含该接口规则。
4. Docker 共存验收：存在 Docker 的 masquerade 规则时，`save` 后的 `masquerade.csv` 不含 Docker 相关接口，且 `load` 不改动 Docker 规则。
