#!/usr/bin/env bash

# nft-mgmt.sh — 使用 nftables 管理入站 IP 白名单与黑名单（支持 IPv4/IPv6 与 CIDR）
# 设计原则：
# - 黑名单：加入即立即丢弃（优先级最高）
# - 白名单：当集合为空时不限制；当非空时，仅允许白名单 IP，其他全部拒绝
# - 采用 inet 表统一管理 ipv4/ipv6；入站在 input 钩子上生效
# - 提供 CLI 子命令，支持直接后缀参数调用
# - 安全：优先 insert 以靠前匹配，失败回退 add；命令失败不让脚本退出

set -euo pipefail

SCRIPT_NAME="nft-mgmt"
SUDO_CMD=""
CONF_DIR="/etc/nftables.d"
CONF_FILE="$CONF_DIR/inbound.nft"

log() { echo "[${SCRIPT_NAME}] $*"; }
err() { echo "[${SCRIPT_NAME}][ERROR] $*" >&2; }

require_root_or_sudo() {
  if [[ $(id -u) -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
      SUDO_CMD="sudo"
    else
      err "需要 root 或安装 sudo。请以 root 运行或先安装 sudo。"; exit 1
    fi
  else
    SUDO_CMD=""
  fi
}

ensure_struct() {
  require_root_or_sudo
  # inet 表与 input/prerouting 链
  $SUDO_CMD nft list table inet filter >/dev/null 2>&1 || $SUDO_CMD nft add table inet filter
  $SUDO_CMD nft list chain inet filter input >/dev/null 2>&1 || \
    $SUDO_CMD nft add chain inet filter input '{ type filter hook input priority 0; policy accept; }'
  # 添加 forward 链，拦截经过路由的转发流量（如 Docker 桥接）
  $SUDO_CMD nft list chain inet filter forward >/dev/null 2>&1 || \
    $SUDO_CMD nft add chain inet filter forward '{ type filter hook forward priority 0; policy accept; }'
  # 添加 prerouting 链以拦截 Docker 端口转发流量（使用 raw 优先级 -300，早于 DNAT）
  $SUDO_CMD nft list chain inet filter prerouting >/dev/null 2>&1 || \
    $SUDO_CMD nft add chain inet filter prerouting '{ type filter hook prerouting priority -300; policy accept; }'
  # 如果已存在但优先级不是 raw（-300），则重建链以保证更早拦截
  if ! $SUDO_CMD nft list chain inet filter prerouting 2>/dev/null | grep -q 'priority raw'; then
    $SUDO_CMD nft flush chain inet filter prerouting >/dev/null 2>&1 || true
    $SUDO_CMD nft delete chain inet filter prerouting >/dev/null 2>&1 || true
    $SUDO_CMD nft add chain inet filter prerouting '{ type filter hook prerouting priority -300; policy accept; }'
  fi
  # sets：黑名单、白名单（分别支持 IPv4/IPv6）
  $SUDO_CMD nft list set inet filter ip_blacklist_v4 >/dev/null 2>&1 || \
    $SUDO_CMD nft add set inet filter ip_blacklist_v4 '{ type ipv4_addr; flags interval; }'
  $SUDO_CMD nft list set inet filter ip_blacklist_v6 >/dev/null 2>&1 || \
    $SUDO_CMD nft add set inet filter ip_blacklist_v6 '{ type ipv6_addr; flags interval; }'
  $SUDO_CMD nft list set inet filter ip_whitelist_v4 >/dev/null 2>&1 || \
    $SUDO_CMD nft add set inet filter ip_whitelist_v4 '{ type ipv4_addr; flags interval; }'
  $SUDO_CMD nft list set inet filter ip_whitelist_v6 >/dev/null 2>&1 || \
    $SUDO_CMD nft add set inet filter ip_whitelist_v6 '{ type ipv6_addr; flags interval; }'
  # 规则：黑名单 drop、白名单逻辑控制锚点（通过 jump 子链实现）
  $SUDO_CMD nft list chain inet filter WL_CTRL >/dev/null 2>&1 || \
    $SUDO_CMD nft add chain inet filter WL_CTRL
  
  # 在 PREROUTING 链中插入黑名单规则（优先级 raw -300，早于 Docker 的 dstnat -100）
  $SUDO_CMD nft list chain inet filter prerouting 2>/dev/null | grep -q 'fib daddr type local ip saddr @ip_blacklist_v4' || \
    $SUDO_CMD nft insert rule inet filter prerouting fib daddr type local ip saddr @ip_blacklist_v4 counter drop >/dev/null 2>&1 || \
    $SUDO_CMD nft add rule inet filter prerouting fib daddr type local ip saddr @ip_blacklist_v4 counter drop >/dev/null 2>&1 || true
  $SUDO_CMD nft list chain inet filter prerouting 2>/dev/null | grep -q 'fib daddr type local ip6 saddr @ip_blacklist_v6' || \
    $SUDO_CMD nft insert rule inet filter prerouting fib daddr type local ip6 saddr @ip_blacklist_v6 counter drop >/dev/null 2>&1 || \
    $SUDO_CMD nft add rule inet filter prerouting fib daddr type local ip6 saddr @ip_blacklist_v6 counter drop >/dev/null 2>&1 || true
  
  # 在 INPUT 链中插入黑名单规则（处理本机直接访问）
  $SUDO_CMD nft list chain inet filter input 2>/dev/null | grep -q 'ip saddr @ip_blacklist_v4 drop' || \
    $SUDO_CMD nft insert rule inet filter input ip saddr @ip_blacklist_v4 counter drop >/dev/null 2>&1 || \
    $SUDO_CMD nft add rule inet filter input ip saddr @ip_blacklist_v4 counter drop >/dev/null 2>&1 || true
  $SUDO_CMD nft list chain inet filter input 2>/dev/null | grep -q 'ip6 saddr @ip_blacklist_v6 drop' || \
    $SUDO_CMD nft insert rule inet filter input ip6 saddr @ip_blacklist_v6 counter drop >/dev/null 2>&1 || \
    $SUDO_CMD nft add rule inet filter input ip6 saddr @ip_blacklist_v6 counter drop >/dev/null 2>&1 || true

  # 在 FORWARD 链中插入黑名单规则（覆盖桥接转发路径）
  $SUDO_CMD nft list chain inet filter forward 2>/dev/null | grep -q 'ip saddr @ip_blacklist_v4 drop' || \
    $SUDO_CMD nft insert rule inet filter forward ip saddr @ip_blacklist_v4 counter drop >/dev/null 2>&1 || \
    $SUDO_CMD nft add rule inet filter forward ip saddr @ip_blacklist_v4 counter drop >/dev/null 2>&1 || true
  $SUDO_CMD nft list chain inet filter forward 2>/dev/null | grep -q 'ip6 saddr @ip_blacklist_v6 drop' || \
    $SUDO_CMD nft insert rule inet filter forward ip6 saddr @ip_blacklist_v6 counter drop >/dev/null 2>&1 || \
    $SUDO_CMD nft add rule inet filter forward ip6 saddr @ip_blacklist_v6 counter drop >/dev/null 2>&1 || true
  # 插入白名单控制跳转（靠前，位于黑名单后）
  $SUDO_CMD nft list chain inet filter input 2>/dev/null | grep -q 'jump WL_CTRL' || \
    $SUDO_CMD nft insert rule inet filter input jump WL_CTRL >/dev/null 2>&1 || \
    $SUDO_CMD nft add rule inet filter input jump WL_CTRL >/dev/null 2>&1 || true
  # WL_CTRL 子链规则编排：当白名单非空时，非白名单拒绝；当空时不限制
  sync_wl_ctrl || true
}

# 根据白名单集合是否为空，重建 WL_CTRL 子链的两种策略
sync_wl_ctrl() {
  require_root_or_sudo
  # 检查白名单是否为空
  local has_wl_v4 has_wl_v6
  has_wl_v4=$($SUDO_CMD nft list set inet filter ip_whitelist_v4 2>/dev/null | awk '/elements/{f=1;next} f && NF>0 {print 1; exit} END{if(!f) print 0}')
  has_wl_v6=$($SUDO_CMD nft list set inet filter ip_whitelist_v6 2>/dev/null | awk '/elements/{f=1;next} f && NF>0 {print 1; exit} END{if(!f) print 0}')
  # 清空 WL_CTRL 并写入策略
  $SUDO_CMD nft list chain inet filter WL_CTRL >/dev/null 2>&1 || \
    $SUDO_CMD nft add chain inet filter WL_CTRL
  $SUDO_CMD nft flush chain inet filter WL_CTRL >/dev/null 2>&1 || true
  if [[ "$has_wl_v4" == "1" || "$has_wl_v6" == "1" ]]; then
    # 白名单非空：允许白名单，其余拒绝
    $SUDO_CMD nft add rule inet filter WL_CTRL ip saddr @ip_whitelist_v4 accept >/dev/null 2>&1 || true
    $SUDO_CMD nft add rule inet filter WL_CTRL ip6 saddr @ip_whitelist_v6 accept >/dev/null 2>&1 || true
    $SUDO_CMD nft add rule inet filter WL_CTRL drop >/dev/null 2>&1 || true
  else
    # 白名单为空：不限制（直接返回，继续后续链/策略）
    $SUDO_CMD nft add rule inet filter WL_CTRL return >/dev/null 2>&1 || true
  fi
}

is_cidr_or_addr() {
  local s="$1"
  [[ -z "$s" ]] && return 1
  # 支持 IPv4/IPv6 与 CIDR（粗略判断）
  if [[ "$s" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then return 0; fi
  if [[ "$s" =~ ^([0-9a-fA-F:]+)(/[0-9]{1,3})?$ ]]; then return 0; fi
  return 1
}

is_ipv4() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; }
is_ipv6() { [[ "$1" =~ ^([0-9a-fA-F:]+)(/[0-9]{1,3})?$ ]] && [[ "$1" == *:* ]]; }

# 判断是否是危险的黑名单目标（回环、本机地址、常见内网段）
is_prohibited_blacklist_target() {
  local ip="$1"
  # 回环地址
  if [[ "$ip" == "127.0.0.1" || "$ip" == "::1" || "$ip" =~ ^127\. || "$ip" =~ ^::1(/|$) ]]; then return 0; fi
  # 常见内网：避免误封
  if [[ "$ip" =~ ^10\. || "$ip" =~ ^192\.168\. || "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then return 0; fi
  # 检测本机真实地址（仅基础检测，IPv4/IPv6）
  local self_ips
  self_ips=$(ip -o addr show | awk '{print $4}' | cut -d/ -f1)
  for s in $self_ips; do
    if [[ "$ip" == "$s" ]]; then return 0; fi
  done
  return 1
}

wl_add() {
  ensure_struct
  local ip="$1"; [[ -z "$ip" ]] && err "缺少 IP/CIDR" && exit 1
  if ! is_cidr_or_addr "$ip"; then err "无效的 IP/CIDR: $ip"; exit 1; fi
  if is_ipv4 "$ip"; then
    $SUDO_CMD nft add element inet filter ip_whitelist_v4 { $ip } >/dev/null 2>&1 || true
  else
    $SUDO_CMD nft add element inet filter ip_whitelist_v6 { $ip } >/dev/null 2>&1 || true
  fi
  sync_wl_ctrl || true
  log "白名单已添加: $ip"
}

wl_del() {
  ensure_struct
  local ip="$1"; [[ -z "$ip" ]] && err "缺少 IP/CIDR" && exit 1
  if ! is_cidr_or_addr "$ip"; then err "无效的 IP/CIDR: $ip"; exit 1; fi
  if is_ipv4 "$ip"; then
    $SUDO_CMD nft delete element inet filter ip_whitelist_v4 { $ip } >/dev/null 2>&1 || true
  else
    $SUDO_CMD nft delete element inet filter ip_whitelist_v6 { $ip } >/dev/null 2>&1 || true
  fi
  sync_wl_ctrl || true
  log "白名单已删除: $ip"
}

wl_clear() {
  ensure_struct
  $SUDO_CMD nft flush set inet filter ip_whitelist_v4 >/dev/null 2>&1 || true
  $SUDO_CMD nft flush set inet filter ip_whitelist_v6 >/dev/null 2>&1 || true
  sync_wl_ctrl || true
  log "白名单已清空"
}

bl_add() {
  ensure_struct
  local ip="$1"; [[ -z "$ip" ]] && err "缺少 IP/CIDR" && exit 1
  if ! is_cidr_or_addr "$ip"; then err "无效的 IP/CIDR: $ip"; exit 1; fi
  # 安全防护：禁止将回环地址或本机实际地址加入黑名单，避免自损
  if is_prohibited_blacklist_target "$ip"; then
    err "禁止将回环或本机地址加入黑名单: $ip"; exit 1
  fi
  if is_ipv4 "$ip"; then
    $SUDO_CMD nft add element inet filter ip_blacklist_v4 { $ip } >/dev/null 2>&1 || true
  else
    $SUDO_CMD nft add element inet filter ip_blacklist_v6 { $ip } >/dev/null 2>&1 || true
  fi
  log "黑名单已添加并即时生效: $ip"
}

bl_del() {
  ensure_struct
  local ip="$1"; [[ -z "$ip" ]] && err "缺少 IP/CIDR" && exit 1
  if ! is_cidr_or_addr "$ip"; then err "无效的 IP/CIDR: $ip"; exit 1; fi
  if is_ipv4 "$ip"; then
    $SUDO_CMD nft delete element inet filter ip_blacklist_v4 { $ip } >/dev/null 2>&1 || true
  else
    $SUDO_CMD nft delete element inet filter ip_blacklist_v6 { $ip } >/dev/null 2>&1 || true
  fi
  log "黑名单已删除: $ip"
}

bl_clear() {
  ensure_struct
  $SUDO_CMD nft flush set inet filter ip_blacklist_v4 >/dev/null 2>&1 || true
  $SUDO_CMD nft flush set inet filter ip_blacklist_v6 >/dev/null 2>&1 || true
  log "黑名单已清空"
}

status() {
  ensure_struct
  echo "==== 当前入站控制（inet filter）===="
  $SUDO_CMD nft list ruleset | sed -n '/table inet filter/,/table /p' | sed '/^table inet filter/,$!d'
  echo
  echo "==== 黑名单拦截点 ===="
  echo "PREROUTING 链（拦截 Docker 端口转发）:"
  $SUDO_CMD nft list chain inet filter prerouting 2>/dev/null || echo "  未创建"
  echo "INPUT 链（拦截本机直接访问）:"
  $SUDO_CMD nft list chain inet filter input 2>/dev/null || echo "  未创建"
  echo
  echo "白名单元素:"
  echo "IPv4:"
  $SUDO_CMD nft list set inet filter ip_whitelist_v4 2>/dev/null || true
  echo "IPv6:"
  $SUDO_CMD nft list set inet filter ip_whitelist_v6 2>/dev/null || true
  echo "黑名单元素:"
  echo "IPv4:"
  $SUDO_CMD nft list set inet filter ip_blacklist_v4 2>/dev/null || true
  echo "IPv6:"
  $SUDO_CMD nft list set inet filter ip_blacklist_v6 2>/dev/null || true
}

save_rules() {
  require_root_or_sudo
  $SUDO_CMD mkdir -p "$CONF_DIR"
  # 仅保存 inet filter 相关片段，避免覆盖系统其它 nftables 配置
  local tmp
  tmp=$(mktemp)
  # 直接导出完整的 table 声明，避免截断导致语法错误
  $SUDO_CMD nft list table inet filter > "$tmp" 2>/dev/null || {
    # 如不存在，先建立结构再导出
    ensure_struct
    $SUDO_CMD nft list table inet filter > "$tmp"
  }
  $SUDO_CMD mv "$tmp" "$CONF_FILE"
  log "已保存 inet filter 片段到 $CONF_FILE"
}

load_rules() {
  require_root_or_sudo
  if [[ ! -f "$CONF_FILE" ]]; then
    err "未找到已保存的规则文件: $CONF_FILE"; exit 1
  fi
  # 仅加载保存的 inet filter 表声明，避免包含其它表片段导致 EOF
  # 如果文件中包含除了 inet filter 外的内容（例如 f2b-table 等），先过滤掉
  local tmp
  tmp=$(mktemp)
  awk 'BEGIN{p=0} /^table inet filter/{p=1} p{print} /^}/ && p{exit}' "$CONF_FILE" > "$tmp"
  if [[ ! -s "$tmp" ]]; then
    err "保存文件中未找到 inet filter 表片段"; rm -f "$tmp"; exit 1
  fi
  # 预先删除旧表以避免声明冲突
  $SUDO_CMD nft list table inet filter >/dev/null 2>&1 && $SUDO_CMD nft delete table inet filter >/dev/null 2>&1 || true
  $SUDO_CMD nft -f "$tmp"
  rm -f "$tmp"
  # 确保白名单控制逻辑与集合状态同步
  sync_wl_ctrl || true
  log "已加载规则片段自 $CONF_FILE"
}

usage() {
  cat <<EOF
用法: $0 <子命令> [参数]

子命令:
  wl-add <IP/CIDR>       将 IP 或 CIDR 加入白名单（集合非空时仅允许白名单）
  wl-del <IP/CIDR>       从白名单移除 IP 或 CIDR
  wl-clear               清空白名单（集合为空时不限制）
  bl-add <IP/CIDR>       将 IP 或 CIDR 加入黑名单（立即 drop）
  bl-del <IP/CIDR>       从黑名单移除 IP 或 CIDR
  bl-clear               清空黑名单
  status                 显示当前结构与元素
  save                   保存当前完整 nft 规则到配置目录
  load                   从配置目录加载已保存的 nft 规则

说明:
  - 白名单集合为空时，不限制黑名单以外的 IP 访问；非空时，仅允许白名单访问。
  - 黑名单始终优先生效：被加入的 IP/CIDR 会立即被丢弃。
  - 支持 IPv4/IPv6 与 CIDR（如 1.2.3.4/24、2001:db8::/32）。
EOF
}

main() {
  local cmd="${1:-}"; shift || true
  case "$cmd" in
    wl-add) wl_add "${1:-}" ;;
    wl-del) wl_del "${1:-}" ;;
    wl-clear) wl_clear ;;
    bl-add) bl_add "${1:-}" ;;
    bl-del) bl_del "${1:-}" ;;
    bl-clear) bl_clear ;;
    status) status ;;
    save) save_rules ;;
    load) load_rules ;;
    ""|-h|--help) usage ;;
    *) err "未知子命令: $cmd"; usage; exit 1 ;;
  esac
}

main "$@"