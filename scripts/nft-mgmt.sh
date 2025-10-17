#!/usr/bin/env bash

# nftmgmt.sh — 交互式 nftables 管理脚本（类似 UFW，扩展白/黑名单、端口、转发、CN 来源）
# 说明：本脚本需 root 权限执行，或系统中存在 sudo。

set -euo pipefail

SCRIPT_NAME="nftmgmt"
RULES_DIR="/etc/nftables.d"
GEOIP_DIR="$RULES_DIR/geoip"
RULES_FILE="$RULES_DIR/rules.nft"
CN_TXT_URL="https://github.com/Loyalsoldier/geoip/raw/refs/heads/release/text/cn.txt"
CN_TXT_PATH="$GEOIP_DIR/cn.txt"
PRIVATE_TXT_URL="https://github.com/Loyalsoldier/geoip/raw/refs/heads/release/text/private.txt"
PRIVATE_TXT_PATH="$GEOIP_DIR/private.txt"
CN_SET_FILE="$GEOIP_DIR/cn_sets.nft"
FORWARD_REG="$RULES_DIR/forward.csv"
POLICY_FLAGS_FILE="$RULES_DIR/policy_flags.env"

SUDO_CMD=""

log() { echo "[${SCRIPT_NAME}] $*"; }
err() { echo "[${SCRIPT_NAME}][ERROR] $*" >&2; }

# 终端颜色（用于状态输出）
GREEN='\033[0;32m'
NC='\033[0m'

require_root_or_sudo() {
  if [[ $(id -u) -ne 0 ]];
  then
    if command -v sudo >/dev/null 2>&1; then
      SUDO_CMD="sudo"
    else
      err "需要 root 或安装 sudo。请以 root 运行或先安装 sudo。"; exit 1
    fi
  else
    SUDO_CMD=""
  fi
}

detect_pkg_mgr() {
  if command -v apt-get >/dev/null 2>&1; then echo apt; return
  elif command -v apt >/dev/null 2>&1; then echo apt; return
  elif command -v dnf >/dev/null 2>&1; then echo dnf; return
  elif command -v yum >/dev/null 2>&1; then echo dnf; return
  elif command -v zypper >/dev/null 2>&1; then echo zypper; return
  elif command -v pacman >/dev/null 2>&1; then echo pacman; return
  else
    echo none; return
  fi
}

pkg_install() {
  local mgr="$1"; shift
  local pkgs=("$@")
  case "$mgr" in
    apt)
      $SUDO_CMD apt-get update -y || true
      $SUDO_CMD apt-get install -y "${pkgs[@]}" ;;
    dnf)
      $SUDO_CMD dnf install -y "${pkgs[@]}" ;;
    zypper)
      $SUDO_CMD zypper -n install "${pkgs[@]}" ;;
    pacman)
      $SUDO_CMD pacman -Sy --noconfirm "${pkgs[@]}" ;;
    *)
      err "无法检测到包管理器，请手动安装: ${pkgs[*]}"; return 1 ;;
  esac
}

ensure_dependencies() {
  require_root_or_sudo

  if ! command -v curl >/dev/null 2>&1; then
    log "未检测到 curl，尝试安装..."
    local mgr; mgr=$(detect_pkg_mgr)
    pkg_install "$mgr" curl || { err "安装 curl 失败"; exit 1; }
  fi

  if ! command -v nft >/dev/null 2>&1; then
    log "未检测到 nftables，尝试安装..."
    local mgr; mgr=$(detect_pkg_mgr)
    case "$mgr" in
      apt) pkg_install "$mgr" nftables ;;
      dnf) pkg_install "$mgr" nftables ;;
      zypper) pkg_install "$mgr" nftables ;;
      pacman) pkg_install "$mgr" nftables ;;
      *) err "无法安装 nftables，请手动安装"; exit 1 ;;
    esac
  fi

  if ! command -v conntrack >/dev/null 2>&1; then
    log "未检测到 conntrack，尝试安装..."
    local mgr; mgr=$(detect_pkg_mgr)
    case "$mgr" in
      apt) pkg_install "$mgr" conntrack ;;
      dnf) pkg_install "$mgr" conntrack-tools ;;
      zypper) pkg_install "$mgr" conntrack-tools ;;
      pacman) pkg_install "$mgr" conntrack-tools ;;
      *) err "无法安装 conntrack，请手动安装"; exit 1 ;;
    esac
  fi


  # 启用并启动 nftables 服务（如果存在），但不强制失败
  if command -v systemctl >/dev/null 2>&1; then
    $SUDO_CMD systemctl enable nftables.service >/dev/null 2>&1 || true
    # 不在此处启动或重载服务，避免系统默认规则覆盖脚本设置
  fi
}

mkdir_p_rules_dir() {
  if [[ ! -d "$RULES_DIR" ]]; then
    $SUDO_CMD mkdir -p "$RULES_DIR"
  fi
  if [[ ! -d "$GEOIP_DIR" ]]; then
    $SUDO_CMD mkdir -p "$GEOIP_DIR"
  fi
}

get_ssh_port() {
  local port
  if [[ -f /etc/ssh/sshd_config ]]; then
    port=$(grep -E "^\s*Port\s+[0-9]+" /etc/ssh/sshd_config | awk '{print $2}' | tail -n1)
  fi
  if [[ -z "${port:-}" ]]; then port=22; fi
  echo "$port"
}

# 解析主机名为 IPv4/IPv6 地址；若已是 IP 则直接返回
resolve_host() {
  local host="$1"
  [[ -z "$host" ]] && echo "" && return 1
  if [[ "$host" =~ ^[0-9.]+$ || "$host" =~ : ]]; then
    echo "$host"; return 0
  fi
  local ip
  ip=$(getent ahostsv4 "$host" | awk 'NR==1{print $1}')
  if [[ -z "$ip" ]]; then
    ip=$(getent hosts "$host" | awk 'NR==1{print $1}')
  fi
  echo "$ip"
}

# 在安全策略下，确保默认端口白名单包含 22/222/80/443（仅 TCP）
ensure_default_ports() {
  $SUDO_CMD nft list set inet filter allowed_tcp_ports >/dev/null 2>&1 || \
    $SUDO_CMD nft add set inet filter allowed_tcp_ports '{ type inet_service; }'
  $SUDO_CMD nft list set inet filter allowed_udp_ports >/dev/null 2>&1 || \
    $SUDO_CMD nft add set inet filter allowed_udp_ports '{ type inet_service; }'
  for p in 22 222 80 443; do
    $SUDO_CMD nft add element inet filter allowed_tcp_ports { $p } >/dev/null 2>&1 || true
  done
  log "已确保默认白名单端口（仅TCP）: 22, 222, 80, 443"
}

# 确保 NAT 表与关键链存在（在未执行 init 的情况下，转发与伪装也能工作）
ensure_nat_table() {
  require_root_or_sudo
  $SUDO_CMD nft list table ip nat >/dev/null 2>&1 || $SUDO_CMD nft add table ip nat
  $SUDO_CMD nft list chain ip nat PREROUTING   >/dev/null 2>&1 || \
    $SUDO_CMD nft add chain ip nat PREROUTING   '{ type nat hook prerouting priority -100; }'
  $SUDO_CMD nft list chain ip nat POSTROUTING  >/dev/null 2>&1 || \
    $SUDO_CMD nft add chain ip nat POSTROUTING  '{ type nat hook postrouting priority 100; }'
}

nft_chain_exists() { nft list chain "$1" "$2" >/dev/null 2>&1; }
nft_table_exists() { nft list table "$1" "$2" >/dev/null 2>&1; }

init_nftables() {
  mkdir_p_rules_dir

  # 若规则集为空，则创建默认表/链/集合
  local rules
  rules=$(nft list ruleset 2>/dev/null || true)
  if [[ -z "$rules" ]]; then
    log "检测到 nftables 为空，创建默认表与链..."
    $SUDO_CMD nft -f - <<'EOF'
add table inet filter
add chain inet filter input { type filter hook input priority 0; policy drop; }
add chain inet filter output { type filter hook output priority 0; policy accept; }
add chain inet filter forward { type filter hook forward priority 0; policy drop; }

# 基础集合
add set inet filter allow_ips { type ipv4_addr; flags interval; }
add set inet filter allow_ips6 { type ipv6_addr; flags interval; }
add set inet filter block_ips { type ipv4_addr; flags interval; }
add set inet filter allowed_tcp_ports { type inet_service; }
add set inet filter allowed_udp_ports { type inet_service; }
add set inet filter fwd_tcp_map { type ipv4_addr . inet_service; }
add set inet filter fwd_udp_map { type ipv4_addr . inet_service; }
add set inet filter cn_ips { type ipv4_addr; flags interval; }
add set inet filter cn_ipv6 { type ipv6_addr; flags interval; }

# 策略子链
add chain inet filter input_any { }
add chain inet filter input_whitelist { }
add chain inet filter input_cn { }

# input 主链规则：状态、lo、黑名单、策略跳转
add rule inet filter input ct state established,related accept
add rule inet filter input iif lo accept
add rule inet filter input ip saddr @block_ips drop
add rule inet filter input jump input_any

# input_any：仅端口白名单
add rule inet filter input_any tcp dport @allowed_tcp_ports accept
add rule inet filter input_any udp dport @allowed_udp_ports accept
add rule inet filter input_any counter drop

# input_whitelist：IP + 端口白名单
add rule inet filter input_whitelist ip saddr @allow_ips tcp dport @allowed_tcp_ports accept
add rule inet filter input_whitelist ip saddr @allow_ips udp dport @allowed_udp_ports accept
add rule inet filter input_whitelist counter drop

# input_cn：仅 CN 来源 + 端口白名单
add rule inet filter input_cn ip saddr @cn_ips tcp dport @allowed_tcp_ports accept
add rule inet filter input_cn ip saddr @cn_ips udp dport @allowed_udp_ports accept
add rule inet filter input_cn ip6 saddr @cn_ipv6 tcp dport @allowed_tcp_ports accept
add rule inet filter input_cn ip6 saddr @cn_ipv6 udp dport @allowed_udp_ports accept
add rule inet filter input_cn counter drop

# forward 链：支持端口转发与状态回包
add rule inet filter forward ct state established,related accept
add rule inet filter forward ip daddr . tcp dport @fwd_tcp_map accept
add rule inet filter forward ip daddr . udp dport @fwd_udp_map accept
add rule inet filter forward counter drop

# （移除 ip family 的 input 钩子以避免绕过 inet 策略）

# NAT 表，链名使用大写以兼容 docker 风格
add table ip nat
add chain ip nat PREROUTING { type nat hook prerouting priority -100; }
add chain ip nat POSTROUTING { type nat hook postrouting priority 100; }
EOF
  else
    # 如果已有规则集，但缺少我们需要的元素，则补齐
    $SUDO_CMD nft -f - <<'EOF'
add table inet filter
add chain inet filter input { type filter hook input priority 0; policy drop; }
add chain inet filter output { type filter hook output priority 0; policy accept; }
add chain inet filter forward { type filter hook forward priority 0; policy drop; }
add set inet filter allow_ips { type ipv4_addr; flags interval; }
add set inet filter allow_ips6 { type ipv6_addr; flags interval; }
add set inet filter block_ips { type ipv4_addr; flags interval; }
add set inet filter allowed_tcp_ports { type inet_service; }
add set inet filter allowed_udp_ports { type inet_service; }
add set inet filter fwd_tcp_map { type ipv4_addr . inet_service; }
add set inet filter fwd_udp_map { type ipv4_addr . inet_service; }
add set inet filter cn_ips { type ipv4_addr; flags interval; }
add set inet filter cn_ipv6 { type ipv6_addr; flags interval; }
add chain inet filter input_any { }
add chain inet filter input_whitelist { }
add chain inet filter input_cn { }
# 不再创建 ip family 的 input 钩子，统一使用 inet family 规则
add table ip nat
add chain ip nat PREROUTING { type nat hook prerouting priority -100; }
add chain ip nat POSTROUTING { type nat hook postrouting priority 100; }
EOF
    # 确保 input 主链含基础三条与策略跳转（以刷新方式保证唯一性）
    $SUDO_CMD nft -f - <<'EOF'
flush chain inet filter input
add rule inet filter input ct state established,related accept
add rule inet filter input iif lo accept
add rule inet filter input ip saddr @block_ips drop
add rule inet filter input jump input_any
EOF
    # 确保策略子链规则存在
    $SUDO_CMD nft -f - <<'EOF'
flush chain inet filter input_any
add rule inet filter input_any tcp dport @allowed_tcp_ports accept
add rule inet filter input_any udp dport @allowed_udp_ports accept
add rule inet filter input_any counter drop

flush chain inet filter input_whitelist
add rule inet filter input_whitelist ip saddr @allow_ips tcp dport @allowed_tcp_ports accept
add rule inet filter input_whitelist ip saddr @allow_ips udp dport @allowed_udp_ports accept
add rule inet filter input_whitelist ip6 saddr @allow_ips6 tcp dport @allowed_tcp_ports accept
add rule inet filter input_whitelist ip6 saddr @allow_ips6 udp dport @allowed_udp_ports accept
EOF
  fi

  # 自动允许 SSH 端口（避免锁死）
  local ssh_port; ssh_port=$(get_ssh_port)
  $SUDO_CMD nft add element inet filter allowed_tcp_ports { $ssh_port } >/dev/null 2>&1 || true
  log "已确保 SSH 入站端口开放: tcp/$ssh_port"
  # 将 SSH 端口在主 input 链上无条件放行，优先于策略跳转
  set_policy_chain any
}

set_policy_chain() {
  # 参数：any|whitelist|cn
  local mode="$1"
  local jump_chain="input_any"
  case "$mode" in
    whitelist) jump_chain="input_whitelist" ;;
    cn) jump_chain="input_cn" ;;
    any) jump_chain="input_any" ;;
    *) err "未知模式 $mode"; return 1 ;;
  esac
  # 确保基础表与集合存在（逐条检查，避免 add 失败导致整段中止）
  $SUDO_CMD nft list table inet filter >/dev/null 2>&1 || $SUDO_CMD nft add table inet filter
  $SUDO_CMD nft list set inet filter allow_ips   >/dev/null 2>&1 || $SUDO_CMD nft add set inet filter allow_ips   '{ type ipv4_addr; flags interval; }'
  $SUDO_CMD nft list set inet filter allow_ips6  >/dev/null 2>&1 || $SUDO_CMD nft add set inet filter allow_ips6  '{ type ipv6_addr; flags interval; }'
  $SUDO_CMD nft list set inet filter block_ips   >/dev/null 2>&1 || $SUDO_CMD nft add set inet filter block_ips   '{ type ipv4_addr; flags interval; }'
  $SUDO_CMD nft list set inet filter allowed_tcp_ports >/dev/null 2>&1 || $SUDO_CMD nft add set inet filter allowed_tcp_ports '{ type inet_service; }'
  $SUDO_CMD nft list set inet filter allowed_udp_ports >/dev/null 2>&1 || $SUDO_CMD nft add set inet filter allowed_udp_ports '{ type inet_service; }'
  $SUDO_CMD nft list set inet filter cn_ips      >/dev/null 2>&1 || $SUDO_CMD nft add set inet filter cn_ips      '{ type ipv4_addr; flags interval; }'
  $SUDO_CMD nft list set inet filter cn_ipv6     >/dev/null 2>&1 || $SUDO_CMD nft add set inet filter cn_ipv6     '{ type ipv6_addr; flags interval; }'
  # 若策略子链不存在则创建，避免后续 flush/add 失败
  $SUDO_CMD nft list chain inet filter input_any >/dev/null 2>&1 || $SUDO_CMD nft add chain inet filter input_any '{ }'
  $SUDO_CMD nft list chain inet filter input_whitelist >/dev/null 2>&1 || $SUDO_CMD nft add chain inet filter input_whitelist '{ }'
  $SUDO_CMD nft list chain inet filter input_cn >/dev/null 2>&1 || $SUDO_CMD nft add chain inet filter input_cn '{ }'
  # CN 模式下确保 CN 集合已填充，避免空集合导致误丢弃
  if [[ "$mode" == "cn" ]]; then
    ensure_cn_set || true
  fi
  # 防止 IPv4 数据包通过 ip family 的 input 钩子（policy accept）绕过策略
  $SUDO_CMD nft list chain ip filter input >/dev/null 2>&1 && $SUDO_CMD nft delete chain ip filter input || true
  local ssh_port; ssh_port=$(get_ssh_port)
  # 刷新并写入主 input 链的基础规则
  $SUDO_CMD nft -f - <<'EOF'
flush chain inet filter input
add rule inet filter input ct state established,related accept
add rule inet filter input iif lo accept
add rule inet filter input ip saddr @block_ips drop
EOF
  # 优先无条件放行 SSH 管理端口，避免锁死
  $SUDO_CMD nft add rule inet filter input tcp dport $ssh_port accept || true
  # 严格模式：在主链丢弃本机目的的非白名单来源新入站连接（不影响既有会话与本机外联）
  if [[ "$mode" == "whitelist" ]]; then
  $SUDO_CMD nft add rule inet filter input fib daddr type local ct state new ip saddr != @allow_ips ip saddr != @cn_ips drop || true
  $SUDO_CMD nft add rule inet filter input fib daddr type local ct state new ip6 saddr != @allow_ips6 ip6 saddr != @cn_ipv6 drop || true
  elif [[ "$mode" == "cn" ]]; then
    # 在 CN 模式下，允许 allow_ips/allow_ips6 作为例外来源（与 CN 集合并集）
    $SUDO_CMD nft add rule inet filter input fib daddr type local ct state new ip saddr != @cn_ips ip saddr != @allow_ips drop || true
    $SUDO_CMD nft add rule inet filter input fib daddr type local ct state new ip6 saddr != @cn_ipv6 ip6 saddr != @allow_ips6 drop || true
  fi
  # 在非 CN 模式下，保留 allow_ips/allow_ips6 + 端口白名单的例外允许
  if [[ "$mode" != "cn" ]]; then
    $SUDO_CMD nft -f - <<'EOF'
add rule inet filter input ip saddr @allow_ips tcp dport @allowed_tcp_ports accept
add rule inet filter input ip saddr @allow_ips udp dport @allowed_udp_ports accept
add rule inet filter input ip6 saddr @allow_ips6 tcp dport @allowed_tcp_ports accept
add rule inet filter input ip6 saddr @allow_ips6 udp dport @allowed_udp_ports accept
EOF
  fi
  # 最终跳转到对应策略子链
  $SUDO_CMD nft add rule inet filter input jump "$jump_chain"
  # 在安全策略（cn/whitelist）下默认加入 22/222/80/443 白名单端口
  if [[ "$mode" == "cn" || "$mode" == "whitelist" ]]; then
    ensure_default_ports || true
  fi
  # 根据策略开关（阻止ICMP/UDP）重建子链规则
  rebuild_policy_chains
  log "已切换入站策略为: $mode"
}

# 读取/保存策略开关（默认：不阻止 ICMP 与 UDP）
get_policy_flags() {
  mkdir_p_rules_dir
  if [[ -f "$POLICY_FLAGS_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$POLICY_FLAGS_FILE"
  fi
  BLOCK_ICMP=${BLOCK_ICMP:-0}
  BLOCK_UDP=${BLOCK_UDP:-0}
}
save_policy_flags() {
  mkdir_p_rules_dir
  cat > "$POLICY_FLAGS_FILE" <<EOF
BLOCK_ICMP=${BLOCK_ICMP}
BLOCK_UDP=${BLOCK_UDP}
EOF
}

# 按当前开关重建三条策略子链规则
rebuild_policy_chains() {
  get_policy_flags
  # 先清空三条子链
  $SUDO_CMD nft -f - <<'EOF'
flush chain inet filter input_any
flush chain inet filter input_whitelist
flush chain inet filter input_cn
EOF
  # input_any：TCP 按白名单；UDP 默认不阻止（开关可改）；ICMP 默认不阻止（开关可改）
  $SUDO_CMD nft add rule inet filter input_any tcp dport @allowed_tcp_ports accept || true
  if [[ "$BLOCK_UDP" -eq 1 ]]; then
    $SUDO_CMD nft add rule inet filter input_any meta l4proto udp udp dport @allowed_udp_ports accept || true
  else
    $SUDO_CMD nft add rule inet filter input_any meta l4proto udp accept || true
  fi
  if [[ "$BLOCK_ICMP" -eq 0 ]]; then
    $SUDO_CMD nft add rule inet filter input_any meta l4proto { icmp, icmpv6 } accept || true
  fi
  $SUDO_CMD nft add rule inet filter input_any counter drop || true

  # input_whitelist：来源白名单 + TCP 端口白名单；UDP 默认不阻止；ICMP 默认不阻止
  $SUDO_CMD nft add rule inet filter input_whitelist ip saddr @allow_ips tcp dport @allowed_tcp_ports accept || true
  # 在白名单策略下，UDP 仅按端口白名单允许（不受阻止UDP开关影响）
  $SUDO_CMD nft add rule inet filter input_whitelist ip saddr @allow_ips udp dport @allowed_udp_ports accept || true
  $SUDO_CMD nft add rule inet filter input_whitelist ip6 saddr @allow_ips6 tcp dport @allowed_tcp_ports accept || true
  $SUDO_CMD nft add rule inet filter input_whitelist ip6 saddr @allow_ips6 udp dport @allowed_udp_ports accept || true
  # 同时允许预定义 CN 集合作为白名单来源（与 allow_ips 并集）
  $SUDO_CMD nft add rule inet filter input_whitelist ip saddr @cn_ips tcp dport @allowed_tcp_ports accept || true
  $SUDO_CMD nft add rule inet filter input_whitelist ip saddr @cn_ips udp dport @allowed_udp_ports accept || true
  $SUDO_CMD nft add rule inet filter input_whitelist ip6 saddr @cn_ipv6 tcp dport @allowed_tcp_ports accept || true
  $SUDO_CMD nft add rule inet filter input_whitelist ip6 saddr @cn_ipv6 udp dport @allowed_udp_ports accept || true
  if [[ "$BLOCK_ICMP" -eq 0 ]]; then
    $SUDO_CMD nft add rule inet filter input_whitelist ip saddr @allow_ips meta l4proto icmp accept || true
    $SUDO_CMD nft add rule inet filter input_whitelist ip6 saddr @allow_ips6 meta l4proto icmpv6 accept || true
    $SUDO_CMD nft add rule inet filter input_whitelist ip saddr @cn_ips meta l4proto icmp accept || true
    $SUDO_CMD nft add rule inet filter input_whitelist ip6 saddr @cn_ipv6 meta l4proto icmpv6 accept || true
  fi
  $SUDO_CMD nft add rule inet filter input_whitelist counter drop || true

  # input_cn：来源 CN + TCP 端口白名单；UDP 默认不阻止；ICMP 默认不阻止
  $SUDO_CMD nft add rule inet filter input_cn ip saddr @cn_ips tcp dport @allowed_tcp_ports accept || true
  $SUDO_CMD nft add rule inet filter input_cn ip6 saddr @cn_ipv6 tcp dport @allowed_tcp_ports accept || true
  # 在 CN 策略下，UDP 仅按端口白名单允许（不受阻止UDP开关影响）
  $SUDO_CMD nft add rule inet filter input_cn ip saddr @cn_ips udp dport @allowed_udp_ports accept || true
  $SUDO_CMD nft add rule inet filter input_cn ip6 saddr @cn_ipv6 udp dport @allowed_udp_ports accept || true
  # 同时允许 allow_ips/allow_ips6 作为 CN 模式的来源例外（与端口白名单配合）
  $SUDO_CMD nft add rule inet filter input_cn ip saddr @allow_ips tcp dport @allowed_tcp_ports accept || true
  $SUDO_CMD nft add rule inet filter input_cn ip6 saddr @allow_ips6 tcp dport @allowed_tcp_ports accept || true
  $SUDO_CMD nft add rule inet filter input_cn ip saddr @allow_ips udp dport @allowed_udp_ports accept || true
  $SUDO_CMD nft add rule inet filter input_cn ip6 saddr @allow_ips6 udp dport @allowed_udp_ports accept || true
  if [[ "$BLOCK_ICMP" -eq 0 ]]; then
    $SUDO_CMD nft add rule inet filter input_cn ip saddr @cn_ips meta l4proto icmp accept || true
    $SUDO_CMD nft add rule inet filter input_cn ip6 saddr @cn_ipv6 meta l4proto icmpv6 accept || true
    $SUDO_CMD nft add rule inet filter input_cn ip saddr @allow_ips meta l4proto icmp accept || true
    $SUDO_CMD nft add rule inet filter input_cn ip6 saddr @allow_ips6 meta l4proto icmpv6 accept || true
  fi
  $SUDO_CMD nft add rule inet filter input_cn counter drop || true
}

toggle_block_icmp() {
  get_policy_flags
  if [[ "$BLOCK_ICMP" -eq 0 ]]; then BLOCK_ICMP=1; else BLOCK_ICMP=0; fi
  save_policy_flags
  rebuild_policy_chains
  if [[ "$BLOCK_ICMP" -eq 1 ]]; then
    log "已开启阻止 ICMP（ICMP/ICMPv6 将被丢弃）"
  else
    log "已关闭阻止 ICMP（允许 ICMP/ICMPv6 入站）"
  fi
}

toggle_block_udp() {
  get_policy_flags
  if [[ "$BLOCK_UDP" -eq 0 ]]; then BLOCK_UDP=1; else BLOCK_UDP=0; fi
  save_policy_flags
  rebuild_policy_chains
  if [[ "$BLOCK_UDP" -eq 1 ]]; then
    log "已开启阻止 UDP（仅按白名单端口放行）"
  else
    log "已关闭阻止 UDP（默认放行 UDP）"
  fi
}

add_allow_ip() {
  local ip="$1"
  # 确保允许集合存在（防止首次使用时缺失）
  $SUDO_CMD nft list set inet filter allow_ips >/dev/null 2>&1 || \
    $SUDO_CMD nft add set inet filter allow_ips '{ type ipv4_addr; flags interval; }'
  $SUDO_CMD nft list set inet filter allow_ips6 >/dev/null 2>&1 || \
    $SUDO_CMD nft add set inet filter allow_ips6 '{ type ipv6_addr; flags interval; }'
  if [[ "$ip" == *:* ]]; then
    $SUDO_CMD nft add element inet filter allow_ips6 { $ip } && log "允许 IPv6 已添加: $ip"
  else
    $SUDO_CMD nft add element inet filter allow_ips { $ip } && log "允许 IPv4 已添加: $ip"
  fi
}
del_allow_ip() {
  local ip="$1"
  # 允许集合可能不存在，先尝试创建以避免删除时报错（无副作用）
  $SUDO_CMD nft list set inet filter allow_ips >/dev/null 2>&1 || \
    $SUDO_CMD nft add set inet filter allow_ips '{ type ipv4_addr; flags interval; }'
  $SUDO_CMD nft list set inet filter allow_ips6 >/dev/null 2>&1 || \
    $SUDO_CMD nft add set inet filter allow_ips6 '{ type ipv6_addr; flags interval; }'
  if [[ "$ip" == *:* ]]; then
    $SUDO_CMD nft delete element inet filter allow_ips6 { $ip } && log "允许 IPv6 已移除: $ip" || true
  else
    $SUDO_CMD nft delete element inet filter allow_ips { $ip } && log "允许 IPv4 已移除: $ip" || true
  fi
}
add_block_ip() { local ip="$1"; $SUDO_CMD nft add element inet filter block_ips { $ip } && log "黑名单 IP 已添加: $ip"; }
del_block_ip() { local ip="$1"; $SUDO_CMD nft delete element inet filter block_ips { $ip } && log "黑名单 IP 已移除: $ip" || true; }

open_port() {
  local proto="$1" port="$2"
  # 确保端口白名单集合存在
  $SUDO_CMD nft list set inet filter allowed_tcp_ports >/dev/null 2>&1 || \
    $SUDO_CMD nft add set inet filter allowed_tcp_ports '{ type inet_service; }'
  $SUDO_CMD nft list set inet filter allowed_udp_ports >/dev/null 2>&1 || \
    $SUDO_CMD nft add set inet filter allowed_udp_ports '{ type inet_service; }'
  case "$proto" in
    tcp) $SUDO_CMD nft add element inet filter allowed_tcp_ports { $port } && log "开放 TCP 端口: $port" ;;
    udp) $SUDO_CMD nft add element inet filter allowed_udp_ports { $port } && log "开放 UDP 端口: $port" ;;
    *) err "协议必须为 tcp 或 udp" ;;
  esac
}

close_port() {
  local proto="$1" port="$2"
  # 确保端口白名单集合存在（避免删除时报错）
  $SUDO_CMD nft list set inet filter allowed_tcp_ports >/dev/null 2>&1 || \
    $SUDO_CMD nft add set inet filter allowed_tcp_ports '{ type inet_service; }'
  $SUDO_CMD nft list set inet filter allowed_udp_ports >/dev/null 2>&1 || \
    $SUDO_CMD nft add set inet filter allowed_udp_ports '{ type inet_service; }'
  case "$proto" in
    tcp) $SUDO_CMD nft delete element inet filter allowed_tcp_ports { $port } && log "关闭 TCP 端口: $port" || true ;;
    udp) $SUDO_CMD nft delete element inet filter allowed_udp_ports { $port } && log "关闭 UDP 端口: $port" || true ;;
    *) err "协议必须为 tcp 或 udp" ;;
  esac
}

add_port_forward() {
  # 参数：proto|any inbound_port dest_host_or_ip dest_port [remark]
  local proto="${1:-any}" pub="${2:?缺少入站端口}" host="${3:?缺少目标}" dport="${4:?缺少目标端口}" remark="${5:-}"
  [[ -z "$proto" ]] && proto="any"
  case "$proto" in
    tcp|udp|any) : ;;
    *) err "协议必须为 tcp/udp/any"; return 1 ;;
  esac
  ensure_nat_table
  local dip; dip=$(resolve_host "$host")
  if [[ -z "$dip" ]]; then err "无法解析目标: $host"; return 1; fi

  # 写入 DNAT 规则并更新 forward 映射集合
  if [[ "$proto" == "tcp" || "$proto" == "any" ]]; then
    $SUDO_CMD nft add rule ip nat PREROUTING tcp dport $pub dnat to $dip:$dport
    $SUDO_CMD nft add element inet filter fwd_tcp_map { $dip . $dport } >/dev/null 2>&1 || true
  fi
  if [[ "$proto" == "udp" || "$proto" == "any" ]]; then
    $SUDO_CMD nft add rule ip nat PREROUTING udp dport $pub dnat to $dip:$dport
    $SUDO_CMD nft add element inet filter fwd_udp_map { $dip . $dport } >/dev/null 2>&1 || true
  fi

  # 记录到注册表
  mkdir_p_rules_dir
  local r="${remark//,/ }"
  echo "$pub,$proto,$dip,$dport,${r}" | $SUDO_CMD tee -a "$FORWARD_REG" >/dev/null

  log "已添加端口转发: $proto $pub -> $dip:$dport${remark:+ ($remark)}"

  # 添加完端口转发后，立即输出当前已添加的转发规则，便于校验
  echo "当前端口转发："
  if [[ -f "$FORWARD_REG" ]]; then
    awk -F',' 'NF>=4{proto=$2; if(proto=="") proto="any"; remark=$5; gsub(/^[[:space:]]+/, "", remark); gsub(/[[:space:]]+$/, "", remark); printf("%s %s %s %s%s\n", $1, proto, $3, $4, (remark? " " remark: ""))}' "$FORWARD_REG"
  else
    echo "无"
  fi
}

del_port_forward() {
  # 参数：proto|any inbound_port dest_host_or_ip dest_port
  local proto="${1:-any}" pub="${2:?缺少入站端口}" host="${3:?缺少目标}" dport="${4:?缺少目标端口}"
  [[ -z "$proto" ]] && proto="any"
  case "$proto" in
    tcp|udp|any) : ;;
    *) err "协议必须为 tcp/udp/any"; return 1 ;;
  esac
  local dip; dip=$(resolve_host "$host")
  if [[ -z "$dip" ]]; then err "无法解析目标: $host"; return 1; fi

  # 查找并删除匹配的 DNAT 规则（按 handle）
  local out handles
  out=$($SUDO_CMD nft -a list chain ip nat PREROUTING 2>/dev/null || true)
  if [[ "$proto" == "tcp" || "$proto" == "any" ]]; then
    handles=$(echo "$out" | awk -v p="$pub" -v ip="$dip" -v dp="$dport" '/tcp dport/ && $0 ~ ("dport " p) && $0 ~ ("dnat to " ip ":" dp) {for(i=1;i<=NF;i++){if($i=="handle"){print $(i+1)}}}')
    while read -r h; do
      [[ -n "$h" ]] && $SUDO_CMD nft delete rule ip nat PREROUTING handle "$h" || true
    done <<< "$handles"
    $SUDO_CMD nft delete element inet filter fwd_tcp_map { $dip . $dport } >/dev/null 2>&1 || true
  fi
  if [[ "$proto" == "udp" || "$proto" == "any" ]]; then
    handles=$(echo "$out" | awk -v p="$pub" -v ip="$dip" -v dp="$dport" '/udp dport/ && $0 ~ ("dport " p) && $0 ~ ("dnat to " ip ":" dp) {for(i=1;i<=NF;i++){if($i=="handle"){print $(i+1)}}}')
    while read -r h; do
      [[ -n "$h" ]] && $SUDO_CMD nft delete rule ip nat PREROUTING handle "$h" || true
    done <<< "$handles"
    $SUDO_CMD nft delete element inet filter fwd_udp_map { $dip . $dport } >/dev/null 2>&1 || true
  fi

  # 更新注册表（删除匹配行）
  if [[ -f "$FORWARD_REG" ]]; then
    local tmp; tmp=$(mktemp)
    awk -F',' -v p="$pub" -v proto="$proto" -v ip="$dip" -v dp="$dport" '{keep=1; if($1==p && $3==ip && $4==dp && (proto=="any" || $2==proto)) keep=0; if(keep) print $0}' "$FORWARD_REG" > "$tmp"
    $SUDO_CMD mv "$tmp" "$FORWARD_REG"
  fi

  log "已移除端口转发: $proto $pub -> $dip:$dport"
}

# 交互式删除端口转发：列出现有 DNAT 规则并按编号删除
interactive_delete_port_forward() {
  ensure_nat_table
  local out; out=$($SUDO_CMD nft -a list chain ip nat PREROUTING 2>/dev/null || true)
  mapfile -t rules < <(echo "$out" | awk '
    /dnat to/ && /(tcp|udp) dport/ {
      proto=""; pub=""; dip=""; dport=""; h="";
      for (i=1; i<=NF; i++) {
        if ($i=="tcp"||$i=="udp") proto=$i;
        if ($i=="dport") pub=$(i+1);
        if ($i=="to") { split($(i+1), a, ":"); dip=a[1]; dport=a[2]; }
        if ($i=="handle") h=$(i+1);
      }
      if (proto && pub && dip && dport && h) { printf("%s %s %s %s %s\n", proto, pub, dip, dport, h); }
    }')
  if [[ ${#rules[@]} -eq 0 ]]; then
    echo "当前无端口转发规则"; return 0
  fi
  echo "当前端口转发："
  local i=0
  for line in "${rules[@]}"; do
    i=$((i+1))
    local proto pub dip dp h
    read -r proto pub dip dp h <<<"$line"
    printf "%d) %s %s -> %s:%s (handle %s)\n" "$i" "$proto" "$pub" "$dip" "$dp" "$h"
  done
  local idx
  read -rp "输入编号（0 返回）： " idx
  [[ -z "$idx" ]] && return 0
  if ! [[ "$idx" =~ ^[0-9]+$ ]]; then echo "无效编号"; return 1; fi
  if [[ "$idx" -eq 0 ]]; then return 0; fi
  if (( idx < 1 || idx > ${#rules[@]} )); then echo "编号超出范围"; return 1; fi
  local selected="${rules[$((idx-1))]}"
  local proto pub dip dp h
  read -r proto pub dip dp h <<<"$selected"
  $SUDO_CMD nft delete rule ip nat PREROUTING handle "$h" || true
  if [[ "$proto" == "tcp" ]]; then
    $SUDO_CMD nft delete element inet filter fwd_tcp_map { $dip . $dp } >/dev/null 2>&1 || true
  else
    $SUDO_CMD nft delete element inet filter fwd_udp_map { $dip . $dp } >/dev/null 2>&1 || true
  fi
  # 更新注册表：若记录为 any，根据剩余协议更新为另一协议，否则移除
  if [[ -f "$FORWARD_REG" ]]; then
    local tmp; tmp=$(mktemp)
    local other; other="tcp"; [[ "$proto" == "tcp" ]] && other="udp"
    local out2; out2=$($SUDO_CMD nft -a list chain ip nat PREROUTING 2>/dev/null || true)
    local other_exists
    other_exists=$(echo "$out2" | awk -v o="$other" -v p="$pub" -v ip="$dip" -v dp="$dp" '/dnat to/ && $0 ~ (o " dport") && $0 ~ ("dport " p) && $0 ~ ("dnat to " ip ":" dp) {print "YES"; exit} END{print ""}')
    awk -F',' -v p="$pub" -v pr="$proto" -v ip="$dip" -v dp="$dp" -v o="$other" -v oe="$other_exists" 'BEGIN{OFS=","}
      {
        if ($1==p && $3==ip && $4==dp) {
          if ($2==pr) { next }
          if ($2=="any") { if (oe=="YES") { $2=o; print $0; next } else { next } }
        }
        print $0
      }' "$FORWARD_REG" > "$tmp"
    $SUDO_CMD mv "$tmp" "$FORWARD_REG"
  fi
  log "已移除端口转发: $proto $pub -> $dip:$dp (handle $h)"
}

enable_masquerade() {
  local iface="$1"
  ensure_nat_table
  $SUDO_CMD nft add rule ip nat POSTROUTING oifname "$iface" masquerade
  log "已在接口 $iface 启用 masquerade"
}

save_rules() { mkdir_p_rules_dir; $SUDO_CMD sh -c "nft list ruleset > '$RULES_FILE'"; log "已保存规则到 $RULES_FILE"; }
load_rules() { if [[ -f "$RULES_FILE" ]]; then $SUDO_CMD nft -f "$RULES_FILE"; log "已加载规则: $RULES_FILE"; else err "未找到规则文件: $RULES_FILE"; fi }

list_status() {
  require_root_or_sudo
  # 策略链
  local input_chain
  input_chain=$($SUDO_CMD nft -a list chain inet filter input 2>/dev/null | awk '/jump (input_any|input_whitelist|input_cn)/{print $2}' | tail -n1)
  printf "\n当前策略链: ${GREEN}%s${NC}\n" "${input_chain:-未知}"

  # 策略开关状态
  get_policy_flags || true
  printf "\n策略开关:\n"
  if [[ "${BLOCK_UDP:-0}" -eq 1 ]]; then echo "UDP阻止: 开启"; else echo "UDP阻止: 关闭"; fi
  if [[ "${BLOCK_ICMP:-0}" -eq 1 ]]; then echo "ICMP阻止: 开启"; else echo "ICMP阻止: 关闭"; fi

  # IP/CIDR 白名单（仅自定义）
  printf "\nIP/CIDR白名单（仅自定义）:\n"
  local allow4 allow6 raw
  raw=$($SUDO_CMD nft list set inet filter allow_ips 2>/dev/null || true)
  allow4=$(echo "$raw" | tr -d '\n' | sed -n 's/.*elements = { *\([^}][^}]*\) *}.*/\1/p' | tr ',' '\n' | sed 's/^ *//; s/ *$//' | sed '/^$/d')
  if [[ -z "$allow4" ]]; then
    allow4=$(echo "$raw" | sed -n '/elements = {/,/}/p' | sed '1d;$d' | tr -d ',' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d')
  fi
  raw=$($SUDO_CMD nft list set inet filter allow_ips6 2>/dev/null || true)
  allow6=$(echo "$raw" | tr -d '\n' | sed -n 's/.*elements = { *\([^}][^}]*\) *}.*/\1/p' | tr ',' '\n' | sed 's/^ *//; s/ *$//' | sed '/^$/d')
  if [[ -z "$allow6" ]]; then
    allow6=$(echo "$raw" | sed -n '/elements = {/,/}/p' | sed '1d;$d' | tr -d ',' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d')
  fi
  if [[ -z "$allow4$allow6" ]]; then
    echo "无"
  else
    printf "%s\n%s\n" "$allow4" "$allow6" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; /^$/d'
  fi

  # IP/CIDR 黑名单
  printf "\nIP/CIDR黑名单:\n"
  local block4
  raw=$($SUDO_CMD nft list set inet filter block_ips 2>/dev/null || true)
  block4=$(echo "$raw" | tr -d '\n' | sed -n 's/.*elements = { *\([^}][^}]*\) *}.*/\1/p' | tr ',' '\n' | sed 's/^ *//; s/ *$//' | sed '/^$/d')
  if [[ -z "$block4" ]]; then
    block4=$(echo "$raw" | sed -n '/elements = {/,/}/p' | sed '1d;$d' | tr -d ',' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d')
  fi
  if [[ -z "$block4" ]]; then echo "无"; else printf "%s\n" "$block4" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; /^$/d'; fi

  # 开放端口（分别展示 TCP/UDP）
  printf "\nTCP开放端口:\n"
  local TSET
  raw=$($SUDO_CMD nft list set inet filter allowed_tcp_ports 2>/dev/null || true)
  TSET=$(echo "$raw" | tr -d '\n' | sed -n 's/.*elements = { *\([^}][^}]*\) *}.*/\1/p' | tr ',' '\n' | sed 's/^ *//; s/ *$//' | sed '/^$/d')
  if [[ -z "$TSET" ]]; then
    TSET=$(echo "$raw" | sed -n '/elements = {/,/}/p' | sed '1d;$d' | tr -d ',' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d')
  fi
  if [[ -z "$TSET" ]]; then echo "无"; else printf "%s\n" "$TSET" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; /^$/d'; fi

  printf "\nUDP开放端口:\n"
  local USET
  raw=$($SUDO_CMD nft list set inet filter allowed_udp_ports 2>/dev/null || true)
  USET=$(echo "$raw" | tr -d '\n' | sed -n 's/.*elements = { *\([^}][^}]*\) *}.*/\1/p' | tr ',' '\n' | sed 's/^ *//; s/ *$//' | sed '/^$/d')
  if [[ -z "$USET" ]]; then
    USET=$(echo "$raw" | sed -n '/elements = {/,/}/p' | sed '1d;$d' | tr -d ',' | sed 's/^[ \t]*//;s/[ \t]*$//' | sed '/^$/d')
  fi
  if [[ -z "$USET" ]]; then echo "无"; else printf "%s\n" "$USET" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; /^$/d'; fi

  # 端口转发：读取注册表
  printf "\n转发端口:\n"
  if [[ -f "$FORWARD_REG" ]]; then
    awk -F',' 'NF>=4{proto=$2; if(proto=="") proto="any"; remark=$5; gsub(/^[[:space:]]+/, "", remark); gsub(/[[:space:]]+$/, "", remark); printf("%s %s %s %s%s\n", $1, proto, $3, $4, (remark? " " remark: ""))}' "$FORWARD_REG"
  else
    echo "无"
  fi
}

ensure_cn_set() {
  # 可选参数：force（强制重新下载 cn.txt）
  local force="${1:-}"
  mkdir_p_rules_dir
  if [[ "$force" == "force" || ! -f "$CN_TXT_PATH" ]]; then
    log "下载 CN IP 库..."
    local tmp
    tmp=$(mktemp)
    if ! curl -L --fail "$CN_TXT_URL" -o "$tmp"; then
      rm -f "$tmp" 2>/dev/null || true
      err "下载 CN IP 库失败"; return 1
    fi
    $SUDO_CMD mv "$tmp" "$CN_TXT_PATH"
  fi
  # 生成 nft set 文件（分别处理 IPv4/IPv6）
  log "生成 CN IPv4/IPv6 集合文件..."
  # 确保集合已存在（适配尚未 init 的情况）
  $SUDO_CMD nft list set inet filter cn_ips >/dev/null 2>&1 || \
    $SUDO_CMD nft add set inet filter cn_ips '{ type ipv4_addr; flags interval; }'
  $SUDO_CMD nft list set inet filter cn_ipv6 >/dev/null 2>&1 || \
    $SUDO_CMD nft add set inet filter cn_ipv6 '{ type ipv6_addr; flags interval; }'
  local ipv4_elems ipv6_elems
  ipv4_elems=$(awk 'BEGIN{first=1} /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+,?$/ {gsub("\r","",$0); gsub(/,$/, "", $0); if(!first){printf(", ")}; printf("%s", $0); first=0}' "$CN_TXT_PATH")
  ipv6_elems=$(awk 'BEGIN{first=1} /^[0-9a-fA-F:]+\/[0-9]+,?$/ && index($0,":")>0 {gsub("\r","",$0); gsub(/,$/, "", $0); if(!first){printf(", ")}; printf("%s", $0); first=0}' "$CN_TXT_PATH")
  local tmpset
  tmpset=$(mktemp)
  {
    echo "flush set inet filter cn_ips"
    if [[ -n "$ipv4_elems" ]]; then
      echo "add element inet filter cn_ips { $ipv4_elems }"
    fi
    echo "flush set inet filter cn_ipv6"
    if [[ -n "$ipv6_elems" ]]; then
      echo "add element inet filter cn_ipv6 { $ipv6_elems }"
    fi
  } > "$tmpset"
  # 以 root 权限写入到系统目录并应用
  $SUDO_CMD mv "$tmpset" "$CN_SET_FILE"
  $SUDO_CMD nft -f "$CN_SET_FILE"
  log "CN IPv4/IPv6 集合已准备：$CN_SET_FILE"
}

# 确保私有/保留地址库已下载
ensure_private_geoip() {
  mkdir_p_rules_dir
  if [[ ! -f "$PRIVATE_TXT_PATH" ]]; then
    log "下载私有/保留地址库 (private.txt)..."
    local tmp
    tmp=$(mktemp)
    if ! curl -L --fail "$PRIVATE_TXT_URL" -o "$tmp"; then
      rm -f "$tmp" 2>/dev/null || true
      err "下载 private.txt 失败"; return 1
    fi
    $SUDO_CMD mv "$tmp" "$PRIVATE_TXT_PATH"
  fi
}

conntrack_kill_ip_port() {
  # 参数：方向(src|dst)、IP、协议(tcp|udp)、端口
  local dir="$1" ip="$2" proto="$3" port="$4"
  case "$dir" in
    src) local flag="-s" ;;
    dst) local flag="-d" ;;
    *) err "方向必须为 src 或 dst"; return 1 ;;
  esac
  case "$proto" in
    tcp|udp) : ;;
    *) err "协议必须为 tcp 或 udp"; return 1 ;;
  esac
  # 在清理前，排除私有/保留地址段
  ensure_private_geoip || true
  if [[ -f "$PRIVATE_TXT_PATH" ]]; then
    local is_priv
    is_priv=$(python3 - "$ip" "$PRIVATE_TXT_PATH" <<'PY'
import sys, ipaddress
ip = sys.argv[1]
path = sys.argv[2]
try:
    addr = ipaddress.ip_address(ip)
except ValueError:
    print("NO"); sys.exit(0)
ok = False
with open(path) as f:
    for line in f:
        s = line.strip()
        if not s or s.startswith('#'):
            continue
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError:
            continue
        if addr.version != net.version:
            continue
        if addr in net:
            ok = True
            break
print("YES" if ok else "NO")
PY
    )
    if [[ "$is_priv" == "YES" ]]; then
      log "跳过私有/保留地址: $ip，不执行 conntrack 清理"
      return 0
    fi
  fi
  # 若来源与端口同时在白名单，则不清理
  local ip_whitelisted="no" port_allowed="no"
  if [[ "$ip" == *:* ]]; then
    $SUDO_CMD nft get element inet filter allow_ips6 { $ip } >/dev/null 2>&1 && ip_whitelisted="yes"
  else
    $SUDO_CMD nft get element inet filter allow_ips { $ip } >/dev/null 2>&1 && ip_whitelisted="yes"
  fi
  case "$proto" in
    tcp) $SUDO_CMD nft get element inet filter allowed_tcp_ports { $port } >/dev/null 2>&1 && port_allowed="yes" ;;
    udp) $SUDO_CMD nft get element inet filter allowed_udp_ports { $port } >/dev/null 2>&1 && port_allowed="yes" ;;
  esac
  if [[ "$ip_whitelisted" == "yes" && "$port_allowed" == "yes" ]]; then
    log "来源与端口在白名单，跳过 conntrack 清理: $ip $proto:$port"
    return 0
  fi
  $SUDO_CMD conntrack -D -p "$proto" $flag "$ip" --dport "$port" || true
  $SUDO_CMD conntrack -D -p "$proto" $flag "$ip" --sport "$port" || true
  log "已尝试删除 conntrack 连接：$dir=$ip $proto:$port"
}

# 自动清理 conntrack：按来源 IP 是否在当前策略允许的地址段内判断
conntrack_auto_clean() {
  require_root_or_sudo
  ensure_private_geoip || true

  # 检测当前策略对应的来源集合（any 模式不按来源限制，跳过）
  local jump_chain; jump_chain=$($SUDO_CMD nft -a list chain inet filter input | grep -E "jump (input_any|input_whitelist|input_cn)" | awk '{print $2}' | tail -n1)
  local set_v4="" set_v6=""
  case "${jump_chain:-input_any}" in
    input_whitelist) set_v4="allow_ips"; set_v6="allow_ips6" ;;
    input_cn) set_v4="cn_ips"; set_v6="cn_ipv6" ;;
    *) log "当前策略为 any（不按来源限制），跳过自动清理"; return 0 ;;
  esac

  # 导出允许来源集合到临时文件（CIDR 列表）
  local tmp4 tmp6 priv_tmp
  tmp4=$(mktemp) ; tmp6=$(mktemp) ; priv_tmp=$(mktemp)
  $SUDO_CMD nft list set inet filter "$set_v4" 2>/dev/null | awk '/elements = \{/{flag=1; next} /\}/{if(flag){flag=0}} flag{gsub(/[,]/,"",$0); gsub(/^\s+|\s+$/,"",$0); if($0) print $0}' > "$tmp4" || true
  $SUDO_CMD nft list set inet filter "$set_v6" 2>/dev/null | awk '/elements = \{/{flag=1; next} /\}/{if(flag){flag=0}} flag{gsub(/[,]/,"",$0); gsub(/^\s+|\s+$/,"",$0); if($0) print $0}' > "$tmp6" || true
  [[ -f "$PRIVATE_TXT_PATH" ]] && cp "$PRIVATE_TXT_PATH" "$priv_tmp" || :

  # 将另一类来源加入白名单并集（确保当前策略下行为与脚本整体一致）
  if [[ "$jump_chain" == "input_cn" ]]; then
    $SUDO_CMD nft list set inet filter allow_ips 2>/dev/null | awk '/elements = \{/{flag=1; next} /\}/{if(flag){flag=0}} flag{gsub(/[,]/,"",$0); gsub(/^\s+|\s+$/,"",$0); if($0) print $0}' >> "$tmp4" || true
    $SUDO_CMD nft list set inet filter allow_ips6 2>/dev/null | awk '/elements = \{/{flag=1; next} /\}/{if(flag){flag=0}} flag{gsub(/[,]/,"",$0); gsub(/^\s+|\s+$/,"",$0); if($0) print $0}' >> "$tmp6" || true
  elif [[ "$jump_chain" == "input_whitelist" ]]; then
    $SUDO_CMD nft list set inet filter cn_ips 2>/dev/null | awk '/elements = \{/{flag=1; next} /\}/{if(flag){flag=0}} flag{gsub(/[,]/,"",$0); gsub(/^\s+|\s+$/,"",$0); if($0) print $0}' >> "$tmp4" || true
    $SUDO_CMD nft list set inet filter cn_ipv6 2>/dev/null | awk '/elements = \{/{flag=1; next} /\}/{if(flag){flag=0}} flag{gsub(/[,]/,"",$0); gsub(/^\s+|\s+$/,"",$0); if($0) print $0}' >> "$tmp6" || true
  fi

  # 收集唯一来源 IP
  mapfile -t srcs < <($SUDO_CMD conntrack -L 2>/dev/null | sed -n 's/.*src=\([^ ]*\).*/\1/p' | sort -u)
  local killed=0 skipped=0 total=${#srcs[@]}
  for ip in "${srcs[@]}"; do
    # Python 判断：在私有/保留或允许集合内则跳过，否则删除该来源的所有连接
    local ok
    ok=$(python3 - "$ip" "$tmp4" "$tmp6" "$priv_tmp" <<'PY'
import sys, ipaddress
ip = sys.argv[1]
v4_file, v6_file, priv_file = sys.argv[2:5]
def load_nets(path):
    nets = []
    try:
        with open(path) as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith('#'):
                    continue
                try:
                    nets.append(ipaddress.ip_network(s, strict=False))
                except Exception:
                    continue
    except Exception:
        pass
    return nets
try:
    addr = ipaddress.ip_address(ip)
except ValueError:
    print("NO"); sys.exit(0)
nets = load_nets(priv_file)
for n in nets:
    if addr.version == n.version and addr in n:
        print("YES_PRIV"); sys.exit(0)
nets = load_nets(v6_file if addr.version==6 else v4_file)
for n in nets:
    if addr.version == n.version and addr in n:
        print("YES"); sys.exit(0)
print("NO")
PY
    )
    if [[ "$ok" == "YES" || "$ok" == "YES_PRIV" ]]; then
      skipped=$((skipped+1))
      continue
    fi
    $SUDO_CMD conntrack -D -s "$ip" >/dev/null 2>&1 || true
    killed=$((killed+1))
  done
  rm -f "$tmp4" "$tmp6" "$priv_tmp" 2>/dev/null || true
  log "conntrack 自动清理完成：总计 $total，跳过 $skipped，删除 $killed"
}

interactive_menu() {
  # 二级菜单：策略与规则管理（每次操作后重印菜单）
  interactive_policy_menu() {
    while true; do
      echo
      PS3="选择策略操作（输入编号，0 返回）："
      select opt in \
        "初始化/修复 nftables" \
        "切换策略：默认（端口白名单）" \
        "切换策略：IP 白名单 + 端口白名单" \
        "切换策略：仅允许 CN 来源 + 端口白名单" \
        "开关：阻止 ICMP" \
        "开关：阻止 UDP"
      do
        case "$REPLY" in
          0) return ;;
          1) ensure_dependencies; init_nftables; list_status; break ;;
          2) set_policy_chain any; list_status; break ;;
          3) set_policy_chain whitelist; list_status; break ;;
          4) ensure_cn_set; set_policy_chain cn; list_status; break ;;
          5) toggle_block_icmp; list_status; break ;;
          6) toggle_block_udp; list_status; break ;;
          *) echo "无效选择"; break ;;
        esac
      done
    done
  }

  interactive_rules_menu() {
    while true; do
      echo
      PS3="选择规则操作（输入编号，0 返回）："
      select opt in \
        "添加允许 IP/CIDR" \
        "移除允许 IP/CIDR" \
        "添加黑名单 IP/CIDR" \
        "移除黑名单 IP/CIDR" \
        "开放端口 (tcp/udp)" \
        "关闭端口 (tcp/udp)" \
        "添加端口转发" \
        "移除端口转发" \
        "启用接口 masquerade"
      do
        case "$REPLY" in
          0) return ;;
          1) read -rp "输入允许 IP 或 CIDR: " ip; add_allow_ip "$ip"; list_status; break ;;
          2) read -rp "输入移除的 IP 或 CIDR: " ip; del_allow_ip "$ip"; list_status; break ;;
          3) read -rp "输入黑名单 IP 或 CIDR: " ip; add_block_ip "$ip"; list_status; break ;;
          4) read -rp "输入移除的黑名单 IP 或 CIDR: " ip; del_block_ip "$ip"; list_status; break ;;
          5) read -rp "协议 (tcp/udp): " proto; read -rp "端口: " port; open_port "$proto" "$port"; list_status; break ;;
          6) read -rp "协议 (tcp/udp): " proto; read -rp "端口: " port; close_port "$proto" "$port"; list_status; break ;;
          7) read -rp "协议 (tcp/udp/any，回车默认 any): " proto; [[ -z "$proto" ]] && proto="any"; read -rp "入站端口: " pub; read -rp "目标 IP/域名: " host; read -rp "目标端口: " dport; read -rp "备注(可选): " remark; add_port_forward "$proto" "$pub" "$host" "$dport" "$remark"; list_status; break ;;
          8) interactive_delete_port_forward; list_status; break ;;
          9) read -rp "输出接口名（例如：eth0）: " iface; enable_masquerade "$iface"; list_status; break ;;
          *) echo "无效选择"; break ;;
        esac
      done
    done
  }

  while true; do
    echo
    PS3="选择操作（输入编号，0 退出）："
    select opt in \
      "防火墙策略（初始化与策略切换）" \
      "规则管理（白/黑名单、端口、转发、伪装）" \
      "保存规则" \
      "加载规则" \
      "显示状态" \
      "conntrack 自动清理 (按来源)"
    do
      case "$REPLY" in
        0) return ;;
        1) interactive_policy_menu; break ;;
        2) interactive_rules_menu; break ;;
        3) save_rules; break ;;
        4) load_rules; break ;;
        5) list_status; break ;;
        6) conntrack_auto_clean; break ;;
        *) echo "无效选择"; break ;;
      esac
    done
  done
}

usage() {
  cat <<EOF
用法：$0 [命令]

  命令：
    init                 初始化/修复 nftables，并自动开放 SSH 端口
    mode any|whitelist|cn  切换入站策略（默认/白名单/CN来源）
    cn update            下载/更新 CN IP 库并应用到集合
    allow add <IP/CIDR>   添加允许来源
    allow del <IP/CIDR>   移除允许来源
    block add <IP/CIDR>   添加黑名单来源
    block del <IP/CIDR>   移除黑名单来源
    port open tcp|udp <PORT>  开放端口
    port close tcp|udp <PORT> 关闭端口
    fwd add tcp|udp|any <IN_PORT> <DST_HOST/IP> <DST_PORT> [REMARK] 添加端口转发
    fwd del tcp|udp|any <IN_PORT> <DST_HOST/IP> <DST_PORT>          移除端口转发
    masq <IFACE>          在接口启用 masquerade
    save                  保存当前规则到 $RULES_FILE
    load                  从 $RULES_FILE 加载规则
    status                显示当前状态与关键集合
    conntrack <src|dst> <IP> <tcp|udp> <PORT>  清理连接
    conntrack                 自动清理不在允许来源段内的连接（基于当前策略）
    menu                  进入交互式菜单
EOF
}

main() {
  local cmd="${1:-menu}"; shift || true
  case "$cmd" in
    init) ensure_dependencies; init_nftables; list_status ;;
    mode) ensure_dependencies; set_policy_chain "${1:-any}"; list_status ;;
    cn)
      ensure_dependencies
      case "${1:-}" in
        update) ensure_cn_set force; list_status ;;
        *) err "cn 子命令需为 update" ;;
      esac ;;
    allow)
      ensure_dependencies
      case "${1:-}" in
        add) add_allow_ip "${2:?缺少 IP/CIDR}"; list_status ;;
        del) del_allow_ip "${2:?缺少 IP/CIDR}"; list_status ;;
        *) err "allow 子命令需为 add/del" ;;
      esac ;;
    block)
      ensure_dependencies
      case "${1:-}" in
        add) add_block_ip "${2:?缺少 IP/CIDR}"; list_status ;;
        del) del_block_ip "${2:?缺少 IP/CIDR}"; list_status ;;
        *) err "block 子命令需为 add/del" ;;
      esac ;;
    port)
      ensure_dependencies
      case "${1:-}" in
        open) open_port "${2:?缺少协议}" "${3:?缺少端口}"; list_status ;;
        close) close_port "${2:?缺少协议}" "${3:?缺少端口}"; list_status ;;
        *) err "port 子命令需为 open/close" ;;
      esac ;;
    fwd)
      ensure_dependencies
      case "${1:-}" in
        add) add_port_forward "${2:-any}" "${3:?缺少入站端口}" "${4:?缺少目标}" "${5:?缺少目标端口}" "${6:-}"; list_status ;;
        del) del_port_forward "${2:-any}" "${3:?缺少入站端口}" "${4:?缺少目标}" "${5:?缺少目标端口}"; list_status ;;
        *) err "fwd 子命令需为 add/del" ;;
      esac ;;
    masq) ensure_dependencies; enable_masquerade "${1:?缺少接口名}" ;;
    save) ensure_dependencies; save_rules ;;
    load) ensure_dependencies; load_rules ;;
    status) ensure_dependencies; list_status ;;
    conntrack)
      ensure_dependencies
      if [[ -z "${1:-}" ]]; then
        conntrack_auto_clean
      else
        conntrack_kill_ip_port "${1:?缺少方向}" "${2:?缺少IP}" "${3:?缺少协议}" "${4:?缺少端口}"
      fi ;;
    menu) ensure_dependencies; interactive_menu ;;
    *) usage ;;
  esac
}

main "$@"