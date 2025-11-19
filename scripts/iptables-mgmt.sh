#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="iptables-mgmt"
SUDO_CMD=""
CONF_DIR="/etc/iptables.d"
CONF_V4="$CONF_DIR/rules.v4"
CONF_V6="$CONF_DIR/rules.v6"
IPSET_FILE="$CONF_DIR/ipset.conf"
RULES_DIR="$CONF_DIR"
FORWARD_REG="$CONF_DIR/forward.csv"

log() { echo "[${SCRIPT_NAME}] $*"; }
err() { echo "[${SCRIPT_NAME}][ERROR] $*" >&2; }
warn() { echo "[${SCRIPT_NAME}][WARN] $*"; }

UPDATE_SRC_URL="${UPDATE_SRC_URL:-https://raw.githubusercontent.com/PandaRyshan/soscripts/refs/heads/main/scripts/iptables-mgmt.sh}"
TARGET_UPDATE_PATH="${TARGET_UPDATE_PATH:-/usr/share/scripts/iptables-mgmt.sh}"

pick_downloader() { if command -v curl >/dev/null 2>&1; then echo "curl"; return 0; fi; if command -v wget >/dev/null 2>&1; then echo "wget"; return 0; fi; echo ""; return 1; }

do_update_self() {
  local proxy=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --proxy=*) proxy="${1#--proxy=}" ;;
      --proxy) shift; proxy="${1:-}" ;;
      *) ;;
    esac
    shift || true
  done
  local url="$UPDATE_SRC_URL" target="$TARGET_UPDATE_PATH" dl=""
  if [[ -n "$proxy" && "$proxy" =~ ^socks ]] && command -v curl >/dev/null 2>&1; then dl="curl"; fi
  [[ -z "$dl" ]] && dl=$(pick_downloader || true)
  [[ -z "$dl" ]] && { err "需要 curl 或 wget 以下载更新"; return 1; }
  local tmp; tmp=$(mktemp)
  if [[ "$dl" == "curl" ]]; then
    local curl_opts=( -fsSL --retry 3 --retry-delay 2 --retry-connrefused --connect-timeout 10 --max-time 60 )
    [[ -n "$proxy" ]] && curl_opts+=( --proxy "$proxy" )
    curl "${curl_opts[@]}" "$url" -o "$tmp" || { rm -f "$tmp"; err "下载失败（curl）"; return 1; }
  else
    local wget_opts=( -q --tries=3 --timeout=15 )
    if [[ -n "$proxy" ]]; then wget_opts+=( -e use_proxy=yes -e https_proxy="$proxy" -e http_proxy="$proxy" ); fi
    wget "${wget_opts[@]}" "$url" -O "$tmp" || { rm -f "$tmp"; err "下载失败（wget）"; return 1; }
  fi
  if [[ ! -s "$tmp" ]] || ! grep -q "main()" "$tmp"; then rm -f "$tmp"; err "下载的文件不合法，更新中止"; return 1; fi
  require_root_or_sudo
  local tdir; tdir=$(dirname "$target")
  $SUDO_CMD mkdir -p "$tdir" || { rm -f "$tmp"; err "创建目标目录失败：$tdir"; return 1; }
  if [[ -f "$target" ]]; then chmod --reference="$target" "$tmp" 2>/dev/null || chmod +x "$tmp" || true; else chmod +x "$tmp" || true; fi
  $SUDO_CMD mv "$tmp" "$target" || { rm -f "$tmp"; err "写入失败：$target"; return 1; }
  log "脚本已更新：$target"
}

require_root_or_sudo() { if [[ $(id -u) -ne 0 ]]; then if command -v sudo >/dev/null 2>&1; then SUDO_CMD="sudo"; else err "需要 root 或安装 sudo。"; exit 1; fi; else SUDO_CMD=""; fi }

is_cidr_or_addr() { local s="$1"; [[ -z "$s" ]] && return 1; [[ "$s" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] && return 0; [[ "$s" =~ ^([0-9a-fA-F:]+)(/[0-9]{1,3})?$ ]] && return 0; return 1; }
is_ipv4() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; }
is_ipv6() { [[ "$1" =~ ^([0-9a-fA-F:]+)(/[0-9]{1,3})?$ ]] && [[ "$1" == *:* ]]; }

is_prohibited_blacklist_target() {
  local ip="$1"
  if [[ "$ip" == "127.0.0.1" || "$ip" == "::1" || "$ip" =~ ^127\. || "$ip" =~ ^::1(/|$) ]]; then return 0; fi
  if [[ "$ip" =~ ^10\. || "$ip" =~ ^192\.168\. || "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then return 0; fi
  local self_ips; self_ips=$(ip -o addr show | awk '{print $4}' | cut -d/ -f1)
  for s in $self_ips; do if [[ "$ip" == "$s" ]]; then return 0; fi; done
  return 1
}

ensure_struct() {
  require_root_or_sudo
  $SUDO_CMD ipset list ip_blacklist_v4 >/dev/null 2>&1 || $SUDO_CMD ipset create ip_blacklist_v4 hash:net family inet -exist
  $SUDO_CMD ipset list ip_blacklist_v6 >/dev/null 2>&1 || $SUDO_CMD ipset create ip_blacklist_v6 hash:net family inet6 -exist
  $SUDO_CMD ipset list ip_whitelist_v4 >/dev/null 2>&1 || $SUDO_CMD ipset create ip_whitelist_v4 hash:net family inet -exist
  $SUDO_CMD ipset list ip_whitelist_v6 >/dev/null 2>&1 || $SUDO_CMD ipset create ip_whitelist_v6 hash:net family inet6 -exist
  $SUDO_CMD iptables -t filter -L WL_CTRL4 >/dev/null 2>&1 || $SUDO_CMD iptables -t filter -N WL_CTRL4
  $SUDO_CMD ip6tables -t filter -L WL_CTRL6 >/dev/null 2>&1 || $SUDO_CMD ip6tables -t filter -N WL_CTRL6
  $SUDO_CMD iptables -C INPUT -m set --match-set ip_blacklist_v4 src -j DROP >/dev/null 2>&1 || $SUDO_CMD iptables -I INPUT 1 -m set --match-set ip_blacklist_v4 src -j DROP
  $SUDO_CMD iptables -C FORWARD -m set --match-set ip_blacklist_v4 src -j DROP >/dev/null 2>&1 || $SUDO_CMD iptables -I FORWARD 1 -m set --match-set ip_blacklist_v4 src -j DROP
  $SUDO_CMD ip6tables -C INPUT -m set --match-set ip_blacklist_v6 src -j DROP >/dev/null 2>&1 || $SUDO_CMD ip6tables -I INPUT 1 -m set --match-set ip_blacklist_v6 src -j DROP
  $SUDO_CMD ip6tables -C FORWARD -m set --match-set ip_blacklist_v6 src -j DROP >/dev/null 2>&1 || $SUDO_CMD ip6tables -I FORWARD 1 -m set --match-set ip_blacklist_v6 src -j DROP
  $SUDO_CMD iptables -C INPUT -j WL_CTRL4 >/dev/null 2>&1 || $SUDO_CMD iptables -I INPUT 2 -j WL_CTRL4
  $SUDO_CMD iptables -C FORWARD -j WL_CTRL4 >/dev/null 2>&1 || $SUDO_CMD iptables -I FORWARD 2 -j WL_CTRL4
  $SUDO_CMD ip6tables -C INPUT -j WL_CTRL6 >/dev/null 2>&1 || $SUDO_CMD ip6tables -I INPUT 2 -j WL_CTRL6
  $SUDO_CMD ip6tables -C FORWARD -j WL_CTRL6 >/dev/null 2>&1 || $SUDO_CMD ip6tables -I FORWARD 2 -j WL_CTRL6
  ensure_forward_baseline || true
  sync_wl_ctrl || true
}

sync_wl_ctrl() {
  require_root_or_sudo
  local has4 has6
  has4=$($SUDO_CMD ipset list ip_whitelist_v4 2>/dev/null | awk '/Members/{f=1;next} f&&NF>0{print 1; exit} END{if(!f) print 0}')
  has6=$($SUDO_CMD ipset list ip_whitelist_v6 2>/dev/null | awk '/Members/{f=1;next} f&&NF>0{print 1; exit} END{if(!f) print 0}')
  $SUDO_CMD iptables -F WL_CTRL4 >/dev/null 2>&1 || true
  $SUDO_CMD ip6tables -F WL_CTRL6 >/dev/null 2>&1 || true
  if [[ "$has4" == "1" ]]; then
    $SUDO_CMD iptables -A WL_CTRL4 -m set --match-set ip_whitelist_v4 src -j ACCEPT
    $SUDO_CMD iptables -A WL_CTRL4 -j DROP
  else
    $SUDO_CMD iptables -A WL_CTRL4 -j RETURN
  fi
  if [[ "$has6" == "1" ]]; then
    $SUDO_CMD ip6tables -A WL_CTRL6 -m set --match-set ip_whitelist_v6 src -j ACCEPT
    $SUDO_CMD ip6tables -A WL_CTRL6 -j DROP
  else
    $SUDO_CMD ip6tables -A WL_CTRL6 -j RETURN
  fi
}

wl_add() { ensure_struct; local ip="$1"; [[ -z "$ip" ]] && err "缺少 IP/CIDR" && exit 1; is_cidr_or_addr "$ip" || { err "无效的 IP/CIDR: $ip"; exit 1; }; if is_ipv4 "$ip"; then $SUDO_CMD ipset add ip_whitelist_v4 "$ip" -exist >/dev/null 2>&1 || true; else $SUDO_CMD ipset add ip_whitelist_v6 "$ip" -exist >/dev/null 2>&1 || true; fi; sync_wl_ctrl || true; log "白名单已添加: $ip"; }
wl_del() { ensure_struct; local ip="$1"; [[ -z "$ip" ]] && err "缺少 IP/CIDR" && exit 1; is_cidr_or_addr "$ip" || { err "无效的 IP/CIDR: $ip"; exit 1; }; if is_ipv4 "$ip"; then $SUDO_CMD ipset del ip_whitelist_v4 "$ip" >/dev/null 2>&1 || true; else $SUDO_CMD ipset del ip_whitelist_v6 "$ip" >/dev/null 2>&1 || true; fi; sync_wl_ctrl || true; log "白名单已删除: $ip"; }
wl_clear() { ensure_struct; $SUDO_CMD ipset flush ip_whitelist_v4 >/dev/null 2>&1 || true; $SUDO_CMD ipset flush ip_whitelist_v6 >/dev/null 2>&1 || true; sync_wl_ctrl || true; log "白名单已清空"; }

bl_add() { ensure_struct; local ip="$1"; [[ -z "$ip" ]] && err "缺少 IP/CIDR" && exit 1; is_cidr_or_addr "$ip" || { err "无效的 IP/CIDR: $ip"; exit 1; }; if is_prohibited_blacklist_target "$ip"; then err "禁止将回环或本机地址加入黑名单: $ip"; exit 1; fi; if is_ipv4 "$ip"; then $SUDO_CMD ipset add ip_blacklist_v4 "$ip" -exist >/dev/null 2>&1 || true; else $SUDO_CMD ipset add ip_blacklist_v6 "$ip" -exist >/devnull 2>&1 || true; fi; log "黑名单已添加并即时生效: $ip"; }
bl_del() { ensure_struct; local ip="$1"; [[ -z "$ip" ]] && err "缺少 IP/CIDR" && exit 1; is_cidr_or_addr "$ip" || { err "无效的 IP/CIDR: $ip"; exit 1; }; if is_ipv4 "$ip"; then $SUDO_CMD ipset del ip_blacklist_v4 "$ip" >/dev/null 2>&1 || true; else $SUDO_CMD ipset del ip_blacklist_v6 "$ip" >/dev/null 2>&1 || true; fi; log "黑名单已删除: $ip"; }
bl_clear() { ensure_struct; $SUDO_CMD ipset flush ip_blacklist_v4 >/dev/null 2>&1 || true; $SUDO_CMD ipset flush ip_blacklist_v6 >/dev/null 2>&1 || true; log "黑名单已清空"; }

resolve_host() { local host="$1"; [[ -z "$host" ]] && echo "" && return 1; if [[ "$host" =~ ^[0-9.]+$ ]]; then echo "$host"; return 0; fi; local ip; ip=$(getent ahostsv4 "$host" | awk 'NR==1{print $1}'); if [[ -z "$ip" ]]; then ip=$(getent hosts "$host" | awk 'NR==1{print $1}'); fi; echo "$ip"; }

sync_forward_registry() {
  require_root_or_sudo
  mkdir_p_rules_dir
  local tmp; tmp=$(mktemp)
  local lines; lines=$($SUDO_CMD iptables -t nat -S PREROUTING 2>/dev/null | awk '/pf-managed/ && /-j DNAT/ {print}')
  if [[ -z "$lines" ]]; then : > "$tmp"; else echo "$lines" | awk 'BEGIN{OFS=","}{p="";pub="";dip="";dp="";for(i=1;i<=NF;i++){if($i=="-p"){p=$(i+1)}else if($i=="--dport"){pub=$(i+1)}else if($i=="--to-destination"){split($(i+1),b,":");dip=b[1];dp=b[2]}};if(pub!=""&&dip!=""&&dp!=""){print pub,p,dip,dp}}' > "$tmp"; fi
  $SUDO_CMD mv "$tmp" "$FORWARD_REG"
}

list_current_forwards() {
  require_root_or_sudo
  mkdir_p_rules_dir
  sync_forward_registry || true
  echo
  echo "当前端口转发规则："
  if [[ -f "$FORWARD_REG" ]]; then
    local i=0
    while IFS=',' read -r pub proto dip dp remark; do
      [[ -z "$pub" || -z "$dip" || -z "$dp" ]] && continue
      [[ -z "$proto" ]] && proto="any"
      i=$((i+1))
      printf "%d) %s %s -> %s:%s%s\n" "$i" "$proto" "$pub" "$dip" "$dp" "${remark:+ ($remark)}"
    done < "$FORWARD_REG"
    [[ "$i" -eq 0 ]] && echo "无"
  else
    echo "无"
  fi
  echo
}

add_forward_rule() {
  require_root_or_sudo
  mkdir_p_rules_dir
  local proto pub host dip dp remark
  read -rp "协议 (any/tcp/udp，默认 any，输入0返回)：" proto || true
  [[ "${proto:-}" == "0" ]] && return 0
  [[ -z "${proto:-}" ]] && proto="any"
  case "$proto" in any|tcp|udp) : ;; *) echo "协议无效"; return 1 ;; esac
  read -rp "入站端口 (数字，输入0返回)：" pub || true
  [[ "${pub:-}" == "0" ]] && return 0
  [[ "${pub:-}" =~ ^[0-9]+$ ]] || { echo "端口无效"; return 1; }
  read -rp "目标 IP/域名 (输入0返回)：" host || true
  [[ "${host:-}" == "0" ]] && return 0
  dip=$(resolve_host "$host"); [[ -z "$dip" ]] && { err "无法解析目标: $host"; return 1; }
  read -rp "目标端口 (数字，输入0返回)：" dp || true
  [[ "${dp:-}" == "0" ]] && return 0
  [[ "${dp:-}" =~ ^[0-9]+$ ]] || { echo "目标端口无效"; return 1; }
  read -rp "备注 (可为空，输入0返回)：" remark || true
  [[ "${remark:-}" == "0" ]] && return 0
  if [[ "$proto" == "tcp" || "$proto" == "any" ]]; then
    $SUDO_CMD iptables -t nat -A PREROUTING -p tcp --dport "$pub" -m comment --comment "pf-managed" -j DNAT --to-destination "$dip":"$dp"
    $SUDO_CMD iptables -C FORWARD -d "$dip" -p tcp --dport "$dp" -m comment --comment "pf-managed" -j ACCEPT >/dev/null 2>&1 || $SUDO_CMD iptables -I FORWARD 1 -d "$dip" -p tcp --dport "$dp" -m comment --comment "pf-managed" -j ACCEPT
  fi
  if [[ "$proto" == "udp" || "$proto" == "any" ]]; then
    $SUDO_CMD iptables -t nat -A PREROUTING -p udp --dport "$pub" -m comment --comment "pf-managed" -j DNAT --to-destination "$dip":"$dp"
    $SUDO_CMD iptables -C FORWARD -d "$dip" -p udp --dport "$dp" -m comment --comment "pf-managed" -j ACCEPT >/dev/null 2>&1 || $SUDO_CMD iptables -I FORWARD 1 -d "$dip" -p udp --dport "$dp" -m comment --comment "pf-managed" -j ACCEPT
  fi
  auto_enable_masquerade_default_eth0 || true
  mkdir_p_rules_dir; touch "$FORWARD_REG"
  local tmp; tmp=$(mktemp)
  $SUDO_CMD awk -F',' -v p="$pub" -v pr="$proto" -v ip="$dip" -v dp="$dp" -v r="$remark" 'BEGIN{OFS=","}{keep=1; if($1==p && $3==ip && $4==dp){keep=0} if(keep) print $0} END{if(pr=="") pr="any"; print p,pr,ip,dp,r}' "$FORWARD_REG" > "$tmp"
  $SUDO_CMD mv "$tmp" "$FORWARD_REG"
  sync_forward_registry || true
  log "已添加端口转发: $proto $pub -> $dip:$dp${remark:+ ($remark)}"
}

delete_forward_rules() {
  require_root_or_sudo
  mkdir_p_rules_dir
  sync_forward_registry || true
  if [[ ! -f "$FORWARD_REG" ]]; then echo "当前无端口转发规则"; return 0; fi
  local lines=(); mapfile -t lines < <(awk -F',' 'NF>=4{proto=$2; if(proto=="") proto="any"; printf("%s,%s,%s,%s,%s\n", $1, proto, $3, $4, $5)}' "$FORWARD_REG")
  if [[ ${#lines[@]} -eq 0 ]]; then echo "当前无端口转发规则"; return 0; fi
  local i=0; for line in "${lines[@]}"; do i=$((i+1)); IFS=',' read -r pub proto dip dp remark <<< "$line"; printf "%d) %s %s -> %s:%s%s\n" "$i" "$proto" "$pub" "$dip" "$dp" "${remark:+ ($remark)}"; done
  local sel; read -rp "输入要删除的编号（可空格/逗号分隔，0 返回）：" sel || true
  [[ -z "${sel:-}" || "$sel" == "0" ]] && return 0
  sel=${sel//,/ }
  for idx in $sel; do
    if ! [[ "$idx" =~ ^[0-9]+$ ]]; then echo "跳过无效编号: $idx"; continue; fi
    if (( idx < 1 || idx > ${#lines[@]} )); then echo "编号超出范围: $idx"; continue; fi
    IFS=',' read -r pub proto dip dp remark <<< "${lines[$((idx-1))]}"
    if [[ "$proto" == "tcp" || "$proto" == "any" ]]; then
      $SUDO_CMD iptables -t nat -D PREROUTING -p tcp --dport "$pub" -m comment --comment "pf-managed" -j DNAT --to-destination "$dip":"$dp" >/dev/null 2>&1 || true
      $SUDO_CMD iptables -D FORWARD -d "$dip" -p tcp --dport "$dp" -m comment --comment "pf-managed" -j ACCEPT >/dev/null 2>&1 || true
    fi
    if [[ "$proto" == "udp" || "$proto" == "any" ]]; then
      $SUDO_CMD iptables -t nat -D PREROUTING -p udp --dport "$pub" -m comment --comment "pf-managed" -j DNAT --to-destination "$dip":"$dp" >/dev/null 2>&1 || true
      $SUDO_CMD iptables -D FORWARD -d "$dip" -p udp --dport "$dp" -m comment --comment "pf-managed" -j ACCEPT >/dev/null 2>&1 || true
    fi
    local tmp; tmp=$(mktemp)
    $SUDO_CMD awk -F',' -v p="$pub" -v pr="$proto" -v ip="$dip" -v dp="$dp" 'BEGIN{OFS=","}{ if($1==p && $3==ip && $4==dp && (pr=="any" || $2==pr)) next; print $0 }' "$FORWARD_REG" > "$tmp"
    $SUDO_CMD mv "$tmp" "$FORWARD_REG"
    log "已移除端口转发: $proto $pub -> $dip:$dp"
  done
}

apply_forward_from_csv() {
  require_root_or_sudo
  mkdir_p_rules_dir
  [[ -f "$FORWARD_REG" ]] || return 0
  while IFS=',' read -r pub proto dip dp remark; do
    [[ -z "$pub" || -z "$dip" || -z "$dp" ]] && continue
    [[ -z "$proto" ]] && proto="any"
    if [[ "$proto" == "tcp" || "$proto" == "any" ]]; then
      $SUDO_CMD iptables -t nat -C PREROUTING -p tcp --dport "$pub" -m comment --comment "pf-managed" -j DNAT --to-destination "$dip":"$dp" >/dev/null 2>&1 || $SUDO_CMD iptables -t nat -A PREROUTING -p tcp --dport "$pub" -m comment --comment "pf-managed" -j DNAT --to-destination "$dip":"$dp"
      $SUDO_CMD iptables -C FORWARD -d "$dip" -p tcp --dport "$dp" -m comment --comment "pf-managed" -j ACCEPT >/dev/null 2>&1 || $SUDO_CMD iptables -I FORWARD 1 -d "$dip" -p tcp --dport "$dp" -m comment --comment "pf-managed" -j ACCEPT
    fi
    if [[ "$proto" == "udp" || "$proto" == "any" ]]; then
      $SUDO_CMD iptables -t nat -C PREROUTING -p udp --dport "$pub" -m comment --comment "pf-managed" -j DNAT --to-destination "$dip":"$dp" >/dev/null 2>&1 || $SUDO_CMD iptables -t nat -A PREROUTING -p udp --dport "$pub" -m comment --comment "pf-managed" -j DNAT --to-destination "$dip":"$dp"
      $SUDO_CMD iptables -C FORWARD -d "$dip" -p udp --dport "$dp" -m comment --comment "pf-managed" -j ACCEPT >/dev/null 2>&1 || $SUDO_CMD iptables -I FORWARD 1 -d "$dip" -p udp --dport "$dp" -m comment --comment "pf-managed" -j ACCEPT
    fi
  done < "$FORWARD_REG"
}

sync_forward_filter_accept() {
  require_root_or_sudo
  mkdir_p_rules_dir
  if [[ -f "$FORWARD_REG" ]]; then
    while IFS=',' read -r pub proto dip dp remark; do
      [[ -z "$pub" || -z "$dip" || -z "$dp" ]] && continue
      [[ -z "$proto" ]] && proto="any"
      if [[ "$proto" == "tcp" || "$proto" == "any" ]]; then
        $SUDO_CMD iptables -C FORWARD -d "$dip" -p tcp --dport "$dp" -j ACCEPT >/dev/null 2>&1 || $SUDO_CMD iptables -I FORWARD 1 -d "$dip" -p tcp --dport "$dp" -m comment --comment "pf-managed" -j ACCEPT
      fi
      if [[ "$proto" == "udp" || "$proto" == "any" ]]; then
        $SUDO_CMD iptables -C FORWARD -d "$dip" -p udp --dport "$dp" -j ACCEPT >/dev/null 2>&1 || $SUDO_CMD iptables -I FORWARD 1 -d "$dip" -p udp --dport "$dp" -m comment --comment "pf-managed" -j ACCEPT
      fi
    done < "$FORWARD_REG"
  fi
}

ensure_forward_baseline() { require_root_or_sudo; $SUDO_CMD iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT >/dev/null 2>&1 || $SUDO_CMD iptables -I FORWARD 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; }

list_net_ifaces() { ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | awk '($0!~/@/){print $0}'; }
default_nat_iface_candidates() { echo "eth0 enp3s0 ens33"; }
pick_available_default_iface() { local candidates ifaces c; candidates=$(default_nat_iface_candidates); ifaces=$(list_net_ifaces); for c in $candidates; do if echo "$ifaces" | grep -qx "$c"; then echo "$c"; return 0; fi; done; echo ""; return 1; }

list_masquerade() {
  require_root_or_sudo
  local ifaces; ifaces=$($SUDO_CMD iptables -t nat -S POSTROUTING 2>/dev/null | awk '/pfm-managed/ && /-j MASQUERADE/ {for(i=1;i<=NF;i++){if($i=="-o"){print $(i+1)}}}' | sort -u)
  echo
  if [[ -z "$ifaces" ]]; then echo "masquerade: 未开启（默认接口 eth0/enp3s0/ens33）"; else echo "masquerade: 已开启于接口 -> $ifaces"; fi
  echo
}

auto_enable_masquerade_default_eth0() {
  require_root_or_sudo
  local iface; iface=$(pick_available_default_iface)
  if [[ -z "$iface" ]]; then warn "未找到默认候选接口 eth0/enp3s0/ens33；跳过自动开启"; return 0; fi
  local has_iface; has_iface=$($SUDO_CMD iptables -t nat -S POSTROUTING 2>/dev/null | awk -v want="$iface" 'BEGIN{f=0} /pfm-managed/ && /-j MASQUERADE/ {for(i=1;i<=NF;i++){if($i=="-o" && $(i+1)==want){f=1; break}}} END{print f}')
  [[ "${has_iface:-0}" -ge 1 ]] && return 0
  $SUDO_CMD iptables -t nat -A POSTROUTING -o "$iface" -m comment --comment "pfm-managed" -j MASQUERADE >/dev/null 2>&1 || true
  log "检测到默认接口未启用 masquerade；已自动在 $iface 启用"
}

enable_masquerade() {
  require_root_or_sudo
  echo "可用网络接口："; list_net_ifaces | tr '\n' ' ' | sed 's/ $//' || true; echo
  local iface; read -rp "选择接口（默认 eth0/enp3s0/ens33，输入0返回）：" iface || true
  if [[ -z "${iface:-}" ]]; then iface=$(pick_available_default_iface); [[ -z "$iface" ]] && iface="eth0"; fi
  [[ "$iface" == "0" ]] && return 0
  $SUDO_CMD iptables -t nat -A POSTROUTING -o "$iface" -m comment --comment "pfm-managed" -j MASQUERADE || true
  log "已在接口 $iface 启用 masquerade"
}

disable_masquerade() {
  require_root_or_sudo
  local out lines; out=$($SUDO_CMD iptables -t nat -S POSTROUTING 2>/dev/null || true)
  mapfile -t lines < <(echo "$out" | awk '/pfm-managed/ && /-j MASQUERADE/ {for(i=1;i<=NF;i++){if($i=="-o"){printf("%s\n", $(i+1))}}}')
  if [[ ${#lines[@]} -eq 0 ]]; then echo "当前未检测到 masquerade 规则"; return 0; fi
  local i=0; for iface in "${lines[@]}"; do i=$((i+1)); printf "%d) %s\n" "$i" "$iface"; done
  local sel; read -rp "输入要关闭的编号（可空格/逗号分隔，0 返回）：" sel || true
  [[ -z "${sel:-}" || "$sel" == "0" ]] && return 0
  sel=${sel//,/ }
  for idx in $sel; do
    if ! [[ "$idx" =~ ^[0-9]+$ ]]; then echo "跳过无效编号: $idx"; continue; fi
    if (( idx < 1 || idx > ${#lines[@]} )); then echo "编号超出范围: $idx"; continue; fi
    local iface="${lines[$((idx-1))]}"
    $SUDO_CMD iptables -t nat -D POSTROUTING -o "$iface" -m comment --comment "pfm-managed" -j MASQUERADE >/dev/null 2>&1 || true
    log "已关闭接口 $iface 的 masquerade"
  done
}

is_masquerade_enabled() { require_root_or_sudo; local has_any; has_any=$($SUDO_CMD iptables -t nat -S POSTROUTING 2>/dev/null | awk 'BEGIN{f=0} /pfm-managed/ && /-j MASQUERADE/ {f=1} END{print f}'); [[ "${has_any:-0}" -ge 1 ]]; }

mkdir_p_rules_dir() { [[ -d "$RULES_DIR" ]] || $SUDO_CMD mkdir -p "$RULES_DIR"; }

udp_block_enable() {
  require_root_or_sudo
  udp_block_disable || true
  $SUDO_CMD iptables -I INPUT 1 -p udp -m comment --comment "udp-block" -j DROP >/dev/null 2>&1 || true
  $SUDO_CMD iptables -t raw -I PREROUTING 1 -m addrtype --dst-type LOCAL -p udp -m comment --comment "udp-block" -j DROP >/dev/null 2>&1 || true
  log "已开启入站 UDP 丢弃（含端口转发拦截）"
}

udp_block_disable() {
  require_root_or_sudo
  $SUDO_CMD iptables -D INPUT -p udp -m comment --comment "udp-block" -j DROP >/dev/null 2>&1 || true
  $SUDO_CMD iptables -t raw -D PREROUTING -m addrtype --dst-type LOCAL -p udp -m comment --comment "udp-block" -j DROP >/dev/null 2>&1 || true
}

status_simple() {
  ensure_struct
  echo "黑名单:"; local bl_v4 bl_v6 bl_all; bl_v4=$(get_set_elements_compact ip_blacklist_v4); bl_v6=$(get_set_elements_compact ip_blacklist_v6); bl_all=$(printf "%s %s" "$bl_v4" "$bl_v6" | tr '\t' ' ' | tr -s ' ' | sed 's/^ *//; s/ *$//'); if [[ -z "$bl_all" ]]; then echo "无"; else echo "$(echo "$bl_all" | sed 's/ /  /g')"; fi; echo
  echo "白名单:"; local wl_v4 wl_v6 wl_all; wl_v4=$(get_set_elements_compact ip_whitelist_v4); wl_v6=$(get_set_elements_compact ip_whitelist_v6); wl_all=$(printf "%s %s" "$wl_v4" "$wl_v6" | tr '\t' ' ' | tr -s ' ' | sed 's/^ *//; s/ *$//'); if [[ -z "$wl_all" ]]; then echo "无"; else echo "$(echo "$wl_all" | sed 's/ /  /g')"; fi; echo
  echo "转发规则:"; require_root_or_sudo; mkdir_p_rules_dir; sync_forward_registry || true; if [[ -f "$FORWARD_REG" ]]; then local i=0; while IFS=',' read -r pub proto dip dp remark; do [[ -z "$pub" || -z "$dip" || -z "$dp" ]] && continue; [[ -z "$proto" ]] && proto="any"; i=$((i+1)); printf "%d) %s %s -> %s:%s%s\n" "$i" "$proto" "$pub" "$dip" "$dp" "${remark:+ ($remark)}"; done < "$FORWARD_REG"; [[ "$i" -eq 0 ]] && echo "无"; else echo "无"; fi; echo
  echo "masquerade:"; if is_masquerade_enabled; then echo " 开启"; else echo " 未开启"; fi
}

status_wl() { ensure_struct; echo "白名单:"; local wl_v4 wl_v6 wl_all; wl_v4=$(get_set_elements_compact ip_whitelist_v4); wl_v6=$(get_set_elements_compact ip_whitelist_v6); wl_all=$(printf "%s %s" "$wl_v4" "$wl_v6" | tr '\t' ' ' | tr -s ' ' | sed 's/^ *//; s/ *$//'); if [[ -z "$wl_all" ]]; then echo "无"; else echo "$(echo "$wl_all" | sed 's/ /  /g')"; fi; }
status_bl() { ensure_struct; echo "黑名单:"; local bl_v4 bl_v6 bl_all; bl_v4=$(get_set_elements_compact ip_blacklist_v4); bl_v6=$(get_set_elements_compact ip_blacklist_v6); bl_all=$(printf "%s %s" "$bl_v4" "$bl_v6" | tr '\t' ' ' | tr -s ' ' | sed 's/^ *//; s/ *$//'); if [[ -z "$bl_all" ]]; then echo "无"; else echo "$(echo "$bl_all" | sed 's/ /  /g')"; fi; }
status_pf() { require_root_or_sudo; mkdir_p_rules_dir; sync_forward_registry || true; echo "转发规则:"; if [[ -f "$FORWARD_REG" ]]; then local i=0; while IFS=',' read -r pub proto dip dp remark; do [[ -z "$pub" || -z "$dip" || -z "$dp" ]] && continue; [[ -z "$proto" ]] && proto="any"; i=$((i+1)); printf "%d) %s %s -> %s:%s%s\n" "$i" "$proto" "$pub" "$dip" "$dp" "${remark:+ ($remark)}"; done < "$FORWARD_REG"; [[ "$i" -eq 0 ]] && echo " 无"; else echo " 无"; fi; }

get_set_elements_compact() { local set_name="$1"; local out elems; out=$($SUDO_CMD ipset list "$set_name" 2>/dev/null || true); elems=$(echo "$out" | awk '/Members/{f=1;next} f{print}' | tr '\t' ' ' | tr -s ' ' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | tr '\n' ' ' | sed 's/,$//'); echo "$elems"; }

save_rules() {
  require_root_or_sudo
  $SUDO_CMD mkdir -p "$CONF_DIR"
  $SUDO_CMD iptables-save > "$CONF_V4" || true
  $SUDO_CMD ip6tables-save > "$CONF_V6" || true
  $SUDO_CMD ipset save > "$IPSET_FILE" || true
  log "已保存 iptables/ipset 规则到 $CONF_DIR"
}

load_rules() {
  require_root_or_sudo
  local loaded=0
  if [[ -f "$CONF_V4" ]]; then $SUDO_CMD iptables-restore < "$CONF_V4" && loaded=1 || warn "恢复 IPv4 规则失败"; fi
  if [[ -f "$CONF_V6" ]]; then $SUDO_CMD ip6tables-restore < "$CONF_V6" && loaded=1 || warn "恢复 IPv6 规则失败"; fi
  if [[ -f "$IPSET_FILE" ]]; then $SUDO_CMD ipset restore < "$IPSET_FILE" || warn "恢复 ipset 规则失败"; fi
  ensure_struct || true
  apply_forward_from_csv || true
  sync_forward_filter_accept || true
  ensure_forward_baseline || true
  if [[ "$loaded" -eq 1 ]]; then log "已加载 iptables 规则并恢复端口转发（来自 CSV）"; else log "未加载规则文件，已确保结构并从 CSV 恢复端口转发"; fi
}

usage() {
  cat <<EOF
用法: $0 <子命令> [参数]

子命令:
  init                        初始化并确保 iptables/ipset 结构就绪
  wl add|del|clear [IP/CIDR]  白名单增删清
  bl add|del|clear [IP/CIDR]  黑名单增删清
  status [wl|bl|pf]           简化状态；支持单独显示白/黑名单、转发规则
  save                        保存 iptables/ipset 规则到配置目录
  load                        从配置目录加载已保存的规则
  update [--proxy=URL]        从仓库拉取最新脚本并写入目标路径
  udp on|off                  控制入站 UDP：off 丢弃所有入站 UDP；on 不加限制

端口转发（pf）与 masquerade（pfm）命令:
  pf                          进入端口转发管理菜单
  pf add [<proto> <pub> <dip/host> <dp> [remark]]
  pf del <proto> <pub> <dip/host> <dp>
  pf clear                    清空所有端口转发规则
  pfm on                      启用默认接口的 masquerade（eth0/enp3s0/ens33）
  pfm off                     禁用当前开启的默认接口 masquerade（需交互选择）
EOF
}

main_menu_forward() {
  while true; do
    echo
    echo "=== 端口转发管理 ==="
    echo "1) 列出当前端口转发规则"
    echo "2) 添加端口转发规则"
    echo "3) 删除端口转发规则"
    echo "4) 清空所有端口转发规则"
    echo "5) 管理 masquerade 设置"
    echo "0) 返回主菜单"
    echo
    read -rp "请选择操作 [0-5]: " choice || true
    case "$choice" in
      1) list_current_forwards ;;
      2) add_forward_rule ;;
      3) delete_forward_rules ;;
      4) clear_forward_rules ;;
      5) masquerade_menu ;;
      0) break ;;
      *) echo "无效选择，请重新输入" ;;
    esac
  done
}

masquerade_menu() {
  while true; do
    echo
    echo "=== Masquerade 管理 ==="
    echo "1) 查看当前 masquerade 状态"
    echo "2) 启用 masquerade"
    echo "3) 禁用 masquerade"
    echo "0) 返回"
    echo
    read -rp "请选择操作 [0-3]: " choice || true
    case "$choice" in
      1) list_masquerade ;;
      2) enable_masquerade ;;
      3) disable_masquerade ;;
      0) break ;;
      *) echo "无效选择，请重新输入" ;;
    esac
  done
}

status() { status_simple; }

init() { echo "初始化 iptables/ipset 配置..."; ensure_struct; }

main() {
  local cmd="${1:-}"; shift || true
  case "$cmd" in
    init) init ;;
    wl-add) wl_add "${1:-}" ;;
    wl-del) wl_del "${1:-}" ;;
    wl-clear) wl_clear ;;
    bl-add) bl_add "${1:-}" ;;
    bl-del) bl_del "${1:-}" ;;
    bl-clear) bl_clear ;;
    status)
      case "${1:-}" in wl) status_wl ;; bl) status_bl ;; pf) status_pf ;; *) status_simple ;; esac ;;
    wl)
      case "${1:-}" in add) shift || true; wl_add "${1:-}" ;; del|rm) shift || true; wl_del "${1:-}" ;; clear|flush) wl_clear ;; *) err "未知 wl 子命令"; usage; exit 1 ;; esac ;;
    bl)
      case "${1:-}" in add) shift || true; bl_add "${1:-}" ;; del|rm) shift || true; bl_del "${1:-}" ;; clear|flush) bl_clear ;; *) err "未知 bl 子命令"; usage; exit 1 ;; esac ;;
    save) save_rules ;;
    load) load_rules ;;
    update) do_update_self "$@" ;;
    udp)
      case "${1:-}" in off) udp_block_enable ;; on) udp_block_disable ;; *) err "未知 udp 子命令"; usage; exit 1 ;; esac ;;
    pf)
      case "${1:-}" in
        add) shift || true; if [ -z "${1:-}" ]; then add_forward_rule; else pf_add_from_args "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-}"; fi ;;
        del) shift || true; if [ -z "${1:-}" ]; then delete_forward_rules; else pf_del_from_args "${1:-}" "${2:-}" "${3:-}" "${4:-}"; fi ;;
        clear) clear_forward_rules ;;
        "") main_menu_forward ;;
        *) err "未知 pf 子命令"; usage; exit 1 ;;
      esac ;;
    pfm)
      case "${1:-}" in on) auto_enable_masquerade_default_eth0 ;; off) disable_masquerade ;; "") masquerade_menu ;; *) err "未知 pfm 子命令"; usage; exit 1 ;; esac ;;
    ""|-h|--help) usage ;;
    *) err "未知子命令: $cmd"; usage; exit 1 ;;
  esac
}

main "$@"
