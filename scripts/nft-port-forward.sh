#!/usr/bin/env bash

# nft-port-forward.sh — 专用于使用 nftables 管理端口转发的交互脚本
# 功能：添加/删除端口转发、打印当前转发规则、保存规则、清空规则、开启/关闭指定网卡的 masquerade

set -euo pipefail

SCRIPT_NAME="nft-port-forward"
RULES_DIR="/etc/nftables.d"
RULES_FILE="$RULES_DIR/rules.nft"
FORWARD_REG="$RULES_DIR/forward.csv"

SUDO_CMD=""

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

mkdir_p_rules_dir() {
  [[ -d "$RULES_DIR" ]] || $SUDO_CMD mkdir -p "$RULES_DIR"
}

ensure_nat_table() {
  require_root_or_sudo
  $SUDO_CMD nft list table ip nat >/dev/null 2>&1 || $SUDO_CMD nft add table ip nat
  $SUDO_CMD nft list chain ip nat PREROUTING   >/dev/null 2>&1 || \
    $SUDO_CMD nft add chain ip nat PREROUTING   '{ type nat hook prerouting priority -100; }'
  $SUDO_CMD nft list chain ip nat POSTROUTING  >/dev/null 2>&1 || \
    $SUDO_CMD nft add chain ip nat POSTROUTING  '{ type nat hook postrouting priority 100; }'
}

# 解析主机名为 IPv4 地址；若已是 IP 则直接返回
resolve_host() {
  local host="$1"
  [[ -z "$host" ]] && echo "" && return 1
  if [[ "$host" =~ ^[0-9.]+$ ]]; then echo "$host"; return 0; fi
  local ip
  ip=$(getent ahostsv4 "$host" | awk 'NR==1{print $1}')
  if [[ -z "$ip" ]]; then ip=$(getent hosts "$host" | awk 'NR==1{print $1}'); fi
  echo "$ip"
}

# 将当前 nft PREROUTING 规则同步到 CSV（保留已有备注，聚合 proto 为 any）
sync_forward_registry() {
  require_root_or_sudo
  ensure_nat_table
  mkdir_p_rules_dir
  local out tmp tmp_in
  out=$($SUDO_CMD nft -a list chain ip nat PREROUTING 2>/dev/null || true)
  tmp=$(mktemp)
  tmp_in=$(mktemp)
  printf "%s\n" "$out" > "$tmp_in"
  if [[ -f "$FORWARD_REG" ]]; then
    $SUDO_CMD awk 'BEGIN{FS=","; OFS=","}
      NR==FNR { if (NF>=4) { key=$1 "," $3 "," $4; r=$5; gsub(/^[[:space:]]+|[[:space:]]+$/, "", r); remark[key]=r } ; next }
      { if ($0 ~ /dnat to/ && ($0 ~ /tcp dport/ || $0 ~ /udp dport/)) {
          proto=""; pub=""; dip=""; dp="";
          n=split($0, a, /[[:space:]]+/);
          for (i=1;i<=n;i++) {
            if (a[i]=="tcp") proto="tcp";
            else if (a[i]=="udp") proto="udp";
            else if (a[i]=="dport") pub=a[i+1];
            else if (a[i]=="to") { split(a[i+1], b, ":"); dip=b[1]; dp=b[2]; }
          }
          if (pub!="" && dip!="" && dp!="") {
            key=pub "," dip "," dp;
            if (protos[key]=="") protos[key]=proto; else if (protos[key]!=proto) protos[key]="any";
          }
        } }
      END { for (k in protos) { split(k, parts, ","); pub=parts[1]; dip=parts[2]; dp=parts[3]; p=protos[k]; r=remark[k]; print pub, p, dip, dp, r } }' "$FORWARD_REG" "$tmp_in" > "$tmp"
  else
    $SUDO_CMD awk 'BEGIN{OFS=","}
      { if ($0 ~ /dnat to/ && ($0 ~ /tcp dport/ || $0 ~ /udp dport/)) {
          proto=""; pub=""; dip=""; dp="";
          n=split($0, a, /[[:space:]]+/);
          for (i=1;i<=n;i++) {
            if (a[i]=="tcp") proto="tcp";
            else if (a[i]=="udp") proto="udp";
            else if (a[i]=="dport") pub=a[i+1];
            else if (a[i]=="to") { split(a[i+1], b, ":"); dip=b[1]; dp=b[2]; }
          }
          if (pub!="" && dip!="" && dp!="") {
            key=pub "," dip "," dp;
            if (protos[key]=="") protos[key]=proto; else if (protos[key]!=proto) protos[key]="any";
          }
        } }
      END { for (k in protos) { split(k, parts, ","); pub=parts[1]; dip=parts[2]; dp=parts[3]; p=protos[k]; print pub, p, dip, dp } }' "$tmp_in" > "$tmp"
  fi
  $SUDO_CMD mv "$tmp" "$FORWARD_REG"
  $SUDO_CMD rm -f "$tmp_in" >/dev/null 2>&1 || true
}

list_current_forwards() {
  require_root_or_sudo
  ensure_nat_table
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
  ensure_nat_table
  mkdir_p_rules_dir
  local proto pub host dip dp remark
  read -rp "协议 (any/tcp/udp，默认 any，输入0返回)：" proto || true
  [[ "${proto:-}" == "0" ]] && return 0
  [[ -z "${proto:-}" ]] && proto="any"
  case "$proto" in any|tcp|udp) : ;; *) echo "协议无效"; return 1 ;; esac
  read -rp "入站端口 (数字，输入0返回)：" pub || true
  [[ "${pub:-}" == "0" ]] && return 0
  if ! [[ "${pub:-}" =~ ^[0-9]+$ ]]; then echo "端口无效"; return 1; fi
  read -rp "目标 IP/域名 (输入0返回)：" host || true
  [[ "${host:-}" == "0" ]] && return 0
  dip=$(resolve_host "$host")
  if [[ -z "$dip" ]]; then err "无法解析目标: $host"; return 1; fi
  read -rp "目标端口 (数字，输入0返回)：" dp || true
  [[ "${dp:-}" == "0" ]] && return 0
  if ! [[ "${dp:-}" =~ ^[0-9]+$ ]]; then echo "目标端口无效"; return 1; fi
  read -rp "备注 (可为空，输入0返回)：" remark || true
  [[ "${remark:-}" == "0" ]] && return 0

  # 添加 nft 规则
  if [[ "$proto" == "tcp" || "$proto" == "any" ]]; then
    if ! $SUDO_CMD nft add rule ip nat PREROUTING tcp dport "$pub" dnat to "$dip":"$dp"; then
      err "添加 TCP 规则失败"; return 1
    fi
    # 允许转发的过滤规则（插入到 FORWARD 链首，避免被默认丢弃）
    $SUDO_CMD nft insert rule ip filter FORWARD ip daddr "$dip" tcp dport "$dp" accept >/dev/null 2>&1 || \
    $SUDO_CMD nft add rule ip filter FORWARD ip daddr "$dip" tcp dport "$dp" accept >/dev/null 2>&1 || true
  fi
  if [[ "$proto" == "udp" || "$proto" == "any" ]]; then
    if ! $SUDO_CMD nft add rule ip nat PREROUTING udp dport "$pub" dnat to "$dip":"$dp"; then
      err "添加 UDP 规则失败"; return 1
    fi
    $SUDO_CMD nft insert rule ip filter FORWARD ip daddr "$dip" udp dport "$dp" accept >/dev/null 2>&1 || \
    $SUDO_CMD nft add rule ip filter FORWARD ip daddr "$dip" udp dport "$dp" accept >/dev/null 2>&1 || true
  fi

  # 更新注册表：合并为 any（若已有另一协议）
  mkdir_p_rules_dir
  touch "$FORWARD_REG"
  local tmp; tmp=$(mktemp)
  $SUDO_CMD awk -F',' -v p="$pub" -v pr="$proto" -v ip="$dip" -v dp="$dp" -v r="$remark" 'BEGIN{OFS=","}
    { keep=1; if ($1==p && $3==ip && $4==dp) { keep=0; } if(keep) print $0 }
    END { if (pr=="") pr="any"; print p, pr, ip, dp, r }' "$FORWARD_REG" > "$tmp"
  $SUDO_CMD mv "$tmp" "$FORWARD_REG"
  # 再次聚合 any 状态
  sync_forward_registry || true
  log "已添加端口转发: $proto $pub -> $dip:$dp${remark:+ ($remark)}"
}

delete_forward_rules() {
  require_root_or_sudo
  ensure_nat_table
  mkdir_p_rules_dir
  sync_forward_registry || true
  if [[ ! -f "$FORWARD_REG" ]]; then echo "当前无端口转发规则"; return 0; fi
  # 展示并输入要删除的序号（可用空格或逗号分隔）
  local lines=()
  mapfile -t lines < <(awk -F',' 'NF>=4{proto=$2; if(proto=="") proto="any"; printf("%s,%s,%s,%s,%s\n", $1, proto, $3, $4, $5)}' "$FORWARD_REG")
  if [[ ${#lines[@]} -eq 0 ]]; then echo "当前无端口转发规则"; return 0; fi
  local i=0; for line in "${lines[@]}"; do i=$((i+1)); IFS=',' read -r pub proto dip dp remark <<< "$line"; printf "%d) %s %s -> %s:%s%s\n" "$i" "$proto" "$pub" "$dip" "$dp" "${remark:+ ($remark)}"; done
  local sel
  read -rp "输入要删除的编号（可空格/逗号分隔，0 返回）：" sel || true
  [[ -z "${sel:-}" || "${sel}" == "0" ]] && return 0
  sel=${sel//,/ }
  for idx in $sel; do
    if ! [[ "$idx" =~ ^[0-9]+$ ]]; then echo "跳过无效编号: $idx"; continue; fi
    if (( idx < 1 || idx > ${#lines[@]} )); then echo "编号超出范围: $idx"; continue; fi
    IFS=',' read -r pub proto dip dp remark <<< "${lines[$((idx-1))]}"
    # 删除 nft 规则（按 handle 搜索匹配规则）
    local out handles
    out=$($SUDO_CMD nft -a list chain ip nat PREROUTING 2>/dev/null || true)
    if [[ "$proto" == "tcp" || "$proto" == "any" ]]; then
      handles=$(echo "$out" | awk -v p="$pub" -v ip="$dip" -v dp="$dp" '/tcp dport/ && $0 ~ ("dport " p) && $0 ~ ("dnat to " ip ":" dp) {for(i=1;i<=NF;i++){if($i=="handle"){print $(i+1)}}}')
      while read -r h; do [[ -n "$h" ]] && $SUDO_CMD nft delete rule ip nat PREROUTING handle "$h" || true; done <<< "$handles"
      # 删除 FORWARD 链上的对应 accept 规则
      local fout fhandles
      fout=$($SUDO_CMD nft -a list chain ip filter FORWARD 2>/dev/null || true)
      fhandles=$(echo "$fout" | awk -v ip="$dip" -v dp="$dp" '/ip daddr/ && /tcp dport/ && $0 ~ ("ip daddr " ip) && $0 ~ ("tcp dport " dp) {for(i=1;i<=NF;i++){if($i=="handle"){print $(i+1)}}}')
      while read -r fh; do [[ -n "$fh" ]] && $SUDO_CMD nft delete rule ip filter FORWARD handle "$fh" || true; done <<< "$fhandles"
    fi
    if [[ "$proto" == "udp" || "$proto" == "any" ]]; then
      handles=$(echo "$out" | awk -v p="$pub" -v ip="$dip" -v dp="$dp" '/udp dport/ && $0 ~ ("dport " p) && $0 ~ ("dnat to " ip ":" dp) {for(i=1;i<=NF;i++){if($i=="handle"){print $(i+1)}}}')
      while read -r h; do [[ -n "$h" ]] && $SUDO_CMD nft delete rule ip nat PREROUTING handle "$h" || true; done <<< "$handles"
      local fout fhandles
      fout=$($SUDO_CMD nft -a list chain ip filter FORWARD 2>/dev/null || true)
      fhandles=$(echo "$fout" | awk -v ip="$dip" -v dp="$dp" '/ip daddr/ && /udp dport/ && $0 ~ ("ip daddr " ip) && $0 ~ ("udp dport " dp) {for(i=1;i<=NF;i++){if($i=="handle"){print $(i+1)}}}')
      while read -r fh; do [[ -n "$fh" ]] && $SUDO_CMD nft delete rule ip filter FORWARD handle "$fh" || true; done <<< "$fhandles"
    fi
    # 更新 CSV：any 记录删除一次；tcp/udp 仅删除匹配协议行
    local tmp; tmp=$(mktemp)
    $SUDO_CMD awk -F',' -v p="$pub" -v pr="$proto" -v ip="$dip" -v dp="$dp" 'BEGIN{OFS=","}
      { if ($1==p && $3==ip && $4==dp && (pr=="any" || $2==pr)) next; print $0 }' "$FORWARD_REG" > "$tmp"
    $SUDO_CMD mv "$tmp" "$FORWARD_REG"
    log "已移除端口转发: $proto $pub -> $dip:$dp"
  done
}

save_rules() {
  require_root_or_sudo
  mkdir_p_rules_dir
  $SUDO_CMD sh -c "nft list ruleset > '$RULES_FILE'"
  log "已保存规则到 $RULES_FILE"
}

clear_forward_rules() {
  require_root_or_sudo
  ensure_nat_table
  $SUDO_CMD nft flush chain ip nat PREROUTING >/dev/null 2>&1 || true
  mkdir_p_rules_dir
  # 同步删除 FORWARD 链上由脚本添加的 accept 规则（基于 CSV）
  if [[ -f "$FORWARD_REG" ]]; then
    while IFS=',' read -r pub proto dip dp remark; do
      [[ -z "$pub" || -z "$dip" || -z "$dp" ]] && continue
      [[ -z "$proto" ]] && proto="any"
      local fout fhandles
      if [[ "$proto" == "tcp" || "$proto" == "any" ]]; then
        fout=$($SUDO_CMD nft -a list chain ip filter FORWARD 2>/dev/null || true)
        fhandles=$(echo "$fout" | awk -v ip="$dip" -v dp="$dp" '/ip daddr/ && /tcp dport/ && $0 ~ ("ip daddr " ip) && $0 ~ ("tcp dport " dp) {for(i=1;i<=NF;i++){if($i=="handle"){print $(i+1)}}}')
        while read -r fh; do [[ -n "$fh" ]] && $SUDO_CMD nft delete rule ip filter FORWARD handle "$fh" || true; done <<< "$fhandles"
      fi
      if [[ "$proto" == "udp" || "$proto" == "any" ]]; then
        fout=$($SUDO_CMD nft -a list chain ip filter FORWARD 2>/dev/null || true)
        fhandles=$(echo "$fout" | awk -v ip="$dip" -v dp="$dp" '/ip daddr/ && /udp dport/ && $0 ~ ("ip daddr " ip) && $0 ~ ("udp dport " dp) {for(i=1;i<=NF;i++){if($i=="handle"){print $(i+1)}}}')
        while read -r fh; do [[ -n "$fh" ]] && $SUDO_CMD nft delete rule ip filter FORWARD handle "$fh" || true; done <<< "$fhandles"
      fi
    done < "$FORWARD_REG"
  fi
  : > "$FORWARD_REG"
  log "已清空端口转发规则（PREROUTING 链已刷新，CSV 已清空）"
}

# 启动时确保 FORWARD 链存在必要的 accept 规则（根据 CSV 聚合）
sync_forward_filter_accept() {
  require_root_or_sudo
  mkdir_p_rules_dir
  if [[ -f "$FORWARD_REG" ]]; then
    while IFS=',' read -r pub proto dip dp remark; do
      [[ -z "$pub" || -z "$dip" || -z "$dp" ]] && continue
      [[ -z "$proto" ]] && proto="any"
      if [[ "$proto" == "tcp" || "$proto" == "any" ]]; then
        $SUDO_CMD nft list chain ip filter FORWARD 2>/dev/null | grep -q "ip daddr $dip tcp dport $dp" || \
          $SUDO_CMD nft insert rule ip filter FORWARD ip daddr "$dip" tcp dport "$dp" accept >/dev/null 2>&1 || \
          $SUDO_CMD nft add rule ip filter FORWARD ip daddr "$dip" tcp dport "$dp" accept >/dev/null 2>&1 || true
      fi
      if [[ "$proto" == "udp" || "$proto" == "any" ]]; then
        $SUDO_CMD nft list chain ip filter FORWARD 2>/dev/null | grep -q "ip daddr $dip udp dport $dp" || \
          $SUDO_CMD nft insert rule ip filter FORWARD ip daddr "$dip" udp dport "$dp" accept >/dev/null 2>&1 || \
          $SUDO_CMD nft add rule ip filter FORWARD ip daddr "$dip" udp dport "$dp" accept >/dev/null 2>&1 || true
      fi
    done < "$FORWARD_REG"
  fi
}

# 确保 FORWARD 链具备状态回包放行，避免回复方向被默认策略或宽泛 drop 阻断
ensure_forward_baseline() {
  require_root_or_sudo
  if ! $SUDO_CMD nft list chain ip filter FORWARD >/dev/null 2>&1; then
    err "未检测到 ip filter FORWARD 链，无法添加状态回包放行"
    return 0
  fi
  # 已存在则跳过
  if $SUDO_CMD nft list chain ip filter FORWARD 2>/dev/null | grep -qE "ct state \{? *established, *related *\}?"; then
    return 0
  fi
  $SUDO_CMD nft insert rule ip filter FORWARD ct state \{ established, related \} accept >/dev/null 2>&1 || \
  $SUDO_CMD nft add rule ip filter FORWARD ct state \{ established, related \} accept >/dev/null 2>&1 || true
}

list_masquerade() {
  require_root_or_sudo
  ensure_nat_table
  local out ifaces
  out=$($SUDO_CMD nft -a list chain ip nat POSTROUTING 2>/dev/null || true)
  ifaces=$(echo "$out" | awk '{if($0 ~ /masquerade/){iface=""; handle=""; for(i=1;i<=NF;i++){if($i=="oifname"){iface=$(i+1)} else if($i=="handle"){handle=$(i+1)}}; gsub(/"/,"",iface); if(iface!="") printf("%s\n", iface)}}' | sort -u)
  echo
  if [[ -z "$ifaces" ]]; then echo "masquerade: 未开启（默认网卡 eth0）"; else echo "masquerade: 已开启于接口 -> $ifaces"; fi
  echo
}

list_net_ifaces() {
  ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | awk '($0!~/@/){print $0}'
}

enable_masquerade() {
  require_root_or_sudo
  ensure_nat_table
  echo "可用网络接口："
  list_net_ifaces | tr '\n' ' ' | sed 's/ $//' || true
  echo
  local iface
  read -rp "选择接口（默认 eth0，输入0返回）：" iface || true
  [[ -z "${iface:-}" ]] && iface="eth0"
  [[ "$iface" == "0" ]] && return 0
  $SUDO_CMD nft add rule ip nat POSTROUTING oifname "$iface" masquerade || true
  log "已在接口 $iface 启用 masquerade"
}

disable_masquerade() {
  require_root_or_sudo
  ensure_nat_table
  local out lines
  out=$($SUDO_CMD nft -a list chain ip nat POSTROUTING 2>/dev/null || true)
  mapfile -t lines < <(echo "$out" | awk '{if($0 ~ /masquerade/){iface=""; handle=""; for(i=1;i<=NF;i++){if($i=="oifname"){iface=$(i+1)} else if($i=="handle"){handle=$(i+1)}}; gsub(/"/,"",iface); if(handle!="") printf("%s,%s\n", iface, handle)}}')
  if [[ ${#lines[@]} -eq 0 ]]; then echo "当前未检测到 masquerade 规则"; return 0; fi
  local i=0
  for line in "${lines[@]}"; do i=$((i+1)); IFS=',' read -r iface handle <<< "$line"; printf "%d) %s (handle %s)\n" "$i" "$iface" "$handle"; done
  local sel
  read -rp "输入要关闭的编号（可空格/逗号分隔，0 返回）：" sel || true
  [[ -z "${sel:-}" || "$sel" == "0" ]] && return 0
  sel=${sel//,/ }
  for idx in $sel; do
    if ! [[ "$idx" =~ ^[0-9]+$ ]]; then echo "跳过无效编号: $idx"; continue; fi
    if (( idx < 1 || idx > ${#lines[@]} )); then echo "编号超出范围: $idx"; continue; fi
    IFS=',' read -r iface handle <<< "${lines[$((idx-1))]}"
    $SUDO_CMD nft delete rule ip nat POSTROUTING handle "$handle" || true
    log "已关闭接口 $iface 的 masquerade"
  done
}

print_default_status() {
  list_current_forwards
  list_masquerade
}

main_menu() {
  while true; do
    echo
    echo "操作菜单："
    echo " 1) 添加端口转发"
    echo " 2) 删除端口转发"
    echo " 3) 保存规则"
    echo " 4) 清空端口转发规则"
    echo " 5) 开启 masquerade"
    echo " 6) 关闭 masquerade"
    echo " 0) 退出"
    local choice
    read -rp "选择：" choice || true
    case "${choice:-}" in
      1) add_forward_rule || true; print_default_status ;;
      2) delete_forward_rules || true; print_default_status ;;
      3) save_rules ;;
      4) clear_forward_rules || true; print_default_status ;;
      5) enable_masquerade || true; print_default_status ;;
      6) disable_masquerade || true; print_default_status ;;
      0) exit 0 ;;
      *) echo "无效选择" ;;
    esac
  done
}

require_root_or_sudo
ensure_nat_table
mkdir_p_rules_dir
sync_forward_filter_accept || true
ensure_forward_baseline || true
print_default_status
main_menu || true