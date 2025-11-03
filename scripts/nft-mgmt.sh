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
CONF_FILE="$CONF_DIR/nftrules.nft"

log() { echo "[${SCRIPT_NAME}] $*"; }
err() { echo "[${SCRIPT_NAME}][ERROR] $*" >&2; }
warn() { echo "[${SCRIPT_NAME}][WARN] $*"; }

# 远程更新源（raw 地址），可通过环境变量覆盖
UPDATE_SRC_URL="${UPDATE_SRC_URL:-https://raw.githubusercontent.com/PandaRyshan/soscripts/refs/heads/main/scripts/nft-mgmt.sh}"
# 更新目标路径，默认写入 /usr/share/scripts/nft-mgmt.sh，可通过环境变量 TARGET_UPDATE_PATH 覆盖
TARGET_UPDATE_PATH="${TARGET_UPDATE_PATH:-/usr/share/scripts/nft-mgmt.sh}"

# 检查可用下载器
pick_downloader() {
    if command -v curl >/dev/null 2>&1; then echo "curl"; return 0; fi
    if command -v wget >/dev/null 2>&1; then echo "wget"; return 0; fi
    echo ""; return 1
}

# 执行自我更新（下载覆盖当前脚本文件），不重启服务
do_update_self() {
    # 可选参数：--proxy=URL 或 --proxy URL
    local proxy=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --proxy=*) proxy="${1#--proxy=}" ;;
            --proxy) shift; proxy="${1:-}" ;;
            *) ;; # 忽略其他参数
        esac
        shift || true
    done

    local url="$UPDATE_SRC_URL"
    local target="$TARGET_UPDATE_PATH"

    # 选择下载器：若为 socks 代理则优先使用 curl
    local dl=""
    if [[ -n "$proxy" && "$proxy" =~ ^socks ]]; then
        if command -v curl >/dev/null 2>&1; then dl="curl"; fi
    fi
    if [[ -z "$dl" ]]; then dl=$(pick_downloader || true); fi
    if [[ -z "$dl" ]]; then
        err "需要 curl 或 wget 以下载更新"
        return 1
    fi

    local tmp; tmp=$(mktemp)
    if [[ "$dl" == "curl" ]]; then
        local curl_opts=( -fsSL --retry 3 --retry-delay 2 --retry-connrefused --connect-timeout 10 --max-time 60 )
        [[ -n "$proxy" ]] && curl_opts+=( --proxy "$proxy" )
        curl "${curl_opts[@]}" "$url" -o "$tmp" || { rm -f "$tmp"; err "下载失败（curl）"; return 1; }
    else
        local wget_opts=( -q --tries=3 --timeout=15 )
        if [[ -n "$proxy" ]]; then
            wget_opts+=( -e use_proxy=yes -e https_proxy="$proxy" -e http_proxy="$proxy" )
        fi
        wget "${wget_opts[@]}" "$url" -O "$tmp" || { rm -f "$tmp"; err "下载失败（wget）"; return 1; }
    fi

    # 简单校验：文件非空且包含 main 函数标识
    if [[ ! -s "$tmp" ]] || ! grep -q "main()" "$tmp"; then
        rm -f "$tmp"; err "下载的文件不合法，更新中止"; return 1
    fi

    # 准备目标目录并写入（需要 root/sudo）
    require_root_or_sudo
    local tdir; tdir=$(dirname "$target")
    $SUDO_CMD mkdir -p "$tdir" || { rm -f "$tmp"; err "创建目标目录失败：$tdir"; return 1; }
    if [[ -f "$target" ]]; then
        chmod --reference="$target" "$tmp" 2>/dev/null || chmod +x "$tmp" || true
    else
        chmod +x "$tmp" || true
    fi
    $SUDO_CMD mv "$tmp" "$target" || { rm -f "$tmp"; err "写入失败：$target"; return 1; }
    log "脚本已更新：$target"
}

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
    
    # 清空所有链中的黑名单规则（避免重复）
    clear_duplicate_blacklist_rules
    
    # 在 PREROUTING 链中插入黑名单规则（优先级 raw -300，早于 Docker 的 dstnat -100）
    $SUDO_CMD nft list chain inet filter prerouting 2>/dev/null | grep -qE 'fib daddr type local ip saddr @ip_blacklist_v4.*drop' || \
        $SUDO_CMD nft insert rule inet filter prerouting fib daddr type local ip saddr @ip_blacklist_v4 counter drop >/dev/null 2>&1 || \
        $SUDO_CMD nft add rule inet filter prerouting fib daddr type local ip saddr @ip_blacklist_v4 counter drop >/dev/null 2>&1 || true
    $SUDO_CMD nft list chain inet filter prerouting 2>/dev/null | grep -qE 'fib daddr type local ip6 saddr @ip_blacklist_v6.*drop' || \
        $SUDO_CMD nft insert rule inet filter prerouting fib daddr type local ip6 saddr @ip_blacklist_v6 counter drop >/dev/null 2>&1 || \
        $SUDO_CMD nft add rule inet filter prerouting fib daddr type local ip6 saddr @ip_blacklist_v6 counter drop >/dev/null 2>&1 || true
    
    # 在 INPUT 链中插入黑名单规则（处理本机直接访问）
    $SUDO_CMD nft list chain inet filter input 2>/dev/null | grep -qE 'ip saddr @ip_blacklist_v4.*drop' || \
        $SUDO_CMD nft insert rule inet filter input ip saddr @ip_blacklist_v4 counter drop >/dev/null 2>&1 || \
        $SUDO_CMD nft add rule inet filter input ip saddr @ip_blacklist_v4 counter drop >/dev/null 2>&1 || true
    $SUDO_CMD nft list chain inet filter input 2>/dev/null | grep -qE 'ip6 saddr @ip_blacklist_v6.*drop' || \
        $SUDO_CMD nft insert rule inet filter input ip6 saddr @ip_blacklist_v6 counter drop >/dev/null 2>&1 || \
        $SUDO_CMD nft add rule inet filter input ip6 saddr @ip_blacklist_v6 counter drop >/dev/null 2>&1 || true

    # 在 FORWARD 链中插入黑名单规则（覆盖桥接转发路径）
    $SUDO_CMD nft list chain inet filter forward 2>/dev/null | grep -qE 'ip saddr @ip_blacklist_v4.*drop' || \
        $SUDO_CMD nft insert rule inet filter forward ip saddr @ip_blacklist_v4 counter drop >/dev/null 2>&1 || \
        $SUDO_CMD nft add rule inet filter forward ip saddr @ip_blacklist_v4 counter drop >/dev/null 2>&1 || true
    $SUDO_CMD nft list chain inet filter forward 2>/dev/null | grep -qE 'ip6 saddr @ip_blacklist_v6.*drop' || \
        $SUDO_CMD nft insert rule inet filter forward ip6 saddr @ip_blacklist_v6 counter drop >/dev/null 2>&1 || \
        $SUDO_CMD nft add rule inet filter forward ip6 saddr @ip_blacklist_v6 counter drop >/dev/null 2>&1 || true
    # 插入白名单控制跳转（靠前，位于黑名单后）
    ensure_single_jump_wl_ctrl || true
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

# 端口转发相关配置
RULES_DIR="/etc/nftables.d"
RULES_FILE="$RULES_DIR/rules.nft"
FORWARD_REG="$RULES_DIR/forward.csv"

# 清除重复的黑名单规则
clear_duplicate_blacklist_rules() {
    require_root_or_sudo
    local chains="input forward prerouting"
    for chain in $chains; do
        # 获取当前链中的所有规则句柄（使用 awk 过滤，避免 pipefail 在无匹配时导致退出）
        local handles
        handles=$($SUDO_CMD nft -a list chain inet filter "$chain" 2>/dev/null | \
            awk '/(ip saddr @ip_blacklist_v4|ip6 saddr @ip_blacklist_v6).*drop/ {print $NF}' | sort -u)

        # 为每个规则句柄删除规则
        for handle in $handles; do
            $SUDO_CMD nft delete rule inet filter "$chain" handle "$handle" >/dev/null 2>&1 || true
        done
    done
    # log "已清除重复的黑名单规则"
}

# 确保 input 链中仅存在一个 'jump WL_CTRL'，并自动去重
ensure_single_jump_wl_ctrl() {
    require_root_or_sudo
    # 若链不存在则直接返回（由 ensure_struct 负责创建）
    $SUDO_CMD nft list chain inet filter input >/dev/null 2>&1 || return 0
    local out; out=$($SUDO_CMD nft -a list chain inet filter input 2>/dev/null || true)
    # 收集匹配 'jump WL_CTRL' 的规则句柄（按链中出现顺序）
    local handles=()
    while IFS= read -r h; do [[ -n "$h" ]] && handles+=("$h"); done < <(
        echo "$out" | awk '{if($0 ~ /jump/ && $0 ~ /WL_CTRL/){for(i=1;i<=NF;i++){if($i=="handle"){print $(i+1)}}}}'
    )
    if [[ ${#handles[@]} -eq 0 ]]; then
        # 不存在则插入一条（优先 insert，失败回退 add）
        $SUDO_CMD nft insert rule inet filter input jump WL_CTRL >/dev/null 2>&1 || \
        $SUDO_CMD nft add rule inet filter input jump WL_CTRL >/dev/null 2>&1 || true
        return 0
    fi
    # 存在多条：保留第一条，删除后续重复项
    local i
    for (( i=1; i<${#handles[@]}; i++ )); do
        $SUDO_CMD nft delete rule inet filter input handle "${handles[$i]}" >/dev/null 2>&1 || true
    done
}

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

# 端口转发相关函数
mkdir_p_rules_dir() {
    [[ -d "$RULES_DIR" ]] || $SUDO_CMD mkdir -p "$RULES_DIR"
}

ensure_nat_table() {
    require_root_or_sudo
    $SUDO_CMD nft list table ip nat >/dev/null 2>&1 || $SUDO_CMD nft add table ip nat
    $SUDO_CMD nft list chain ip nat PREROUTING     >/dev/null 2>&1 || \
        $SUDO_CMD nft add chain ip nat PREROUTING     '{ type nat hook prerouting priority -100; }'
    $SUDO_CMD nft list chain ip nat POSTROUTING    >/dev/null 2>&1 || \
        $SUDO_CMD nft add chain ip nat POSTROUTING    '{ type nat hook postrouting priority 100; }'
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

    auto_enable_masquerade_default_eth0 || true

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

save_forward_rules() {
    require_root_or_sudo
    mkdir_p_rules_dir
    # 过滤 iptables-nft 打印的 Warning 行，避免加载时解析失败
    $SUDO_CMD sh -c "nft list ruleset | sed '/^Warning:/d' > '$RULES_FILE'"
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

# 使用参数添加端口转发：pf add <proto:any|tcp|udp> <pub_port> <dest_ip/host> <dest_port> [remark]
pf_add_from_args() {
    require_root_or_sudo
    ensure_nat_table
    mkdir_p_rules_dir
    local proto pub host dip dp remark
    proto="$1"; pub="$2"; host="$3"; dp="$4"; remark="${5:-}"
    if [[ -z "$proto" || -z "$pub" || -z "$host" || -z "$dp" ]]; then err "参数不足：pf add <proto> <pub> <dip/host> <dp> [remark]"; return 1; fi
    case "$proto" in any|tcp|udp) : ;; *) err "协议无效: $proto"; return 1 ;; esac
    if ! [[ "$pub" =~ ^[0-9]+$ ]]; then err "端口无效: $pub"; return 1; fi
    if ! [[ "$dp" =~ ^[0-9]+$ ]]; then err "目标端口无效: $dp"; return 1; fi
    dip=$(resolve_host "$host"); [[ -z "$dip" ]] && err "无法解析目标: $host" && return 1

    # 添加 nft 规则
    if [[ "$proto" == "tcp" || "$proto" == "any" ]]; then
        if ! $SUDO_CMD nft add rule ip nat PREROUTING tcp dport "$pub" dnat to "$dip":"$dp"; then
            err "添加 TCP 规则失败"; return 1
        fi
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

    auto_enable_masquerade_default_eth0 || true

    # 更新注册表：写入记录并聚合 any
    mkdir_p_rules_dir
    touch "$FORWARD_REG"
    local tmp; tmp=$(mktemp)
    $SUDO_CMD awk -F',' -v p="$pub" -v pr="$proto" -v ip="$dip" -v dp="$dp" -v r="$remark" 'BEGIN{OFS=","}
        { keep=1; if ($1==p && $3==ip && $4==dp) { keep=0; } if(keep) print $0 }
        END { if (pr=="") pr="any"; print p, pr, ip, dp, r }' "$FORWARD_REG" > "$tmp"
    $SUDO_CMD mv "$tmp" "$FORWARD_REG"
    sync_forward_registry || true
    log "已添加端口转发: $proto $pub -> $dip:$dp${remark:+ ($remark)}"
}

# 使用参数删除端口转发：pf del <proto:any|tcp|udp> <pub_port> <dest_ip/host> <dest_port>
pf_del_from_args() {
    require_root_or_sudo
    ensure_nat_table
    mkdir_p_rules_dir
    local proto pub host dip dp
    proto="$1"; pub="$2"; host="$3"; dp="$4"
    if [[ -z "$proto" || -z "$pub" || -z "$host" || -z "$dp" ]]; then err "参数不足：pf del <proto> <pub> <dip/host> <dp>"; return 1; fi
    case "$proto" in any|tcp|udp) : ;; *) err "协议无效: $proto"; return 1 ;; esac
    if ! [[ "$pub" =~ ^[0-9]+$ ]]; then err "端口无效: $pub"; return 1; fi
    if ! [[ "$dp" =~ ^[0-9]+$ ]]; then err "目标端口无效: $dp"; return 1; fi
    dip=$(resolve_host "$host"); [[ -z "$dip" ]] && err "无法解析目标: $host" && return 1

    local out handles fout fhandles
    out=$($SUDO_CMD nft -a list chain ip nat PREROUTING 2>/dev/null || true)
    if [[ "$proto" == "tcp" || "$proto" == "any" ]]; then
        handles=$(echo "$out" | awk -v p="$pub" -v ip="$dip" -v dp="$dp" '/tcp dport/ && $0 ~ ("dport " p) && $0 ~ ("dnat to " ip ":" dp) {for(i=1;i<=NF;i++){if($i=="handle"){print $(i+1)}}}')
        while read -r h; do [[ -n "$h" ]] && $SUDO_CMD nft delete rule ip nat PREROUTING handle "$h" || true; done <<< "$handles"
        fout=$($SUDO_CMD nft -a list chain ip filter FORWARD 2>/dev/null || true)
        fhandles=$(echo "$fout" | awk -v ip="$dip" -v dp="$dp" '/ip daddr/ && /tcp dport/ && $0 ~ ("ip daddr " ip) && $0 ~ ("tcp dport " dp) {for(i=1;i<=NF;i++){if($i=="handle"){print $(i+1)}}}')
        while read -r fh; do [[ -n "$fh" ]] && $SUDO_CMD nft delete rule ip filter FORWARD handle "$fh" || true; done <<< "$fhandles"
    fi
    if [[ "$proto" == "udp" || "$proto" == "any" ]]; then
        handles=$(echo "$out" | awk -v p="$pub" -v ip="$dip" -v dp="$dp" '/udp dport/ && $0 ~ ("dport " p) && $0 ~ ("dnat to " ip ":" dp) {for(i=1;i<=NF;i++){if($i=="handle"){print $(i+1)}}}')
        while read -r h; do [[ -n "$h" ]] && $SUDO_CMD nft delete rule ip nat PREROUTING handle "$h" || true; done <<< "$handles"
        fout=$($SUDO_CMD nft -a list chain ip filter FORWARD 2>/dev/null || true)
        fhandles=$(echo "$fout" | awk -v ip="$dip" -v dp="$dp" '/ip daddr/ && /udp dport/ && $0 ~ ("ip daddr " ip) && $0 ~ ("udp dport " dp) {for(i=1;i<=NF;i++){if($i=="handle"){print $(i+1)}}}')
        while read -r fh; do [[ -n "$fh" ]] && $SUDO_CMD nft delete rule ip filter FORWARD handle "$fh" || true; done <<< "$fhandles"
    fi

    local tmp; tmp=$(mktemp)
    $SUDO_CMD awk -F',' -v p="$pub" -v pr="$proto" -v ip="$dip" -v dp="$dp" 'BEGIN{OFS=","}
        { if ($1==p && $3==ip && $4==dp && (pr=="any" || $2==pr)) next; print $0 }' "$FORWARD_REG" > "$tmp"
    $SUDO_CMD mv "$tmp" "$FORWARD_REG"
    log "已移除端口转发: $proto $pub -> $dip:$dp"
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
        warn "未检测到 ip filter FORWARD 链，无法添加状态回包放行"
        return 0
    fi
    # 已存在则跳过
    if $SUDO_CMD nft list chain ip filter FORWARD 2>/dev/null | grep -qE "ct state \\{? *established, *related *\\}?"; then
        return 0
    fi
    $SUDO_CMD nft insert rule ip filter FORWARD ct state \\{ established, related \\} accept >/dev/null 2>&1 || \
    $SUDO_CMD nft add rule ip filter FORWARD ct state \\{ established, related \\} accept >/dev/null 2>&1 || true
}

list_masquerade() {
    require_root_or_sudo
    ensure_nat_table
    local out ifaces
    out=$($SUDO_CMD nft -a list chain ip nat POSTROUTING 2>/dev/null || true)
    ifaces=$(echo "$out" | awk '{if($0 ~ /masquerade/){iface=""; handle=""; for(i=1;i<=NF;i++){if($i=="oifname"){iface=$(i+1)} else if($i=="handle"){handle=$(i+1)}}; gsub(/"/,"",iface); if(iface!="") printf("%s\n", iface)}}' | sort -u)
    echo
    if [[ -z "$ifaces" ]]; then echo "masquerade: 未开启（默认接口 eth0/enp3s0/ens33）"; else echo "masquerade: 已开启于接口 -> $ifaces"; fi
    echo
}

auto_enable_masquerade_default_eth0() {
    require_root_or_sudo
    ensure_nat_table
    local iface
    iface=$(pick_available_default_iface)
    if [[ -z "$iface" ]]; then
        warn "未找到默认候选接口 eth0/enp3s0/ens33；跳过自动开启"
        return 0
    fi
    # 若该候选接口尚未启用 masquerade，则自动添加
    local has_iface
    has_iface=$($SUDO_CMD nft list chain ip nat POSTROUTING 2>/dev/null | awk -v want="$iface" 'BEGIN{f=0}
        /masquerade/ {
            for(i=1;i<=NF;i++){
                if($i=="oifname" && $(i+1)!="!="){
                    iface=$(i+1); gsub(/"/,"",iface);
                    if(iface==want){ f=1; break }
                }
            }
        }
        END{print f}')
    if [[ "${has_iface:-0}" -ge 1 ]]; then return 0; fi
    $SUDO_CMD nft add rule ip nat POSTROUTING oifname "$iface" masquerade >/dev/null 2>&1 || true
    log "检测到默认接口未启用 masquerade；已自动在 $iface 启用"
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
    read -rp "选择接口（默认 eth0/enp3s0/ens33，输入0返回）：" iface || true
    if [[ -z "${iface:-}" ]]; then
        iface=$(pick_available_default_iface)
        [[ -z "$iface" ]] && iface="eth0"
    fi
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

print_forward_status() {
    list_current_forwards
    list_masquerade
}

# 紧凑打印集合元素（单行，空则返回空字符串）
get_set_elements_compact() {
    local set_name="$1"
    local out elems
    out=$($SUDO_CMD nft list set inet filter "$set_name" 2>/dev/null || true)
    # 解析 elements，无论元素在同一行还是多行都能提取
    elems=$(echo "$out" | awk '
        /elements/ {
            m=$0
            s=""
            if (m ~ /\{/){ sub(/.*\{/, "", m) } else { m="" }
            if (m ~ /\}/){ sub(/\}.*/, "", m); s=m; print s; exit }
            s=m
            while (getline > 0) {
                line=$0
                if (line ~ /\}/) { sub(/\}.*/, "", line); s = s " " line; print s; exit }
                s = s " " line
            }
        }
    ' | tr '\t' ' ' | tr -s ' ' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | tr -d ',' )
    echo "$elems"
}

# 候选默认外网接口名称
default_nat_iface_candidates() { echo "eth0 enp3s0 ens33"; }

# 选择第一个可用的默认外网接口（存在于当前系统的链路）
pick_available_default_iface() {
    local candidates ifaces c
    candidates=$(default_nat_iface_candidates)
    ifaces=$(list_net_ifaces)
    for c in $candidates; do
        if echo "$ifaces" | grep -qx "$c"; then
            echo "$c"; return 0
        fi
    done
    echo ""; return 1
}

# 判断 masquerade 是否开启（任意接口）
is_masquerade_enabled() {
    require_root_or_sudo
    ensure_nat_table
    # 存在 eth0/enp3s0/ens33 任一接口的 masquerade 则视为开启
    local has_any
    has_any=$($SUDO_CMD nft list chain ip nat POSTROUTING 2>/dev/null | awk 'BEGIN{f=0}
        /masquerade/ {
            for(i=1;i<=NF;i++){
                if($i=="oifname" && $(i+1)!="!="){
                    iface=$(i+1); gsub(/"/,"",iface);
                    if(iface=="eth0" || iface=="enp3s0" || iface=="ens33"){ f=1; break }
                }
            }
        }
        END{print f}')
    [[ "${has_any:-0}" -ge 1 ]]
}

# 简化版状态（默认）
status_simple() {
    ensure_struct
    # 黑名单
    echo "黑名单:"
    local bl_v4 bl_v6 bl_all
    bl_v4=$(get_set_elements_compact ip_blacklist_v4)
    bl_v6=$(get_set_elements_compact ip_blacklist_v6)
    bl_all=$(printf "%s %s" "$bl_v4" "$bl_v6" | tr '\t' ' ' | tr -s ' ' | sed 's/^ *//; s/ *$//')
    if [[ -z "$bl_all" ]]; then echo "无"; else echo "$(echo "$bl_all" | sed 's/ /  /g')"; fi
    echo
    # 白名单
    echo "白名单:"
    local wl_v4 wl_v6 wl_all
    wl_v4=$(get_set_elements_compact ip_whitelist_v4)
    wl_v6=$(get_set_elements_compact ip_whitelist_v6)
    wl_all=$(printf "%s %s" "$wl_v4" "$wl_v6" | tr '\t' ' ' | tr -s ' ' | sed 's/^ *//; s/ *$//')
    if [[ -z "$wl_all" ]]; then echo "无"; else echo "$(echo "$wl_all" | sed 's/ /  /g')"; fi
    echo
    # 转发规则
    echo "转发规则:"
    require_root_or_sudo; ensure_nat_table; mkdir_p_rules_dir; sync_forward_registry || true
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
    # masquerade 状态
    echo "masquerade:"
    if is_masquerade_enabled; then echo " 开启"; else echo " 未开启"; fi
}

# 仅显示白名单
status_wl() {
    ensure_struct
    echo "白名单:"
    local wl_v4 wl_v6 wl_all
    wl_v4=$(get_set_elements_compact ip_whitelist_v4)
    wl_v6=$(get_set_elements_compact ip_whitelist_v6)
    wl_all=$(printf "%s %s" "$wl_v4" "$wl_v6" | tr '\t' ' ' | tr -s ' ' | sed 's/^ *//; s/ *$//')
    if [[ -z "$wl_all" ]]; then echo "无"; else echo "$(echo "$wl_all" | sed 's/ /  /g')"; fi
}

# 仅显示黑名单
status_bl() {
    ensure_struct
    echo "黑名单:"
    local bl_v4 bl_v6 bl_all
    bl_v4=$(get_set_elements_compact ip_blacklist_v4)
    bl_v6=$(get_set_elements_compact ip_blacklist_v6)
    bl_all=$(printf "%s %s" "$bl_v4" "$bl_v6" | tr '\t' ' ' | tr -s ' ' | sed 's/^ *//; s/ *$//')
    if [[ -z "$bl_all" ]]; then echo "无"; else echo "$(echo "$bl_all" | sed 's/ /  /g')"; fi
}

# 仅显示转发规则
status_pf() {
    require_root_or_sudo; ensure_nat_table; mkdir_p_rules_dir; sync_forward_registry || true
    echo "转发规则:"
    if [[ -f "$FORWARD_REG" ]]; then
        local i=0
        while IFS=',' read -r pub proto dip dp remark; do
            [[ -z "$pub" || -z "$dip" || -z "$dp" ]] && continue
            [[ -z "$proto" ]] && proto="any"
            i=$((i+1))
            printf "%d) %s %s -> %s:%s%s\n" "$i" "$proto" "$pub" "$dip" "$dp" "${remark:+ ($remark)}"
        done < "$FORWARD_REG"
        [[ "$i" -eq 0 ]] && echo " 无"
    else
        echo " 无"
    fi
}

init() {
    echo "初始化 nftables 配置..."
    ensure_struct
}

status() {
    ensure_struct
    echo "==== 当前入站控制（inet filter）===="
    $SUDO_CMD nft list ruleset | sed -n '/table inet filter/,/table /p' | sed '/^table inet filter/,$!d'
    echo
    echo "==== 黑名单拦截点 ===="
    echo "PREROUTING 链（拦截 Docker 端口转发）:"
    $SUDO_CMD nft list chain inet filter prerouting 2>/dev/null || echo "    未创建"
    echo "INPUT 链（拦截本机直接访问）:"
    $SUDO_CMD nft list chain inet filter input 2>/dev/null || echo "    未创建"
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
    # 仅保存我们管理的 inet filter 表，避免将 iptables-nft 兼容层的 xt 规则写入文件导致加载失败
    $SUDO_CMD sh -c "nft list table inet filter > '$CONF_FILE'"
    log "已保存 inet filter 规则到 $CONF_FILE"
}

load_rules() {
    require_root_or_sudo
    local loaded=0
    if [[ ! -f "$CONF_FILE" ]]; then
        warn "未找到已保存的规则文件: $CONF_FILE；跳过加载，继续启动"
    else
        # 加载 inet filter 规则
        if ! $SUDO_CMD nft -f "$CONF_FILE"; then
            warn "加载规则失败：解析或应用 $CONF_FILE 出错；跳过加载，继续启动"
        else
            loaded=1
            log "已加载 inet filter 规则"
        fi
    fi
    # 加载后确保自定义结构与锚点一致（尤其是 WL_CTRL、黑名单拦截点）
    ensure_struct || true
    # 先确保 NAT 表与 FORWARD 基线存在
    ensure_nat_table || true
    ensure_forward_baseline || true
    # 根据 CSV 重新应用端口转发（PREROUTING dnat），并同步 FORWARD 过滤接受规则
    apply_forward_from_csv || true
    sync_forward_filter_accept || true
    # 确保白名单控制逻辑与集合状态同步
    sync_wl_ctrl || true
    if [[ "$loaded" -eq 1 ]]; then
        log "已加载 inet filter 规则并恢复端口转发（来自 CSV）"
    else
        log "未加载规则文件（已跳过/失败），已确保结构并从 CSV 恢复端口转发"
    fi
}

# 根据 CSV 重新应用 PREROUTING 端口转发规则（支持 proto any/tcp/udp）
apply_forward_from_csv() {
    require_root_or_sudo
    ensure_nat_table
    mkdir_p_rules_dir
    if [[ ! -f "$FORWARD_REG" ]]; then return 0; fi
    while IFS=',' read -r pub proto dip dp remark; do
        [[ -z "$pub" || -z "$dip" || -z "$dp" ]] && continue
        [[ -z "$proto" ]] && proto="any"
        if [[ "$proto" == "tcp" || "$proto" == "any" ]]; then
            $SUDO_CMD nft list chain ip nat PREROUTING 2>/dev/null | grep -q "tcp dport $pub dnat to $dip:$dp" || \
                $SUDO_CMD nft add rule ip nat PREROUTING tcp dport "$pub" dnat to "$dip":"$dp" >/dev/null 2>&1 || true
        fi
        if [[ "$proto" == "udp" || "$proto" == "any" ]]; then
            $SUDO_CMD nft list chain ip nat PREROUTING 2>/dev/null | grep -q "udp dport $pub dnat to $dip:$dp" || \
                $SUDO_CMD nft add rule ip nat PREROUTING udp dport "$pub" dnat to "$dip":"$dp" >/dev/null 2>&1 || true
        fi
    done < "$FORWARD_REG"
}

usage() {
    cat <<EOF
用法: $0 <子命令> [参数]

子命令:
    init                        初始化并确保 nftables 结构就绪
    wl add|del|clear [IP/CIDR]  新版分组命令：白名单增删清
    bl add|del|clear [IP/CIDR]  新版分组命令：黑名单增删清
    status [wl|bl|pf|debug]     简化状态；支持单独显示白/黑名单、转发规则；debug 为详细版
    save                        保存当前完整 nft 规则到配置目录
    load                        从配置目录加载已保存的 nft 规则
    update [--proxy=URL]        从仓库拉取最新 nft-mgmt.sh 并写入目标路径
                                 - 支持代理：如 --proxy=socks5://10.10.10.1:7799
                                 - 环境变量覆盖：UPDATE_SRC_URL、TARGET_UPDATE_PATH

端口转发（pf）与 masquerade（pfm）命令：
    pf                         进入端口转发管理菜单
    pf add <proto> <pub> <dip/host> <dp> [remark]
                               通过参数添加端口转发（proto: any|tcp|udp）
    pf del <proto> <pub> <dip/host> <dp>
                               通过参数删除端口转发（精准删除，无需备注）
    pf clear                   清空所有端口转发规则
    pfm on                     启用默认接口的 masquerade（eth0/enp3s0/ens33）
    pfm off                    关闭当前开启的默认接口 masquerade（需交互选择）

说明:
    - 白名单集合为空时，不限制黑名单以外的 IP 访问；非空时，仅允许白名单访问。
    - 黑名单始终优先生效：被加入的 IP/CIDR 会立即被丢弃。
    - 支持 IPv4/IPv6 与 CIDR（如 1.2.3.4/24、2001:db8::/32）。
EOF
}

# 端口转发管理菜单
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
        read -rp "请选择操作 [0-6]: " choice || true
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

# masquerade 管理菜单
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
        # status 主命令支持简化与子视图：默认简化；status wl/bl/pf 支持单独显示
        status)
            case "${1:-}" in
                wl) status_wl ;;
                bl) status_bl ;;
                pf) status_pf ;;
                debug) status ;;    # 保留旧版详细输出为 debug
                *) status_simple ;;
            esac
            ;;
        # 新增分组子命令：wl add/del/clear 与 bl add/del/clear
        wl)
            case "${1:-}" in
                add) shift || true; wl_add "${1:-}" ;;
                del|rm) shift || true; wl_del "${1:-}" ;;
                clear|flush) wl_clear ;;
                *) err "未知 wl 子命令"; usage; exit 1 ;;
            esac
            ;;
        bl)
            case "${1:-}" in
                add) shift || true; bl_add "${1:-}" ;;
                del|rm) shift || true; bl_del "${1:-}" ;;
                clear|flush) bl_clear ;;
                *) err "未知 bl 子命令"; usage; exit 1 ;;
            esac
            ;;
        save) save_rules ;;
        load) load_rules ;;
        update) do_update_self "$@" ;;
        pf)
            case "${1:-}" in
                add) shift || true; pf_add_from_args "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-}" ;;
                del)
                    shift || true
                    if [ -z "${1:-}" ]; then
                        delete_forward_rules
                    else
                        pf_del_from_args "${1:-}" "${2:-}" "${3:-}" "${4:-}"
                    fi
                    ;;
                clear) clear_forward_rules ;;
                "") main_menu_forward ;;
                *) err "未知 pf 子命令"; usage; exit 1 ;;
            esac
            ;;
        pfm)
            case "${1:-}" in
                on) auto_enable_masquerade_default_eth0 ;;
                off) disable_masquerade ;;
                "") masquerade_menu ;;
                *) err "未知 pfm 子命令"; usage; exit 1 ;;
            esac
            ;;
        ""|-h|--help) usage ;;
        *) err "未知子命令: $cmd"; usage; exit 1 ;;
    esac
}

main "$@"