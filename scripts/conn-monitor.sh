#!/bin/bash
# tcp monitor with email alert, cooldown, detailed connection statistics, and color coding

# ==================== 颜色定义 ====================
# 基本颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 连接数颜色阈值
LOW_THRESHOLD=1200    # 绿色 < 1200
MID_THRESHOLD=1700    # 黄色 1200-1700，红色 > 1700

# 单IP连接数颜色阈值
IP_LOW_THRESHOLD=150  # 绿色 < 150
IP_MID_THRESHOLD=200  # 黄色 150-200，红色 > 200

# ==================== 辅助函数 ====================
# 校验 IPv4 地址是否合法（格式和每段 0-255）
is_valid_ipv4() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
    for o in "$o1" "$o2" "$o3" "$o4"; do
        if ! [[ "$o" =~ ^[0-9]+$ ]] || (( o < 0 || o > 255 )); then
            return 1
        fi
    done
    return 0
}

# 判断是否为 RFC1918 私有 IPv4（10/8、172.16/12、192.168/16）
is_private_ipv4() {
    local ip="$1"
    is_valid_ipv4 "$ip" || return 1
    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
    if (( o1 == 10 )); then
        return 0
    fi
    if (( o1 == 172 )) && (( o2 >= 16 && o2 <= 31 )); then
        return 0
    fi
    if (( o1 == 192 && o2 == 168 )); then
        return 0
    fi
    return 1
}

# ==================== 邮件配置 ====================
MAIL_SERVER="${MAIL_SERVER:-}"
MAIL_PORT="${MAIL_PORT:-}"
MAIL_USE_TLS="true"
MAIL_USERNAME="${MAIL_USERNAME:-}"
MAIL_PASSWORD="${MAIL_PASSWORD:-}"
MAIL_TO=(${MAIL_TO:-})

SWAKS_TIMEOUT=${SWAKS_TIMEOUT:-12}
CONNTRACK_TIMEOUT=${CONNTRACK_TIMEOUT:-5}
CURL_TIMEOUT=${CURL_TIMEOUT:-5}
CURL_CONNECT_TIMEOUT=${CURL_CONNECT_TIMEOUT:-3}
INSTALL_TIMEOUT=${INSTALL_TIMEOUT:-30}
MAIL_TLS_MODE=${MAIL_TLS_MODE:-auto}

# 全局邮件就绪标志：配置完整时为 true，否则为 false
MAIL_READY=false

# ==================== 监控配置 ====================
INTERVAL=10
THRESHOLD=1500
COOLDOWN_PERIOD=300
# 允许用户自定义填写一个 IP（比如内网 IP），否则自动获取当前公网 IPv4
# 显式声明覆盖变量，默认为空，便于用户通过环境变量传入
LOCAL_IP_OVERRIDE="${LOCAL_IP_OVERRIDE:-}"

# 解析本机 IP：优先使用用户覆盖且合法的 IPv4，否则回退到公网 IPv4
if [[ -n "$LOCAL_IP_OVERRIDE" ]] && is_valid_ipv4 "$LOCAL_IP_OVERRIDE"; then
    LOCAL_IP="$LOCAL_IP_OVERRIDE"
    LOCAL_IP_SOURCE="override"
else
    LOCAL_IP="$(curl -s --max-time "$CURL_TIMEOUT" --connect-timeout "$CURL_CONNECT_TIMEOUT" -4 ifconfig.me || true)"
    if [[ -z "$LOCAL_IP" ]]; then
        LOCAL_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++){if($i=="src"){print $(i+1); break}}}')"
    fi
    LOCAL_IP_SOURCE="public"
fi

# ==================== 路径配置 ====================
SCRIPT_DIR="$HOME/scripts"
DATA_DIR="$SCRIPT_DIR/data"
LOG_DIR="/var/log/conn-monitor"
mkdir -p "$LOG_DIR"

# ==================== 依赖检测 ====================
check_and_install_dependencies() {
    local bins=("conntrack")
    local pkgs=("conntrack")

    if [[ "$MAIL_READY" == true ]]; then
        bins+=("swaks")
        pkgs+=("swaks")
    fi

    for i in "${!bins[@]}"; do
        if ! command -v "${bins[$i]}" &>/dev/null; then
            echo "缺少依赖: ${bins[$i]}，正在尝试安装..."
            if command -v apt-get &>/dev/null && [[ "$EUID" -eq 0 ]]; then
                timeout "${INSTALL_TIMEOUT}s" apt-get update -y >/dev/null 2>&1 || true
                timeout "${INSTALL_TIMEOUT}s" apt-get install -y ${pkgs[$i]} >/dev/null 2>&1 || {
                    echo "安装 ${bins[$i]} 失败，请手动安装"; exit 1;
                }
                echo "${bins[$i]} 安装成功"
            else
                echo "无法自动安装 ${bins[$i]}，请手动安装"; exit 1
            fi
        fi
    done
}

# ==================== 配置检查 ====================
# 评估邮件配置是否完整，不再强制退出，仅设置 MAIL_READY 并提示
check_config_vars() {
    local required_vars=("MAIL_SERVER" "MAIL_PORT" "MAIL_USERNAME" "MAIL_PASSWORD")
    local missing_vars=()
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var}" ]]; then
            missing_vars+=("$var")
        fi
    done
    local recipients_ok=true
    if [[ ${#MAIL_TO[@]} -eq 0 ]]; then
        recipients_ok=false
    elif [[ ${MAIL_TO[0]} == "" ]]; then
        recipients_ok=false
    fi
    if [[ ${#missing_vars[@]} -eq 0 && "$recipients_ok" == true ]]; then
        MAIL_READY=true
        echo "邮件配置完整，启用邮件通知"
    else
        MAIL_READY=false
        echo "提示: 邮件配置不完整，已禁用邮件通知。缺失项: ${missing_vars[*]}，收件人有效: ${recipients_ok}"
    fi
}

# ==================== 邮件预警 ====================
send_alert_email() {
    local total=$1
    local top_connections=$2
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local subject_raw="TCP连接数预警 - ${timestamp}"
    local subject_mime="=?UTF-8?B?$(printf '%s' "$subject_raw" | base64 -w 0)?="
    local body_raw="警告: TCP连接数已达到 ${total}，超过阈值 ${THRESHOLD}\n时间: ${timestamp}\n主机: $(hostname)\n\n源IP状态分布（Top5）：\n${top_connections}"
    local body_b64=$(printf "%b" "$body_raw" | base64 -w 0)

    local tls_opt
    case "$MAIL_TLS_MODE" in
        auto)
            if [[ "$MAIL_PORT" == "465" ]]; then tls_opt="--tls-on-connect"; else tls_opt="--tls"; fi ;;
        starttls) tls_opt="--tls" ;;
        ssl) tls_opt="--tls-on-connect" ;;
        none) tls_opt="" ;;
        *) tls_opt="--tls" ;;
    esac

    if [[ "$MAIL_READY" != true ]]; then
        echo "提示: 邮件配置不完整，跳过邮件发送"
        LAST_ALERT_TIME=$(date +%s)
        return 0
    fi

    for recipient in "${MAIL_TO[@]}"; do
        echo "发送预警邮件到: $recipient"
        swaks --to "$recipient" --from "$MAIL_USERNAME" \
              --server "$MAIL_SERVER" --port "$MAIL_PORT" \
              --auth-user "$MAIL_USERNAME" --auth-password "$MAIL_PASSWORD" \
              ${tls_opt} \
              --timeout "$SWAKS_TIMEOUT" \
              --header "MIME-Version: 1.0" \
              --header "Content-Type: text/plain; charset=UTF-8" \
              --header "Content-Transfer-Encoding: base64" \
              --header "Subject: $subject_mime" \
              --body "$body_b64" --silent

        if [ $? -eq 0 ]; then
            echo "邮件成功发送到: $recipient"
        else
            echo "邮件发送失败到: $recipient"
        fi
    done

    LAST_ALERT_TIME=$(date +%s)
}

# ==================== 冷却判断 ====================
can_send_alert() {
    if [ -z "$LAST_ALERT_TIME" ]; then return 0; fi
    local now=$(date +%s)
    local diff=$((now - LAST_ALERT_TIME))
    if [ $diff -ge $COOLDOWN_PERIOD ]; then return 0; else return 1; fi
}

# ==================== 获取连接统计 ====================
get_connection_stats() {
    local connections
    connections=$(timeout "${CONNTRACK_TIMEOUT}s" conntrack -L -d ${LOCAL_IP} 2>/dev/null | grep -E "tcp" | grep -v "CONNTRACK" || true)

    if [ -z "$connections" ]; then
        echo "0"
        echo ""
        return
    fi

    # 生成每IP的各TCP状态计数，绑定到与 dst=LOCAL_IP 同一段的 src=
    local result
    result=$(echo "$connections" | awk -v lip="$LOCAL_IP" '
    {
        state=$4;
        remote="";
        for (i=1;i<=NF;i++) {
            if ($i ~ /^src=/) {
                remote=substr($i,5);
            } else if ($i == "dst=" lip) {
                if (remote!="") {
                    key=remote SUBSEP state;
                    sc[key]++;
                    tot[remote]++;
                }
                break;
            }
        }
    }
    END {
        for (ip in tot) {
            out="";
            est_key=ip SUBSEP "ESTABLISHED";
            if (sc[est_key] > 0) {
                out = out " ESTABLISHED:" sc[est_key];
            }
            for (k in sc) {
                split(k, parts, SUBSEP);
                if (parts[1] == ip && parts[2] != "ESTABLISHED") {
                    out = out " " parts[2] ":" sc[k];
                }
            }
            printf "%d %s%s\n", tot[ip], ip, out;
        }
    }' | sort -nr -k1,1 | head -10 | awk '{ $1=""; sub(/^ /,"",$0); print }')

    # 统计总数（绑定到同一段）
    local total
    total=$(echo "$connections" | awk -v lip="$LOCAL_IP" '
    BEGIN { grand=0 }
    {
        remote="";
        for (i=1;i<=NF;i++) {
            if ($i ~ /^src=/) {
                remote=substr($i,5);
            } else if ($i == "dst=" lip) {
                if (remote!="") grand++;
                break;
            }
        }
    }
    END { print grand }')

    echo "$total"
    echo "$result"
}

kill_timewait() {
    local out4 out6 d4 d6 total
    out4=$(timeout "${CONNTRACK_TIMEOUT}s" conntrack -D -p tcp --state TIME_WAIT 2>/dev/null || true)
    d4=$(echo "$out4" | sed -n 's/.*: \([0-9][0-9]*\) flow entries have been deleted.*/\1/p')
    out6=$(timeout "${CONNTRACK_TIMEOUT}s" conntrack -D -f ipv6 -p tcp --state TIME_WAIT 2>/dev/null || true)
    d6=$(echo "$out6" | sed -n 's/.*: \([0-9][0-9]*\) flow entries have been deleted.*/\1/p')
    total=$(( ${d4:-0} + ${d6:-0} ))
    echo "已删除 TIME_WAIT TCP 连接: ${total}"
}

kill_top_connections() {
    local list topip
    list=$(timeout "${CONNTRACK_TIMEOUT}s" conntrack -L -d ${LOCAL_IP} 2>/dev/null || true)
    if [[ -z "$list" ]]; then
        echo "未获取到连接表，可能需要 root 权限"
        return 1
    fi
    topip=$(echo "$list" | awk -v lip="$LOCAL_IP" '
    {
        remote="";
        for (i=1;i<=NF;i++) {
            if ($i ~ /^src=/) {
                remote=substr($i,5);
            } else if ($i == "dst=" lip) {
                if (remote!="") {
                    tot[remote]++;
                }
                break;
            }
        }
    }
    END {
        best=""; bestv=0;
        for (ip in tot) {
            if (tot[ip] > bestv) { bestv=tot[ip]; best=ip; }
        }
        if (best != "") print best;
    }')
    if [[ -z "$topip" ]]; then
        echo "未找到连接最多的源IP"
        return 1
    fi
    echo "删除源IP: ${topip} 的 TCP 连接"
    local out4 out6 d4 d6 total
    out4=$(timeout "${CONNTRACK_TIMEOUT}s" conntrack -D -p tcp -s "$topip" 2>/dev/null || true)
    d4=$(echo "$out4" | sed -n 's/.*: \([0-9][0-9]*\) flow entries have been deleted.*/\1/p')
    out6=$(timeout "${CONNTRACK_TIMEOUT}s" conntrack -D -f ipv6 -p tcp -s "$topip" 2>/dev/null || true)
    d6=$(echo "$out6" | sed -n 's/.*: \([0-9][0-9]*\) flow entries have been deleted.*/\1/p')
    total=$(( ${d4:-0} + ${d6:-0} ))
    echo "已删除连接数: ${total}"
}

# ==================== 颜色选择函数 ====================
get_total_color() {
    local total=$1
    if [ "$total" -lt $LOW_THRESHOLD ]; then
        echo "$GREEN"
    elif [ "$total" -lt $MID_THRESHOLD ]; then
        echo "$YELLOW"
    else
        echo "$RED"
    fi
}

get_ip_color() {
    local count=$1
    local ip=$2
    # 本机IP始终显示蓝色
    if [ "$ip" == "$LOCAL_IP" ]; then
        echo "$BLUE"
    elif is_private_ipv4 "$ip"; then
        echo "$BLUE"
    elif [ "$count" -lt $IP_LOW_THRESHOLD ]; then
        echo "$GREEN"
    elif [ "$count" -lt $IP_MID_THRESHOLD ]; then
        echo "$YELLOW"
    else
        echo "$RED"
    fi
}

# ==================== 格式化输出 ====================
format_output() {
    local timestamp=$1
    local total=$2
    local stats=$3

    # 获取总数颜色
    local total_color=$(get_total_color "$total")

    output="[${timestamp}]\n"
    output+="TCP连接数：${total_color}${total}${NC}\n"

    if [ -n "$stats" ] && [ "$total" -gt 0 ]; then
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            # 第一个字段是IP，后续是 "状态:数量"
            local ip rest sum cnt tok ip_color
            ip=$(printf "%s" "$line" | awk '{print $1}')
            rest=$(printf "%s" "$line" | cut -d' ' -f2-)
            sum=0
            for tok in $rest; do
                cnt="${tok#*:}"
                if [[ "$cnt" =~ ^[0-9]+$ ]]; then
                    sum=$((sum + cnt))
                fi
            done
            ip_color=$(get_ip_color "$sum" "$ip")
            output+="${ip_color}${ip}${NC} ${rest}\n"
        done <<< "$stats"
    else
        output+="暂无连接统计\n"
    fi

    # 添加空行分隔
    output+="\n"
    printf "%s" "$output"
}

# ==================== 主逻辑 ====================
main()
{
    check_config_vars
    check_and_install_dependencies

    # 运行时提示：如果使用的是公网 IP 进行过滤，明确告知用户
    if [[ "$LOCAL_IP_SOURCE" == "public" ]]; then
        echo -e "提示: 未设置 LOCAL_IP_OVERRIDE 或无效，使用当前公网 IPv4 过滤: ${BLUE}${LOCAL_IP}${NC}"
        echo -e "如需使用内网/指定 IP，请在运行前设置环境变量: `LOCAL_IP_OVERRIDE=192.168.x.y`"
    else
        echo -e "已使用用户覆盖的本机 IP: ${BLUE}${LOCAL_IP}${NC}"
    fi

    echo -e "开始监控TCP连接数，阈值: ${THRESHOLD}，本机IP: ${BLUE}${LOCAL_IP}${NC}"
    echo -e "颜色说明:"
    echo -e "  ${GREEN}绿色${NC}: 连接数 < ${LOW_THRESHOLD} (总数) / < ${IP_LOW_THRESHOLD} (单IP)"
    echo -e "  ${YELLOW}黄色${NC}: ${LOW_THRESHOLD} ≤ 连接数 < ${MID_THRESHOLD} (总数) / ${IP_LOW_THRESHOLD} ≤ 连接数 < ${IP_MID_THRESHOLD} (单IP)"
    echo -e "  ${RED}红色${NC}: 连接数 ≥ ${MID_THRESHOLD} (总数) / ≥ ${IP_MID_THRESHOLD} (单IP)"
    echo -e "  ${BLUE}蓝色${NC}: 本机IP (${LOCAL_IP})"
    echo "日志保存到: $LOG_DIR"
    echo "收件人: ${MAIL_TO[*]}"
    if [[ "$MAIL_READY" != true ]]; then
        echo "提示: 邮件配置不完整或未启用，将不发送邮件"
    fi
    echo ""

    LAST_ALERT_TIME=""
    ALERT_ACTIVE=false

    while true; do
        DATE=$(date +"%Y-%m-%d")
        TIMESTAMP=$(date +"%H:%M:%S")
        LOG_FILE="$LOG_DIR/tcp_monitor_$DATE.log"

        local stats_result
        stats_result=$(get_connection_stats)
        local total=$(echo "$stats_result" | head -n 1)
        local connections=$(echo "$stats_result" | tail -n +2)

        if ! [[ "$total" =~ ^[0-9]+$ ]]; then
            total=0
            connections=""
        fi

        output=$(format_output "$TIMESTAMP" "$total" "$connections")
        printf "%b" "$output"
        printf "%b" "$output" >> "$LOG_FILE"

        if [ "$total" -gt "$THRESHOLD" ]; then
            if [ "$ALERT_ACTIVE" = false ]; then
                echo "警告: TCP连接数超过阈值 ${THRESHOLD}!"
                ALERT_ACTIVE=true
            fi

            if can_send_alert; then
                echo "尝试发送预警邮件..."
                top_connections=$(echo "$connections" | head -5)
                send_alert_email "$total" "$top_connections"
            fi
        else
            if [ "$ALERT_ACTIVE" = true ]; then
                echo "TCP连接数已恢复正常"
                ALERT_ACTIVE=false
            fi
        fi

        sleep "$INTERVAL"
    done
}

case "${1:-}" in
    -kw|--kill-timewait)
        kill_timewait
        ;;
    -kt|--kill-top)
        kill_top_connections
        ;;
    *)
        main
        ;;
esac
