#!/bin/bash

# 调试模式开关（可用环境变量覆盖）
DEBUG=${DEBUG:-false}
# 设置为 true 启用详细调试信息
# DEBUG=true

# 帮助信息
show_usage() {
    echo "用法: $0 <IP地址> <端口列表/范围> [SNI主机名]"
    echo "支持输入:"
    echo "  - 单端口: 443"
    echo "  - 多端口: 443,444"
    echo "  - 混合: 443,8001-8002"
    echo "  - 范围: 8001-8002"
    echo "兼容旧用法: $0 <IP> <起始端口> <结束端口>"
    echo "选项:"
    echo "  -h | --help | help   显示此帮助"
    echo "环境变量:"
    echo "  DEBUG=true           启用调试输出"
    echo "  MAX_JOBS=8           并发扫描上限"
    echo "  SNI_HOST=<hostname>  指定 SNI 主机名"
    echo "  USE_NMAP=true        允许轻量 nmap 确认"
}

# 处理帮助选项（优先级最高）
if [ $# -ge 1 ]; then
    case "$1" in
        -h|--help|help)
            show_usage
            exit 0
            ;;
    esac
fi

# 检查输入参数（支持混合端口列表/范围）
if [ $# -lt 2 ] || [ $# -gt 3 ]; then
    show_usage
    exit 1
fi

IP=$1
PORTS_SPEC=$2
# 兼容旧调用形式：$0 IP START END（第三参数为数字时视为范围）
if [ $# -eq 3 ] && [[ "$2" =~ ^[0-9]+$ ]] && [[ "$3" =~ ^[0-9]+$ ]]; then
    PORTS_SPEC="$2-$3"
    SNI_HOST=${SNI_HOST:-}
else
    SNI_HOST=${3:-${SNI_HOST:-}}
fi

# 用户显示用：去空格后的原始端口说明（不展开）
PORTS_SPEC_CLEAN="${PORTS_SPEC// /}"

# 可选工具检测（按需使用，不强制退出）
HAS_NMAP=false; command -v nmap >/dev/null 2>&1 && HAS_NMAP=true
HAS_OPENSSL=false; command -v openssl >/dev/null 2>&1 && HAS_OPENSSL=true
HAS_CURL=false; command -v curl >/dev/null 2>&1 && HAS_CURL=true
HAS_NC=false; command -v nc >/dev/null 2>&1 && HAS_NC=true
USE_NMAP=${USE_NMAP:-false}  # 默认不使用 nmap，除非显式启用
MAX_JOBS=${MAX_JOBS:-8}      # 并发上限（可通过环境变量覆盖）

# 调试输出函数
debug_echo() {
    if [ "$DEBUG" = true ]; then
        echo "DEBUG: $1" >&2
    fi
}

# 解析端口列表/范围为去重排序后的数组（在扫描配置之前完成）
resolve_ports() {
    local spec="$1"
    local parts=()
    local list=()
    # 归一化，移除空格
    spec="${spec// /}"
    IFS=',' read -r -a parts <<< "$spec"
    for token in "${parts[@]}"; do
        [[ -z "$token" ]] && continue
        if [[ "$token" == *"-"* ]]; then
            # 范围解析：a-b 或 b-a
            local a="${token%%-*}"
            local b="${token#*-}"
            if [[ "$a" =~ ^[0-9]+$ ]] && [[ "$b" =~ ^[0-9]+$ ]]; then
                if ((a<1 || a>65535 || b<1 || b>65535)); then
                    debug_echo "忽略越界范围: $token"; continue
                fi
                if ((a<=b)); then
                    for p in $(seq "$a" "$b"); do list+=("$p"); done
                else
                    for p in $(seq "$b" "$a"); do list+=("$p"); done
                fi
            else
                debug_echo "忽略非法范围: $token"
            fi
        elif [[ "$token" =~ ^[0-9]+$ ]]; then
            local p="$token"
            if ((p>=1 && p<=65535)); then
                list+=("$p")
            else
                debug_echo "忽略越界端口: $p"
            fi
        else
            debug_echo "忽略非法端口片段: $token"
        fi
    done
    # 去重排序输出
    if ((${#list[@]})); then
        printf "%s\n" "${list[@]}" | sort -n -u | tr '\n' ' '
    else
        echo ""
    fi
}

# 生成端口数组（用于扫描）
PORTS_STR=$(resolve_ports "$PORTS_SPEC")
read -r -a PORT_LIST <<< "$PORTS_STR"
if [ ${#PORT_LIST[@]} -eq 0 ]; then
    echo "错误: 端口列表为空或不合法: $PORTS_SPEC" >&2
    exit 1
fi
debug_echo "解析端口: $PORTS_SPEC -> ${PORT_LIST[*]}"

# 创建唯一的临时目录
TEMP_DIR=$(mktemp -d -p /tmp port_scan_XXXXXX)
debug_echo "创建临时目录: $TEMP_DIR"

# 设置信号处理，确保临时文件被清理
cleanup() {
    debug_echo "清理临时文件: $TEMP_DIR"
    rm -rf "$TEMP_DIR"
    exit 0
}
trap cleanup EXIT INT TERM

# 快速 TCP 连接探测（/dev/tcp），用于判断端口是否可达
quick_connect() {
    local ip=$1 port=$2
    # 优先使用 bash /dev/tcp 写入方式，避免阻塞读取
    if timeout 1 bash -c ">/dev/tcp/${ip}/${port}" >/dev/null 2>&1; then
        return 0
    fi
    # 退回到 nc 探测
    if $HAS_NC && nc -z -w1 "$ip" "$port" >/dev/null 2>&1; then
        return 0
    fi
    # 最后退回到 openssl（仅用于 TLS 端口的连通性探测）
    if $HAS_OPENSSL && echo "Q" | timeout 1 openssl s_client -connect "$ip:$port" -servername "$ip" -brief >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# 读取服务器初始横幅/数据，用于非TLS协议粗识别
read_banner() {
    local ip=$1 port=$2
    local data=""
    # 尝试通过 /dev/tcp 读取少量数据
    if data=$(timeout 1 bash -c "head -c 128 < /dev/tcp/${ip}/${port}" 2>/dev/null); then
        echo "$data"; return 0
    fi
    # 回退到 nc
    if $HAS_NC; then
        data=$(timeout 1 nc -w1 "$ip" "$port" < /dev/null 2>/dev/null | head -c 128)
        echo "$data"; return 0
    fi
    echo ""
    return 0
}

# 专门检查HTTPS服务的函数
check_https_service() {
    local port=$1
    local detection_method=$2

    debug_echo "端口 $port: 开始HTTPS/TLS详细检测"

    echo "  TLS/HTTPS详细信息:"
    echo "  检测方法: $detection_method"

    # 获取证书信息
    debug_echo "端口 $port: 尝试获取证书信息"
    if ! $HAS_OPENSSL; then
        echo "  OpenSSL 不可用，跳过证书详情"
    else
        local SNI_OPT=()
        if [ -n "$SNI_HOST" ]; then SNI_OPT=("-servername" "$SNI_HOST"); fi
        # 先尝试不带 SNI，再尝试带 SNI
        local cert_check=""
        cert_check=$(echo "Q" | timeout 3 openssl s_client -connect $IP:$port 2>/dev/null)
        if ! echo "$cert_check" | grep -q "CONNECTED" && [ -n "$SNI_HOST" ]; then
            cert_check=$(echo "Q" | timeout 3 openssl s_client -connect $IP:$port "${SNI_OPT[@]}" 2>/dev/null)
        fi

        if echo "$cert_check" | grep -q "BEGIN CERTIFICATE"; then
            debug_echo "端口 $port: 检测到有效TLS证书"

        # 提取证书信息
        local cert_info=$(echo "$cert_check" | openssl x509 -noout -dates 2>/dev/null)
        if [ -n "$cert_info" ]; then
            echo "  证书有效期:"
            echo "$cert_info" | while read line; do
                echo "    $line"
            done
        fi

        local cert_subject=$(echo "$cert_check" | openssl x509 -noout -subject 2>/dev/null)
        if [ -n "$cert_subject" ]; then
            echo "  证书主题: $cert_subject"
        fi
        else
            debug_echo "端口 $port: 未检测到有效TLS证书"
            echo "  证书状态: 未检测到有效证书"

            # 检查是否至少建立了TLS连接
            if echo "$cert_check" | grep -q "CONNECTED"; then
                echo "  连接状态: TLS握手成功，但无证书"
            else
                echo "  连接状态: TLS握手失败"
            fi
        fi
    fi

    # 从一次完整握手中提取关键信息（版本/加密套件/ALPN/证书）
    if $HAS_OPENSSL; then
        local sni_arg=""; [ -n "$SNI_HOST" ] && sni_arg="-servername $SNI_HOST" || sni_arg="-servername $IP"
        local full_ssl=$(echo "Q" | timeout 4 openssl s_client -connect $IP:$port $sni_arg 2>&1)

        # 协议版本
        local proto_line=$(echo "$full_ssl" | grep -E "Protocol\s*:" | head -n1)
        local tls_ver=$(echo "$proto_line" | awk -F':' '{gsub(/ /,""); print $2}')
        [ -z "$tls_ver" ] && tls_ver=$(echo "$full_ssl" | grep -Eo "TLSv[0-9\.]+" | head -n1)
        [ -n "$tls_ver" ] && echo "  握手协议版本: $tls_ver"

        # 加密套件
        local cipher_line=$(echo "$full_ssl" | grep -E "Cipher\s*:" | head -n1)
        local tls_cipher=$(echo "$cipher_line" | awk -F':' '{gsub(/ /,""); print $2}')
        [ -n "$tls_cipher" ] && echo "  加密套件: $tls_cipher"

        # ALPN（需要客户端声明候选）
        local alpn_out=$(echo "Q" | timeout 4 openssl s_client -connect $IP:$port $sni_arg -alpn h2,http/1.1 2>&1)
        local alpn_line=$(echo "$alpn_out" | grep -E "ALPN protocol|ALPN, server accepted" | head -n1)
        local alpn_proto=$(echo "$alpn_line" | awk -F':' '{gsub(/ /,""); print $2}')
        # 一些 OpenSSL 输出为 "ALPN, server accepted to use h2"
        if [ -z "$alpn_proto" ]; then
            alpn_proto=$(echo "$alpn_line" | grep -Eo "h2|http/1\.1|spdy" | head -n1)
        fi
        [ -n "$alpn_proto" ] && echo "  ALPN: $alpn_proto"

        # 证书信息（如有）
        if echo "$full_ssl" | grep -q "BEGIN CERTIFICATE"; then
            local subject_line=$(echo "$full_ssl" | grep -E "subject=" | head -n1)
            local issuer_line=$(echo "$full_ssl" | grep -E "issuer=" | head -n1)
            local not_before=$(echo "$full_ssl" | grep -E "notBefore=" | head -n1 | sed 's/.*notBefore=//')
            local not_after=$(echo "$full_ssl" | grep -E "notAfter=" | head -n1 | sed 's/.*notAfter=//')
            # 提取 CN
            local cert_cn=$(echo "$subject_line" | grep -Eo "CN=[^,]+" | sed 's/CN=//')
            [ -n "$cert_cn" ] && echo "  证书主题: subject=CN=$cert_cn"
            [ -n "$issuer_line" ] && echo "  证书颁发者: ${issuer_line}"
            if [ -n "$not_before" ] || [ -n "$not_after" ]; then
                echo "  证书有效期:"
                [ -n "$not_before" ] && echo "    notBefore=$not_before"
                [ -n "$not_after" ] && echo "    notAfter=$not_after"
            fi
        fi
    fi
}

# 改进的TLS检测函数
check_tls_service() {
    local port=$1

    debug_echo "端口 $port: 开始详细TLS检测"

    local detection_method=""
    local tls_detected=false
    local has_certificate=false

    # 方法1: 基本的openssl连接测试
    debug_echo "端口 $port: 方法1 - 基本openssl连接测试"
    local basic_ssl=""
    if $HAS_OPENSSL; then
        # 依次尝试：无SNI、SNI_HOST（如提供）、SNI=IP（兼容旧行为），使用完整输出以便解析协议版本
        basic_ssl=$(echo "Q" | timeout 4 openssl s_client -connect $IP:$port 2>&1)
        if ! echo "$basic_ssl" | grep -Eq "Protocol\s*:|Cipher\s*:" && [ -n "$SNI_HOST" ]; then
            basic_ssl=$(echo "Q" | timeout 4 openssl s_client -connect $IP:$port -servername "$SNI_HOST" 2>&1)
        fi
        if ! echo "$basic_ssl" | grep -Eq "Protocol\s*:|Cipher\s*:"; then
            basic_ssl=$(echo "Q" | timeout 4 openssl s_client -connect $IP:$port -servername "$IP" 2>&1)
        fi
    fi

    # 判断握手是否成功：同时存在 Protocol 与 Cipher 行，且无致命失败提示
    local has_proto=$(echo "$basic_ssl" | grep -E "Protocol\s*:" -c)
    local has_cipher=$(echo "$basic_ssl" | grep -E "Cipher\s*:" -c)
    local has_failure=$(echo "$basic_ssl" | grep -E "handshake failure|SSL alert|no shared cipher|no peer certificate" -c)

    if [ "$has_proto" -ge 1 ] && [ "$has_cipher" -ge 1 ] && [ "$has_failure" -eq 0 ]; then
        tls_detected=true
        # 解析 TLS 版本
        local tls_ver_line=$(echo "$basic_ssl" | grep -E "Protocol\s*:" | head -n1)
        local tls_ver=$(echo "$tls_ver_line" | awk -F':' '{gsub(/ /,""); print $2}')
        if [ -z "$tls_ver" ]; then
            tls_ver=$(echo "$basic_ssl" | grep -Eo "TLSv[0-9\.]+" | head -n1)
        fi
        detection_method=${tls_ver:+"openssl-$tls_ver"}
        debug_echo "端口 $port: openssl连接成功"

        if echo "$basic_ssl" | grep -q "BEGIN CERTIFICATE"; then
            has_certificate=true
            detection_method=${detection_method:-"openssl-conn"}
            debug_echo "端口 $port: 检测到有效TLS证书"
        else
            debug_echo "端口 $port: openssl连接成功但无证书"
        fi
    else
        debug_echo "端口 $port: openssl连接失败"
    fi

    # 方法2: 尝试不同的TLS版本
    if [ "$tls_detected" = false ]; then
        debug_echo "端口 $port: 方法2 - 尝试特定TLS版本"
        for tls_version in tls1_3 tls1_2 tls1_1 tls1; do
            local tls_test=""
            if $HAS_OPENSSL; then
                tls_test=$(echo "Q" | timeout 4 openssl s_client -connect $IP:$port -$tls_version 2>&1)
                if ! echo "$tls_test" | grep -q "CONNECTED" && [ -n "$SNI_HOST" ]; then
                    tls_test=$(echo "Q" | timeout 4 openssl s_client -connect $IP:$port -$tls_version -servername "$SNI_HOST" 2>&1)
                fi
                if ! echo "$tls_test" | grep -q "CONNECTED"; then
                    tls_test=$(echo "Q" | timeout 4 openssl s_client -connect $IP:$port -$tls_version -servername "$IP" 2>&1)
                fi
            fi
            local t_has_proto=$(echo "$tls_test" | grep -E "Protocol\s*:" -c)
            local t_has_cipher=$(echo "$tls_test" | grep -E "Cipher\s*:" -c)
            local t_has_failure=$(echo "$tls_test" | grep -E "handshake failure|SSL alert|no shared cipher|no peer certificate" -c)
            if [ "$t_has_proto" -ge 1 ] && [ "$t_has_cipher" -ge 1 ] && [ "$t_has_failure" -eq 0 ]; then
                tls_detected=true
                detection_method="openssl-$tls_version"
                debug_echo "端口 $port: 通过$tls_version检测到TLS"
                break
            fi
        done
    fi

    # 返回检测结果
    if [ "$tls_detected" = true ]; then
        if [ "$has_certificate" = true ]; then
            echo "TLS_with_cert:$detection_method"
        else
            echo "TLS_no_cert:$detection_method"
        fi
    else
        echo "NOT_TLS"
    fi
}

# 单个端口扫描函数（不使用临时文件）
scan_single_port() {
    local port=$1
    local output_file="$TEMP_DIR/result_$port"
    local tmp_file="$TEMP_DIR/.tmp_$port"

    debug_echo "开始扫描端口 $port"

    # 优先使用 curl（最快）尝试 HTTP/HTTPS 探测
    local detected_service=""
    local detection_method=""
    local service_info=""

    if $HAS_CURL; then
        debug_echo "端口 $port: 尝试 HTTP 探测 (curl)"
        local http_url="http://$IP:$port"
        local http_response=""
        if [ -n "$SNI_HOST" ]; then
            http_url="http://$SNI_HOST:$port"
            http_response=$(timeout 3 curl -s -I --connect-timeout 1 --max-time 2 -H "Host: $SNI_HOST" "http://$IP:$port" 2>/dev/null)
        else
            http_response=$(timeout 3 curl -s -I --connect-timeout 1 --max-time 2 "$http_url" 2>/dev/null)
        fi
        if echo "$http_response" | grep -q "^HTTP/"; then
            detected_service="HTTP"
            detection_method="curl-HTTP"
            service_info=$(echo "$http_response" | head -n1)
        fi
    fi

    if [ -z "$detected_service" ] && $HAS_CURL; then
        debug_echo "端口 $port: 尝试 HTTPS 探测 (curl -k)"
        local https_url="https://$IP:$port"
        local https_response=""
        if [ -n "$SNI_HOST" ]; then
            https_url="https://$SNI_HOST:$port"
            https_response=$(timeout 3 curl -k -s -I --connect-timeout 1 --max-time 2 --resolve "$SNI_HOST:$port:$IP" "$https_url" 2>/dev/null)
        else
            https_response=$(timeout 3 curl -k -s -I --connect-timeout 1 --max-time 2 "$https_url" 2>/dev/null)
        fi
        if echo "$https_response" | grep -q "^HTTP/"; then
            detected_service="HTTPS"
            detection_method="curl-HTTPS"
            service_info=$(echo "$https_response" | head -n1)
        fi
    fi

    # 若已通过 curl 识别到服务，直接输出并返回，避免后续慢操作
    if [ -n "$detected_service" ]; then
        {
            echo "端口 $port: $detected_service 服务检测到 (方法: $detection_method)"
            [ -n "$service_info" ] && echo "  服务信息: $service_info"
            if [[ "$detected_service" == "HTTPS" ]]; then
                $HAS_OPENSSL && check_https_service $port "$detection_method"
            fi
            echo "----------------------------------------------"
        } > "$tmp_file" && mv "$tmp_file" "$output_file"
        return 0
    fi

    # 若仍未知，做快速 TCP 连接探测（适配 DNAT 情况）
    if [ -z "$detected_service" ]; then
        debug_echo "端口 $port: 快速 TCP 连接探测 (/dev/tcp)"
        local tcp_ok=false
        if quick_connect "$IP" "$port"; then
            tcp_ok=true
            debug_echo "端口 $port: TCP 可达"
        else
            debug_echo "端口 $port: TCP 不可达（快速探测失败）"
        fi

        # 无论快速探测结果如何，都尝试TLS检测（以适配需要SNI的场景）
        local tls_result=$(check_tls_service $port)
            if echo "$tls_result" | grep -q "TLS_with_cert"; then
                detected_service="TLS-Other"
                detection_method=$(echo "$tls_result" | cut -d: -f2)
            elif echo "$tls_result" | grep -q "TLS_no_cert"; then
                detected_service="TLS-Other"
                detection_method=$(echo "$tls_result" | cut -d: -f2)
            fi

        # 根据探测结果输出并返回
        if [ -n "$detected_service" ]; then
            {
                echo "端口 $port: $detected_service 服务检测到 (方法: $detection_method)"
                [ -n "$service_info" ] && echo "  服务信息: $service_info"
                if [[ "$detected_service" == *"TLS"* ]]; then
                    $HAS_OPENSSL && check_https_service $port "$detection_method"
                fi
                echo "----------------------------------------------"
            } > "$tmp_file" && mv "$tmp_file" "$output_file"
            return 0
        fi

        # 未识别具体服务但 TCP 可达：尝试读取横幅进行粗分类
        if [ "$tcp_ok" = true ]; then
            local banner
            banner=$(read_banner "$IP" "$port")
            if echo "$banner" | grep -q "^SSH-"; then
                {
                    echo "端口 $port: SSH 服务检测到 (横幅)"
                    echo "  Banner: $(echo "$banner" | tr -d '\r' | head -n1)"
                    echo "----------------------------------------------"
                } > "$tmp_file" && mv "$tmp_file" "$output_file"
            elif echo "$banner" | grep -q "HTTP/"; then
                {
                    echo "端口 $port: HTTP 服务检测到 (横幅)"
                    echo "  Banner: $(echo "$banner" | tr -d '\r' | head -n1)"
                    echo "----------------------------------------------"
                } > "$tmp_file" && mv "$tmp_file" "$output_file"
            elif [[ -z "$banner" ]]; then
                {
                    echo "端口 $port: Likely-Encrypted(non-TLS)"
                    echo "  备注: 无明文banner，可能为自定义加密或协议静默"
                    echo "----------------------------------------------"
                } > "$tmp_file" && mv "$tmp_file" "$output_file"
            else
                {
                    echo "端口 $port: 开放端口 (服务未识别)"
                    echo "  原始片段: $(echo "$banner" | tr -d '\r' | head -n1)"
                    echo "----------------------------------------------"
                } > "$tmp_file" && mv "$tmp_file" "$output_file"
            fi
            return 0
        fi
        # 若TCP不可达且无TLS迹象：维持关闭/过滤状态（空文件）
    fi

    # 如果仍未知且允许使用 nmap，则用轻量模式确认端口与服务
    local nmap_result=""
    if [ -z "$detected_service" ] && $USE_NMAP && $HAS_NMAP; then
        debug_echo "端口 $port: 执行 nmap 轻量扫描"
        nmap_result=$(nmap -sT -Pn --version-light -p $port $IP 2>/dev/null | grep "$port/tcp")
    fi

    if [ -n "$nmap_result" ] && echo "$nmap_result" | grep -q "open"; then
        debug_echo "端口 $port: 状态为 open"
        service_info=$(echo "$nmap_result" | sed 's/^[^ ]* *//')
        debug_echo "端口 $port: nmap 服务信息 - $service_info"
        # 检测 HTTP/HTTPS/TLS 关键词
        if [ -z "$detected_service" ] && echo "$nmap_result" | grep -qi "http"; then
            detected_service="HTTP"
            detection_method="nmap服务检测"
        fi
        if [ -z "$detected_service" ] && echo "$nmap_result" | grep -qi "ssl\|https\|tls"; then
            detected_service="HTTPS/TLS"
            detection_method="nmap服务检测"
        fi

        # 尝试 HTTP 请求
        if [ -z "$detected_service" ]; then
            debug_echo "端口 $port: 尝试HTTP请求"
            local http_response=$(timeout 5 curl -s -I "http://$IP:$port" 2>/dev/null)
            local http_exit_code=$?

            if [ $http_exit_code -eq 0 ] && echo "$http_response" | grep -q "HTTP"; then
                detected_service="HTTP"
                detection_method="HTTP请求成功"
                debug_echo "端口 $port: 通过HTTP请求检测到HTTP服务"
            else
                debug_echo "端口 $port: HTTP请求失败或无效响应"
            fi
        fi

        # 尝试 HTTPS 请求（忽略证书验证）
        if [ -z "$detected_service" ]; then
            debug_echo "端口 $port: 尝试HTTPS请求"
            local https_response=$(timeout 5 curl -k -s -I "https://$IP:$port" 2>/dev/null)
            local https_exit_code=$?

            if [ $https_exit_code -eq 0 ] && echo "$https_response" | grep -q "HTTP"; then
                detected_service="HTTPS"
                detection_method="HTTPS请求成功"
                debug_echo "端口 $port: 通过HTTPS请求检测到HTTPS服务"
            else
                debug_echo "端口 $port: HTTPS请求失败或无效响应"
            fi
        fi

        # 如果检测到服务，输出详细信息到文件
        if [ -n "$detected_service" ]; then
            {
                echo "端口 $port: $detected_service 服务检测到 (方法: $detection_method)"
                [ -n "$service_info" ] && echo "  服务信息: $service_info"
                # 如果是TLS/HTTPS，获取详细信息
                if [[ "$detected_service" == *"TLS"* ]] || [[ "$detected_service" == "HTTPS" ]]; then
                    $HAS_OPENSSL && check_https_service $port "$detection_method"
                elif [[ "$detected_service" == "TLS-Other" ]]; then
                    echo "  备注: 检测到加密流量，但未验证为标准TLS服务"
                fi
                echo "----------------------------------------------"
            } > "$tmp_file" && mv "$tmp_file" "$output_file"
        else
            debug_echo "端口 $port: 开放但未识别出具体服务"
            {
                echo "端口 $port: 开放端口 (服务未识别)"
                [ -n "$service_info" ] && echo "  原始信息: $service_info"
                echo "----------------------------------------------"
            } > "$tmp_file" && mv "$tmp_file" "$output_file"
        fi
    else
        debug_echo "端口 $port: 状态为关闭或过滤"
        # 对于关闭的端口，我们不输出任何内容到结果文件
        : > "$output_file"  # 创建空文件标记已完成
    fi
}

# 显示配置信息
echo "扫描配置:"
echo "  目标IP: $IP"
echo "  端口: $PORTS_SPEC_CLEAN"
echo "  调试模式: $DEBUG"
echo "=============================================="

# 导出函数和变量供子进程使用
export -f scan_single_port
export -f check_https_service
export -f check_tls_service
export -f debug_echo
export IP
export DEBUG
export TEMP_DIR
export SNI_HOST

# 使用更安全的并发控制
for port in "${PORT_LIST[@]}"; do
    (scan_single_port $port) &
    # 控制并发数量
    while [[ $(jobs -r -p | wc -l) -ge $MAX_JOBS ]]; do
        wait -n || break
    done
done

# 等待所有后台任务完成
wait

# 收集并排序所有结果
echo "扫描结果:"
for port in "${PORT_LIST[@]}"; do
    result_file="$TEMP_DIR/result_$port"
    if [ -f "$result_file" ] && [ -s "$result_file" ]; then
        cat "$result_file"
    fi
done

echo "=============================================="
echo "扫描完成"
# 解析端口列表/范围为去重排序后的数组
resolve_ports() {
    local spec="$1"
    local parts=()
    local list=()
    # 归一化，移除空格
    spec="${spec// /}"
    IFS=',' read -r -a parts <<< "$spec"
    for token in "${parts[@]}"; do
        [[ -z "$token" ]] && continue
        if [[ "$token" == *"-"* ]]; then
            # 范围解析：a-b 或 b-a
            local a="${token%%-*}"
            local b="${token#*-}"
            if [[ "$a" =~ ^[0-9]+$ ]] && [[ "$b" =~ ^[0-9]+$ ]]; then
                if ((a<1 || a>65535 || b<1 || b>65535)); then
                    debug_echo "忽略越界范围: $token"; continue
                fi
                if ((a<=b)); then
                    for p in $(seq "$a" "$b"); do list+=("$p"); done
                else
                    for p in $(seq "$b" "$a"); do list+=("$p"); done
                fi
            else
                debug_echo "忽略非法范围: $token"
            fi
        elif [[ "$token" =~ ^[0-9]+$ ]]; then
            local p="$token"
            if ((p>=1 && p<=65535)); then
                list+=("$p")
            else
                debug_echo "忽略越界端口: $p"
            fi
        else
            debug_echo "忽略非法端口片段: $token"
        fi
    done
    # 去重排序输出
    if ((${#list[@]})); then
        printf "%s\n" "${list[@]}" | sort -n -u | tr '\n' ' '
    else
        echo ""
    fi
}

# 生成端口数组（用 read 方式更稳健地填充数组）
PORTS_STR=$(resolve_ports "$PORTS_SPEC")
read -r -a PORT_LIST <<< "$PORTS_STR"
if [ ${#PORT_LIST[@]} -eq 0 ]; then
    echo "错误: 端口列表为空或不合法: $PORTS_SPEC" >&2
    exit 1
fi
debug_echo "解析端口: $PORTS_SPEC -> ${PORT_LIST[*]}"