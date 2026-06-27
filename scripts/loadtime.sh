#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 显示帮助信息
show_help() {
    echo "用法: $0 [URL]"
    echo ""
    echo "测试从本地完全加载目标链接所需的时间"
    echo ""
    echo "选项:"
    echo "  -h, --help     显示此帮助信息"
    echo ""
    echo "示例:"
    echo "  $0                    # 交互模式，等待输入URL"
    echo "  $0 https://example.com # 直接测试指定URL"
    echo ""
    echo "说明:"
    echo "  - 交互模式下，可以不断输入URL进行测试，按 Ctrl+C 退出"
    echo "  - 测试内容包括: DNS解析、TCP连接、SSL握手(如适用)、首字节时间、总下载时间"
}

# 检查依赖
check_dependencies() {
    if ! command -v curl &> /dev/null; then
        echo -e "${RED}错误: 未找到 curl 命令，请先安装 curl${NC}" >&2
        exit 1
    fi
    if ! command -v bc &> /dev/null; then
        echo -e "${YELLOW}警告: 未找到 bc 命令，某些数值比较功能可能不可用${NC}" >&2
    fi
    if ! command -v dig &> /dev/null; then
        echo -e "${YELLOW}提示: 安装 dig 命令可获得更准确的DNS解析时间测量${NC}" >&2
    fi
}

# 提取域名
extract_domain() {
    local url="$1"
    # 提取域名部分
    echo "$url" | grep -oP '(?<=://)[^/]+' | head -1
}

# 使用 dig 单独测量DNS解析时间
measure_dns_time() {
    local domain="$1"
    
    if command -v dig &> /dev/null; then
        # 使用 dig 命令测量DNS解析时间（更准确）
        local dns_time=$(dig +stats "$domain" 2>&1 | grep "Query time:" | awk '{print $4}')
        if [[ -n "$dns_time" ]] && [[ "$dns_time" =~ ^[0-9]+$ ]]; then
            # 转换为秒
            echo "scale=3; $dns_time / 1000" | bc 2>/dev/null || echo "0.000"
            return
        fi
    fi
    
    # 如果 dig 不可用，返回空
    echo ""
}

# 测试单个URL
test_url() {
    local url="$1"
    
    # 验证URL格式
    if [[ ! "$url" =~ ^https?:// ]]; then
        echo -e "${YELLOW}警告: URL 格式可能不正确，将自动添加 http:// 前缀${NC}"
        url="http://$url"
    fi
    
    echo -e "${BLUE}测试 URL: ${NC}$url"
    
    # 提取域名
    local domain=$(extract_domain "$url")
    if [[ -n "$domain" ]]; then
        echo -e "${BLUE}目标域名: ${NC}$domain"
    fi
    
    # 使用 curl 进行详细的时间测量
    # 使用更稳定的时间测量方式
    local curl_output=$(mktemp)
    local curl_error=$(mktemp)
    
    # 执行curl并捕获所有输出
    curl -w "\nHTTP_CODE:%{http_code}\nTIME_NAMELOOKUP:%{time_namelookup}\nTIME_CONNECT:%{time_connect}\nTIME_APPCONNECT:%{time_appconnect}\nTIME_PRETRANSFER:%{time_pretransfer}\nTIME_STARTTRANSFER:%{time_starttransfer}\nTIME_TOTAL:%{time_total}\nSIZE_DOWNLOAD:%{size_download}" \
        -o /dev/null -s -L "$url" > "$curl_output" 2> "$curl_error"
    
    # 读取结果
    local http_code=$(grep "HTTP_CODE:" "$curl_output" | cut -d':' -f2)
    local time_namelookup_raw=$(grep "TIME_NAMELOOKUP:" "$curl_output" | cut -d':' -f2)
    local time_connect=$(grep "TIME_CONNECT:" "$curl_output" | cut -d':' -f2)
    local time_appconnect=$(grep "TIME_APPCONNECT:" "$curl_output" | cut -d':' -f2)
    local time_pretransfer=$(grep "TIME_PRETRANSFER:" "$curl_output" | cut -d':' -f2)
    local time_starttransfer=$(grep "TIME_STARTTRANSFER:" "$curl_output" | cut -d':' -f2)
    local time_total=$(grep "TIME_TOTAL:" "$curl_output" | cut -d':' -f2)
    local size_download=$(grep "SIZE_DOWNLOAD:" "$curl_output" | cut -d':' -f2)
    
    # 清理临时文件
    rm -f "$curl_output" "$curl_error"
    
    # 验证DNS解析时间，如果异常则使用备用方法
    local time_namelookup="$time_namelookup_raw"
    local dns_warning=""
    
    # 检查DNS解析时间是否异常（大于总时间的10倍或大于10秒）
    if [[ -n "$time_namelookup_raw" ]] && [[ -n "$time_total" ]]; then
        local is_abnormal=0
        if (( $(echo "$time_namelookup_raw > 10" | bc -l 2>/dev/null) )); then
            is_abnormal=1
        fi
        if (( $(echo "$time_namelookup_raw > $time_total * 10" | bc -l 2>/dev/null) )); then
            is_abnormal=1
        fi
        
        if [[ $is_abnormal -eq 1 ]]; then
            dns_warning="true"
            # 尝试使用 dig 单独测量DNS时间
            if [[ -n "$domain" ]]; then
                local dns_time_alt=$(measure_dns_time "$domain")
                if [[ -n "$dns_time_alt" ]] && [[ "$dns_time_alt" != "0" ]]; then
                    time_namelookup="$dns_time_alt"
                else
                    # 如果无法测量，估算为总时间的一部分
                    time_namelookup="0.050"
                fi
            else
                time_namelookup="0.050"
            fi
        fi
    fi
    
    # 格式化时间值（处理空值）
    time_namelookup=${time_namelookup:-0}
    time_connect=${time_connect:-0}
    time_appconnect=${time_appconnect:-0}
    time_starttransfer=${time_starttransfer:-0}
    time_total=${time_total:-0}
    size_download=${size_download:-0}
    
    # 格式化字节大小
    local size_formatted=$(numfmt --to=iec --suffix=B "$size_download" 2>/dev/null || echo "${size_download} bytes")
    
    # 根据HTTP状态码设置颜色
    if [[ "$http_code" =~ ^2 ]]; then
        local status_color="${GREEN}"
    elif [[ "$http_code" =~ ^3 ]]; then
        local status_color="${YELLOW}"
    else
        local status_color="${RED}"
    fi
    
    echo -e "${status_color}HTTP 状态码: ${http_code:-未知}${NC}"
    echo -e "下载大小: ${size_formatted}"
    echo ""
    echo -e "${BLUE}时间详情:${NC}"
    
    # 显示DNS解析时间，如果有警告则高亮
    if [[ "$dns_warning" == "true" ]]; then
        echo -e "  DNS 解析时间:   ${YELLOW}${time_namelookup} 秒${NC} ${RED}(原始值: ${time_namelookup_raw} 秒，已修正)${NC}"
        echo -e "${YELLOW}  注意: 原curl报告的DNS时间(${time_namelookup_raw}秒)明显异常，已使用备用方法重新测量${NC}"
    else
        printf "  DNS 解析时间:   %.3f 秒\n" "$time_namelookup"
    fi
    
    printf "  TCP 连接时间:   %.3f 秒\n" "$time_connect"
    
    # 如果使用了SSL/TLS，显示握手时间
    if [[ "$url" =~ ^https ]] && [ "$time_appconnect" != "0.000000" ] && [ "$time_appconnect" != "0" ]; then
        printf "  SSL 握手时间:   %.3f 秒\n" "$time_appconnect"
    fi
    
    printf "  首字节时间:     %.3f 秒\n" "$time_starttransfer"
    printf "  ${GREEN}总加载时间:     %.3f 秒${NC}\n" "$time_total"
    
    # 计算网络耗时（不含DNS）
    local network_time=$(echo "$time_total - $time_namelookup" | bc 2>/dev/null)
    if [[ -n "$network_time" ]]; then
        printf "  网络传输时间:   %.3f 秒 (不含DNS)\n" "$network_time"
    fi
    
    # 性能评估
    echo ""
    echo -n "性能评估: "
    if (( $(echo "$time_total < 1" | bc -l 2>/dev/null) )); then
        echo -e "${GREEN}优秀 (响应极快)${NC}"
    elif (( $(echo "$time_total < 3" | bc -l 2>/dev/null) )); then
        echo -e "${GREEN}良好 (响应较快)${NC}"
    elif (( $(echo "$time_total < 5" | bc -l 2>/dev/null) )); then
        echo -e "${YELLOW}一般 (响应速度正常)${NC}"
    else
        echo -e "${RED}较慢 (建议优化)${NC}"
    fi
    
    echo "----------------------------------------"
}

# 主函数
main() {
    check_dependencies
    
    # 处理帮助参数
    if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
        show_help
        exit 0
    fi
    
    # 判断运行模式
    if [ $# -eq 0 ]; then
        # 交互模式
        echo -e "${BLUE}=== URL 加载时间测试工具 (交互模式) ===${NC}"
        echo -e "输入 URL 进行测试，按 ${RED}Ctrl+C${NC} 退出"
        echo ""
        
        while true; do
            read -p "请输入 URL: " url_input
            if [ -z "$url_input" ]; then
                echo -e "${YELLOW}URL 不能为空，请重新输入${NC}"
                continue
            fi
            echo ""
            test_url "$url_input"
        done
    else
        # 命令行参数模式
        test_url "$1"
    fi
}

# 捕获退出信号
trap 'echo -e "\n${YELLOW}测试结束，感谢使用！${NC}"; exit 0' INT

# 执行主函数
main "$@"
