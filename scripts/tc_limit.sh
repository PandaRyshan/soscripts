#!/bin/bash

# =====================================================
# CLI 带宽限速工具 (基于 tc)
# 用法:
#   tc_limit --on [速度]    开启限速，速度单位: mbit (默认150)
#   tc_limit --off          关闭限速
#   tc_limit --status       查看当前限速状态
# =====================================================

# --- 配置区（可自定义） ---
INTERFACE=$(ip route show default | awk '{print $5}' | head -n1)  # 自动检测默认网卡
DEFAULT_SPEED=150
UNIT="mbit"                  # 单位: kbit, mbit, gbit
# --- 配置结束 ---

# 颜色输出（便于阅读）
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 函数: 显示帮助信息
show_help() {
    cat << EOF
用法: $0 [OPTION]

选项:
  --on [速度]     开启限速。速度单位为 ${UNIT}，默认 ${DEFAULT_SPEED}${UNIT}
  --off           关闭限速（删除所有 tc 规则）
  --status        查看当前限速状态
  -h, --help      显示此帮助信息

示例:
  $0 --on           # 限速为 ${DEFAULT_SPEED}${UNIT}
  $0 --on 200       # 限速为 200${UNIT}
  $0 --off          # 取消限速
  $0 --status       # 查看当前配置

注意: 需要 root 权限运行。
EOF
}

# 函数: 检查是否为 root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}错误: 此命令需要 root 权限，请使用 sudo 运行${NC}"
        exit 1
    fi
}

# 函数: 检查 tc 命令是否存在
check_tc() {
    if ! command -v tc &> /dev/null; then
        echo -e "${RED}错误: 未找到 tc 命令，请安装 iproute2 包${NC}"
        exit 1
    fi
}

# 函数: 获取当前限速值（如果有）
get_current_limit() {
    # 使用更宽松的正则，匹配 rate 后面的数值
    local rate=$(tc class show dev $INTERFACE 2>/dev/null | grep -oE 'rate [0-9.]+[KkMmGg]bit' | head -n1 | awk '{print $2}')
    if [[ -n "$rate" ]]; then
        echo "$rate"
    else
        echo "无"
    fi
}

# 函数: 开启限速
turn_on() {
    local speed=$1

    # 验证速度是否为数字
    if ! [[ "$speed" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}错误: 速度必须是正整数，例如 170${NC}"
        exit 1
    fi

    local limit="${speed}${UNIT}"

    echo -e "${YELLOW}正在为网卡 $INTERFACE 设置限速: $limit${NC}"

    # 1. 清空旧规则
    tc qdisc del dev $INTERFACE root 2>/dev/null

    # 2. 添加根队列 (HTB)，指定 r2q 为 1000 避免 quantum 过大
    #    r2q 值越大，quantum 越小。这里设为 100 是安全值。
    tc qdisc add dev $INTERFACE root handle 1: htb default 10 r2q 100 || {
        echo -e "${RED}错误: 添加根队列失败${NC}"
        exit 1
    }

    # 3. 添加主类，显式指定 quantum 为 1500 字节
    #    quantum 通常设置为 MTU 大小 (1500) 或其倍数
    tc class add dev $INTERFACE parent 1: classid 1:1 htb rate $limit ceil $limit quantum 1500 || {
        echo -e "${RED}错误: 添加主类失败${NC}"
        exit 1
    }

    # 4. 添加默认子类，同样指定 quantum
    tc class add dev $INTERFACE parent 1:1 classid 1:10 htb rate $limit ceil $limit quantum 1500 || {
        echo -e "${RED}错误: 添加子类失败${NC}"
        exit 1
    }

    # 5. 添加过滤器 (匹配所有 IP 流量)
    tc filter add dev $INTERFACE protocol ip parent 1:0 prio 1 u32 match ip dst 0.0.0.0/0 flowid 1:10
    tc filter add dev $INTERFACE protocol ip parent 1:0 prio 1 u32 match ip src 0.0.0.0/0 flowid 1:10

    # 验证是否成功
    local current=$(get_current_limit)
    if [[ "$current" != "无" ]]; then
        echo -e "${GREEN}✓ 限速已生效: ${current} (上限 ${limit})${NC}"
    else
        echo -e "${RED}✗ 限速设置失败，请检查系统日志${NC}"
        echo -e "${YELLOW}调试信息:${NC}"
        tc qdisc show dev $INTERFACE
        tc class show dev $INTERFACE
        exit 1
    fi
}

# 函数: 关闭限速
turn_off() {
    echo -e "${YELLOW}正在关闭 $INTERFACE 上的限速规则...${NC}"
    tc qdisc del dev $INTERFACE root 2>/dev/null

    # 验证是否已清除
    local current=$(get_current_limit)
    if [[ "$current" == "无" ]]; then
        echo -e "${GREEN}✓ 限速已关闭${NC}"
    else
        echo -e "${RED}✗ 关闭失败，请手动检查: tc qdisc show dev $INTERFACE${NC}"
        exit 1
    fi
}

# 函数: 显示状态
show_status() {
    echo -e "${YELLOW}=== 网卡: $INTERFACE ===${NC}"

    # 显示队列规则
    echo -e "\n${YELLOW}队列规则:${NC}"
    tc qdisc show dev $INTERFACE

    # 显示类详情（包含实际速率）
    echo -e "\n${YELLOW}限速类详情:${NC}"
    tc class show dev $INTERFACE | grep -E "class htb|rate|ceil" || echo "  无限速类"

    # 显示实时流量统计
    echo -e "\n${YELLOW}实时统计 (按 Ctrl+C 退出):${NC}"
    echo -e "  可以使用以下命令查看实时数据:"
    echo -e "  watch -n 1 'tc -s class show dev $INTERFACE'"
}

# ============= 主入口 =============

# 参数解析
if [[ $# -eq 0 ]]; then
    show_help
    exit 0
fi

check_tc

case "$1" in
    --on)
        check_root
        # 如果提供了第二个参数，则使用它，否则使用默认值
        if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
            turn_on "$2"
        else
            turn_on "$DEFAULT_SPEED"
        fi
        ;;
    --off)
        check_root
        turn_off
        ;;
    --status)
        check_root  # status 也需要读 tc 配置
        show_status
        ;;
    -h|--help)
        show_help
        ;;
    *)
        echo -e "${RED}未知参数: $1${NC}"
        show_help
        exit 1
        ;;
esac

exit 0
