#!/usr/bin/env bash
# nft-mgmt-test.sh — nft-mgmt masquerade 持久化的端到端测试
#
# 在私有 netns 中运行（unshare -rmn），并把 tmpfs 挂到 /etc 作为覆盖层，
# 因此既不会改动宿主机的 nftables 规则，也不会碰宿主机的 /etc/nftables.d。
#
# 用法:
#   bash scripts/tests/nft-mgmt-test.sh
#
# 环境变量:
#   SCRIPT_UNDER_TEST   被测脚本路径，默认 <repo>/scripts/nft-mgmt.sh
#
# 退出码: 全部通过 0；任一断言失败非 0。

set -uo pipefail

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SELF_PATH="$SELF_DIR/$(basename "${BASH_SOURCE[0]}")"
REPO_ROOT=$(cd "$SELF_DIR/../.." && pwd)
SCRIPT_UNDER_TEST="${SCRIPT_UNDER_TEST:-$REPO_ROOT/scripts/nft-mgmt.sh}"

# ---------- 自举：进入私有 netns ----------
if [[ "${NFT_MGMT_TEST_IN_NETNS:-}" != "1" ]]; then
    for dep in nft unshare ip mktemp awk; do
        command -v "$dep" >/dev/null 2>&1 || { echo "[test][ERROR] 缺少依赖: $dep" >&2; exit 1; }
    done
    [[ -f "$SCRIPT_UNDER_TEST" ]] || { echo "[test][ERROR] 被测脚本不存在: $SCRIPT_UNDER_TEST" >&2; exit 1; }
    if ! unshare -rmn --propagation private true 2>/dev/null; then
        echo "[test][ERROR] 无法创建 unprivileged user+net namespace。" >&2
        echo "[test][ERROR] 请确认内核与发行版未禁用用户命名空间；本测试不会降级为直接操作宿主机。" >&2
        exit 1
    fi
    exec unshare -rmn --propagation private env \
        NFT_MGMT_TEST_IN_NETNS=1 SCRIPT_UNDER_TEST="$SCRIPT_UNDER_TEST" \
        bash "$SELF_PATH" "$@"
fi

# ---------- 隔离环境准备 ----------
CONF_DIR="/etc/nftables.d"
MASQ_REG="$CONF_DIR/masquerade.csv"
FORWARD_REG="$CONF_DIR/forward.csv"
CONF_FILE="$CONF_DIR/nftrules.nft"

if ! mount -t tmpfs tmpfs /etc; then
    echo "[test][ERROR] 无法在 /etc 挂载 tmpfs 覆盖层" >&2
    exit 1
fi
mkdir -p "$CONF_DIR"
for iface in dummy0 eth0; do
    ip link add "$iface" type dummy 2>/dev/null && ip link set "$iface" up || {
        echo "[test][ERROR] 创建测试接口失败: $iface" >&2; exit 1; }
done

echo "[test] 被测脚本: $SCRIPT_UNDER_TEST"
echo "[test] 运行环境: 私有 netns, uid=$(id -u), 接口: $(ip -o link show | awk -F': ' '{print $2}' | tr '\n' ' ')"

# ---------- 断言工具 ----------
PASS=0
FAIL=0
FAILED=()

ok()   { printf '  ok   %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  FAIL %s\n       期望: %s\n       实际: %s\n' "$1" "$2" "$3"; FAIL=$((FAIL + 1)); FAILED+=("$1"); }

check_eq()       { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "$2" "$3"; fi; }
check_contains() { if [[ "$3" == *"$2"* ]]; then ok "$1"; else bad "$1" "包含 $2" "$3"; fi; }

# ---------- 被测对象与查询工具 ----------
nf() { bash "$SCRIPT_UNDER_TEST" "$@"; }

reset_state() {
    # 保证 ip nat 表存在，使各场景与执行顺序无关
    if ! nft list chain ip nat POSTROUTING >/dev/null 2>&1; then
        nft add table ip nat
        nft add chain ip nat POSTROUTING '{ type nat hook postrouting priority 100; }'
    fi
    nft flush chain ip nat POSTROUTING >/dev/null 2>&1 || true
    rm -f "$CONF_FILE" "$MASQ_REG" "$FORWARD_REG" 2>/dev/null || true
    # 与 systemd 单元一致：先 init 建结构，使 save 具备可保存的 inet filter 表
    nf init >/dev/null 2>&1 || true
}

registry_content() {
    [[ -f "$MASQ_REG" ]] || return 0
    awk 'NF { print $1 }' "$MASQ_REG" | sort | tr '\n' ' ' | sed 's/ *$//'
}

count_iface_rules() {
    nft -a list chain ip nat POSTROUTING 2>/dev/null | \
        awk -v pat="oifname \"$1\"" '/masquerade/ && index($0, pat) > 0 { c++ } END { print c + 0 }'
}

count_exclusion_rules() {
    nft -a list chain ip nat POSTROUTING 2>/dev/null | \
        awk '/masquerade/ && /!=/ { c++ } END { print c + 0 }'
}

masq_status_text() {
    nf status 2>/dev/null | awk '/^masquerade:/ { getline; gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0); print; exit }'
}

# ---------- 场景 1: save/load 往返 ----------
echo
echo "== 场景 1: save/load 往返 =="
reset_state
nf pfm on dummy0 >/dev/null 2>&1
nf save >/dev/null 2>&1
check_eq "save 后注册表记录 dummy0" "dummy0" "$(registry_content)"
nft flush chain ip nat POSTROUTING >/dev/null 2>&1 || true
check_eq "清空 POSTROUTING 后规则数为 0（模拟重启）" "0" "$(count_iface_rules dummy0)"
nf load >/dev/null 2>&1
check_eq "load 后 dummy0 规则恢复为 1 条" "1" "$(count_iface_rules dummy0)"

# ---------- 场景 2: 排除 Docker 风格规则 ----------
echo
echo "== 场景 2: 排除 Docker 风格规则 =="
reset_state
nft add rule ip nat POSTROUTING ip saddr 172.17.0.0/16 oifname != "docker0" masquerade >/dev/null 2>&1
nf pfm on dummy0 >/dev/null 2>&1
nf save >/dev/null 2>&1
check_eq "注册表仅记录脚本启用的 dummy0" "dummy0" "$(registry_content)"
nf load >/dev/null 2>&1
check_eq "Docker 风格规则在 load 后仍存在且未被复制" "1" "$(count_exclusion_rules)"

# ---------- 场景 3: 幂等 ----------
echo
echo "== 场景 3: 幂等 =="
reset_state
nf pfm on dummy0 >/dev/null 2>&1
nf pfm on dummy0 >/dev/null 2>&1
check_eq "重复启用后 dummy0 规则数仍为 1" "1" "$(count_iface_rules dummy0)"
check_eq "重复启用后注册表无重复项" "dummy0" "$(registry_content)"

# ---------- 场景 4: 接口不存在的容错 ----------
echo
echo "== 场景 4: 接口不存在的容错 =="
reset_state
printf 'ens9\n' > "$MASQ_REG"
load_out=$(nf load 2>&1)
check_contains "load 输出提示接口不存在" "ens9" "$load_out"
check_eq "未为不存在的接口下发规则" "0" "$(count_iface_rules ens9)"

# ---------- 场景 5: 禁用 ----------
echo
echo "== 场景 5: 禁用 =="
reset_state
nf pfm on dummy0 >/dev/null 2>&1
nf pfm off dummy0 >/dev/null 2>&1
check_eq "禁用后 dummy0 规则数为 0" "0" "$(count_iface_rules dummy0)"
check_eq "禁用后注册表为空" "" "$(registry_content)"

# ---------- 场景 6: 未启用 masquerade 时的 save ----------
echo
echo "== 场景 6: 未启用 masquerade 时的 save =="
reset_state
nf save >/dev/null 2>&1
save_rc=$?
check_eq "无 masquerade 时 save 返回 0" "0" "$save_rc"
if [[ -f "$MASQ_REG" ]]; then ok "save 后注册表文件存在"; else bad "save 后注册表文件存在" "文件存在" "文件缺失"; fi
check_eq "注册表内容为空" "" "$(registry_content)"

# ---------- 场景 7: 默认候选接口路径 ----------
echo
echo "== 场景 7: 默认候选接口路径 =="
reset_state
nf pfm on >/dev/null 2>&1
check_eq "无参数 pfm on 选中默认接口 eth0" "1" "$(count_iface_rules eth0)"
check_eq "注册表记录 eth0" "eth0" "$(registry_content)"
check_eq "status 判定 masquerade 为开启" "开启" "$(masq_status_text)"

reset_state
nf pfm on dummy0 >/dev/null 2>&1
check_eq "仅非默认接口启用时 status 判定为未开启" "未开启" "$(masq_status_text)"

if nf pfm on nosuchiface >/dev/null 2>&1; then
    bad "pfm on 不存在的接口应失败" "非 0 退出码" "0"
else
    ok "pfm on 不存在的接口应失败"
fi
check_eq "未为不存在的接口下发规则" "0" "$(count_iface_rules nosuchiface)"

# ---------- 场景 8: 多接口注册表读写（读全量→过滤→覆盖写不丢其他条目） ----------
echo
echo "== 场景 8: 多接口注册表读写 =="
reset_state
nf pfm on dummy0 >/dev/null 2>&1
nf pfm on eth0 >/dev/null 2>&1
check_eq "两个接口都写入注册表" "dummy0 eth0" "$(registry_content)"
nf pfm off dummy0 >/dev/null 2>&1
check_eq "禁用其一后注册表保留另一个接口" "eth0" "$(registry_content)"
check_eq "禁用其一后另一接口规则仍在" "1" "$(count_iface_rules eth0)"
check_eq "被禁用的接口规则已删除" "0" "$(count_iface_rules dummy0)"
nf save >/dev/null 2>&1
check_eq "save 后注册表仍只含 eth0" "eth0" "$(registry_content)"

# ---------- 汇总 ----------
echo
echo "== 结果: 通过 $PASS, 失败 $FAIL =="
if [[ "$FAIL" -gt 0 ]]; then
    echo "失败项:"
    printf '  - %s\n' "${FAILED[@]}"
    exit 1
fi
exit 0
