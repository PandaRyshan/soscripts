#!/usr/bin/env bash

set -euo pipefail

DEFAULT_RATE=150
DEFAULT_BURST=16
IFB="ifb0"

get_iface() {
    ip route get 1.1.1.1 2>/dev/null | awk '
        {
            for(i=1;i<=NF;i++){
                if($i=="dev"){
                    print $(i+1)
                    exit
                }
            }
        }'
}

IFACE="$(get_iface)"

usage() {
cat <<EOF
tc_limit - Linux ingress/egress bandwidth limiter

Usage:
  tc_limit --on [RATE] [BURST]
  tc_limit --off
  tc_limit --status
  tc_limit -h
  tc_limit --help

Options:

  --on [RATE]
      Enable bandwidth limiting.

      RATE unit: Mbps (default 150Mbps)
      BURST unit: kbit (default 16kbit)

      Example:
          tc_limit --on
          tc_limit --on 150
          tc_limit --on 100

      Default:
          ${DEFAULT_RATE} Mbps
          ${DEFAULT_BURST} kbps

  --off
      Disable all limits.

  --status
      Show current status.

  -h, --help
      Show this help.

Examples:

  tc_limit --on
  tc_limit --on 150
  tc_limit --off
  tc_limit --status

EOF
}

cleanup() {
    tc qdisc del dev "$IFACE" root 2>/dev/null || true
    tc qdisc del dev "$IFACE" ingress 2>/dev/null || true

    tc qdisc del dev "$IFB" root 2>/dev/null || true

    ip link set "$IFB" down 2>/dev/null || true

    echo "[OK] Bandwidth limit disabled"
}

enable_limit() {
    local RATE="$1"
    local BURST="$2"

    echo "[INFO] Interface : $IFACE"
    echo "[INFO] Rate      : ${RATE} Mbps"
    echo "[INFO] BURST     : ${BURST} kbps"

    cleanup >/dev/null 2>&1 || true

    modprobe ifb numifbs=1

    ip link add "$IFB" type ifb 2>/dev/null || true
    ip link set "$IFB" up

    #
    # Egress
    #
    tc qdisc add dev "$IFACE" root handle 1: htb default 10

    tc class add dev "$IFACE" parent 1: classid 1:10 \
        htb rate "${RATE}mbit" ceil "${RATE}mbit" burst "${BURST}kbit" cburst "${BURST}kbit"

    #
    # Ingress -> IFB
    #
    tc qdisc add dev "$IFACE" handle ffff: ingress

    tc filter add dev "$IFACE" parent ffff: \
        protocol all u32 match u32 0 0 \
        action mirred egress redirect dev "$IFB"

    #
    # IFB limit
    #
    tc qdisc add dev "$IFB" root handle 2: htb default 20

    tc class add dev "$IFB" parent 2: classid 2:20 \
        htb rate "${RATE}mbit" ceil "${RATE}mbit" burst "${BURST}kbit" cburst "${BURST}kbit"

    echo
    echo "[OK] Bandwidth limit enabled"
    echo "     Egress : ${RATE} Mbps"
    echo "     Ingress: ${RATE} Mbps"
}

status() {
    echo
    echo "========== Interface =========="
    echo "$IFACE"

    echo
    echo "========== Egress =========="
    tc qdisc show dev "$IFACE" || true

    echo
    echo "========== Ingress(IFB) =========="
    tc qdisc show dev "$IFB" || true

    echo
    echo "========== Statistics =========="
    tc -s class show dev "$IFACE" 2>/dev/null || true

    echo
    tc -s class show dev "$IFB" 2>/dev/null || true
}

main() {

    case "${1:-}" in

        --on)
            RATE="${2:-$DEFAULT_RATE}"
            BURST="${3:-$DEFAULT_BURST}"

            if ! [[ "$RATE" =~ ^[0-9]+$ ]]; then
                echo "Invalid rate: $RATE"
                exit 1
            fi

            if ! [[ "$BURST" =~ ^[0-9]+$ ]]; then
                echo "Invalid burst: $BURST"
                exit 1
            fi

            enable_limit "$RATE" "$BURST"
            ;;

        --off)
            cleanup
            ;;

        --status)
            status
            ;;

        -h|--help)
            usage
            ;;

        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
