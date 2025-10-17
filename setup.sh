#!/usr/bin/env bash

set -euo pipefail

# 安装目标
USER_SCRIPTS_DIR="${HOME}/.local/scripts"
BIN_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"

# 远程仓库（raw 文件地址）
BASE_RAW="https://github.com/PandaRyshan/soscripts/raw/refs/heads/main"

# 需要安装的脚本与 systemd 服务文件
SCRIPTS=(
  nft-mgmt.sh
  scan-tls-port.sh
  conn-monitor.sh
)
SERVICES=(
  nftmgmt.service
  conn-monitor.service
)

log() { echo "[setup] $*"; }
err() { echo "[setup][ERROR] $*" >&2; }

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

download_scripts() {
  mkdir -p "$USER_SCRIPTS_DIR"
  for f in "${SCRIPTS[@]}"; do
    local src_url="${BASE_RAW}/scripts/${f}"
    local dst_path="${USER_SCRIPTS_DIR}/${f}"
    log "下载脚本: ${src_url} -> ${dst_path}"
    curl -fsSL "$src_url" -o "$dst_path"
    chmod +x "$dst_path"
    local name_no_ext="${f%.sh}"
    log "创建可执行链接: ${BIN_DIR}/${name_no_ext} -> ${dst_path}"
    $SUDO_CMD ln -sf "$dst_path" "${BIN_DIR}/${name_no_ext}"
  done
}

install_services() {
  require_root_or_sudo
  for unit in "${SERVICES[@]}"; do
    local src_url="${BASE_RAW}/services/${unit}"
    local dst_path="${SYSTEMD_DIR}/${unit}"
    log "下载 systemd 单元: ${src_url} -> ${dst_path}"
    $SUDO_CMD curl -fsSL "$src_url" -o "$dst_path"
  done
  log "刷新 systemd 单元缓存"
  $SUDO_CMD systemctl daemon-reload || true
  for unit in "${SERVICES[@]}"; do
    log "启用开机自启: ${unit}"
    $SUDO_CMD systemctl enable "$unit" || true
  done
}

main() {
  require_root_or_sudo
  download_scripts
  install_services
  log "完成安装。你可以运行: nft-mgmt --help 或相关脚本命令。"
}

main "$@"