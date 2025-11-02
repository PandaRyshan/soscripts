#!/usr/bin/env bash

set -euo pipefail

# 安装目标
SHARE_SCRIPTS_DIR="/usr/share/scripts"
BIN_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"

# 远程仓库（raw 文件地址）
BASE_RAW="https://github.com/PandaRyshan/soscripts/raw/refs/heads/main"

# 需要安装的脚本与 systemd 服务文件
SCRIPTS=(
  nft-mgmt.sh
  conn-monitor.sh
)
SERVICES=(
  nft-mgmt.service
  conn-monitor.service
)

# 依赖包定义
CONN_MONITOR_DEPS=(
  conntrack
  curl
  swaks
)
NFT_MGMT_DEPS=(
  nftables
)
FAIL2BAN_DEPS=(
  fail2ban
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

# 安装依赖包
install_dependencies() {
  require_root_or_sudo
  log "更新软件包列表..."
  $SUDO_CMD apt-get update -y
  
  # 安装通用依赖
  local all_deps=("${CONN_MONITOR_DEPS[@]}" "${NFT_MGMT_DEPS[@]}" "${FAIL2BAN_DEPS[@]}")
  local unique_deps=()
  local seen=()
  
  for dep in "${all_deps[@]}"; do
    if [[ ! " ${seen[@]} " =~ " ${dep} " ]]; then
      unique_deps+=("$dep")
      seen+=("$dep")
    fi
  done
  
  log "安装依赖包: ${unique_deps[*]}"
  $SUDO_CMD apt-get install -y "${unique_deps[@]}"
}

# 下载 fail2ban 配置文件
download_fail2ban_configs() {
  require_root_or_sudo
  log "下载 fail2ban 配置文件..."
  
  # fail2ban 配置目录
  local FAIL2BAN_DIR="/etc/fail2ban"
  local FAIL2BAN_ACTION_DIR="$FAIL2BAN_DIR/action.d"
  local FAIL2BAN_FILTER_DIR="$FAIL2BAN_DIR/filter.d"
  
  # 确保目录存在
  $SUDO_CMD mkdir -p "$FAIL2BAN_ACTION_DIR"
  $SUDO_CMD mkdir -p "$FAIL2BAN_FILTER_DIR"
  
  # 配置文件映射
  local configs=(
    "configs/fail2ban/jail.local:$FAIL2BAN_DIR/jail.local"
    "configs/fail2ban/nft-inet-blacklist.conf:$FAIL2BAN_ACTION_DIR/nft-inet-blacklist.conf"
    "configs/fail2ban/haproxy-docker.conf:$FAIL2BAN_FILTER_DIR/haproxy-docker.conf"
  )
  
  for config_pair in "${configs[@]}"; do
    IFS=':' read -r src_path dst_path <<< "$config_pair"
    local src_url="${BASE_RAW}/${src_path}"
    log "下载配置文件: ${src_url} -> ${dst_path}"
    $SUDO_CMD curl -fsSL "$src_url" -o "$dst_path"
    $SUDO_CMD chmod 644 "$dst_path"
  done
  
  log "fail2ban 配置文件下载完成"
}

# 安装并配置 fail2ban
install_fail2ban() {
  require_root_or_sudo
  log "安装并配置 fail2ban..."
  
  # 检查是否已安装
  if command -v fail2ban-client >/dev/null 2>&1; then
    log "fail2ban 已安装，跳过安装步骤"
  else
    log "安装 fail2ban..."
    $SUDO_CMD apt-get install -y fail2ban
  fi
  
  # 下载配置文件
  download_fail2ban_configs
  
  # 启用并启动 fail2ban 服务
  log "启用并启动 fail2ban 服务..."
  $SUDO_CMD systemctl enable --now fail2ban
  
  # 重启 fail2ban 服务以应用新配置
  log "重启 fail2ban 服务以应用配置..."
  $SUDO_CMD systemctl restart fail2ban
  
  # 检查服务状态
  log "检查 fail2ban 服务状态..."
  $SUDO_CMD systemctl status fail2ban --no-pager -l || true
}

download_scripts() {
  require_root_or_sudo
  # 确保目标目录存在
  $SUDO_CMD mkdir -p "$SHARE_SCRIPTS_DIR"
  $SUDO_CMD mkdir -p "$BIN_DIR"
  
  log "确保脚本目录存在: $SHARE_SCRIPTS_DIR"
  $SUDO_CMD mkdir -p "$SHARE_SCRIPTS_DIR"
  
  for f in "${SCRIPTS[@]}"; do
    local src_url="${BASE_RAW}/scripts/${f}"
    local dst_path="${SHARE_SCRIPTS_DIR}/${f}"
    log "下载脚本: ${src_url} -> ${dst_path}"
    $SUDO_CMD curl -fsSL "$src_url" -o "$dst_path"
    $SUDO_CMD chmod +x "$dst_path"
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
  $SUDO_CMD systemctl daemon-reload
}

enable_and_start_services() {
  require_root_or_sudo
  for unit in "${SERVICES[@]}"; do
    log "启用并启动服务: ${unit}"
    $SUDO_CMD systemctl enable --now "$unit"
    log "检查服务状态: ${unit}"
    $SUDO_CMD systemctl status "$unit" --no-pager -l || true
  done
}

main() {
  require_root_or_sudo
  log "开始安装 soscripts..."
  
  # 安装依赖包
  install_dependencies
  
  # 下载脚本并创建链接
  download_scripts
  
  # 安装systemd服务
  install_services
  
  # 启用并启动服务（nft-mgmt必须先启动）
  enable_and_start_services
  
  # 安装并配置fail2ban（在nft-mgmt之后）
  install_fail2ban
  
  log "安装完成！"
  log "可用的命令:"
  log "  - nft-mgmt: nftables 管理工具"
  log "  - conn-monitor: 连接监控工具"
  log "服务状态:"
  $SUDO_CMD systemctl status nft-mgmt.service conn-monitor.service fail2ban.service --no-pager -l || true
}

main "$@"