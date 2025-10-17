## 主要功能

1. IP/端口白名单/黑名单
2. 管理端口转发
3. 开放/阻止ICMP

## 快速安装

使用一键安装脚本（需要 bash、curl、systemd 环境）：

```
curl -fsSL https://github.com/PandaRyshan/soscripts/raw/refs/heads/main/setup.sh | bash
```

该命令会：
- 下载 `scripts/` 下的脚本到 `~/.local/scripts/` 并赋予执行权限
- 在 `/usr/local/bin/` 创建软链接（去掉 `.sh` 后缀作为命令名）
- 下载并安装 `services/` 下的 systemd 单元，刷新并启用开机自启

安装完成后，可直接使用以下命令（示例）：
- `nft-mgmt`（对应 `nft-mgmt.sh`）
- `scan-tls-port`（对应 `scan-tls-port.sh`）
- `conn-monitor`（对应 `conn-monitor.sh`）
