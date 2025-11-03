#!/bin/bash

# 检查是否为 root 用户
if [[ $EUID -ne 0 ]]; then
    echo "错误：此脚本必须以 root 权限运行。" >&2
    exit 1
fi

# 显示菜单
echo "====================================="
echo "       交换文件管理脚本"
echo "====================================="
echo "1. 创建交换文件"
echo "2. 删除交换文件"
echo "====================================="
read -p "请选择操作 (1 或 2): " OPTION

case $OPTION in
    1)
        # 创建交换文件功能
        # 检测根文件系统类型
        FS_TYPE=$(findmnt -n -o FSTYPE /)
        if [[ "$FS_TYPE" != "ext4" && "$FS_TYPE" != "btrfs" ]]; then
            echo "错误：当前根目录文件系统类型为 $FS_TYPE，本脚本仅支持 ext4 和 btrfs。" >&2
            exit 1
        fi

        # 检查是否已存在交换文件
        if [[ -f /swapfile ]]; then
            echo "警告：/swapfile 已存在。"
            read -p "是否要覆盖？(y/N): " OVERWRITE
            if [[ ! $OVERWRITE =~ ^[Yy]$ ]]; then
                echo "操作已取消。"
                exit 0
            fi

            # 禁用现有交换文件
            if swapon --show | grep -q "/swapfile"; then
                swapoff /swapfile
            fi
        fi

        # 询问交换文件大小
        read -p "请输入交换文件大小（例如 512M、1G、1.5G）: " SWAP_SIZE

        # 验证输入格式
        if ! [[ $SWAP_SIZE =~ ^[0-9]+(\.[0-9]+)?[MG]$ ]]; then
            echo "错误：请输入有效的容量大小（如 512M 或 1G）。" >&2
            exit 1
        fi

        # 创建交换文件
        echo "正在创建 ${SWAP_SIZE} 的交换文件..."
        if [[ "$FS_TYPE" == "btrfs" ]]; then
            # Btrfs 需要特殊处理
            truncate -s 0 /swapfile
            chattr +C /swapfile
            btrfs property set /swapfile compression none
            fallocate -l $SWAP_SIZE /swapfile
        else
            # Ext4 标准创建方式
            fallocate -l $SWAP_SIZE /swapfile
        fi

        # 设置权限
        chmod 600 /swapfile

        # 格式化交换文件
        mkswap /swapfile

        # 启用交换文件
        swapon /swapfile

        # 备份 fstab
        cp /etc/fstab /etc/fstab.bak

        # 添加到 fstab
        if ! grep -q "/swapfile" /etc/fstab; then
            echo "/swapfile none swap sw 0 0" >> /etc/fstab
            echo "已将交换文件添加到 /etc/fstab"
        else
            echo "警告：/etc/fstab 中已存在交换文件配置，已更新为新配置。"
            # 删除旧配置并添加新配置
            sed -i '/\/swapfile/d' /etc/fstab
            echo "/swapfile none swap sw 0 0" >> /etc/fstab
        fi

        # 输出结果
        echo "交换文件创建成功！"
        echo "大小：$SWAP_SIZE"
        echo "文件系统类型：$FS_TYPE"
        echo "当前交换空间："
        swapon --show
        ;;

    2)
        # 删除交换文件功能
        if [[ ! -f /swapfile ]]; then
            echo "错误：/swapfile 不存在，无需删除。" >&2
            exit 1
        fi

        echo "正在删除交换文件..."

        # 禁用交换文件
        if swapon --show | grep -q "/swapfile"; then
            swapoff /swapfile
            echo "已禁用交换文件。"
        fi

        # 删除文件
        rm -f /swapfile
        echo "已删除 /swapfile 文件。"

        # 从 fstab 中移除配置
        if grep -q "/swapfile" /etc/fstab; then
            sed -i '/\/swapfile/d' /etc/fstab
            echo "已从 /etc/fstab 中移除交换文件配置。"
        else
            echo "警告：/etc/fstab 中没有找到交换文件配置。"
        fi

        echo "交换文件已成功删除。"
        ;;

    *)
        echo "错误：无效选项。" >&2
        exit 1
        ;;
esac