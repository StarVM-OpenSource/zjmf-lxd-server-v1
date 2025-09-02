
#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
    log_error "请使用root权限运行此脚本"
    exit 1
fi

if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [ "$ID" != "ubuntu" ] && [ "$ID" != "debian" ]; then
        log_error "不支持的系统类型：$ID，仅支持Ubuntu和Debian系统"
        exit 1
    fi
else
    log_error "无法检测系统类型，仅支持Ubuntu和Debian系统"
    exit 1
fi

arch=$(uname -m)
if [ "$arch" != "x86_64" ] && [ "$arch" != "aarch64" ] && [ "$arch" != "arm64" ]; then
    log_error "不支持的CPU架构：$arch，仅支持amd64和arm64架构"
    exit 1
fi

apt update -y
apt install -y snapd
systemctl enable --now snapd
snap install lxd

echo
log_info "LXD安装完成"
log_error "只能手动初始化，初始化储存Ubuntu选择zfs/Debian选择btrfs 然后硬盘大小自行设置，请运行以下命令："
echo -e "${YELLOW}lxd init${NC}"
echo
