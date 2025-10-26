#!/bin/bash

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

NAME="LXD"
FORCE=false
DELETE=false

log() { echo -e "$1"; }
ok() { log "${GREEN}[OK]${NC} $1"; }
info() { log "${BLUE}[INFO]${NC} $1"; }
warn() { log "${YELLOW}[WARN]${NC} $1"; }
err() { log "${RED}[ERR]${NC} $1"; exit 1; }

[[ $EUID -ne 0 ]] && err "请使用 root 运行"

while [[ $# -gt 0 ]]; do
  case $1 in
    -f|--force) FORCE=true; shift;;
    -d|--delete) DELETE=true; shift;;
    -h|--help)
      echo "========================================"
      echo "        LXD 安装脚本"
      echo "========================================"
      echo
      echo "用法: $0 [选项]"
      echo
      echo "选项:"
      echo "  -f, --force    强制重新安装（即使已安装 LXD）"
      echo "  -d, --delete   卸载 LXD 及所有数据"
      echo "  -h, --help     显示此帮助信息"
      echo
      echo "示例:"
      echo "  $0              # 安装 LXD"
      echo "  $0 -f           # 强制重新安装"
      echo "  $0 -d           # 卸载 LXD"
      echo
      echo "详细教程: https://github.com/xkatld/zjmf-lxd-server/wiki"
      exit 0;;
    *) err "未知参数: $1 (使用 -h 查看帮助)";;
  esac
done

if [[ $DELETE == true ]]; then
  echo
  echo "========================================"
  echo "          卸载 LXD"
  echo "========================================"
  echo
  
  warn "此操作将完全卸载 LXD 及其所有数据！"
  echo
  
  # 检测已安装的 LXD
  FOUND_LXD=false
  
  if [[ -f /snap/bin/lxd || -f /snap/bin/lxc || -f /var/lib/snapd/snap/bin/lxd || -f /var/lib/snapd/snap/bin/lxc ]]; then
    echo "  - 检测到 Snap 安装的 LXD"
    FOUND_LXD=true
  fi
  
  if [[ -f /usr/bin/lxd || -f /usr/bin/lxc ]]; then
    echo "  - 检测到 APT/DEB 安装的 LXD"
    FOUND_LXD=true
  fi
  
  if [[ -f /usr/local/bin/lxd || -f /usr/local/bin/lxc ]]; then
    echo "  - 检测到本地编译的 LXD"
    FOUND_LXD=true
  fi
  
  if [[ $FOUND_LXD == false ]]; then
    warn "未检测到已安装的 LXD"
    exit 0
  fi
  
  echo
  read -p "确定要继续吗? (y/N): " CONFIRM
  if [[ $CONFIRM != "y" && $CONFIRM != "Y" ]]; then
    ok "取消卸载操作"
    exit 0
  fi
  
  echo
  info "停止 LXD 服务..."
  systemctl stop lxd 2>/dev/null || true
  systemctl stop lxd.socket 2>/dev/null || true
  systemctl stop lxd-containers 2>/dev/null || true
  
  # 检测包管理器
  PKG_MANAGER=""
  if command -v apt-get &> /dev/null; then
    PKG_MANAGER="apt"
  elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
  elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
  elif command -v zypper &> /dev/null; then
    PKG_MANAGER="zypper"
  elif command -v pacman &> /dev/null; then
    PKG_MANAGER="pacman"
  fi
  
  # 卸载 Snap LXD
  if [[ -f /snap/bin/lxd || -f /snap/bin/lxc || -f /var/lib/snapd/snap/bin/lxd || -f /var/lib/snapd/snap/bin/lxc ]]; then
    info "卸载 Snap LXD..."
    snap remove lxd 2>/dev/null || warn "Snap LXD 卸载失败"
  fi
  
  # 卸载 APT/DEB LXD
  if [[ -f /usr/bin/lxd || -f /usr/bin/lxc ]]; then
    info "卸载 APT/DEB LXD..."
    case $PKG_MANAGER in
      apt)
        apt-get purge -y lxd lxd-client lxc lxc-utils 2>/dev/null || true
        apt-get autoremove -y 2>/dev/null || true
        ;;
      yum)
        yum remove -y lxd lxc 2>/dev/null || true
        ;;
      dnf)
        dnf remove -y lxd lxc 2>/dev/null || true
        ;;
      zypper)
        zypper remove -y lxd lxc 2>/dev/null || true
        ;;
      pacman)
        pacman -Rns --noconfirm lxd lxc 2>/dev/null || true
        ;;
    esac
  fi
  
  # 删除本地编译的 LXD
  if [[ -f /usr/local/bin/lxd || -f /usr/local/bin/lxc ]]; then
    info "删除本地编译的 LXD..."
    rm -f /usr/local/bin/lxd /usr/local/bin/lxc 2>/dev/null || true
  fi
  
  info "清理 LXD 数据和配置..."
  rm -rf /var/lib/lxd 2>/dev/null || true
  rm -rf /var/log/lxd 2>/dev/null || true
  rm -rf /etc/lxd 2>/dev/null || true
  rm -rf ~/.config/lxc 2>/dev/null || true
  
  info "清理环境变量配置..."
  if [[ -f /etc/profile.d/snap.sh ]]; then
    rm -f /etc/profile.d/snap.sh
    ok "已删除环境变量配置文件"
  fi
  
  info "清理符号链接..."
  if [[ -L /snap ]]; then
    rm -f /snap
    ok "已删除符号链接 /snap"
  fi
  
  echo
  ok "LXD 卸载完成！"
  echo
  warn "环境变量已清理，建议重新登录系统或重启终端"
  exit 0
fi

echo
echo "========================================"
echo "      步骤 1/5: 检测系统环境"
echo "========================================"
echo

info "检测操作系统..."
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    info "系统: $ID $VERSION_ID"
else
    warn "无法检测系统类型，将尝试继续安装"
fi

info "检测系统架构..."
arch=$(uname -m)
case $arch in
    x86_64)
        info "架构: amd64"
        ;;
    aarch64|arm64)
        info "架构: arm64"
        ;;
    *)
        err "不支持的架构: $arch (仅支持 amd64/arm64)"
        ;;
esac

info "检查 LXD 是否已安装..."
LXD_INSTALLED=false
INSTALL_TYPE=""

if [[ -f /snap/bin/lxd || -f /snap/bin/lxc || -f /var/lib/snapd/snap/bin/lxd || -f /var/lib/snapd/snap/bin/lxc ]]; then
    LXD_INSTALLED=true
    INSTALL_TYPE="snap"
fi

if [[ -f /usr/bin/lxd || -f /usr/bin/lxc ]]; then
    LXD_INSTALLED=true
    INSTALL_TYPE="${INSTALL_TYPE:+$INSTALL_TYPE 和 }apt/deb"
fi

if [[ -f /usr/local/bin/lxd || -f /usr/local/bin/lxc ]]; then
    LXD_INSTALLED=true
    INSTALL_TYPE="${INSTALL_TYPE:+$INSTALL_TYPE 和 }本地编译"
fi

if [[ $LXD_INSTALLED == true ]]; then
    if [[ $FORCE == true ]]; then
        echo
        warn "检测到 LXD 已安装 (安装方式: $INSTALL_TYPE)"
        warn "使用了 -f 参数，将强制重新安装"
        echo
        read -p "确定要继续吗? (y/N): " FORCE_CONFIRM
        if [[ $FORCE_CONFIRM != "y" && $FORCE_CONFIRM != "Y" ]]; then
            ok "取消重新安装操作"
            exit 0
        fi
    else
        echo
        err "LXD 已安装 (安装方式: $INSTALL_TYPE)
    
提示：
  - 卸载: $0 -d
  - 强制重新安装: $0 -f"
    fi
fi

ok "环境检测通过"

echo
echo "========================================"
echo "       步骤 2/5: 安装 Snap"
echo "========================================"
echo

info "检测 snapd 是否已安装..."
SNAPD_INSTALLED=false
if [[ -f /usr/bin/snap || -f /usr/sbin/snapd || -f /usr/lib/snapd/snapd ]]; then
    SNAPD_INSTALLED=true
    info "检测到 snapd 已安装"
fi

info "检测包管理器..."
PKG_MANAGER=""
if command -v apt-get &> /dev/null; then
    PKG_MANAGER="apt"
    info "包管理器: APT (Debian/Ubuntu)"
elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
    info "包管理器: YUM (CentOS/RHEL)"
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
    info "包管理器: DNF (Fedora/RHEL 8+)"
elif command -v zypper &> /dev/null; then
    PKG_MANAGER="zypper"
    info "包管理器: Zypper (openSUSE)"
elif command -v pacman &> /dev/null; then
    PKG_MANAGER="pacman"
    info "包管理器: Pacman (Arch Linux)"
else
    err "无法检测到支持的包管理器"
fi

if [[ $SNAPD_INSTALLED == true ]]; then
    info "卸载旧的 snapd..."
    case $PKG_MANAGER in
        apt)
            apt-get purge -y snapd 2>/dev/null || true
            apt-get autoremove -y 2>/dev/null || true
            ;;
        yum)
            yum remove -y snapd 2>/dev/null || true
            ;;
        dnf)
            dnf remove -y snapd 2>/dev/null || true
            ;;
        zypper)
            zypper remove -y snapd 2>/dev/null || true
            ;;
        pacman)
            pacman -Rns --noconfirm snapd 2>/dev/null || true
            ;;
    esac
fi

info "更新软件包列表..."
case $PKG_MANAGER in
    apt)
        apt-get update -y || err "软件包列表更新失败"
        ;;
    yum)
        yum makecache -y || warn "软件包缓存更新失败"
        ;;
    dnf)
        dnf makecache -y || warn "软件包缓存更新失败"
        ;;
    zypper)
        zypper refresh || warn "软件包列表更新失败"
        ;;
    pacman)
        pacman -Sy || warn "软件包列表更新失败"
        ;;
esac

info "安装 snapd..."
case $PKG_MANAGER in
    apt)
        apt-get install -y snapd || err "snapd 安装失败"
        ;;
    yum)
        yum install -y epel-release || true
        yum install -y snapd || err "snapd 安装失败"
        ;;
    dnf)
        dnf install -y snapd || err "snapd 安装失败"
        ;;
    zypper)
        zypper install -y snapd || err "snapd 安装失败"
        ;;
    pacman)
        pacman -S --noconfirm snapd || err "snapd 安装失败"
        ;;
esac

info "启用 snapd 服务..."
systemctl enable --now snapd || err "snapd 服务启用失败"
systemctl enable --now snapd.socket 2>/dev/null || true

# RHEL/CentOS/AlmaLinux 等系统需要额外启用 snapd.seeded
if [[ "$PKG_MANAGER" == "yum" || "$PKG_MANAGER" == "dnf" ]]; then
    info "启用 snapd.seeded 服务 (RHEL/CentOS 系统)..."
    systemctl enable --now snapd.seeded 2>/dev/null || true
fi

info "配置系统环境变量..."
if [[ ! -f /etc/profile.d/snap.sh ]]; then
  cat > /etc/profile.d/snap.sh <<'EOF'
# 添加 Snap 二进制文件目录到 PATH
# 支持不同发行版的 snap 路径
export PATH="/snap/bin:/var/lib/snapd/snap/bin:$PATH"
EOF
  chmod +x /etc/profile.d/snap.sh
  ok "环境变量配置已写入 /etc/profile.d/snap.sh"
else
  info "环境变量配置已存在"
fi

info "更新当前会话环境变量..."
export PATH="/snap/bin:/var/lib/snapd/snap/bin:$PATH"

info "等待 snapd 服务就绪..."
sleep 5

info "查询 snap 版本..."
if [[ -f /usr/bin/snap ]]; then
    SNAP_VERSION=$(/usr/bin/snap --version 2>/dev/null | head -1 || echo "未知")
    ok "Snap 版本: $SNAP_VERSION"
else
    warn "snap 命令不可用"
fi

echo
echo "========================================"
echo "       步骤 3/5: 安装 LXD"
echo "========================================"
echo

info "创建必要的系统目录..."
mkdir -p /usr/src 2>/dev/null || true
mkdir -p /lib/modules 2>/dev/null || true

info "安装 LXD (Snap)..."
snap install lxd --channel=latest/stable || err "LXD 安装失败"

info "更新当前会话环境变量..."
export PATH="/snap/bin:/var/lib/snapd/snap/bin:$PATH"

info "检测 LXD 安装路径..."
LXD_BIN_DIR=""
if [[ -f /snap/bin/lxd ]]; then
    LXD_BIN_DIR="/snap/bin"
    ok "LXD 路径: /snap/bin (Debian/Ubuntu 风格)"
elif [[ -f /var/lib/snapd/snap/bin/lxd ]]; then
    LXD_BIN_DIR="/var/lib/snapd/snap/bin"
    ok "LXD 路径: /var/lib/snapd/snap/bin (RHEL/CentOS 风格)"
    
    # 创建符号链接以保持一致性
    info "创建符号链接 /snap -> /var/lib/snapd/snap..."
    if [[ ! -e /snap ]]; then
        ln -s /var/lib/snapd/snap /snap 2>/dev/null || warn "符号链接创建失败（不影响使用）"
    fi
else
    err "lxd 命令不可用，安装失败"
fi

info "验证 LXD 安装..."
if [[ ! -f "$LXD_BIN_DIR/lxd" ]]; then
    err "lxd 命令不可用，安装失败"
fi

if [[ ! -f "$LXD_BIN_DIR/lxc" ]]; then
    err "lxc 命令不可用，安装失败"
fi

ok "LXD 安装验证通过"

echo
echo "========================================"
echo "       步骤 4/5: 优化配置"
echo "========================================"
echo

info "配置性能优化..."
snap set lxd daemon.debug=false 2>/dev/null || warn "性能优化配置失败"

info "重启 LXD 服务..."
snap restart lxd 2>/dev/null || warn "LXD 服务重启失败"

info "等待 LXD 服务就绪..."
sleep 3

echo
ok "LXD 安装完成！"
echo "  安装路径: $LXD_BIN_DIR"
echo "  LXD 版本: $($LXD_BIN_DIR/lxd --version 2>/dev/null || echo '未知')"
echo "  LXC 版本: $($LXD_BIN_DIR/lxc --version 2>/dev/null || echo '未知')"
echo "  性能优化: 已关闭调试日志"
echo

echo "========================================"
echo "      步骤 5/5: 初始化 LXD"
echo "========================================"
echo

warn "请按照提示配置 LXD："
echo "  - 存储后端推荐: lvm / btrfs / zfs (因系统或喜好而异)"
echo "  - 网络配置可使用默认值"
echo

# 执行 lxd init 命令，让用户交互式配置
$LXD_BIN_DIR/lxd init

if [[ $? -eq 0 ]]; then
    echo
    ok "LXD 初始化完成！"
    echo
    info "验证 LXD 配置..."
    $LXD_BIN_DIR/lxc network list 2>/dev/null && ok "网络配置正常"
    $LXD_BIN_DIR/lxc storage list 2>/dev/null && ok "存储池配置正常"
else
    echo
    err "LXD 初始化失败"
fi

echo
ok "LXD 安装并初始化完成！"
echo
warn "如果当前终端中 lxc/lxd 命令不可用，请执行以下命令之一："
echo "  1. 重新登录系统"
echo "  2. 执行: source /etc/profile.d/snap.sh"
echo "  3. 执行: export PATH=\"/snap/bin:/var/lib/snapd/snap/bin:\$PATH\""
echo
ok "详细教程: https://github.com/xkatld/zjmf-lxd-server/wiki"