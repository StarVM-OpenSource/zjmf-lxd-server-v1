#!/bin/bash

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

REPO="https://github.com/xkatld/zjmf-lxd-server"
VERSION=""
NAME="lxdapi"
DIR="/opt/$NAME"
CFG="$DIR/config.yaml"
SERVICE="/etc/systemd/system/$NAME.service"
DB_FILE="lxdapi.db"
FORCE=false
DELETE=false

log() { echo -e "$1"; }
ok() { log "${GREEN}[OK]${NC} $1"; }
info() { log "${BLUE}[INFO]${NC} $1"; }
err() { log "${RED}[ERR]${NC} $1"; exit 1; }

[[ $EUID -ne 0 ]] && err "请使用 root 运行"

while [[ $# -gt 0 ]]; do
  case $1 in
    -v|--version) VERSION="$2"; [[ $VERSION != v* ]] && VERSION="v$VERSION"; shift 2;;
    -f|--force) FORCE=true; shift;;
    -d|--delete) DELETE=true; shift;;
    -h|--help) echo "$0 -v 版本 [-f] [-d]"; exit 0;;
    *) err "未知参数 $1";;
  esac
done

if [[ $DELETE == true ]]; then
  echo "警告: 此操作将删除所有数据，包括数据库文件！"
  read -p "确定要继续吗? (y/N): " CONFIRM
  if [[ $CONFIRM != "y" && $CONFIRM != "Y" ]]; then
    ok "取消删除操作"
    exit 0
  fi
  
  systemctl stop $NAME 2>/dev/null || true
  systemctl disable $NAME 2>/dev/null || true
  rm -f "$SERVICE"
  systemctl daemon-reload
  if [[ -d "$DIR" ]]; then
    rm -rf "$DIR"
    ok "已强制删除 $NAME 服务和目录"
  else
    ok "目录 $DIR 不存在，无需删除"
  fi
  exit 0
fi

if [[ -z "$VERSION" ]]; then
  err "必须提供版本号参数，使用 -v 或 --version 指定版本"
fi

arch=$(uname -m)
case $arch in
  x86_64) BIN="lxdapi-amd64";;
  aarch64|arm64) BIN="lxdapi-arm64";;
  *) err "不支持的架构: $arch，仅支持 amd64 和 arm64";;
esac

if ! command -v lxd &> /dev/null; then
  err "未检测到 LXD，请先安装 LXD"
fi

lxd_version=$(lxd --version 2>/dev/null | grep -oE '^[0-9]+')
if [[ -z "$lxd_version" || "$lxd_version" -lt 5 ]]; then
  err "LXD 版本必须 >= 5.0，当前版本: $(lxd --version)"
fi

DOWNLOAD_URL="$REPO/releases/download/$VERSION/$BIN.zip"

UPGRADE=false
if [[ -d "$DIR" ]] && [[ -f "$DIR/version" ]]; then
  CUR=$(cat "$DIR/version")
  if [[ $CUR != "$VERSION" || $FORCE == true ]]; then
    UPGRADE=true
    info "升级: $CUR -> $VERSION"
  else
    ok "已是最新版本 $VERSION"
    exit 0
  fi
fi

apt update -y
apt install -y curl wget unzip openssl xxd systemd || err "依赖安装失败"

systemctl stop $NAME 2>/dev/null || true

TMP_DIR=$(mktemp -d)

if [[ $UPGRADE == true ]]; then
  # 备份配置文件和数据库
  if [[ -f "$CFG" ]]; then
    cp "$CFG" "$TMP_DIR/config.yaml.bak" && ok "配置文件已备份"
  fi
  if [[ -f "$DIR/$DB_FILE" ]]; then
    cp "$DIR/$DB_FILE" "$TMP_DIR/" && ok "数据库已备份"
    [[ -f "$DIR/$DB_FILE-shm" ]] && cp "$DIR/$DB_FILE-shm" "$TMP_DIR/" 
    [[ -f "$DIR/$DB_FILE-wal" ]] && cp "$DIR/$DB_FILE-wal" "$TMP_DIR/"
  fi
  rm -rf "$DIR"/*
fi
mkdir -p "$DIR"

TMP=$(mktemp -d)
wget -qO "$TMP/app.zip" "$DOWNLOAD_URL" || err "下载失败"
unzip -qo "$TMP/app.zip" -d "$DIR"
chmod +x "$DIR/$BIN"
echo "$VERSION" > "$DIR/version"
rm -rf "$TMP"

# 恢复配置文件和数据库
if [[ -f "$TMP_DIR/config.yaml.bak" ]]; then
  mv "$TMP_DIR/config.yaml.bak" "$CFG"
  ok "配置文件已恢复"
fi
if [[ -f "$TMP_DIR/$DB_FILE" ]]; then
  mv "$TMP_DIR/$DB_FILE" "$DIR/"
  [[ -f "$TMP_DIR/$DB_FILE-shm" ]] && mv "$TMP_DIR/$DB_FILE-shm" "$DIR/"
  [[ -f "$TMP_DIR/$DB_FILE-wal" ]] && mv "$TMP_DIR/$DB_FILE-wal" "$DIR/"
  ok "数据库已恢复"
fi
rm -rf "$TMP_DIR"

# 只有在配置文件不存在时才进行交互式配置
if [[ ! -f "$CFG" ]]; then
  info "未找到配置文件，正在进行初始化配置"
  DEFAULT_IP=$(curl -s 4.ipw.cn || echo "127.0.0.1")
  DEFAULT_HASH=$(openssl rand -hex 8 | tr 'a-f' 'A-F')

  read -p "外网IP [$DEFAULT_IP]: " EXTERNAL_IP
  EXTERNAL_IP=${EXTERNAL_IP:-$DEFAULT_IP}

  read -p "API Hash [$DEFAULT_HASH]: " API_HASH
  API_HASH=${API_HASH:-$DEFAULT_HASH}
  
  sed -i "s/PUBLIC_NETWORK_IP_ADDRESS/$EXTERNAL_IP/g" "$CFG"
  sed -i "s/API_ACCESS_HASH/$API_HASH/g" "$CFG"
fi

cat > "$SERVICE" <<EOF
[Unit]
Description=lxdapi-xkatld
After=network.target

[Service]
WorkingDirectory=$DIR
ExecStart=$DIR/$BIN
Restart=always
RestartSec=5
Environment=GIN_MODE=release
StandardOutput=append:$DIR/$NAME.log
StandardError=append:$DIR/$NAME.log

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now $NAME

echo
ok "安装/升级完成"
echo "数据目录: $DIR"
echo "服务状态信息:"
systemctl status $NAME --no-pager