#!/bin/bash

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

REPO="https://github.com/StarVM-OpenSource/zjmf-lxd-server-v1"
VERSION=""
NAME="lxdweb"
DIR="/opt/$NAME"
CFG="$DIR/config.yaml"
SERVICE="/etc/systemd/system/$NAME.service"
DB_FILE="lxdweb.db"
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
    -v|--version) VERSION="$2"; [[ $VERSION != v* ]] && VERSION="v$VERSION"; shift 2;;
    -f|--force) FORCE=true; shift;;
    -d|--delete) DELETE=true; shift;;
    -h|--help) echo "$0 -v 版本 [-f] [-d]"; exit 0;;
    *) err "未知参数 $1";;
  esac
done

if [[ $DELETE == true ]]; then
  echo "警告: 此操作将删除所有数据，包括数据库文件和备份！"
  
  if [[ -d "$DIR/backups" ]]; then
    backup_count=$(ls "$DIR/backups"/lxdweb_backup_*.zip 2>/dev/null | wc -l)
    if [[ $backup_count -gt 0 ]]; then
      echo "发现 $backup_count 个数据库备份文件将被删除"
      echo "备份文件位置: $DIR/backups/"
    fi
  fi
  
  read -p "确定要继续吗? (y/N): " CONFIRM
  if [[ $CONFIRM != "y" && $CONFIRM != "Y" ]]; then
    ok "取消删除操作"
    exit 0
  fi
  
  systemctl stop $NAME 2>/dev/null || true
  systemctl disable $NAME 2>/dev/null || true
  rm -f "$SERVICE"
  systemctl daemon-reload
  
  WRAPPER="/usr/local/bin/lxdweb"
  if [[ -f "$WRAPPER" ]]; then
    rm -f "$WRAPPER"
    ok "已删除全局命令: lxdweb"
  fi
  
  if [[ -d "$DIR" ]]; then
    rm -rf "$DIR"
    ok "已强制删除 $NAME 服务和目录（包括所有备份）"
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
  x86_64) BIN="lxdweb-amd64";;
  aarch64|arm64) BIN="lxdweb-arm64";;
  *) err "不支持的架构: $arch，仅支持 amd64 和 arm64";;
esac

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
apt install -y curl wget unzip zip openssl systemd || err "依赖安装失败"

systemctl stop $NAME 2>/dev/null || true

backup_database() {
  local backup_dir="$DIR/backups"
  local timestamp=$(date +"%Y%m%d_%H%M%S")
  local backup_name="lxdweb_backup_${timestamp}"
  
  if [[ ! -f "$DIR/$DB_FILE" ]]; then
    info "SQLite数据库文件不存在，跳过数据库备份"
    return 1
  fi
  
  if ! command -v zip &> /dev/null; then
    warn "zip 命令未安装，跳过数据库备份"
    return 1
  fi
  
  mkdir -p "$backup_dir" || {
    warn "创建备份目录失败: $backup_dir"
    return 1
  }
  
  local temp_backup_dir=$(mktemp -d)
  
  if ! cp "$DIR/$DB_FILE" "$temp_backup_dir/"; then
    warn "复制数据库文件失败"
    rm -rf "$temp_backup_dir"
    return 1
  fi
  
  [[ -f "$DIR/$DB_FILE-shm" ]] && cp "$DIR/$DB_FILE-shm" "$temp_backup_dir/" 2>/dev/null
  [[ -f "$DIR/$DB_FILE-wal" ]] && cp "$DIR/$DB_FILE-wal" "$temp_backup_dir/" 2>/dev/null
  
  local current_dir=$(pwd)
  cd "$temp_backup_dir" || {
    warn "切换到临时目录失败"
    rm -rf "$temp_backup_dir"
    return 1
  }
  
  if ! zip -q "${backup_name}.zip" * 2>/dev/null; then
    warn "压缩数据库文件失败"
    cd "$current_dir"
    rm -rf "$temp_backup_dir"
    return 1
  fi
  
  if ! mv "${backup_name}.zip" "$backup_dir/"; then
    warn "移动备份文件失败"
    cd "$current_dir"
    rm -rf "$temp_backup_dir"
    return 1
  fi
  
  cd "$current_dir"
  rm -rf "$temp_backup_dir"
  
  if [[ -f "$backup_dir/${backup_name}.zip" ]]; then
    local backup_size=$(du -h "$backup_dir/${backup_name}.zip" 2>/dev/null | cut -f1)
    ok "SQLite数据库已备份: ${backup_name}.zip (大小: $backup_size)"
    
    local old_backups=($(ls -t "$backup_dir"/lxdweb_backup_*.zip 2>/dev/null))
    if [[ ${#old_backups[@]} -gt 2 ]]; then
      for ((i=2; i<${#old_backups[@]}; i++)); do
        rm -f "${old_backups[$i]}" 2>/dev/null
        info "清理旧数据库备份: $(basename "${old_backups[$i]}")"
      done
    fi
    
    return 0
  fi
  
  warn "备份文件未找到，数据库备份可能失败"
  return 1
}

TMP_DB=$(mktemp -d)
if [[ $UPGRADE == true ]]; then
  backup_database
  
  if [[ -f "$DIR/$DB_FILE" ]]; then
    cp "$DIR/$DB_FILE" "$TMP_DB/" && info "临时备份已创建"
    [[ -f "$DIR/$DB_FILE-shm" ]] && cp "$DIR/$DB_FILE-shm" "$TMP_DB/" 
    [[ -f "$DIR/$DB_FILE-wal" ]] && cp "$DIR/$DB_FILE-wal" "$TMP_DB/"
  fi
  
  info "清理旧文件（保留 backups 目录和备份文件）"
  find "$DIR" -maxdepth 1 -type f ! -name "lxdweb_backup_*.zip" -delete 2>/dev/null || true
  for subdir in "$DIR"/*; do
    if [[ -d "$subdir" ]] && [[ "$(basename "$subdir")" != "backups" ]]; then
      rm -rf "$subdir" 2>/dev/null || true
    fi
  done
elif [[ -d "$DIR" ]]; then
  backup_database
fi
mkdir -p "$DIR"
mkdir -p "$DIR/backups"

TMP=$(mktemp -d)
wget -qO "$TMP/app.zip" "$DOWNLOAD_URL" || err "下载失败"
unzip -qo "$TMP/app.zip" -d "$DIR"
chmod +x "$DIR/$BIN"
echo "$VERSION" > "$DIR/version"
rm -rf "$TMP"

if [[ -f "$TMP_DB/$DB_FILE" ]]; then
  mv "$TMP_DB/$DB_FILE" "$DIR/"
  [[ -f "$TMP_DB/$DB_FILE-shm" ]] && mv "$TMP_DB/$DB_FILE-shm" "$DIR/"
  [[ -f "$TMP_DB/$DB_FILE-wal" ]] && mv "$TMP_DB/$DB_FILE-wal" "$DIR/"
  ok "数据库已恢复"
else
  backup_dir="$DIR/backups"
  if [[ -d "$backup_dir" ]]; then
    latest_backup=$(ls -t "$backup_dir"/lxdweb_backup_*.zip 2>/dev/null | head -1)
    if [[ -n "$latest_backup" ]]; then
      local temp_restore_dir=$(mktemp -d)
      
      if unzip -q "$latest_backup" -d "$temp_restore_dir"; then
        [[ -f "$temp_restore_dir/$DB_FILE" ]] && cp "$temp_restore_dir/$DB_FILE" "$DIR/"
        [[ -f "$temp_restore_dir/$DB_FILE-shm" ]] && cp "$temp_restore_dir/$DB_FILE-shm" "$DIR/"
        [[ -f "$temp_restore_dir/$DB_FILE-wal" ]] && cp "$temp_restore_dir/$DB_FILE-wal" "$DIR/"
        
        ok "从压缩备份恢复数据库: $(basename "$latest_backup")"
      else
        warn "解压备份文件失败: $(basename "$latest_backup")"
      fi
      
      rm -rf "$temp_restore_dir"
    fi
  fi
fi
rm -rf "$TMP_DB"

DEFAULT_PORT="3000"
DEFAULT_SESSION_SECRET=$(openssl rand -hex 32)

if [[ ! -f "$CFG" ]]; then
  info "配置文件不存在，创建默认配置..."
  
  read -p "Web 界面端口 [$DEFAULT_PORT]: " WEB_PORT
  WEB_PORT=${WEB_PORT:-$DEFAULT_PORT}
  
  read -p "Session 密钥 [自动生成]: " SESSION_SECRET
  SESSION_SECRET=${SESSION_SECRET:-$DEFAULT_SESSION_SECRET}
  
  cat > "$CFG" <<EOF
server:
  # 服务器监听地址
  address: "0.0.0.0:$WEB_PORT"
  # 运行模式: debug | release
  mode: "release"
  # 会话密钥
  session_secret: "$SESSION_SECRET"
  # 启用 HTTPS
  enable_https: true
  # 证书文件路径
  cert_file: "cert.pem"
  # 密钥文件路径
  key_file: "key.pem"

database:
  # 数据库文件路径
  path: "$DB_FILE"

logging:
  # 日志级别: debug | info | warn | error
  level: "error"
  # 日志文件保存路径
  file: "lxdweb.log"
  # 单个日志文件最大大小（MB）
  max_size: 10
  # 保留的旧日志文件数量
  max_backups: 2
  # 保留的旧日志文件天数
  max_age: 30
  # 是否压缩旧日志文件
  compress: true
  # 开发模式（控制台输出格式）
  dev_mode: false
EOF
  ok "配置文件已创建: $CFG (HTTPS已启用)"
else
  info "配置文件已存在，跳过配置"
fi

cat > "$SERVICE" <<EOF
[Unit]
Description=lxdweb-xkatld
After=network.target

[Service]
WorkingDirectory=$DIR
ExecStart=$DIR/$BIN
Restart=always
RestartSec=5
Environment=GIN_MODE=release

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now $NAME

WRAPPER="/usr/local/bin/lxdweb"
cat > "$WRAPPER" <<'WRAPPER_EOF'
#!/bin/bash
# lxdweb 命令行工具包装脚本
DIR="/opt/lxdweb"
BIN=$(ls "$DIR"/lxdweb-* 2>/dev/null | head -1)

if [[ -z "$BIN" || ! -x "$BIN" ]]; then
  echo "错误: 未找到 lxdweb 可执行文件" >&2
  exit 1
fi

cd "$DIR" && exec "$BIN" "$@"
WRAPPER_EOF

chmod +x "$WRAPPER"
ok "已创建全局命令: lxdweb"

echo
ok "安装/升级完成"
echo "数据目录: $DIR"
echo "Web 端口: $(grep 'address:' $CFG | awk -F: '{print $NF}' | tr -d ' "')"
echo "配置文件: $CFG"
echo "数据库: SQLite ($DB_FILE)"

if [[ -d "$DIR/backups" ]]; then
    backup_count=$(ls "$DIR/backups"/lxdweb_backup_*.zip 2>/dev/null | wc -l)
    if [[ $backup_count -gt 0 ]]; then
        latest_backup=$(ls -t "$DIR/backups"/lxdweb_backup_*.zip 2>/dev/null | head -1)
        backup_size=$(du -h "$latest_backup" 2>/dev/null | cut -f1)
        echo "数据备份: $backup_count 个压缩备份 (最新: $(basename "$latest_backup"), 大小: $backup_size)"
    fi
fi

echo
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "管理员账户管理命令 (服务后台运行时可用):"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  lxdweb admin create          创建新管理员"
echo "  lxdweb admin password        修改管理员密码"
echo "  lxdweb admin list            列出所有管理员"
echo "  lxdweb admin delete          删除管理员"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo
echo "服务状态信息:"
systemctl status $NAME --no-pager

