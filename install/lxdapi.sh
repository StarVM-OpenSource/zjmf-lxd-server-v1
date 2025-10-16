#!/bin/bash

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

REPO="https://github.com/StarVM-OpenSource/zjmf-lxd-server-v1"
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
		db_backup_count=$(ls "$DIR/backups"/lxdapi_backup_*.zip 2>/dev/null | wc -l)
		nat_v4_count=$(ls "$DIR/backups"/iptables_rules_v4_* 2>/dev/null | wc -l)
		nat_v6_count=$(ls "$DIR/backups"/iptables_rules_v6_* 2>/dev/null | wc -l)
		
		if [[ $db_backup_count -gt 0 ]] || [[ $nat_v4_count -gt 0 ]] || [[ $nat_v6_count -gt 0 ]]; then
			echo "备份文件位置: $DIR/backups/"
			[[ $db_backup_count -gt 0 ]] && echo "  - SQLite数据库备份: $db_backup_count 个"
			[[ $nat_v4_count -gt 0 ]] && echo "  - NAT规则备份(IPv4): $nat_v4_count 个"
			[[ $nat_v6_count -gt 0 ]] && echo "  - NAT规则备份(IPv6): $nat_v6_count 个"
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
apt install -y curl wget unzip zip openssl xxd systemd iptables-persistent || err "依赖安装失败"

systemctl stop $NAME 2>/dev/null || true

backup_nat_rules() {
	local backup_dir="$DIR/backups"
	local timestamp=$(date +"%Y%m%d_%H%M%S")
	
	mkdir -p "$backup_dir" || {
		warn "创建备份目录失败: $backup_dir"
		return 1
	}
	
	local has_backup=false
	
	if [[ -f "/etc/iptables/rules.v4" ]]; then
		cp "/etc/iptables/rules.v4" "$backup_dir/iptables_rules_v4_${timestamp}" 2>/dev/null && has_backup=true
	fi
	
	if [[ -f "/etc/iptables/rules.v6" ]]; then
		cp "/etc/iptables/rules.v6" "$backup_dir/iptables_rules_v6_${timestamp}" 2>/dev/null && has_backup=true
	fi
	
	if [[ $has_backup == true ]]; then
		ok "NAT规则已备份 (iptables持久化文件)"
		
		local old_v4_backups=($(ls -t "$backup_dir"/iptables_rules_v4_* 2>/dev/null))
		if [[ ${#old_v4_backups[@]} -gt 2 ]]; then
			for ((i=2; i<${#old_v4_backups[@]}; i++)); do
				rm -f "${old_v4_backups[$i]}" 2>/dev/null
			done
		fi
		
		local old_v6_backups=($(ls -t "$backup_dir"/iptables_rules_v6_* 2>/dev/null))
		if [[ ${#old_v6_backups[@]} -gt 2 ]]; then
			for ((i=2; i<${#old_v6_backups[@]}; i++)); do
				rm -f "${old_v6_backups[$i]}" 2>/dev/null
			done
		fi
		
		return 0
	else
		info "未找到 iptables 持久化文件，跳过 NAT 规则备份"
		return 1
	fi
}

backup_database() {
	local backup_dir="$DIR/backups"
	local timestamp=$(date +"%Y%m%d_%H%M%S")
	local backup_name="lxdapi_backup_${timestamp}"
	
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
		
		local old_backups=($(ls -t "$backup_dir"/lxdapi_backup_*.zip 2>/dev/null))
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

check_db_backup_warning() {
	if [[ -f "$CFG" ]]; then
		local current_db_type=$(grep -E "^\s*type:" "$CFG" 2>/dev/null | sed 's/.*type:\s*["\x27]*\([^"\x27]*\)["\x27]*.*/\1/' | tr -d ' ')
		if [[ "$current_db_type" == "mysql" || "$current_db_type" == "mariadb" || "$current_db_type" == "postgres" ]]; then
			echo
			warn "$current_db_type 数据库需要您自行备份，请注意数据安全"
			echo
			read -p "确认继续升级? (y/N): " DB_UPGRADE_CONFIRM
			if [[ $DB_UPGRADE_CONFIRM != "y" && $DB_UPGRADE_CONFIRM != "Y" ]]; then
				echo "已取消升级，请先备份数据库"
				exit 0
			fi
		fi
	fi
}

# ========== 新增：备份旧版本关键配置变量的函数 ==========
backup_old_config_vars() {
	local config_file="$CFG"
	local tmp_file="$1" # 临时文件路径

	if [[ -f "$config_file" ]]; then
		info "尝试从旧配置文件 $config_file 备份关键变量..."
		
		# 1. 提取 SERVER_PORT (system.server.port)
		# 匹配行: port: 9836
		OLD_SERVER_PORT=$(grep -E '^\s*port:\s*[0-9]+' "$config_file" 2>/dev/null | head -1 | awk '{print $2}')
		[[ -n "$OLD_SERVER_PORT" ]] && echo "SERVER_PORT=$OLD_SERVER_PORT" >> "$tmp_file"

		# 2. 提取 PUBLIC_NETWORK_IP_ADDRESS (system.server.tls.server_ips 下的第一个 IP)
		# 匹配行: - "129.148.51.176"
		OLD_EXTERNAL_IP=$(grep -A 10 'server_ips:' "$config_file" 2>/dev/null | grep -E '^\s*-\s*\"[0-9a-fA-F.:]+\"$' | head -1 | sed -E 's/^\s*-\s*"([^"]+)".*/\1/')
		[[ -n "$OLD_EXTERNAL_IP" ]] && echo "EXTERNAL_IP=$OLD_EXTERNAL_IP" >> "$tmp_file"

		# 3. 提取 API_ACCESS_HASH (security.api_hash)
		# 匹配行: api_hash: "683C28197D72AF3C"
		OLD_API_HASH=$(grep -A 5 'security:' "$config_file" 2>/dev/null | grep -E '^\s*api_hash:\s*\"[0-9a-fA-F]+\"$' | head -1 | sed -E 's/^\s*api_hash:\s*"([^"]+)".*/\1/')
		[[ -n "$OLD_API_HASH" ]] && echo "API_HASH=$OLD_API_HASH" >> "$tmp_file"
		
		if [[ -f "$tmp_file" ]]; then
			# 打印备份成功的变量
			source "$tmp_file" 2>/dev/null
			ok "核心变量已备份: IP=$EXTERNAL_IP, Hash=$API_HASH, Port=$SERVER_PORT"
		else
			warn "未从旧配置中成功提取关键变量。"
		fi
	else
		info "旧配置文件 $config_file 不存在，跳过变量备份"
	fi
}
# =======================================================


mkdir -p "$DIR/backups"

TMP_DB=$(mktemp -d)
TMP_CFG_VARS=$(mktemp) # 用于存储备份的核心配置变量

if [[ $UPGRADE == true ]]; then
	check_db_backup_warning
	
	# === 升级时备份关键配置变量 ===
	backup_old_config_vars "$TMP_CFG_VARS"
	
	backup_nat_rules
	backup_database
	
	if [[ -f "$DIR/$DB_FILE" ]]; then
		cp "$DIR/$DB_FILE" "$TMP_DB/" && info "临时数据库备份已创建"
		[[ -f "$DIR/$DB_FILE-shm" ]] && cp "$DIR/$DB_FILE-shm" "$TMP_DB/"	
		[[ -f "$DIR/$DB_FILE-wal" ]] && cp "$DIR/$DB_FILE-wal" "$TMP_DB/"
	fi
	
	info "清理旧文件（保留 backups 目录和备份文件）"
	# 清理旧文件，注意 TMP_CFG_VARS 存储在其他位置，不会被删除
	find "$DIR" -maxdepth 1 -type f ! -name "lxdapi_backup_*.zip" ! -name "iptables_rules_*" -delete 2>/dev/null || true
	for subdir in "$DIR"/*; do
		if [[ -d "$subdir" ]] && [[ "$(basename "$subdir")" != "backups" ]]; then
			rm -rf "$subdir" 2>/dev/null || true
		fi
	done
elif [[ -d "$DIR" ]]; then
	# 非升级，但目录存在时也进行备份（以防首次安装失败后重试）
	backup_nat_rules
	backup_database
fi
mkdir -p "$DIR"

# 下载并解压新版本
TMP=$(mktemp -d)
wget -qO "$TMP/app.zip" "$DOWNLOAD_URL" || err "下载失败"
unzip -qo "$TMP/app.zip" -d "$DIR"
chmod +x "$DIR/$BIN"
echo "$VERSION" > "$DIR/version"
rm -rf "$TMP"

# 数据库恢复逻辑...
if [[ -f "$TMP_DB/$DB_FILE" ]]; then
	mv "$TMP_DB/$DB_FILE" "$DIR/"
	[[ -f "$TMP_DB/$DB_FILE-shm" ]] && mv "$TMP_DB/$DB_FILE-shm" "$DIR/"
	[[ -f "$TMP_DB/$DB_FILE-wal" ]] && mv "$TMP_DB/$DB_FILE-wal" "$DIR/"
	ok "数据库已恢复"
	rm -rf "$TMP_DB"
else
	# 从压缩备份恢复逻辑
	# ... (保持原脚本的压缩备份恢复逻辑)
	
	backup_dir="$DIR/backups"
	if [[ -d "$backup_dir" ]]; then
	  latest_backup=$(ls -t "$backup_dir"/lxdapi_backup_*.zip 2>/dev/null | head -1)
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

get_default_interface() {
	ip route | grep default | head -1 | awk '{print $5}' || echo "eth0"
}

get_interface_ipv4() {
	local interface="$1"
	ip -4 addr show "$interface" 2>/dev/null | grep inet | grep -v 127.0.0.1 | head -1 | awk '{print $2}' | cut -d/ -f1 || echo ""
}

get_interface_ipv6() {
	local interface="$1"
	ip -6 addr show "$interface" 2>/dev/null | grep inet6 | grep -v "::1" | grep -v "fe80" | head -1 | awk '{print $2}' | cut -d/ -f1 || echo ""
}

# 初始默认值，用于非升级情况或备份失败时
DEFAULT_INTERFACE=$(get_default_interface)
DEFAULT_IPV4=$(get_interface_ipv4 "$DEFAULT_INTERFACE")
DEFAULT_IPV6=$(get_interface_ipv6 "$DEFAULT_INTERFACE")
DEFAULT_IP=$(curl -s 4.ipw.cn || echo "$DEFAULT_IPV4")
DEFAULT_HASH=$(openssl rand -hex 8 | tr 'a-f' 'A-F')
DEFAULT_PORT="8080"

# ========== 恢复备份的核心配置变量，作为向导默认值 ==========
EXTERNAL_IP=$DEFAULT_IP
API_HASH=$DEFAULT_HASH
SERVER_PORT=$DEFAULT_PORT

if [[ -f "$TMP_CFG_VARS" ]]; then
	# 加载备份变量，会覆盖上面的 DEFAULT 值
	source "$TMP_CFG_VARS" 2>/dev/null
	
	# 确保变量被设置，如果备份值为空，则使用默认值
	EXTERNAL_IP=${EXTERNAL_IP:-$DEFAULT_IP}
	API_HASH=${API_HASH:-$DEFAULT_HASH}
	SERVER_PORT=${SERVER_PORT:-$DEFAULT_PORT}
	
	info "已从旧版本配置恢复 EXTERNAL_IP, API_HASH, SERVER_PORT 作为向导默认值"
fi
rm -f "$TMP_CFG_VARS"
# ========================================================


echo
echo "========================================"
echo "  LXD API 服务配置向导 - $VERSION"
echo "========================================"
echo

echo "==== 步骤 1/6: 基础信息配置 ===="
echo

# 使用恢复后的变量作为提示默认值
read -p "服务器外网 IP [$EXTERNAL_IP]: " EXTERNAL_IP_INPUT
EXTERNAL_IP=${EXTERNAL_IP_INPUT:-$EXTERNAL_IP}

read -p "API 访问密钥 [$API_HASH]: " API_HASH_INPUT
API_HASH=${API_HASH_INPUT:-$API_HASH}

read -p "API 服务端口 [$SERVER_PORT]: " SERVER_PORT_INPUT
SERVER_PORT=${SERVER_PORT_INPUT:-$SERVER_PORT}

ok "基础信息配置完成"
echo

# ... (脚本的其余部分保持不变，因为它已经使用了 $EXTERNAL_IP, $API_HASH, $SERVER_PORT 这些变量)
# ...