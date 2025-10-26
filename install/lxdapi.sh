#!/bin/bash

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

REPO="https://github.com/StarVM-OpenSource/zjmf-lxd-server-v1"
Gitee_REPO="https://gitee.com/starvm/lxdapi" # Gitee 镜像地址
VERSION=""
NAME="lxdapi"
DIR="/opt/$NAME"
CFG="$DIR/config.yaml"
SERVICE="/etc/systemd/system/$NAME.service"
DB_FILE="lxdapi.db"
FORCE=false
DELETE=false
CN_MODE=false # 是否启用国内镜像模式

log() { echo -e "$1"; }
ok() { log "${GREEN}[OK]${NC} $1"; }
info() { log "${BLUE}[INFO]${NC} $1"; }
warn() { log "${YELLOW}[WARN]${NC} $1"; }
err() { log "${RED}[ERR]${NC} $1"; exit 1; }

[[ $EUID -ne 0 ]] && err "请使用 root 运行"

# 修复后的参数解析循环
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--version) VERSION="$2"; [[ $VERSION != v* ]] && VERSION="v$VERSION"; shift 2;;
        -f|--force) FORCE=true; shift;;
        -d|--delete) DELETE=true; shift;;
        -cn) CN_MODE=true; shift;;
        -h|--help) echo "$0 -v 版本 [-f] [-d] [-cn]"; exit 0;;
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

# 步骤 4/8: 安装系统依赖
apt update -y
apt install -y curl wget unzip zip openssl xxd systemd iptables-persistent lxcfs || err "依赖安装失败"
systemctl stop $NAME 2>/dev/null || true


# NAT 规则备份函数
backup_nat_rules() {
    local backup_dir="$DIR/backups"
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    mkdir -p "$backup_dir" || { warn "创建备份目录失败: $backup_dir"; return 1; }
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
            for ((i=2; i<${#old_v4_backups[@]}; i++)); do rm -f "${old_v4_backups[$i]}" 2>/dev/null; done
        fi
        local old_v6_backups=($(ls -t "$backup_dir"/iptables_rules_v6_* 2>/dev/null))
        if [[ ${#old_v6_backups[@]} -gt 2 ]]; then
            for ((i=2; i<${#old_v6_backups[@]}; i++)); do rm -f "${old_v6_backups[$i]}" 2>/dev/null; done
        fi
        return 0
    else
        info "未找到 iptables 持久化文件，跳过 NAT 规则备份"
        return 1
    fi
}

# 数据库备份函数 (保留，但不被调用，因为用户要求移除 zip 备份)
backup_database() {
    local backup_dir="$DIR/backups"
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local backup_name="lxdapi_backup_${timestamp}"
    
    if [[ ! -f "$DIR/$DB_FILE" ]]; then
        info "SQLite数据库文件不存在，跳过数据库备份"
        return 1
    fi
    # ... (原有 zip 备份逻辑)
    warn "跳过 ZIP 数据库备份 (此功能已被用户要求移除调用)"
    return 1
}

# ========== 修正后的：备份旧版本关键配置变量的函数 ==========
backup_old_config_vars() {
    local config_file="$CFG"
    local tmp_file="$1" # 临时文件路径

    if [[ -f "$config_file" ]]; then
        info "尝试从旧配置文件 $config_file 备份关键变量..."
        
        # 1. 提取 SERVER_PORT (system.server.port)
        # 此处的 grep 正则表达式没有问题
        OLD_SERVER_PORT=$(grep -E '^\s*port:\s*[0-9]+' "$config_file" 2>/dev/null | head -1 | awk '{print $2}')
        [[ -n "$OLD_SERVER_PORT" ]] && echo "SERVER_PORT=$OLD_SERVER_PORT" >> "$tmp_file"

        # 2. 提取 PUBLIC_NETWORK_IP_ADDRESS (system.server.tls.server_ips 下的第一个 IP)
        # 修正：移除 grep 正则表达式末尾的 '$'，以匹配带注释的行。
        OLD_EXTERNAL_IP=$(grep -A 10 'server_ips:' "$config_file" 2>/dev/null | grep -E '^\s*-\s*\"[0-9a-fA-F.:]+\"' | head -1 | sed -E 's/^\s*-\s*"([^"]+)".*/\1/')
        [[ -n "$OLD_EXTERNAL_IP" ]] && echo "EXTERNAL_IP=$OLD_EXTERNAL_IP" >> "$tmp_file"

        # 3. 提取 API_ACCESS_HASH (security.api_hash)
        # 修正：移除 grep 正则表达式末尾的 '$'，以匹配带注释的行。
        OLD_API_HASH=$(grep -A 5 'security:' "$config_file" 2>/dev/null | grep -E '^\s*api_hash:\s*\"[0-9a-fA-F]+\"' | head -1 | sed -E 's/^\s*api_hash:\s*"([^"]+)".*/\1/')
        [[ -n "$OLD_API_HASH" ]] && echo "API_HASH=$OLD_API_HASH" >> "$tmp_file"
        
        if [[ -f "$tmp_file" ]]; then
            source "$tmp_file" 2>/dev/null
            # 打印备份成功的变量
            ok "核心变量已备份: IP=${EXTERNAL_IP:-N/A}, Hash=${API_HASH:-N/A}, Port=${SERVER_PORT:-N/A}"
        else
            warn "未从旧配置中成功提取关键变量。"
        fi
    else
        info "旧配置文件 $config_file 不存在，跳过变量备份"
    fi
}
# =======================================================

mkdir -p "$DIR/backups"

# ⚠️ 临时数据库目录改为用户要求的 /tmp/ 路径
TEMP_DB_DIR="/tmp/lxdapi_db_upgrade_temp"
TMP_CFG_VARS=$(mktemp)

if [[ $UPGRADE == true ]]; then
    backup_old_config_vars "$TMP_CFG_VARS"
    backup_nat_rules
    # ⚠️ 移除 backup_database 调用 (不再创建 zip 备份)
    
    # ⚠️ 临时数据库保护：使用 mv 移动到 /tmp/
    if [[ -f "$DIR/$DB_FILE" ]]; then
        mkdir -p "$TEMP_DB_DIR" 2>/dev/null
        
        info "正在将 SQLite 数据库文件临时移动到 $TEMP_DB_DIR/ ..."
        # 移动主文件
        if mv "$DIR/$DB_FILE" "$TEMP_DB_DIR/" 2>/dev/null; then
            # 移动 shm 和 wal 文件
            [[ -f "$DIR/$DB_FILE-shm" ]] && mv "$DIR/$DB_FILE-shm" "$TEMP_DB_DIR/" 2>/dev/null
            [[ -f "$DIR/$DB_FILE-wal" ]] && mv "$DIR/$DB_FILE-wal" "$TEMP_DB_DIR/" 2>/dev/null
            ok "临时数据保护完成"
        else
            warn "移动数据库文件失败，请检查权限。继续尝试升级..."
        fi
    fi
    
    info "清理旧文件（保留 backups 目录和备份文件）"
    find "$DIR" -maxdepth 1 -type f ! -name "lxdapi_backup_*.zip" ! -name "iptables_rules_*" -delete 2>/dev/null || true
    for subdir in "$DIR"/*; do
        if [[ -d "$subdir" ]] && [[ "$(basename "$subdir")" != "backups" ]]; then
            rm -rf "$subdir" 2>/dev/null || true
        fi
    done
elif [[ -d "$DIR" ]]; then
    backup_nat_rules
    # ⚠️ 移除 backup_database 调用 (不再创建 zip 备份)
fi
mkdir -p "$DIR"

# ========== 下载并解压新版本 (根据 -cn 选择主下载源) ==========
TMP=$(mktemp -d)

if [[ $CN_MODE == true ]]; then
    PRIMARY_URL="$Gitee_REPO/releases/download/$VERSION/$BIN.zip"
    SECONDARY_URL="$REPO/releases/download/$VERSION/$BIN.zip"
    PRIMARY_NAME="Gitee 镜像"
    SECONDARY_NAME="GitHub"
    info "检测到 -cn 参数，将优先使用 Gitee 镜像下载"
else
    PRIMARY_URL="$REPO/releases/download/$VERSION/$BIN.zip"
    SECONDARY_URL="$Gitee_REPO/releases/download/$VERSION/$BIN.zip"
    PRIMARY_NAME="GitHub"
    SECONDARY_NAME="Gitee 镜像"
fi

# 尝试从主源下载
info "尝试从主下载源 ($PRIMARY_NAME) 下载: $PRIMARY_URL"
wget -qO "$TMP/app.zip" "$PRIMARY_URL"
DOWNLOAD_STATUS=$?

if [[ $DOWNLOAD_STATUS -ne 0 ]]; then
    warn "$PRIMARY_NAME 下载失败 (状态: $DOWNLOAD_STATUS)。尝试使用备用源 ($SECONDARY_NAME) 下载..."
    wget -qO "$TMP/app.zip" "$SECONDARY_URL"
    DOWNLOAD_STATUS=$?
    
    if [[ $DOWNLOAD_STATUS -ne 0 ]]; then
        rm -rf "$TMP"
        err "备用源 ($SECONDARY_NAME) 下载也失败，请检查网络或版本号: $VERSION"
    else
        ok "成功通过 $SECONDARY_NAME 下载"
    fi
else
    ok "成功通过 $PRIMARY_NAME 下载"
fi

unzip -qo "$TMP/app.zip" -d "$DIR"
chmod +x "$DIR/$BIN"
echo "$VERSION" > "$DIR/version"
rm -rf "$TMP"
# ==============================================================

# ⚠️ 数据库恢复逻辑：从 /tmp/lxdapi_db_upgrade_temp/ 移动回来
info "正在恢复 SQLite 数据库..."
if [[ -f "$TEMP_DB_DIR/$DB_FILE" ]]; then
    mv "$TEMP_DB_DIR/$DB_FILE" "$DIR/"
    [[ -f "$TEMP_DB_DIR/$DB_FILE-shm" ]] && mv "$TEMP_DB_DIR/$DB_FILE-shm" "$DIR/"
    [[ -f "$TEMP_DB_DIR/$DB_FILE-wal" ]] && mv "$TEMP_DB_DIR/$DB_FILE-wal" "$DIR/"
    ok "数据库已从 $TEMP_DB_DIR/ 恢复"
else
    warn "未找到临时数据库文件 ($TEMP_DB_DIR/$DB_FILE)。如果这是首次安装或您手动删除了文件，请忽略。"
fi
rm -rf "$TEMP_DB_DIR" # 清理临时目录

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

DEFAULT_INTERFACE=$(get_default_interface)
DEFAULT_IPV4=$(get_interface_ipv4 "$DEFAULT_INTERFACE")
DEFAULT_IPV6=$(get_interface_ipv6 "$DEFAULT_INTERFACE")
DEFAULT_IP=$(curl -s 4.ipw.cn || echo "$DEFAULT_IPV4")
DEFAULT_HASH=$(openssl rand -hex 8 | tr 'a-f' 'A-F')

# ⚠️ 端口随机化：随机生成 1000 到 9999 之间的端口
RANDOM_PORT=$(( $RANDOM % 9000 + 1000 ))
DEFAULT_PORT="$RANDOM_PORT"

# 恢复备份的核心配置变量，作为最终值
EXTERNAL_IP=$DEFAULT_IP
API_HASH=$DEFAULT_HASH
SERVER_PORT=$DEFAULT_PORT

if [[ -f "$TMP_CFG_VARS" ]]; then
    source "$TMP_CFG_VARS" 2>/dev/null
    EXTERNAL_IP=${EXTERNAL_IP:-$DEFAULT_IP}
    API_HASH=${API_HASH:-$DEFAULT_HASH}
    # 如果旧配置中有端口，将优先使用旧端口，否则使用随机端口
    SERVER_PORT=${SERVER_PORT:-$DEFAULT_PORT} 
fi
rm -f "$TMP_CFG_VARS"


echo
echo "========================================"
echo "    LXD API 服务精简配置向导 - $VERSION"
echo "========================================"
echo

# 1. 基础信息配置 (自动跳过)
info "==== 步骤 1/6: 基础信息配置 (自动配置) ===="

# 只有在非交互模式下才跳过，但由于当前脚本是交互式的，我们保留用户确认的步骤
# 移除原脚本中强制跳过用户输入的逻辑
# ----------------------------------------------------
echo
# 提示用户当前端口是随机生成的（或从旧配置恢复的）
info "API 服务端口已设置为: ${SERVER_PORT}"

read -p "服务器外网 IP [$EXTERNAL_IP]: " EXTERNAL_IP_INPUT
EXTERNAL_IP=${EXTERNAL_IP_INPUT:-$EXTERNAL_IP}

read -p "API 访问密钥 [$API_HASH]: " API_HASH_INPUT
API_HASH=${API_HASH_INPUT:-$API_HASH}

read -p "API 服务端口 [使用当前值: $SERVER_PORT]: " SERVER_PORT_INPUT
SERVER_PORT=${SERVER_PORT_INPUT:-$SERVER_PORT}

ok "基础信息配置完成"
echo
# ----------------------------------------------------


# 2. 存储池配置 (自动跳过 - 使用所有检测到的)
info "==== 步骤 2/6: 存储池配置 (自动配置) ===="
DETECTED_POOLS=$(lxc storage list --format csv 2>/dev/null | cut -d, -f1 | grep -v "^NAME$" | head -10 | tr '\n' ' ')
if [[ -n "$DETECTED_POOLS" ]]; then
    STORAGE_POOLS=""
    for pool in $DETECTED_POOLS; do
        if [[ -n "$STORAGE_POOLS" ]]; then
            STORAGE_POOLS="$STORAGE_POOLS, \"$pool\""
        else
            STORAGE_POOLS="\"$pool\""
        fi
    done
    ok "已自动配置存储池 (所有检测到的): $DETECTED_POOLS"
else
    STORAGE_POOLS="\"default\""
    ok "未检测到存储池，使用默认配置: default"
fi
echo

# 3. 数据库与队列后端组合 (固定为 SQLite + Database Queue)
info "==== 步骤 3/6: 数据库与队列后端组合 (固定配置) ===="
DB_TYPE="sqlite"
QUEUE_BACKEND="database"

# 定义占位符变量，确保 config.yaml 模板中的所有数据库/队列占位符都能被安全替换
REDIS_HOST=""
REDIS_PORT=""
REDIS_PASSWORD=""
DB_POSTGRES_HOST=""
DB_POSTGRES_PORT=""
DB_POSTGRES_USER=""
DB_POSTGRES_PASSWORD=""
DB_POSTGRES_DATABASE=""
DB_MYSQL_HOST=""
DB_MYSQL_PORT=""
DB_MYSQL_USER=""
DB_MYSQL_PASSWORD=""
DB_MYSQL_DATABASE=""

ok "已固定配置: SQLite + Database 队列 (轻量级/无需依赖)"
echo

# 4. 流量监控性能配置 (固定为最小模式)
info "==== 步骤 4/6: 流量监控性能配置 (固定配置) ===="
TRAFFIC_MODE=4
TRAFFIC_INTERVAL=30
TRAFFIC_BATCH_SIZE=3
TRAFFIC_LIMIT_CHECK_INTERVAL=60
TRAFFIC_LIMIT_CHECK_BATCH_SIZE=3
TRAFFIC_AUTO_RESET_INTERVAL=3600
TRAFFIC_AUTO_RESET_BATCH_SIZE=3
ok "已固定配置: 最小模式 (统计间隔: ${TRAFFIC_INTERVAL}秒, 检测间隔: ${TRAFFIC_LIMIT_CHECK_INTERVAL}秒)"
echo

# 5. 网络管理方案 (用户交互)
echo "==== 步骤 5/6: 网络管理方案 ===="
echo
echo "请选择网络模式："
echo "1. IPv4 NAT (基础模式)"
echo "2. IPv4 NAT + IPv6 NAT (双栈 NAT)"
echo "3. IPv4 NAT + IPv6 NAT + IPv6 独立绑定 (全功能模式)"
echo "4. IPv4 NAT + IPv6 独立绑定 (混合模式)"
echo "5. IPv6 独立绑定 (纯 IPv6 模式)"
echo
read -p "请选择网络模式 [1-5]: " NETWORK_MODE

while [[ ! $NETWORK_MODE =~ ^[1-5]$ ]]; do
    warn "无效选择，请输入 1-5"
    read -p "请选择网络模式 [1-5]: " NETWORK_MODE
done

case $NETWORK_MODE in
    1)
        NAT_SUPPORT="true"
        IPV6_NAT_SUPPORT="false"
        IPV6_BINDING_ENABLED="false"
        ok "已选择: IPv4 NAT (基础模式)"
        ;;
    2)
        NAT_SUPPORT="true"
        IPV6_NAT_SUPPORT="true"
        IPV6_BINDING_ENABLED="false"
        ok "已选择: IPv4 NAT + IPv6 NAT (双栈 NAT)"
        ;;
    3)
        NAT_SUPPORT="true"
        IPV6_NAT_SUPPORT="true"
        IPV6_BINDING_ENABLED="true"
        ok "已选择: IPv4 NAT + IPv6 NAT + IPv6 独立绑定 (全功能模式)"
        ;;
    4)
        NAT_SUPPORT="true"
        IPV6_NAT_SUPPORT="false"
        IPV6_BINDING_ENABLED="true"
        ok "已选择: IPv4 NAT + IPv6 独立绑定 (混合模式)"
        ;;
    5)
        NAT_SUPPORT="false"
        IPV6_NAT_SUPPORT="false"
        IPV6_BINDING_ENABLED="true"
        ok "已选择: IPv6 独立绑定 (纯 IPv6 模式)"
        ;;
esac

echo
echo "==== 网络接口配置 ===="
read -p "外网网卡接口 [$DEFAULT_INTERFACE]: " NETWORK_INTERFACE
NETWORK_INTERFACE=${NETWORK_INTERFACE:-$DEFAULT_INTERFACE}

if [[ $NAT_SUPPORT == "true" ]]; then
    read -p "外网 IPv4 地址 [$DEFAULT_IPV4]: " NETWORK_IPV4
    NETWORK_IPV4=${NETWORK_IPV4:-$DEFAULT_IPV4}
else
    NETWORK_IPV4=""
fi

if [[ $IPV6_NAT_SUPPORT == "true" ]]; then
    read -p "外网 IPv6 地址 [$DEFAULT_IPV6]: " NETWORK_IPV6
    NETWORK_IPV6=${NETWORK_IPV6:-$DEFAULT_IPV6}
else
    NETWORK_IPV6=""
fi

if [[ $IPV6_BINDING_ENABLED == "true" ]]; then
    echo
    echo "==== IPv6 独立绑定配置 ===="
    read -p "IPv6 绑定网卡接口 [$DEFAULT_INTERFACE]: " IPV6_BINDING_INTERFACE
    IPV6_BINDING_INTERFACE=${IPV6_BINDING_INTERFACE:-$DEFAULT_INTERFACE}
    
    while [[ -z "$IPV6_POOL_START" ]]; do
        read -p "IPv6 地址池起始地址 (如: 2001:db8::1000): " IPV6_POOL_START
        if [[ -z "$IPV6_POOL_START" ]]; then
            warn "IPv6 地址池起始地址不能为空，请重新输入"
        fi
    done
else
    IPV6_BINDING_INTERFACE=""
    IPV6_POOL_START=""
fi

ok "网络配置完成"
echo

# 6. Nginx 反向代理配置 (用户交互)
echo "==== 步骤 6/6: Nginx 反向代理配置 ===="
echo
echo "是否启用 Nginx 反向代理功能？"
echo "此功能允许为容器配置域名反向代理（需要已安装 Nginx）"
echo
read -p "是否启用 Nginx 反向代理? (y/N): " ENABLE_NGINX_PROXY

if [[ $ENABLE_NGINX_PROXY == "y" || $ENABLE_NGINX_PROXY == "Y" ]]; then
    NGINX_PROXY_ENABLED="true"
    
    # 检测并安装 Nginx
    if ! command -v nginx &> /dev/null; then
        info "正在安装 Nginx..."
        apt update -y && apt install -y nginx || err "Nginx 安装失败"
        systemctl enable nginx
        systemctl start nginx
        ok "Nginx 安装完成"
    else
        ok "检测到 Nginx 已安装"
    fi
    
    # 配置 Nginx 日志轮转（保留3天）
    if [[ -d "/etc/logrotate.d" ]]; then
        cat > /etc/logrotate.d/nginx-lxdapi <<'EOF'
/var/log/nginx/*-access.log /var/log/nginx/*-error.log {
    daily
    rotate 3
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        [ -f /var/run/nginx.pid ] && kill -USR1 `cat /var/run/nginx.pid`
    endscript
}
EOF
        ok "Nginx 日志轮转配置已创建（保留3天）"
    fi
    
    ok "Nginx 反向代理功能已启用"
else
    NGINX_PROXY_ENABLED="false"
    ok "已禁用 Nginx 反向代理功能"
fi

echo

echo "==== 正在生成配置文件 ===="

replace_config_var() {
    local placeholder="$1"
    local value="$2"
    escaped_value=$(printf '%s\n' "$value" | sed -e 's/[\/&]/\\&/g')
    sed -i "s/\${$placeholder}/$escaped_value/g" "$CFG"
}

# 自动获取CPU核心数作为worker_count
CPU_CORES=$(nproc 2>/dev/null || echo "4")
if [[ $CPU_CORES -lt 2 ]]; then WORKER_COUNT=2
elif [[ $CPU_CORES -gt 16 ]]; then WORKER_COUNT=16
else WORKER_COUNT=$CPU_CORES
fi
info "检测到 CPU 核心数: $CPU_CORES，设置 Worker 数量为: $WORKER_COUNT"

replace_config_var "SERVER_PORT" "$SERVER_PORT"
replace_config_var "PUBLIC_NETWORK_IP_ADDRESS" "$EXTERNAL_IP"
replace_config_var "API_ACCESS_HASH" "$API_HASH"
replace_config_var "STORAGE_POOLS" "$STORAGE_POOLS"
replace_config_var "WORKER_COUNT" "$WORKER_COUNT"

# DB/Queue 核心配置 (固定为 SQLite/Database)
replace_config_var "DB_TYPE" "$DB_TYPE"
replace_config_var "QUEUE_BACKEND" "$QUEUE_BACKEND"

# 替换所有数据库/队列的占位符为空值或安全默认值
replace_config_var "REDIS_HOST" "$REDIS_HOST"
replace_config_var "REDIS_PORT" "$REDIS_PORT"
replace_config_var "REDIS_PASSWORD" "$REDIS_PASSWORD"
replace_config_var "DB_MYSQL_HOST" "$DB_MYSQL_HOST"
replace_config_var "DB_MYSQL_PORT" "$DB_MYSQL_PORT"
replace_config_var "DB_MYSQL_USER" "$DB_MYSQL_USER"
replace_config_var "DB_MYSQL_PASSWORD" "$DB_MYSQL_PASSWORD"
replace_config_var "DB_MYSQL_DATABASE" "$DB_MYSQL_DATABASE"
replace_config_var "DB_POSTGRES_HOST" "$DB_POSTGRES_HOST"
replace_config_var "DB_POSTGRES_PORT" "$DB_POSTGRES_PORT"
replace_config_var "DB_POSTGRES_USER" "$DB_POSTGRES_USER"
replace_config_var "DB_POSTGRES_PASSWORD" "$DB_POSTGRES_PASSWORD"
replace_config_var "DB_POSTGRES_DATABASE" "$DB_POSTGRES_DATABASE"

# 网络/流量/Nginx 配置
replace_config_var "NAT_SUPPORT" "$NAT_SUPPORT"
replace_config_var "IPV6_NAT_SUPPORT" "$IPV6_NAT_SUPPORT"
replace_config_var "NETWORK_EXTERNAL_INTERFACE" "$NETWORK_INTERFACE"
replace_config_var "NETWORK_EXTERNAL_IPV4" "$NETWORK_IPV4"
replace_config_var "NETWORK_EXTERNAL_IPV6" "$NETWORK_IPV6"
replace_config_var "IPV6_BINDING_ENABLED" "$IPV6_BINDING_ENABLED"
replace_config_var "IPV6_BINDING_INTERFACE" "$IPV6_BINDING_INTERFACE"
replace_config_var "IPV6_POOL_START" "$IPV6_POOL_START"
replace_config_var "TRAFFIC_INTERVAL" "$TRAFFIC_INTERVAL"
replace_config_var "TRAFFIC_BATCH_SIZE" "$TRAFFIC_BATCH_SIZE"
replace_config_var "TRAFFIC_LIMIT_CHECK_INTERVAL" "$TRAFFIC_LIMIT_CHECK_INTERVAL"
replace_config_var "TRAFFIC_LIMIT_CHECK_BATCH_SIZE" "$TRAFFIC_LIMIT_CHECK_BATCH_SIZE"
replace_config_var "TRAFFIC_AUTO_RESET_INTERVAL" "$TRAFFIC_AUTO_RESET_INTERVAL"
replace_config_var "TRAFFIC_AUTO_RESET_BATCH_SIZE" "$TRAFFIC_AUTO_RESET_BATCH_SIZE"
replace_config_var "NGINX_PROXY_ENABLED" "$NGINX_PROXY_ENABLED"

ok "配置文件已生成"
echo

echo "==== 创建系统服务 ===="

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

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now $NAME

ok "系统服务已创建并启动"
echo

echo "========================================"
echo "          安装/升级完成"
echo "========================================"
echo
echo "服务信息:"
echo "  数据目录: $DIR"
echo "  外网 IP: $EXTERNAL_IP"
echo "  API 端口: $SERVER_PORT"
echo "  API Hash: $API_HASH"
echo
echo "数据库配置:"
echo "  数据库: SQLite (lxdapi.db)"
echo "  任务队列: Database"
echo
echo "存储池配置: [$STORAGE_POOLS]"
echo
echo "网络模式:"
case $NETWORK_MODE in
    1) echo "  IPv4 NAT";;
    2) echo "  IPv4 + IPv6 NAT";;
    3) echo "  全功能模式 (IPv4 NAT + IPv6 NAT + IPv6 独立绑定)";;
    4) echo "  混合模式 (IPv4 NAT + IPv6 独立绑定)";;
    5) echo "  纯 IPv6 模式";;
esac
echo
echo "流量监控性能:"
echo "  模式: 最小模式 (统计间隔: ${TRAFFIC_INTERVAL}秒, 检测间隔: ${TRAFFIC_LIMIT_CHECK_INTERVAL}秒)"
echo
echo "反向代理:"
if [[ $NGINX_PROXY_ENABLED == "true" ]]; then
    echo "  状态: 已启用 (Nginx 已安装并启动)"
else
    echo "  状态: 未启用"
fi
echo

if [[ -d "$DIR/backups" ]]; then
    db_backup_count=$(ls "$DIR/backups"/lxdapi_backup_*.zip 2>/dev/null | wc -l)
    nat_v4_count=$(ls "$DIR/backups"/iptables_rules_v4_* 2>/dev/null | wc -l)
    nat_v6_count=$(ls "$DIR/backups"/iptables_rules_v6_* 2>/dev/null | wc -l)
    
    if [[ $db_backup_count -gt 0 ]] || [[ $nat_v4_count -gt 0 ]] || [[ $nat_v6_count -gt 0 ]]; then
        echo "备份信息:"
        
        if [[ $db_backup_count -gt 0 ]]; then
            latest_db_backup=$(ls -t "$DIR/backups"/lxdapi_backup_*.zip 2>/dev/null | head -1)
            db_backup_size=$(du -h "$latest_db_backup" 2>/dev/null | cut -f1)
            echo "  SQLite数据库: $db_backup_count 个 (最新: $(basename "$latest_db_backup"), 大小: $db_backup_size)"
        fi
        
        if [[ $nat_v4_count -gt 0 ]]; then
            latest_nat_v4=$(ls -t "$DIR/backups"/iptables_rules_v4_* 2>/dev/null | head -1)
            nat_v4_size=$(du -h "$latest_nat_v4" 2>/dev/null | cut -f1)
            echo "  NAT规则(IPv4): $nat_v4_count 个 (最新: $(basename "$latest_nat_v4"), 大小: $nat_v4_size)"
        fi
        
        if [[ $nat_v6_count -gt 0 ]]; then
            latest_nat_v6=$(ls -t "$DIR/backups"/iptables_rules_v6_* 2>/dev/null | head -1)
            nat_v6_size=$(du -h "$latest_nat_v6" 2>/dev/null | cut -f1)
            echo "  NAT规则(IPv6): $nat_v6_count 个 (最新: $(basename "$latest_nat_v6"), 大小: $nat_v6_size)"
        fi
        
        echo
    fi
fi

echo "========================================"
echo "服务状态:"
echo "========================================"
systemctl status $NAME --no-pager