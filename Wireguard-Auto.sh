#!/bin/bash
# WireGuard高级管理脚本 v2.2（修正子网分配）
# 功能：多接口管理 | 客户端管理 | 配置备份恢复
# 更新：修复子网段计算逻辑，确保不同接口获得独立子网

# 错误处理
exiterr() { echo "错误: $1" >&2; exit 1; }
check_root() { [ "$(id -u)" -eq 0 ] || exiterr "需要root权限"; }

# 全局配置
CONFIG_DIR="/etc/wireguard"
BASE_SUBNET="10.29"
EXPORT_DIR="$HOME/wg-configs"
DEFAULT_BACKUP_DIR="/var/backups/wireguard"

# ================= 核心功能函数 =================

# 获取接口信息
get_interface_info() {
    local iface=$1
    config_file="${CONFIG_DIR}/${iface}.conf"
    [ -f "$config_file" ] || exiterr "接口 $iface 不存在"
    
    # 从Address字段提取子网第三段（如wg0→0，wg1→1）
    export SUB_NET=$(awk -F '[./]' '/Address/{print $3}' "$config_file")
    export PUBLIC_IP=$(awk -F: '/Endpoint/{print $1}' "${EXPORT_DIR}/${iface}-"* 2>/dev/null | head -1)
    export PORT=$(awk -F= '/ListenPort/{print $2}' "$config_file" | tr -d ' ')
}

# 生成唯一客户端ID
generate_client_id() {
    echo "client_$(date +%s%N | md5sum | head -c 8)"
}

# 生成客户端IP
generate_client_ip() {
    local iface=$1
    last_ip=$(grep AllowedIPs "${CONFIG_DIR}/${iface}.conf" | awk -F '[./]' '{print $4}' | sort -n | tail -1)
    echo "${BASE_SUBNET}.${SUB_NET}.$((last_ip + 1))"  # 使用SUB_NET变量
}

# ================= 客户端管理 =================

add_client() {
    local iface=$1
    get_interface_info "$iface"
    
    # 生成客户端信息
    CLIENT_ID=$(generate_client_id)
    CLIENT_IP=$(generate_client_ip "$iface")
    CLIENT_CONF="${EXPORT_DIR}/${iface}-${CLIENT_ID}.conf"
    
    # 生成密钥
    CLIENT_PRIVKEY=$(wg genkey)
    CLIENT_PUBKEY=$(echo "$CLIENT_PRIVKEY" | wg pubkey)
    CLIENT_PSK=$(wg genpsk)

    # 更新服务端配置
    cat >> "${CONFIG_DIR}/${iface}.conf" <<EOF

# ${CLIENT_ID}
[Peer]
PublicKey = ${CLIENT_PUBKEY}
PresharedKey = ${CLIENT_PSK}
AllowedIPs = ${CLIENT_IP}/32
EOF

    # 生成客户端配置
    cat > "$CLIENT_CONF" <<EOF
[Interface]
Address = ${CLIENT_IP}/24
PrivateKey = ${CLIENT_PRIVKEY}
DNS = 8.8.8.8,1.1.1.1

[Peer]
PublicKey = $(grep PrivateKey "${CONFIG_DIR}/${iface}.conf" | cut -d' ' -f3 | wg pubkey)
PresharedKey = ${CLIENT_PSK}
Endpoint = ${PUBLIC_IP}:${PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

    # 热重载配置
    wg syncconf "$iface" <(wg-quick strip "$iface")
    echo "客户端添加成功 → ${CLIENT_CONF}"
}

list_clients() {
    local iface=$1
    get_interface_info "$iface"
    
    echo "接口 ${iface} 客户端列表："
    echo "┌────────────┬───────────────┬─────────────────────────────┐"
    echo "│ 客户端ID   │ 客户端IP      │ 配置文件路径               │"
    echo "├────────────┼───────────────┼─────────────────────────────┤"
    
    grep -B3 "# client_" "${CONFIG_DIR}/${iface}.conf" | awk -v iface="$iface" '
    /# client_/ {
        client_id=substr($2,2)
        getline
        getline
        split($3, ip, "/")
        printf "│ %-10s │ %-13s │ %-27s │\n", 
            client_id, ip[1], ENVIRON["EXPORT_DIR"] "/" iface "-" client_id ".conf"
    }'
    
    echo "└────────────┴───────────────┴─────────────────────────────┘"
}

delete_client() {
    local iface=$1
    local client_id=$2
    
    # 验证客户端存在
    config_file="${CONFIG_DIR}/${iface}.conf"
    [ -f "${EXPORT_DIR}/${iface}-${client_id}.conf" ] || exiterr "客户端配置文件不存在"
    grep -q "# ${client_id}" "$config_file" || exiterr "客户端未在配置中找到"

    # 删除配置块（4行）
    sed -i "/# ${client_id}/,+3d" "$config_file"
    
    # 删除客户端文件
    rm -f "${EXPORT_DIR}/${iface}-${client_id}.conf"
    
    # 重载配置
    wg syncconf "$iface" <(wg-quick strip "$iface")
    echo "客户端 ${client_id} 已成功删除"
}

# ================= 配置备份恢复 =================

backup_config() {
    local backup_path="${1:-${DEFAULT_BACKUP_DIR}/wg-backup-$(date +%Y%m%d-%H%M%S).tgz}"
    mkdir -p "$(dirname "$backup_path")"
    
    echo "正在备份配置到: ${backup_path}"
    tar czPf "$backup_path" \
        --exclude="*.tmp" \
        -C "$CONFIG_DIR" . \
        -C "$EXPORT_DIR" . 2>/dev/null
    
    [ $? -eq 0 ] && echo "备份成功" || exiterr "备份失败"
    ls -lh "$backup_path"
}

restore_config() {
    local backup_file=$1
    [ -f "$backup_file" ] || exiterr "备份文件不存在"
    
    echo "正在停止所有WireGuard接口..."
    systemctl stop 'wg-quick@*' 2>/dev/null
    
    echo "清理旧配置..."
    rm -f "${CONFIG_DIR}"/*.conf
    rm -f "${EXPORT_DIR}"/*.conf
    
    echo "恢复备份文件: ${backup_file}"
    tar xzPf "$backup_file" -C / 2>/dev/null
    
    echo "重启WireGuard服务..."
    local count=0
    for conf in "${CONFIG_DIR}"/*.conf; do
        [ -f "$conf" ] || continue
        iface=$(basename "$conf" .conf)
        wg-quick up "$iface"
        ((count++))
    done
    
    echo "配置恢复完成！成功重启 ${count} 个接口"
}

# ================= 接口管理 =================

create_interface() {
    local iface=$1
    local public_ip=$2
    local port=$3
    
    # 输入验证
    check_ip "$public_ip" || exiterr "无效IP地址: $public_ip"
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -le 65535 ] || exiterr "无效端口号: $port"
    [[ "$iface" =~ ^wg[0-9]+$ ]] || exiterr "接口名必须以wg开头加数字 (如wg0)"
    
    # 提取接口数字后缀（如wg0→0）
    interface_num="${iface#wg}"
    
    # 生成服务端IP（关键修正：直接使用接口数字作为子网段）
    SERVER_PRIVKEY=$(wg genkey)
    SERVER_PUBKEY=$(echo "$SERVER_PRIVKEY" | wg pubkey)
    
    # 创建配置文件（确保子网第三段与接口数字一致）
    cat > "${CONFIG_DIR}/${iface}.conf" <<EOF
[Interface]
Address = ${BASE_SUBNET}.${interface_num}.1/24
ListenPort = $port
PrivateKey = $SERVER_PRIVKEY
EOF

    # 初始生成10个客户端（子网段自动跟随接口数字）
    for i in {1..10}; do
        add_client "$iface" >/dev/null
    done

    # 配置防火墙（使用正确的子网段）
    if command -v ufw >/dev/null; then
        ufw allow $port/udp
        ufw route allow in on $iface out on eth0
    elif command -v firewall-cmd >/dev/null; then
        firewall-cmd --permanent --add-port=$port/udp
        firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=${BASE_SUBNET}.${interface_num}.0/24 masquerade"
        firewall-cmd --reload
    else
        iptables -A INPUT -p udp --dport $port -j ACCEPT
        iptables -t nat -A POSTROUTING -s ${BASE_SUBNET}.${interface_num}.0/24 -j SNAT --to-source $public_ip
    fi

    # 启动服务
    wg-quick up "$iface"
    systemctl enable wg-quick@"$iface" >/dev/null 2>&1
    
    echo "接口 ${iface} 创建成功！"
    echo "公网IP: ${public_ip} 端口: ${port}"
    echo "子网段: ${BASE_SUBNET}.${interface_num}.0/24"
    echo "初始客户端配置已生成到: ${EXPORT_DIR}"
}

# ================= 主控制流程 =================

main() {
    check_root
    mkdir -p "$EXPORT_DIR"
    
    case $1 in
        create)
            [ $# -eq 4 ] || exiterr "用法: $0 create [接口名] [公网IP] [端口]"
            create_interface "$2" "$3" "$4"
            ;;
        add-client)
            [ $# -eq 2 ] || exiterr "用法: $0 add-client [接口名]"
            add_client "$2"
            ;;
        list-clients)
            [ $# -eq 2 ] || exiterr "用法: $0 list-clients [接口名]"
            list_clients "$2"
            ;;
        delete-client)
            [ $# -eq 3 ] || exiterr "用法: $0 delete-client [接口名] [客户端ID]"
            delete_client "$2" "$3"
            ;;
        backup-config)
            backup_config "$2"
            ;;
        restore-config)
            [ $# -eq 2 ] || exiterr "用法: $0 restore-config [备份文件路径]"
            restore_config "$2"
            ;;
        *)
            echo "WireGuard高级管理系统 v2.1"
            echo "命令列表:"
            echo "  create [接口名] [IP] [端口]   创建新接口 (例: create wg0 203.0.113.5 51820)"
            echo "  add-client [接口名]           添加客户端"
            echo "  list-clients [接口名]         查看客户端列表"
            echo "  delete-client [接口名] [ID]   删除客户端 (例: delete-client wg0 client_1a2b3c4d)"
            echo "  backup-config [路径]          备份配置到指定路径 (默认: ${DEFAULT_BACKUP_DIR})"
            echo "  restore-config [备份文件]      从备份恢复配置"
            echo
            echo "配置文件存储:"
            echo "  服务端配置: ${CONFIG_DIR}/"
            echo "  客户端配置: ${EXPORT_DIR}/"
            exit 1
            ;;
    esac
}

# 辅助函数
check_ip() { 
    [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
    for i in ${1//./ }; do
        [ "$i" -le 255 ] || return 1
    done
    return 0
}

# 执行主程序
main "$@"
