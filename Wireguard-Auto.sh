#!/bin/bash
# WireGuard多接口管理脚本增强版
# 支持命令：
#   create [接口名] [公网IP] [端口] → 创建新接口
#   add-client [接口名] → 添加客户端到指定接口

# 错误处理
exiterr() { echo "错误: $1" >&2; exit 1; }
check_root() { [ "$(id -u)" -eq 0 ] || exiterr "需要root权限"; }

# 全局配置
CONFIG_DIR="/etc/wireguard"
BASE_SUBNET="10.29"
EXPORT_DIR="$HOME/wg-configs"

# 获取接口基础信息
get_interface_info() {
    local iface=$1
    config_file="${CONFIG_DIR}/${iface}.conf"
    
    [ -f "$config_file" ] || exiterr "接口 $iface 不存在"
    
    export SUB_NET=$(awk -F '[ ./]' '/Address/{print $4}' "$config_file")
    export PUBLIC_IP=$(awk '/Endpoint/{split($3, a, ":"); print a[1]}' "${EXPORT_DIR}/${iface}-client1.conf")
    export PORT=$(awk -F: '/ListenPort/{print $2}' "$config_file")
}

# 生成唯一客户端IP
generate_client_ip() {
    local iface=$1
    last_ip=$(grep AllowedIPs "${CONFIG_DIR}/${iface}.conf" | awk -F '[ ./]' '{print $4}' | sort -n | tail -1)
    echo "${BASE_SUBNET}.${SUB_NET}.$((last_ip + 1))"
}

# 添加客户端核心逻辑
add_client() {
    local iface=$1
    get_interface_info "$iface"
    
    # 生成客户端信息
    CLIENT_IP=$(generate_client_ip "$iface")
    CLIENT_NAME="client-$(date +%s | tail -c 4)"
    CLIENT_CONF="${EXPORT_DIR}/${iface}-${CLIENT_NAME}.conf"
    
    # 生成密钥
    CLIENT_PRIVKEY=$(wg genkey)
    CLIENT_PUBKEY=$(echo "$CLIENT_PRIVKEY" | wg pubkey)
    CLIENT_PSK=$(wg genpsk)

    # 更新服务端配置
    cat >> "${CONFIG_DIR}/${iface}.conf" <<EOF

# ${CLIENT_NAME}
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
DNS = 8.8.8.8,8.8.4.4

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

# 创建新接口
create_interface() {
    local iface=$1
    local public_ip=$2
    local port=$3
    
    # 验证输入
    check_ip "$public_ip" || exiterr "无效IP地址"
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -le 65535 ] || exiterr "无效端口号"

    # 生成服务端密钥
    SERVER_PRIVKEY=$(wg genkey)
    SERVER_PUBKEY=$(echo "$SERVER_PRIVKEY" | wg pubkey)
    
    # 创建配置文件
    cat > "${CONFIG_DIR}/${iface}.conf" <<EOF
[Interface]
Address = ${BASE_SUBNET}.${iface#wg}.1/24
ListenPort = $port
PrivateKey = $SERVER_PRIVKEY
EOF

    # 初始生成10个客户端
    for i in {1..10}; do
        add_client "$iface"
    done

    # 配置防火墙
    iptables -A INPUT -p udp --dport "$port" -j ACCEPT
    iptables -t nat -A POSTROUTING -s "${BASE_SUBNET}.${iface#wg}.0/24" -j SNAT --to-source "$public_ip"
    
    # 启动服务
    wg-quick up "$iface"
    systemctl enable wg-quick@"$iface" >/dev/null 2>&1
}

# 主控制流程
main() {
    check_root
    mkdir -p "$EXPORT_DIR"
    
    case $1 in
        create)
            [ $# -eq 4 ] || exiterr "用法: $0 create [接口名] [公网IP] [端口]"
            create_interface "$2" "$3" "$4"
            echo "接口 $2 创建成功，10个初始客户端已生成"
            ;;
        add-client)
            [ $# -eq 2 ] || exiterr "用法: $0 add-client [接口名]"
            add_client "$2"
            ;;
        *)
            echo "WireGuard多接口管理系统"
            echo "命令列表:"
            echo "  create [接口名] [IP] [端口]  创建新接口"
            echo "  add-client [接口名]         添加客户端"
            exit 1
            ;;
    esac
}

# 辅助函数
check_ip() {
    local ip=$1
    [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
    for i in ${ip//./ }; do
        [ "$i" -le 255 ] || return 1
    done
    return 0
}

main "$@"
