#!/bin/bash
# WireGuard 自动管理脚本（修正版 v3.3）

set -e

CONFIG_DIR="/etc/wireguard"
EXPORT_DIR="/etc/wireguard/clients"
BASE_SUBNET="10.29"
DEFAULT_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n 1)

check_root() { [ "$(id -u)" -eq 0 ] || { echo "需要 root 权限"; exit 1; }; }

install_dependencies() {
    echo "检查并安装 WireGuard 及所有依赖..."
    
    # 更新软件包索引
    apt update
    
    # 安装 WireGuard 及必要的工具
    apt install -y wireguard wireguard-tools iptables iproute2 qrencode resolvconf net-tools curl bash-completion ufw dnsutils iptables-persistent netfilter-persistent openresolv jq bc
    
    # 确保 iptables 位置正确
    if [ ! -f "/usr/bin/iptables" ] && [ -f "/usr/sbin/iptables" ]; then
        ln -s /usr/sbin/iptables /usr/bin/iptables
    fi

    # 启用并持久化 iptables 规则
    systemctl enable netfilter-persistent
    netfilter-persistent save
}

# 确保客户端配置目录存在并设置权限
setup_client_directory() {
    mkdir -p "$EXPORT_DIR"
    chmod 755 "$EXPORT_DIR"
    chown root:root "$EXPORT_DIR"
}

# 生成客户端 IP
generate_client_ip() {
    local iface=$1
    local last_ip=$(grep AllowedIPs "${CONFIG_DIR}/${iface}.conf" | awk -F '[./]' '{print $4}' | sort -n | tail -1)
    [ -z "$last_ip" ] && last_ip=2  # 默认从 .2 开始
    echo "${BASE_SUBNET}.$((10 + ${iface#wg})).${last_ip}"
}

# 生成客户端 ID
generate_client_id() { echo "client_$(date +%s%N | md5sum | head -c 8)"; }

# 获取接口信息
get_interface_info() {
    local iface=$1
    local config_file="${CONFIG_DIR}/${iface}.conf"
    [ -f "$config_file" ] || { echo "接口 $iface 不存在"; exit 1; }
    
    PUBLIC_IP=$(awk '/# PublicIP:/ {print $3}' "$config_file")
    PORT=$(awk '/# Port:/ {print $3}' "$config_file")
    [ -z "$PUBLIC_IP" ] && { echo "未找到公网 IP"; exit 1; }
    [ -z "$PORT" ] && { echo "未找到监听端口"; exit 1; }
}

# 添加客户端
add_client() {
    local iface=$1
    [ -f "${CONFIG_DIR}/${iface}.conf" ] || { echo "接口 $iface 不存在"; exit 1; }
    get_interface_info "$iface"

    setup_client_directory  # 确保目录存在

    CLIENT_ID=$(generate_client_id)
    CLIENT_IP=$(generate_client_ip "$iface")
    CLIENT_CONF="${EXPORT_DIR}/${iface}-${CLIENT_ID}.conf"

    CLIENT_PRIVKEY=$(wg genkey)
    CLIENT_PUBKEY=$(echo "$CLIENT_PRIVKEY" | wg pubkey)
    CLIENT_PSK=$(wg genpsk)

    # 获取服务端公钥（修正获取方式）
    SERVER_PUBLIC_KEY=$(awk '/PrivateKey/ {print $3}' "${CONFIG_DIR}/${iface}.conf" | wg pubkey)

    # 追加到服务端配置
    cat >> "${CONFIG_DIR}/${iface}.conf" <<EOF

# ${CLIENT_ID}
[Peer]
PublicKey = ${CLIENT_PUBKEY}
PresharedKey = ${CLIENT_PSK}
AllowedIPs = ${CLIENT_IP}/32
EOF

    # 生成客户端配置文件
    cat > "$CLIENT_CONF" <<EOF
[Interface]
Address = ${CLIENT_IP}/24
PrivateKey = ${CLIENT_PRIVKEY}
DNS = 8.8.8.8,1.1.1.1

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
PresharedKey = ${CLIENT_PSK}
Endpoint = ${PUBLIC_IP}:${PORT}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

    # 设置文件权限
    chmod 600 "$CLIENT_CONF"
    chown root:root "$CLIENT_CONF"

    # 确保客户端配置文件生成
    if [ ! -f "$CLIENT_CONF" ]; then
        echo "❌ 客户端配置文件生成失败: $CLIENT_CONF"
        exit 1
    fi

    # 同步 WireGuard 配置
    wg addconf "$iface" <(wg-quick strip "$iface")

    echo "✅ 客户端添加成功 → ${CLIENT_CONF}"
    ls -l "$EXPORT_DIR"  # 确保目录里有文件
}

# 启动 WireGuard 接口
start_wg_interface() {
    local iface=$1
    echo "启动 WireGuard 接口: $iface"
    systemctl enable --now wg-quick@"$iface" || { echo "接口 $iface 启动失败"; exit 1; }
}

# 创建 WireGuard 接口
create_interface() {
    local iface=$1 public_ip=$2 port=$3
    
    install_dependencies
    setup_client_directory  # 确保目录存在
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"

    SERVER_PRIVKEY=$(wg genkey)
    SERVER_PUBKEY=$(echo "$SERVER_PRIVKEY" | wg pubkey)

    subnet="${BASE_SUBNET}.$((10 + ${iface#wg}))"

    cat > "${CONFIG_DIR}/${iface}.conf" <<EOF
# PublicIP: $public_ip
# Port: $port
[Interface]
Address = ${subnet}.1/24
ListenPort = $port
PrivateKey = $SERVER_PRIVKEY
PostUp = iptables -t nat -A POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE || true
PostDown = iptables -t nat -D POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE || true
EOF

    chmod 600 "${CONFIG_DIR}/${iface}.conf"
    chown root:root "${CONFIG_DIR}/${iface}.conf"

    start_wg_interface "$iface"
    echo "接口 ${iface} 创建成功！"
}

# 主控制流程
main() {
    check_root
    setup_client_directory  # 确保目录存在

    case $1 in
        create)
            [ $# -eq 4 ] || { echo "用法: $0 create [接口名] [公网IP] [端口]"; exit 1; }
            create_interface "$2" "$3" "$4"
            ;;
        add-client)
            [ $# -eq 2 ] || { echo "用法: $0 add-client [接口名]"; exit 1; }
            add_client "$2"
            ;;
        *)
            echo "WireGuard 自动管理 v3.3"
            echo "用法:"
            echo "  $0 create [接口名] [公网IP] [端口]   创建 WireGuard 接口"
            echo "  $0 add-client [接口名]                添加客户端"
            exit 1
            ;;
    esac
}

main "$@"
