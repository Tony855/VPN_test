#!/bin/bash
set -e

# 自动检测默认网络接口（用于 ip6tables 规则）
DEFAULT_IF=$(ip route | grep '^default' | awk '{print $5}' | head -n 1)
if [ -z "$DEFAULT_IF" ]; then
    echo "无法检测到默认网络接口。"
    exit 1
fi

# 获取所有公共 IPv4 地址
PUBLIC_IPV4S=($(ip -4 addr show scope global | grep -oP '(?<=inet\\s)\\d+\\.\\d+\\.\\d+\\.\\d+'))
if [ ${#PUBLIC_IPV4S[@]} -eq 0 ]; then
    echo "未找到公共 IPv4 地址，脚本退出。"
    exit 1
fi

WG_CONFIG_DIR="/etc/wireguard"
mkdir -p "$WG_CONFIG_DIR"

WG_PORT_START=51820    # 起始端口
WG_IPV6_SUBNET="fd00::" # 内部 WireGuard IPv6 子网前缀

# 针对每个公共 IPv4 分别创建 WireGuard 配置
for i in "${!PUBLIC_IPV4S[@]}"; do
    PUBLIC_IP="${PUBLIC_IPV4S[$i]}"
    WG_INTERFACE="wg$i"
    LISTEN_PORT=$((WG_PORT_START + i))
    SERVER_IPV6="${WG_IPV6_SUBNET}$((i+1))/64"
    
    # 生成服务器密钥对
    umask 077
    SERVER_PRIVATE_KEY=$(wg genkey)
    SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | wg pubkey)
    
    # 创建 WireGuard 服务器配置文件（${WG_INTERFACE}.conf）
    SERVER_CONF="$WG_CONFIG_DIR/${WG_INTERFACE}.conf"
    cat > "$SERVER_CONF" <<EOL
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = $SERVER_IPV6
ListenPort = $LISTEN_PORT
PostUp = ip6tables -t nat -A POSTROUTING -o $DEFAULT_IF -j MASQUERADE
PostDown = ip6tables -t nat -D POSTROUTING -o $DEFAULT_IF -j MASQUERADE
EOL

    # 为对应客户端生成密钥对及配置
    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)
    CLIENT_IPV6="${WG_IPV6_SUBNET}$((i+2))/64"

    # 将客户端作为对等端添加到服务器配置中
    cat >> "$SERVER_CONF" <<EOL

[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $CLIENT_IPV6/128
EOL

    # 生成客户端配置文件（client_wgX.conf）
    CLIENT_CONF="$WG_CONFIG_DIR/client_${WG_INTERFACE}.conf"
    cat > "$CLIENT_CONF" <<EOL
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IPV6

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = ${PUBLIC_IP}:${LISTEN_PORT}
AllowedIPs = ::/0
PersistentKeepalive = 25
EOL

    # 启用并启动对应的 WireGuard 接口服务
    systemctl enable --now wg-quick@${WG_INTERFACE}
done

echo "WireGuard 安装和配置完成。客户端配置文件位于 $WG_CONFIG_DIR/client_*.conf"
