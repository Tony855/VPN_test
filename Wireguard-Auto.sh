#!/bin/bash

set -e

# 获取所有公共 IPv4 地址
PUBLIC_IPV4S=($(ip -4 addr show scope global | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+'))
if [[ ${#PUBLIC_IPV4S[@]} -eq 0 ]]; then
    echo "未找到公共 IPv4 地址，脚本退出。"
    exit 1
fi

# 配置变量
WG_CONFIG_DIR="/etc/wireguard"
WG_INTERFACE="wg0"
WG_PORT_START=52620  # 起始端口
CLIENT_COUNT=${#PUBLIC_IPV4S[@]}  # 客户端数量取决于可用IPv4

# 安装 WireGuard
if ! command -v wg &> /dev/null; then
    apt update && apt install -y wireguard
fi

# 清理旧配置
rm -rf "$WG_CONFIG_DIR"/*
mkdir -p "$WG_CONFIG_DIR"

# 生成服务器密钥对
umask 077
wg genkey | tee "$WG_CONFIG_DIR/server_private.key" | wg pubkey > "$WG_CONFIG_DIR/server_public.key"
SERVER_PRIVATE_KEY=$(cat "$WG_CONFIG_DIR/server_private.key")

# 创建 WireGuard 服务器配置
cat > "$WG_CONFIG_DIR/$WG_INTERFACE.conf" <<EOL
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = fd00::1/64
ListenPort = $WG_PORT_START
PostUp = ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
EOL

# 生成客户端配置
for i in "${!PUBLIC_IPV4S[@]}"; do
    CLIENT_IPv4=${PUBLIC_IPV4S[$i]}
    CLIENT_PORT=$((WG_PORT_START + i))
    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)
    CLIENT_IPv6="fd00::$(printf "%x" $((i + 2)))/64"
    
    # 添加到服务器配置
    cat >> "$WG_CONFIG_DIR/$WG_INTERFACE.conf" <<EOL

[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $CLIENT_IPv6/128
EOL

    # 生成客户端配置文件
    CLIENT_CONFIG="$WG_CONFIG_DIR/client_$i.conf"
    cat > "$CLIENT_CONFIG" <<EOL
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IPv6

[Peer]
PublicKey = $(cat "$WG_CONFIG_DIR/server_public.key")
Endpoint = $CLIENT_IPv4:$CLIENT_PORT
AllowedIPs = ::/0
PersistentKeepalive = 25
EOL

done

# 启动 WireGuard
systemctl enable --now wg-quick@$WG_INTERFACE

echo "WireGuard 安装和配置完成。客户端配置文件位于 $WG_CONFIG_DIR/client_*.conf"
