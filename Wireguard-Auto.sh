#!/bin/bash
# 修复版WireGuard自动配置脚本 v2.1

#====================== 初始化设置 ======================#
WG_DIR="/etc/wireguard"
DEFAULT_DNS="8.8.8.8,8.8.4.4"
MAIN_IFACE=$(ip route | awk '/default/{print $5;exit}')  # 动态获取主接口
declare -a PUBLIC_IPS

#====================== 核心函数 ======================#
die() { echo -e "\033[31m错误: $1\033[0m" >&2; exit 1; }

check_root() {
    [ "$(id -u)" -ne 0 ] && die "必须使用root权限运行"
}

install_deps() {
    echo "▶ 正在安装系统依赖..."
    if command -v apt-get &>/dev/null; then
        apt-get update || die "更新软件源失败"
        apt-get install -y --no-install-recommends \
            wireguard-tools qrencode iptables \
            || die "安装依赖失败"
    elif command -v yum &>/dev/null; then
        yum install -y epel-release || die "EPEL源安装失败"
        yum install -y wireguard-tools qrencode || die "安装依赖失败"
    else
        die "不支持的包管理器"
    fi
}

detect_public_ips() {
    echo "▶ 检测公网IP地址..."
    # 方法1：检测本地非私有IP
    mapfile -t LOCAL_IPS < <(ip -4 addr | awk '/inet /{print $2}' | cut -d/ -f1)
    for ip in "${LOCAL_IPS[@]}"; do
        if [[ ! $ip =~ ^10\. && ! $ip =~ ^172\.(1[6-9]|2[0-9]|3[0-1]) && ! $ip =~ ^192\.168 ]]; then
            PUBLIC_IPS+=("$ip")
        fi
    done

    # 方法2：通过外部API获取
    if [ ${#PUBLIC_IPS[@]} -eq 0 ]; then
        API_IP=$(curl -4s icanhazip.com)
        [ -n "$API_IP" ] && PUBLIC_IPS+=("$API_IP") || die "公网IP检测失败"
    fi
    
    echo "✅ 检测到公网IP：${PUBLIC_IPS[*]}"
}

init_wg_config() {
    echo "▶ 初始化WireGuard配置..."
    mkdir -p "$WG_DIR" || die "无法创建配置目录"
    local PORT=51620
    
    for idx in "${!PUBLIC_IPS[@]}"; do
        local IFACE="wg${idx}"
        local CONF="${WG_DIR}/${IFACE}.conf"
        
        # 生成服务端密钥
        local SERVER_PRIVKEY=$(wg genkey)
        local SERVER_PUBKEY=$(wg pubkey <<< "$SERVER_PRIVKEY")
        
        # 生成配置文件
        cat > "$CONF" << EOF
[Interface]
Address = 10.29.29.1/24
PrivateKey = $SERVER_PRIVKEY
ListenPort = $((PORT + idx))
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $MAIN_IFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $MAIN_IFACE -j MASQUERADE
# PublicIP = ${PUBLIC_IPS[$idx]}
EOF
        
        chmod 600 "$CONF"
        systemctl enable --now "wg-quick@${IFACE}.service" || die "启动服务失败"
        echo "✅ 接口 ${IFACE} 配置完成"
    done
}

add_client() {
    [ $# -lt 2 ] && die "用法: $0 add <接口> <客户端名> [DNS]"
    local IFACE="$1" CLIENT="$2" DNS="${3:-$DEFAULT_DNS}"
    local CONF="${WG_DIR}/${IFACE}.conf"
    
    [ -f "$CONF" ] || die "接口配置 $CONF 不存在"
    
    # 计算客户端序号
    local CLIENT_COUNT=$(grep -c '^# BEGIN_PEER' "$CONF")
    local OCTET=$((254 - CLIENT_COUNT))
    [ $OCTET -lt 2 ] && die "IP地址池已耗尽"
    
    # 生成客户端密钥
    local CLIENT_PRIVKEY=$(wg genkey)
    local CLIENT_PUBKEY=$(wg pubkey <<< "$CLIENT_PRIVKEY")
    local PSK=$(wg genpsk)
    
    # 更新服务端配置
    cat >> "$CONF" << EOF

# BEGIN_PEER $CLIENT
[Peer]
PublicKey = $CLIENT_PUBKEY
PresharedKey = $PSK
AllowedIPs = 10.29.29.$OCTET/32
# END_PEER $CLIENT
EOF
    
    # 生成客户端配置
    mkdir -p "${WG_DIR}/clients"
    local CLIENT_CONF="${WG_DIR}/clients/${CLIENT}.conf"
    cat > "$CLIENT_CONF" << EOF
[Interface]
PrivateKey = $CLIENT_PRIVKEY
Address = 10.29.29.$OCTET/24
DNS = $DNS

[Peer]
PublicKey = $(wg pubkey <<< "$(awk '/PrivateKey/{print $3}' "$CONF")")
PresharedKey = $PSK
Endpoint = $(awk -F' = ' '/# PublicIP/{print $2}' "$CONF"):$(awk '/ListenPort/{print $3}' "$CONF")
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
    
    echo -e "\033[32m✔ 客户端 ${CLIENT} 已创建: ${CLIENT_CONF}\033[0m"
}

#====================== 主流程 ======================#
case "$1" in
    install)
        check_root
        install_deps
        detect_public_ips
        init_wg_config
        ;;
    add)
        check_root
        add_client "$2" "$3" "$4"
        ;;
    *)
        cat << EOF
WireGuard管理脚本 v2.1
命令:
  install  初始化安装
  add     添加客户端 (示例: $0 add wg0 client1)
EOF
        ;;
esac
