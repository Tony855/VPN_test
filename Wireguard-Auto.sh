#!/bin/bash
#
# 修复版WireGuard全自动配置脚本
# 更新内容：
# 1. 增强IP检测可靠性
# 2. 添加依赖安装验证
# 3. 自动适配网络接口名称
# 4. 修复客户端生成逻辑

exiterr()  { echo "错误: $1" >&2; exit 1; }
check_root() { [ "$(id -u)" -ne 0 ] && exiterr "请使用root权限执行脚本"; }

#====================== 初始化配置 ======================#
WG_DIR="/etc/wireguard"
DEFAULT_DNS="8.8.8.8,8.8.4.4"
MAIN_IFACE=$(ip route | awk '/default/ {print $5}' | head -1)  # 自动获取主接口

#====================== 核心函数 ======================#
install_deps() {
    echo "正在安装系统依赖..."
    if command -v apt-get >/dev/null; then
        apt-get update
        apt-get install -y wireguard-tools qrencode iptables || exiterr "依赖安装失败"
    elif command -v yum >/dev/null; then
        yum install -y epel-release
        yum install -y wireguard-tools qrencode || exiterr "依赖安装失败"
    else
        exiterr "不支持的Linux发行版"
    fi
}

get_public_ips() {
    echo "检测公网IP地址..."
    ips=()
    # 方法1：检测本地非私有IP
    while read -r ip; do
        [[ $ip =~ ^10\. ]] || [[ $ip =~ ^172\.(1[6-9]|2[0-9]|3[0-1]) ]] || [[ $ip =~ ^192\.168 ]] || continue
        ips+=("$ip")
    done < <(ip -4 addr | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)

    # 方法2：通过API获取
    [ ${#ips[@]} -eq 0 ] && {
        public_ip=$(curl -4s icanhazip.com)
        [ -z "$public_ip" ] && exiterr "公网IP检测失败"
        ips+=("$public_ip")
    }
    
    echo "检测到公网IP：${ips[*]}"
}

create_wg_config() {
    echo "正在生成WireGuard配置..."
    mkdir -p $WG_DIR
    port=51620
    
    for idx in "${!ips[@]}"; do
        interface="wg${idx}"
        conf_file="${WG_DIR}/${interface}.conf"
        
        cat << EOF > "$conf_file"
[Interface]
Address = 10.29.29.1/24
PrivateKey = $(wg genkey)
ListenPort = $((port + idx))
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $MAIN_IFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $MAIN_IFACE -j MASQUERADE
# PublicIP = ${ips[$idx]}
EOF

        chmod 600 "$conf_file"
        systemctl enable --now wg-quick@${interface}.service
    done
}

add_client() {
    [ $# -lt 2 ] && exiterr "用法: $0 add <接口> <客户端名> [DNS]"
    interface=$1
    client=$2
    dns=${3:-$DEFAULT_DNS}
    conf_file="${WG_DIR}/${interface}.conf"
    
    [ ! -f "$conf_file" ] && exiterr "接口 $interface 不存在"

    # 计算客户端IP
    client_count=$(grep -c '^# BEGIN_PEER' "$conf_file")
    octet=$((254 - client_count))
    client_ip="10.29.29.$octet"

    # 生成密钥
    client_privkey=$(wg genkey)
    client_pubkey=$(wg pubkey <<< "$client_privkey")
    psk=$(wg genpsk)

    # 更新服务端配置
    cat << EOF >> "$conf_file"

# BEGIN_PEER $client
[Peer]
PublicKey = $client_pubkey
PresharedKey = $psk
AllowedIPs = $client_ip/32
# END_PEER $client
EOF

    # 生成客户端配置
    mkdir -p "${WG_DIR}/clients"
    cat << EOF > "${WG_DIR}/clients/${client}.conf"
[Interface]
PrivateKey = $client_privkey
Address = $client_ip/24
DNS = $dns

[Peer]
PublicKey = $(grep PrivateKey "$conf_file" | awk '{print $3}' | wg pubkey)
PresharedKey = $psk
Endpoint = $(grep '# PublicIP' "$conf_file" | awk '{print $3}'):$(grep ListenPort "$conf_file" | awk '{print $3}')
AllowedIPs = 0.0.0.0/0,::/0
PersistentKeepalive = 25
EOF

    echo "客户端 $client 已创建：${WG_DIR}/clients/${client}.conf"
}

#====================== 主流程 ======================#
case "$1" in
    install)
        check_root
        install_deps
        get_public_ips
        create_wg_config
        echo "安装成功！已创建 ${#ips[@]} 个WireGuard接口"
        ;;
    add)
        check_root
        add_client "$2" "$3" "$4"
        ;;
    *)
        cat << EOF
WireGuard管理脚本
用法:
  $0 install     初始化安装
  $0 add <接口> <客户端名> [DNS]  添加客户端
示例:
  $0 install
  $0 add wg0 myclient
  $0 add wg0 workpc 1.1.1.1
EOF
        ;;
esac
