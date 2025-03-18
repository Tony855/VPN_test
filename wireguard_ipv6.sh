#!/bin/bash

# 定义配置目录和IP池文件
CONFIG_DIR="/etc/wireguard"
CLIENT_DIR="$CONFIG_DIR/clients"
PUBLIC_IP_FILE="$CONFIG_DIR/public_ips.txt"
PUBLIC_IP6_FILE="$CONFIG_DIR/public_ip6s.txt"
USED_IP_FILE="$CONFIG_DIR/used_ips.txt"
USED_IP6_FILE="$CONFIG_DIR/used_ip6s.txt"

# 检查root权限
if [ "$EUID" -ne 0 ]; then
    echo "请使用sudo或root用户运行此脚本"
    exit 1
fi

# ========================
# 依赖安装函数
# ========================
install_dependencies() {
    echo "正在安装依赖和配置系统..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update && apt-get install -y wireguard-tools iptables iptables-persistent sipcalc qrencode curl

    # 自动保存iptables规则
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

    # 配置sysctl参数
    sysctl_conf=(
        "net.ipv4.ip_forward=1"
        "net.ipv6.conf.all.forwarding=1"
        "net.core.default_qdisc=fq"
        "net.ipv4.tcp_congestion_control=bbr"
    )
    for param in "${sysctl_conf[@]}"; do
        grep -qxF "$param" /etc/sysctl.conf || echo "$param" >> /etc/sysctl.conf
    done
    sysctl -p >/dev/null 2>&1
    echo "系统配置完成！"
}

# ========================
# IP池管理功能
# ========================
init_ip_pool() {
    # IPv4池初始化
    if [ ! -f "$PUBLIC_IP_FILE" ]; then
        echo "错误: 公网IPv4池文件不存在！"
        echo "请先创建 $PUBLIC_IP_FILE"
        exit 1
    fi
    touch "$USED_IP_FILE" 2>/dev/null || :

    # IPv6池初始化
    if [ ! -f "$PUBLIC_IP6_FILE" ]; then
        echo "错误: 公网IPv6池文件不存在！"
        echo "请先创建 $PUBLIC_IP6_FILE"
        exit 1
    fi
    touch "$USED_IP6_FILE" 2>/dev/null || :
}

get_available_ip() {
    local pool_file=$1
    local used_file=$2
    while read -r ip; do
        if ! grep -qxF "$ip" "$used_file"; then
            echo "$ip"
            return 0
        fi
    done < "$pool_file"
    echo "错误: 所有公网IP已分配完毕（$pool_file）"
    return 1
}

mark_ip_used() {
    local ip=$1
    local used_file=$2
    echo "$ip" >> "$used_file"
}

rollback_ip_allocation() {
    local ip=$1
    local used_file=$2
    sed -i "/^$ip$/d" "$used_file" 2>/dev/null
}

# ========================
# 核心功能
# ========================
validate_subnet() {
    local subnet=$1
    if [[ "$subnet" == *:* ]]; then
        sipcalc "$subnet" >/dev/null 2>&1 || { echo "错误: 无效的IPv6子网格式"; return 1; }
    else
        sipcalc "$subnet" >/dev/null 2>&1 || { echo "错误: 无效的IPv4子网格式"; return 1; }
    fi
    return 0
}

generate_client_ip() {
    local subnet=$1
    local config_file=$2
    local existing_ips=($(grep AllowedIPs "$CONFIG_DIR/$config_file.conf" 2>/dev/null | awk '{print $3}' | cut -d'/' -f1))

    if [[ "$subnet" == *:* ]]; then
        # IPv6地址分配
        network_info=$(sipcalc "$subnet")
        network_start=$(echo "$network_info" | grep "Expanded address" | awk '{print $4}')
        prefix_length=$(echo "$subnet" | cut -d'/' -f2)

        # 生成随机后缀（避免冲突）
        for _ in {1..10}; do
            suffix=$(od -An -N8 -tx8 /dev/urandom | tr -d ' ' | sed 's/^0000//')
            candidate_ip="${network_start%::*}::${suffix:0:4}:${suffix:4:4}"
            candidate_ip=$(echo "$candidate_ip" | sed 's/:0*/:/g; s/::*/::/g')
            if ! [[ " ${existing_ips[@]} " =~ " $candidate_ip " ]]; then
                echo "$candidate_ip"
                return 0
            fi
        done
        echo "错误: IPv6子网中没有可用地址"
        return 1
    else
        # IPv4地址分配
        network_info=$(sipcalc "$subnet")
        network_start=$(echo "$network_info" | grep "Network address" | awk '{print $4}')
        IFS='.' read -r a b c d <<< "$network_start"
        for i in $(seq 2 254); do
            candidate_ip="$a.$b.$c.$((d + i))"
            [[ " ${existing_ips[@]} " =~ " $candidate_ip " ]] || break
        done
        echo "$candidate_ip"
    fi
}

get_available_port() {
    base_port=51620
    while :; do
        if ! ss -uln | grep -q ":$base_port "; then
            echo $base_port
            break
        fi
        ((base_port++))
    done
}

create_interface() {
    init_ip_pool
    echo "正在创建新WireGuard接口..."

    # 分配公网IP
    public_ip4=$(get_available_ip "$PUBLIC_IP_FILE" "$USED_IP_FILE") || { echo "$public_ip4"; return 1; }
    public_ip6=$(get_available_ip "$PUBLIC_IP6_FILE" "$USED_IP6_FILE") || { echo "$public_ip6"; return 1; }
    mark_ip_used "$public_ip4" "$USED_IP_FILE"
    mark_ip_used "$public_ip6" "$USED_IP6_FILE"

    # 输入子网
    while true; do
        read -p "输入IPv4子网（如 10.10.0.0/24）: " subnet4
        validate_subnet "$subnet4" && break
    done
    while true; do
        read -p "输入IPv6子网（如 fd00:1234::/64）: " subnet6
        validate_subnet "$subnet6" && break
    done

    # 生成网关地址
    gateway_ip4=$(sipcalc "$subnet4" | grep "Host address" | awk '{print $4}')
    gateway_ip6=$(sipcalc "$subnet6" | grep "Expanded address" | awk '{print $4}' | sed 's/::1$/::1/')

    # 接口命名
    existing_interfaces=$(ls "$CONFIG_DIR"/wg*.conf 2>/dev/null | sed 's/.*wg\([0-9]\+\).conf/\1/' | sort -n)
    max_interface=$(echo "$existing_interfaces" | tail -n 1)
    [ -z "$max_interface" ] && max_interface=-1
    new_interface=$((max_interface + 1))
    default_iface="wg${new_interface}"

    read -p "输入接口名称（默认 $default_iface）: " iface
    iface=${iface:-$default_iface}

    [[ "$iface" =~ [^a-zA-Z0-9] ]] && {
        rollback_ip_allocation "$public_ip4" "$USED_IP_FILE"
        rollback_ip_allocation "$public_ip6" "$USED_IP6_FILE"
        echo "错误: 接口名称非法"
        return 1
    }
    [ -f "$CONFIG_DIR/$iface.conf" ] && {
        rollback_ip_allocation "$public_ip4" "$USED_IP_FILE"
        rollback_ip_allocation "$public_ip6" "$USED_IP6_FILE"
        echo "错误: 接口已存在"
        return 1
    }

    ext_if=$(ip route show default | awk '/default/ {print $5}' | head -1)
    [ -z "$ext_if" ] && {
        rollback_ip_allocation "$public_ip4" "$USED_IP_FILE"
        rollback_ip_allocation "$public_ip6" "$USED_IP6_FILE"
        echo "错误: 未找到默认出口接口"
        return 1
    }

    port=$(get_available_port)
    server_private=$(wg genkey)
    server_public=$(echo "$server_private" | wg pubkey)

    # 生成配置文件
    cat > "$CONFIG_DIR/$iface.conf" <<EOF
[Interface]
Address = $gateway_ip4/$(echo "$subnet4" | cut -d'/' -f2), $gateway_ip6/$(echo "$subnet6" | cut -d'/' -f2)
PrivateKey = $server_private
ListenPort = $port

# IPv4 NAT规则
PostUp = iptables -t nat -A POSTROUTING -s $subnet4 -o $ext_if -j SNAT --to-source $public_ip4
PostDown = iptables -t nat -D POSTROUTING -s $subnet4 -o $ext_if -j SNAT --to-source $public_ip4

# IPv6 NAT规则
PostUp = ip6tables -t nat -A POSTROUTING -s $subnet6 -o $ext_if -j SNAT --to-source $public_ip6
PostDown = ip6tables -t nat -D POSTROUTING -s $subnet6 -o $ext_if -j SNAT --to-source $public_ip6
EOF

    chmod 600 "$CONFIG_DIR/$iface.conf"

    if systemctl enable --now "wg-quick@$iface" &>/dev/null; then
        echo "接口 $iface 创建成功！"
        echo "分配公网IPv4: $public_ip4"
        echo "分配公网IPv6: $public_ip6"
        echo "内网IPv4子网: $subnet4"
        echo "内网IPv6子网: $subnet6"
    else
        rollback_ip_allocation "$public_ip4" "$USED_IP_FILE"
        rollback_ip_allocation "$public_ip6" "$USED_IP6_FILE"
        echo "错误: 服务启动失败"
        return 1
    fi
}

add_client() {
    echo "正在添加新客户端..."

    latest_iface=$(ls -t "$CONFIG_DIR"/*.conf | xargs -n1 basename | cut -d. -f1 | head -1)
    [ -z "$latest_iface" ] && { echo "错误: 没有可用接口"; return 1; }

    read -p "选择接口（默认 $latest_iface）: " iface
    iface=${iface:-$latest_iface}
    [ ! -f "$CONFIG_DIR/$iface.conf" ] && { echo "错误: 接口不存在"; return 1; }

    # 提取配置信息
    subnet4=$(grep 'PostUp.*iptables' "$CONFIG_DIR/$iface.conf" | grep -m1 'SNAT' | awk '{print $8}')
    subnet6=$(grep 'PostUp.*ip6tables' "$CONFIG_DIR/$iface.conf" | grep -m1 'SNAT' | awk '{print $8}')
    public_ip4=$(grep 'SNAT' "$CONFIG_DIR/$iface.conf" | grep 'iptables' | awk '{print $NF}' | head -1)
    public_ip6=$(grep 'SNAT' "$CONFIG_DIR/$iface.conf" | grep 'ip6tables' | awk '{print $NF}' | head -1)

    # 生成客户端IP
    client_ip4=$(generate_client_ip "$subnet4" "$iface") || { echo "$client_ip4"; return 1; }
    client_ip6=$(generate_client_ip "$subnet6" "$iface") || { echo "$client_ip6"; return 1; }

    # 客户端命名
    client_count=$(ls "$CLIENT_DIR/$iface"/*.conf 2>/dev/null | wc -l)
    default_name="client$((client_count + 1))"
    read -p "输入客户端名称（默认 $default_name）: " client_name
    client_name=${client_name:-$default_name}
    [[ "$client_name" =~ [/\\] ]] && { echo "错误: 名称含非法字符"; return 1; }

    # 生成密钥
    client_private=$(wg genkey)
    client_public=$(echo "$client_private" | wg pubkey)
    client_preshared=$(wg genpsk)

    # 更新服务端配置
    cat >> "$CONFIG_DIR/$iface.conf" <<EOF

[Peer]
# $client_name
PublicKey = $client_public
PresharedKey = $client_preshared
AllowedIPs = $client_ip4/32, $client_ip6/128
EOF

    # 生成客户端配置
    mkdir -p "$CLIENT_DIR/$iface"
    client_file="$CLIENT_DIR/$iface/$client_name.conf"
    cat > "$client_file" <<EOF
[Interface]
PrivateKey = $client_private
Address = $client_ip4/$(echo "$subnet4" | cut -d'/' -f2), $client_ip6/$(echo "$subnet6" | cut -d'/' -f2)
DNS = 2001:4860:4860::8888, 8.8.8.8

[Peer]
PublicKey = $(wg pubkey < <(grep 'PrivateKey' "$CONFIG_DIR/$iface.conf" | awk '{print $3}'))
PresharedKey = $client_preshared
Endpoint = [$public_ip6]:$(grep ListenPort "$CONFIG_DIR/$iface.conf" | awk '{print $3}')
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

    # 生成二维码
    qrencode -t ansiutf8 < "$client_file"
    qrencode -o "${client_file}.png" < "$client_file"

    systemctl restart "wg-quick@$iface" &>/dev/null || wg syncconf "$iface" <(wg-quick strip "$iface")
    echo "客户端 $client_name 添加成功！双栈配置已生成：$client_file"
}

uninstall_wireguard() {
    read -p "确定要完全卸载WireGuard吗？(y/N) " confirm
    [[ ! $confirm =~ ^[Yy]$ ]] && return

    echo "正在卸载WireGuard..."
    find "$CONFIG_DIR" -name '*.conf' -exec basename {} .conf \; | while read -r iface; do
        systemctl stop "wg-quick@$iface"
    done

    rm -rf "$CONFIG_DIR"
    apt-get purge -y wireguard-tools iptables-persistent qrencode

    iptables -F
    iptables -t nat -F
    ip6tables -F
    ip6tables -t nat -F

    echo "WireGuard已完全卸载"
}

# ========================
# 主菜单
# ========================
main_menu() {
    PS3='请选择操作: '
    options=("安装依赖" "创建接口" "添加客户端" "完全卸载" "退出")
    select opt in "${options[@]}"; do
        case $opt in
            "安装依赖") install_dependencies ;;
            "创建接口") create_interface ;;
            "添加客户端") add_client ;;
            "完全卸载") uninstall_wireguard ;;
            "退出")
                iptables-save > /etc/iptables/rules.v4
                ip6tables-save > /etc/iptables/rules.v6
                echo "配置已保存，再见！"
                break ;;
            *) echo "无效选项" ;;
        esac
    done
}

mkdir -p "$CLIENT_DIR"
main_menu
