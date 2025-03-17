#!/bin/bash

# 定义配置目录和IP池文件
CONFIG_DIR="/etc/wireguard"
CLIENT_DIR="$CONFIG_DIR/clients"
PUBLIC_IP_FILE="$CONFIG_DIR/public_ips.txt"
USED_IP_FILE="$CONFIG_DIR/used_ips.txt"

# 检查root权限
if [ "$EUID" -ne 0 ]; then
    echo "请使用sudo或root用户运行此脚本"
    exit 1
fi

# ========================
# 依赖安装函数（修正位置）
# ========================
install_dependencies() {
    echo "正在安装依赖和配置系统..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update && apt-get install -y wireguard-tools iptables iptables-persistent sipcalc qrencode curl
    
    # 自动保存iptables规则
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    
    # 配置sysctl参数
    sysctl_conf=("net.ipv4.ip_forward=1" "net.core.default_qdisc=fq" "net.ipv4.tcp_congestion_control=bbr")
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
    if [ ! -f "$PUBLIC_IP_FILE" ]; then
        echo "错误: 公网IP池文件不存在！"
        echo "请先创建 $PUBLIC_IP_FILE"
        echo "文件格式：每行一个公网IP地址"
        exit 1
    fi
    touch "$USED_IP_FILE" 2>/dev/null || :
}

get_available_public_ip() {
    while read -r ip; do
        if ! grep -qxF "$ip" "$USED_IP_FILE"; then
            echo "$ip"
            return 0
        fi
    done < "$PUBLIC_IP_FILE"
    
    echo "错误: 所有公网IP已分配完毕"
    return 1
}

mark_ip_used() {
    echo "$1" >> "$USED_IP_FILE"
}

rollback_ip_allocation() {
    sed -i "/^$1$/d" "$USED_IP_FILE" 2>/dev/null
}

# ========================
# 核心功能
# ========================
generate_client_ip() {
    local subnet=$1
    local config_file=$2
    local existing_ips=($(grep AllowedIPs "$CONFIG_DIR/$config_file.conf" 2>/dev/null | awk '{print $3}' | cut -d'/' -f1))
    
    local network_info=$(sipcalc "$subnet" 2>/dev/null)
    local network=$(echo "$network_info" | grep "Network address" | awk '{print $4}')
    local broadcast=$(echo "$network_info" | grep "Broadcast address" | awk '{print $4}')
    
    for i in $(seq 2 254); do
        candidate_ip=$(echo "$network" | awk -F. -v i="$i" '{OFS="."; $4=i; print $0}')
        [[ "$candidate_ip" == "$broadcast" ]] && continue
        [[ " ${existing_ips[@]} " =~ " $candidate_ip " ]] || break
    done
    
    echo "$candidate_ip"
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
    
    public_ip=$(get_available_public_ip) || { echo "$public_ip"; return 1; }
    mark_ip_used "$public_ip"
    
    # 计算新接口编号
    existing_interfaces=$(ls "$CONFIG_DIR"/wg*.conf 2>/dev/null | sed 's/.*wg\([0-9]\+\).conf/\1/' 2>/dev/null | sort -n)
    max_interface=$(echo "$existing_interfaces" | tail -n 1)
    [ -z "$max_interface" ] && max_interface=-1
    new_interface=$((max_interface + 1))

    default_iface="wg${new_interface}"
    read -p "输入接口名称（默认 $default_iface）: " iface
    iface=${iface:-$default_iface}
    
    [[ "$iface" =~ [^a-zA-Z0-9] ]] && { echo "错误: 接口名称非法"; rollback_ip_allocation "$public_ip"; return 1; }
    [ -f "$CONFIG_DIR/$iface.conf" ] && { echo "错误: 接口已存在"; rollback_ip_allocation "$public_ip"; return 1; }

    ext_if=$(ip route show default | awk '/default/ {print $5}' | head -1)
    [ -z "$ext_if" ] && { echo "错误: 未找到默认出口接口"; rollback_ip_allocation "$public_ip"; return 1; }

    port=$(get_available_port)
    subnet="10.10.${new_interface}.0/24"  # 修正为正确子网

    server_private=$(wg genkey)
    server_public=$(echo "$server_private" | wg pubkey)

    cat > "$CONFIG_DIR/$iface.conf" <<EOF
[Interface]
Address = 10.10.${new_interface}.1  # 子网网关
PrivateKey = $server_private
ListenPort = $port

# NAT规则（仅处理无独立IP的客户端）
PostUp = iptables -t nat -A POSTROUTING -s 10.10.${new_interface}.0/24 -o $ext_if -j SNAT --to-source $public_ip
PostDown = iptables -t nat -D POSTROUTING -s 10.10.${new_interface}.0/24 -o $ext_if -j SNAT --to-source $public_ip
EOF

    chmod 600 "$CONFIG_DIR/$iface.conf"

    if systemctl enable --now "wg-quick@$iface" &>/dev/null; then
        echo "接口 $iface 创建成功！"
        echo "分配公网IP: $public_ip"
        echo "内网子网: 10.10.${new_interface}.0/24"
    else
        rollback_ip_allocation "$public_ip"
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

    ext_if=$(grep 'POSTROUTING' "$CONFIG_DIR/$iface.conf" | awk '{print $9}' | head -1)
    public_ip=$(grep 'SNAT' "$CONFIG_DIR/$iface.conf" | awk '{print $NF}' | head -1 | tr -d '\r\n')
    subnet=$(grep '^Address' "$CONFIG_DIR/$iface.conf" | awk '{print $3}')

    client_count=$(ls "$CLIENT_DIR/$iface"/*.conf 2>/dev/null | wc -l)
    default_name="client$((client_count + 1))"
    
    read -p "输入客户端名称（默认 $default_name）: " client_name
    client_name=${client_name:-$default_name}
    [[ "$client_name" =~ [/\\] ]] && { echo "错误: 名称含非法字符"; return 1; }

    client_ip=$(generate_client_ip "$subnet" "$iface")
    client_private=$(wg genkey)
    client_public=$(echo "$client_private" | wg pubkey)
    client_preshared=$(wg genpsk)  # 生成PresharedKey

    cat >> "$CONFIG_DIR/$iface.conf" <<EOF

[Peer]
# $client_name
PublicKey = $client_public
PresharedKey = $client_preshared
AllowedIPs = $client_ip/32
EOF

    read -p "是否为该客户端指定独立公网IP？(y/N) " custom_ip
    if [[ $custom_ip =~ ^[Yy]$ ]]; then
        read -p "输入自定义公网IP: " client_nat_ip
        rule_cmd="iptables -t nat -I POSTROUTING 1 -s $client_ip/24 -o $ext_if -j MASQUERADE --to-source $client_nat_ip"
        post_down_cmd="iptables -t nat -D POSTROUTING -s $client_ip/24 -o $ext_if -j SNAT --to-source $client_nat_ip"
        
        sed -i "/PostUp/a $rule_cmd" "$CONFIG_DIR/$iface.conf"
        sed -i "/PostDown/a $post_down_cmd" "$CONFIG_DIR/$iface.conf"
        
        eval "$rule_cmd"  # 立即生效新增规则
    fi

    mkdir -p "$CLIENT_DIR/$iface"
    client_file="$CLIENT_DIR/$iface/$client_name.conf"
    cat > "$client_file" <<EOF
[Interface]
PrivateKey = $client_private
Address = $client_ip/24
DNS = 8.8.8.8, 9.9.9.9

[Peer]
PublicKey = $(grep 'PrivateKey' "$CONFIG_DIR/$iface.conf" | awk '{print $3}' | wg pubkey)
PresharedKey = $client_preshared
Endpoint = $(echo "$public_ip" | tr -d '\r'):$(grep ListenPort "$CONFIG_DIR/$iface.conf" | awk '{print $3}')
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

    qrencode -t ansiutf8 < "$client_file"
    qrencode -o "${client_file}.png" < "$client_file"

    # 重启接口以确保配置生效
    if systemctl restart "wg-quick@$iface" &>/dev/null; then
        echo "接口 $iface 已重启"
    else
        echo "警告: 接口重启失败，尝试动态加载配置..."
        wg syncconf "$iface" <(wg-quick strip "$iface")
    fi

    echo "客户端 $client_name 添加成功！"
    echo "出口公网IP: ${client_nat_ip:-$public_ip}"
    echo "配置文件路径：$client_file"
    echo "二维码文件：${client_file}.png"
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
    
    echo "WireGuard已完全卸载"
}

# ========================
# 主菜单（确保函数已定义）
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
                echo "配置已保存，再见！"
                break ;;
            *) echo "无效选项" ;;
        esac
    done
}

# 初始化目录并启动
mkdir -p "$CLIENT_DIR"
main_menu
