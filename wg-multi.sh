#!/bin/bash

# 定义配置目录
CONFIG_DIR="/etc/wireguard"
CLIENT_DIR="$CONFIG_DIR/clients"

# 检查root权限
if [ "$EUID" -ne 0 ]; then
    echo "请使用sudo或root用户运行此脚本"
    exit 1
fi

install_dependencies() {
    echo "正在安装依赖和配置系统..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update && apt-get install -y wireguard-tools iptables iptables-persistent sipcalc
    
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    
    sysctl_conf=("net.ipv4.ip_forward=1" "net.core.default_qdisc=fq" "net.ipv4.tcp_congestion_control=bbr")
    for param in "${sysctl_conf[@]}"; do
        grep -qxF "$param" /etc/sysctl.conf || echo "$param" >> /etc/sysctl.conf
    done
    sysctl -p
    echo "系统配置完成！"
}

# 创建配置目录
mkdir -p "$CLIENT_DIR"

# 生成唯一客户端IP
generate_client_ip() {
    subnet=$1
    existing_ips=($(grep AllowedIPs "$CONFIG_DIR/$2.conf" | awk '{print $3}' | cut -d'/' -f1))
    
    IFS='/' read -r base_ip cidr <<< "$subnet"
    network=$(sipcalc "$subnet" | grep "Network address" | awk '{print $4}')
    broadcast=$(sipcalc "$subnet" | grep "Broadcast address" | awk '{print $4}')
    
    for i in $(seq 2 254); do
        candidate_ip=$(echo $network | awk -F. -v i="$i" '{OFS="."; $4=i; print $0}')
        [[ "$candidate_ip" == "$broadcast" ]] && continue
        [[ " ${existing_ips[@]} " =~ " $candidate_ip " ]] || break
    done
    
    echo "$candidate_ip"
}

# 创建新接口
create_interface() {
    echo "正在创建新WireGuard接口..."
    
    read -p "输入接口名称 (例如 wg0): " iface
    read -p "输入公网出口接口 (例如 eth0): " ext_if
    read -p "输入监听端口 (默认 51620): " port
    read -p "输入内网CIDR (例如 10.10.0.1/24): " subnet
    read -p "输入默认NAT公网IP (留空则不设置): " nat_ip
    
    port=${port:-51820}
    server_private=$(wg genkey)
    server_public=$(echo $server_private | wg pubkey)
    
    # 生成配置文件
    cat > "$CONFIG_DIR/$iface.conf" <<EOF
[Interface]
Address = $(echo $subnet | cut -d/ -f1)
PrivateKey = $server_private
ListenPort = $port
EOF
    systemctl enable --now wg-quick@$iface
    echo "接口 $iface 创建成功！"
}

# 添加客户端
add_client() {
    echo "正在添加新客户端..."
    
    read -p "选择接口名称: " iface
    [ ! -f "$CONFIG_DIR/$iface.conf" ] && echo "接口不存在！" && exit 1
    
    read -p "输入客户端名称: " client_name
    read -p "自定义NAT公网IP (留空使用接口默认): " client_nat_ip
    read -p "自定义NAT端口范围 (例如 20000-30000): " client_ports
    
    # 获取接口信息
    subnet=$(grep '^Address' "$CONFIG_DIR/$iface.conf" | awk '{print $3}')
    server_public=$(grep 'PrivateKey' "$CONFIG_DIR/$iface.conf" | awk '{print $3}' | wg pubkey)
    listen_port=$(grep 'ListenPort' "$CONFIG_DIR/$iface.conf" | awk '{print $3}')
    ext_if=$(grep 'POSTROUTING' "$CONFIG_DIR/$iface.conf" | awk '{print $9}' | head -1)
    endpoint_ip=$(grep 'SNAT' "$CONFIG_DIR/$iface.conf" | awk '{print $12}' | cut -d':' -f1 | head -1)

    # 生成客户端配置
    client_ip=$(generate_client_ip $subnet $iface)
    client_private=$(wg genkey)
    client_public=$(echo $client_private | wg pubkey)
    client_cidr="$client_ip/32"

    # 添加Peer到服务端
    cat >> "$CONFIG_DIR/$iface.conf" <<EOF

[Peer]
# $client_name
PublicKey = $client_public
AllowedIPs = $client_cidr
EOF

    # 添加客户端NAT规则
    if [ -n "$client_nat_ip" ]; then
        rule_cmd="iptables -t nat -I POSTROUTING 1 -s $client_cidr -o $ext_if -j SNAT --to-source $client_nat_ip"
        [ -n "$client_ports" ] && rule_cmd+=" --to-ports $client_ports"
        
        sed -i "/PostUp/a $rule_cmd" "$CONFIG_DIR/$iface.conf"
        sed -i "/PostDown/a ${rule_cmd/ -I / -D }" "$CONFIG_DIR/$iface.conf"
    fi

    # 生成客户端文件
    mkdir -p "$CLIENT_DIR/$iface"
    cat > "$CLIENT_DIR/$iface/$client_name.conf" <<EOF
[Interface]
PrivateKey = $client_private
Address = $client_cidr
DNS = 8.8.8.8, 9.9.9.9

[Peer]
PublicKey = $server_public
Endpoint = ${endpoint_ip}:${listen_port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

    # 重新加载配置
    wg syncconf $iface <(wg-quick strip $iface)
    echo "客户端 $client_name 添加成功！"
    echo "配置文件路径：$CLIENT_DIR/$iface/$client_name.conf"
}

# 主菜单
PS3='请选择操作: '
options=("创建新接口" "添加客户端" "退出")
select opt in "${options[@]}"
do
    case $opt in
        "创建新接口")
            create_interface
            ;;
        "添加客户端")
            add_client
            ;;
        "退出")
            break
            ;;
        *) echo "无效选项";;
    esac
done

# 保存防火墙规则
iptables-save > /etc/iptables/rules.v4
echo "配置完成！所有更改已持久化"
