#!/bin/bash

# 定义配置目录
CONFIG_DIR="/etc/wireguard"
CLIENT_DIR="$CONFIG_DIR/clients"

# 检查root权限
if [ "$EUID" -ne 0 ]; then
    echo "请使用sudo或root用户运行此脚本"
    exit 1
fi

# 安装依赖和系统配置
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

# 通用输入函数
input_with_default() {
    local prompt=$1
    local default=$2
    read -p "$prompt (默认：$default): " value
    echo "${value:-$default}"
}

# 生成唯一客户端IP
generate_client_ip() {
    subnet=$1
    existing_ips=($(grep AllowedIPs "$CONFIG_DIR/${2}.conf" | awk '{print $3}' | cut -d'/' -f1))
    
    IFS='/' read -r base_ip cidr <<< "$subnet"
    network=$(sipcalc "$subnet" | grep "Network address" -m1 | awk '{print $4}')
    broadcast=$(sipcalc "$subnet" | grep "Broadcast address" -m1 | awk '{print $4}')
    
    for i in $(seq 2 254); do
        candidate_ip="${network%.*}.$i"
        [[ "$candidate_ip" != "$broadcast" && ! " ${existing_ips[@]} " =~ " $candidate_ip " ]] && break
    done
    
    echo "$candidate_ip"
}

# 创建新接口
create_interface() {
    echo "正在创建新WireGuard接口..."
    iface=$(input_with_default "输入接口名称" "wg0")
    ext_if=$(input_with_default "输入公网出口接口" "eth0")
    port=$(input_with_default "输入监听端口" "56120")
    subnet=$(input_with_default "输入内网CIDR" "10.10.0.1/24")
    nat_ip=$(input_with_default "输入默认NAT公网IP" "")
    
    server_private=$(wg genkey)
    server_public=$(wg pubkey <<< "$server_private")
    base_ip=$(cut -d/ -f1 <<< "$subnet")
    
    cat > "$CONFIG_DIR/$iface.conf" <<EOF
[Interface]
Address = $base_ip/24
PrivateKey = $server_private
ListenPort = $port
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT
EOF

    [ -n "$nat_ip" ] && {
        echo "PostUp = iptables -t nat -A POSTROUTING -o $ext_if -j SNAT --to-source $nat_ip" >> "$CONFIG_DIR/$iface.conf"
        echo "PostDown = iptables -t nat -D POSTROUTING -o $ext_if -j SNAT --to-source $nat_ip" >> "$CONFIG_DIR/$iface.conf"
    }

    systemctl enable --now "wg-quick@$iface" && echo "接口 $iface 创建成功！"
    echo "# Last Peer" >> "$CONFIG_DIR/$iface.conf"
}

# 添加客户端（关键修正部分）
add_client() {
    echo "已存在接口: $(ls $CONFIG_DIR/*.conf | xargs -n1 basename | sed 's/.conf//')"
    iface=$(input_with_default "选择接口名称" "wg0")
    [ ! -f "$CONFIG_DIR/$iface.conf" ] && echo "接口不存在！" && exit 1
    
    client_name=$(input_with_default "输入客户端名称" "client_$(date +%s)")
    
    # 自动获取公网信息（增强检测）
    auto_ext_if=$(ip route show default | awk '/default/ {print $5}' | head -1)
    auto_endpoint_ip=$(
        curl -4 --max-time 3 -s ifconfig.me || 
        curl -4 --max-time 3 -s icanhazip.com || 
        curl -4 --max-time 3 -s ipinfo.io/ip || 
        dig +short myip.opendns.com @resolver1.opendns.com || 
        echo "NONE"
    )
    
    subnet=$(awk -F' = ' '/Address/{print $2}' "$CONFIG_DIR/$iface.conf")
    listen_port=$(awk -F' = ' '/ListenPort/{print $2}' "$CONFIG_DIR/$iface.conf")
    server_public=$(awk -F' = ' '/PrivateKey/{print $2 | "wg pubkey"}' "$CONFIG_DIR/$iface.conf")
    
    auto_nat_ip=$(awk '/SNAT/ && /PostUp/ {print $13}' "$CONFIG_DIR/$iface.conf" | cut -d':' -f1 | head -1)
    [ -z "$auto_nat_ip" ] && auto_nat_ip=$auto_endpoint_ip
    
    echo "自动检测到以下配置："
    echo "公网出口接口: $auto_ext_if"
    echo "公网IP地址: $auto_endpoint_ip"
    echo "内网子网: $subnet"
    
    if [ "$auto_endpoint_ip" = "NONE" ]; then
        echo "警告：无法自动检测公网IP！"
        while true; do
            auto_endpoint_ip=$(input_with_default "输入服务器公网IP" "")
            # 添加IP格式验证逻辑
            if [[ "$auto_endpoint_ip" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})$ ]]; then
                break
            else
                echo "错误：IP地址格式无效！"
            fi
        done
        confirm="n"  # 强制手动输入后不再询问确认
    else
        read -p "确认使用自动检测配置？[Y/n] " confirm
    fi
    
    [[ "$confirm" =~ [nN] ]] && {
        while true; do
            client_nat_ip=$(input_with_default "自定义NAT公网IP" "$auto_nat_ip")
            client_nat_ip=$(echo "$client_nat_ip" | tr -d '[:space:]')  # 清理输入
            [ -z "$client_nat_ip" ] && break

            # 增强IP格式验证
            if [[ ! "$client_nat_ip" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})$ ]]; then
                echo "错误：IP地址格式无效！请输入类似 203.0.113.5 的IPv4地址"
                exit 1
            fi

            IFS='.' read -ra ip_parts <<< "$client_nat_ip"
            for part in "${ip_parts[@]}"; do
                if [[ "$part" =~ ^0[0-9]+$ ]]; then
                    echo "错误：IP地址段 '$part' 包含前导零（示例：192.068.0.1 → 应改为 192.68.0.1）"
                    exit 1
                elif (( part > 255 )); then
                    echo "错误：IP地址段 '$part' 超过255"
                    exit 1
                fi
            done
            break
        done
        client_ports=$(input_with_default "自定义NAT端口范围" "")
    } || {
        client_nat_ip="$auto_nat_ip"
        client_ports=""
    }

    if [ "$client_nat_ip" = "NONE" ]; then
        client_nat_ip="$auto_nat_ip"
    fi

    client_ip=$(generate_client_ip "$subnet" "$iface")
    client_private=$(wg genkey)
    client_public=$(wg pubkey <<< "$client_private")
	client_preshared=$(wg genpsk)
    
    # 修正：在服务器配置中插入完整的Peer参数
    sed -i "/# Last Peer/a [Peer]\n# $client_name\nPublicKey = $client_public\nPresharedKey = $client_preshared\nAllowedIPs = $client_ip/32\nEndpoint = $auto_endpoint_ip:$listen_port\nPersistentKeepalive = 25" "$CONFIG_DIR/$iface.conf"

    if [[ -n "$client_nat_ip" && "$client_nat_ip" != "NONE" ]]; then
        if [[ "$auto_endpoint_ip" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]{1,2})$ ]]; then
            client_subnet="$client_ip/32"
            rule_cmd=$(printf "iptables -t nat -I POSTROUTING 1 -s %s -o %s -j SNAT --to-source %s" "$client_subnet" "$auto_ext_if" "$client_nat_ip")
            sed -i "/PostUp/a $rule_cmd" "$CONFIG_DIR/$iface.conf"
            sed -i "/PostDown/a ${rule_cmd/ -I / -D }" "$CONFIG_DIR/$iface.conf"
        else
            echo "错误：无效的NAT公网IP格式！"
            exit 1
        fi
    fi

    mkdir -p "$CLIENT_DIR/$iface"
    cat > "$CLIENT_DIR/$iface/$client_name.conf" <<EOF
[Interface]
PrivateKey = $client_private
Address = $client_ip/32
DNS = 8.8.8.8, 9.9.9.9

[Peer]
PublicKey = $server_public
PresharedKey = $client_preshared  # 新增
Endpoint = $auto_endpoint_ip:$listen_port
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

    wg syncconf "$iface" <(wg-quick strip "$iface")
    echo "客户端 $client_name 添加成功！配置文件：$CLIENT_DIR/$iface/$client_name.conf"
}

# 主菜单
main_menu() {
    PS3='请选择操作: '
    options=("安装依赖和配置系统" "创建新接口" "添加客户端" "退出")
    select opt in "${options[@]}"; do
        case $opt in
            "安装依赖和配置系统") install_dependencies ;;
            "创建新接口") create_interface ;;
            "添加客户端") add_client ;;
            "退出") 
                iptables-save > /etc/iptables/rules.v4
                echo "配置完成！所有更改已持久化"
                break ;;
            *) echo "无效选项" ;;
        esac
    done
}

main_menu
