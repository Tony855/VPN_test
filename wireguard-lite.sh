#!/bin/bash

# 定义配置目录和IP池文件
CONFIG_DIR="/etc/wireguard"
CLIENT_DIR="$CONFIG_DIR/clients"
PUBLIC_IP_FILE="$CONFIG_DIR/public_ips.txt"
USED_IP_FILE="$CONFIG_DIR/used_ips.txt"
FIXED_IFACE="wg0"  # 固定接口名称
SUBNET="10.19.0.0/24"  # 固定子网
LOG_FILE="/var/log/wireguard-lite.log"

# 检查root权限
if [ "$EUID" -ne 0 ]; then
    echo "请使用sudo或root用户运行此脚本"
    exit 1
fi

# ========================
# 通用功能函数
# ========================
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

validate_ip() {
    local ip=$1
    if ! [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "错误: IP格式无效"
        return 1
    fi
    return 0
}

backup_config() {
    cp "$CONFIG_DIR/$FIXED_IFACE.conf" "$CONFIG_DIR/$FIXED_IFACE.conf.bak" 2>/dev/null && \
    chmod 600 "$CONFIG_DIR/$FIXED_IFACE.conf.bak"
}

# ========================
# 依赖安装函数
# ========================
install_dependencies() {
    echo "正在安装依赖和配置系统..."
    log "开始安装依赖"
    export DEBIAN_FRONTEND=noninteractive
    
    if ! apt-get update && apt-get install -y wireguard-tools iptables iptables-persistent sipcalc qrencode curl iftop; then
        echo "错误: 依赖安装失败"
        log "依赖安装失败"
        exit 1
    fi
    
    # 自动保存iptables规则
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    
    # 配置sysctl参数
    sysctl_conf=("net.ipv4.ip_forward=1" "net.core.default_qdisc=fq" "net.ipv4.tcp_congestion_control=bbr")
    for param in "${sysctl_conf[@]}"; do
        grep -qxF "$param" /etc/sysctl.conf || echo "$param" >> /etc/sysctl.conf
    done
    
    if ! sysctl -p >/dev/null 2>&1; then
        echo "警告: sysctl加载失败"
        log "sysctl加载失败"
    fi
    
    echo "系统配置完成！"
    log "依赖安装完成"
}

# ========================
# IP池管理功能
# ========================
init_ip_pool() {
    if [ ! -f "$PUBLIC_IP_FILE" ]; then
        echo "错误: 公网IP池文件不存在！"
        echo "请先创建 $PUBLIC_IP_FILE"
        echo "文件格式：每行一个公网IP地址"
        log "公网IP池文件不存在"
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
    log "公网IP已耗尽"
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
    local subnet=$(echo "$SUBNET" | cut -d',' -f1)
    local existing_ips=($(grep -A1 '^\[Peer\]' "$CONFIG_DIR/$FIXED_IFACE.conf" 2>/dev/null | 
                       grep AllowedIPs | awk -F'[ ,/]' '{print $3}' | sort -u))
    
    local network_info=$(sipcalc "$subnet" 2>/dev/null)
    local network=$(echo "$network_info" | grep "Network address" | awk '{print $4}')
    local broadcast=$(echo "$network_info" | grep "Broadcast address" | awk '{print $4}')
    
    for i in $(seq 2 254); do
        candidate_ip="${network%.*}.$i"
        [[ "$candidate_ip" == "$broadcast" ]] && continue
        if ! [[ " ${existing_ips[@]} " =~ " $candidate_ip " ]]; then
            echo "$candidate_ip"
            return 0
        fi
    done
    
    echo "错误: 子网IP已耗尽"
    log "子网IP耗尽"
    return 1
}

get_available_port() {
    base_port=51620
    while [ $base_port -lt 52000 ]; do
        if ! ss -uln | grep -q ":$base_port "; then
            echo $base_port
            return 0
        fi
        ((base_port++))
    done
    echo "错误: 未找到可用端口"
    log "端口扫描失败"
    return 1
}

create_interface() {
    init_ip_pool
    echo "正在创建WireGuard接口..."
    log "开始创建接口"
    
    public_ip=$(get_available_public_ip) || { echo "$public_ip"; return 1; }
    mark_ip_used "$public_ip"

    if [ -f "$CONFIG_DIR/$FIXED_IFACE.conf" ]; then
        echo "错误: 接口 $FIXED_IFACE 已存在"
        log "接口已存在"
        rollback_ip_allocation "$public_ip"
        return 1
    fi

    ext_if=$(ip route show default | awk '/default/ {print $5}' | head -1)
    [ -z "$ext_if" ] && { 
        echo "错误: 未找到默认出口接口"
        log "未找到出口接口"
        rollback_ip_allocation "$public_ip"
        return 1 
    }

    port=$(get_available_port) || { 
        rollback_ip_allocation "$public_ip"
        return 1 
    }

    server_private=$(wg genkey)
    server_public=$(echo "$server_private" | wg pubkey)

    cat > "$CONFIG_DIR/$FIXED_IFACE.conf" <<EOF
[Interface]
Address = ${SUBNET%.*}.1/24
PrivateKey = $server_private
ListenPort = $port

# NAT规则
PostUp = iptables -t nat -A POSTROUTING -s $SUBNET -o $ext_if -j SNAT --to-source $public_ip
PostDown = iptables -t nat -D POSTROUTING -s $SUBNET -o $ext_if -j SNAT --to-source $public_ip
EOF

    chmod 600 "$CONFIG_DIR/$FIXED_IFACE.conf"

    if systemctl enable --now "wg-quick@$FIXED_IFACE" &>/dev/null; then
        echo "接口 $FIXED_IFACE 创建成功！"
        echo "分配公网IP: $public_ip"
        echo "内网子网: $SUBNET"
        log "接口创建成功"
    else
        rollback_ip_allocation "$public_ip"
        rm -f "$CONFIG_DIR/$FIXED_IFACE.conf"
        echo "错误: 服务启动失败"
        log "接口启动失败"
        return 1
    fi
}

add_client() {
    echo "正在添加新客户端..."
    log "开始添加客户端"
    
    if [ ! -f "$CONFIG_DIR/$FIXED_IFACE.conf" ]; then
        echo "错误: 接口 $FIXED_IFACE 不存在"
        log "接口不存在"
        return 1
    fi

    ext_if=$(grep 'POSTROUTING' "$CONFIG_DIR/$FIXED_IFACE.conf" | awk '{print $9}' | head -1)
    public_ip=$(grep 'SNAT' "$CONFIG_DIR/$FIXED_IFACE.conf" | awk '{print $NF}' | head -1 | tr -d '\r\n')

    client_count=$(ls "$CLIENT_DIR/$FIXED_IFACE"/*.conf 2>/dev/null | wc -l)
    default_name="client$((client_count + 1))"
    
    read -p "输入客户端名称（默认 $default_name）: " client_name
    client_name=${client_name:-$default_name}
    [[ "$client_name" =~ [/\\] ]] && { 
        echo "错误: 名称含非法字符"
        log "非法客户端名称"
        return 1 
    }

    client_ip=$(generate_client_ip "$SUBNET" "$FIXED_IFACE") || { 
        echo "$client_ip"
        return 1 
    }
    
    client_private=$(wg genkey)
    client_public=$(echo "$client_private" | wg pubkey)
    client_preshared=$(wg genpsk)

    # 备份当前配置
    backup_config

    # 添加Peer配置
    tmp_conf=$(mktemp /tmp/wg_conf.XXXXXX)
    chmod 600 "$tmp_conf"
    trap "rm -f '$tmp_conf'" EXIT

    grep -v '^$' "$CONFIG_DIR/$FIXED_IFACE.conf" > "$tmp_conf"
    cat >> "$tmp_conf" <<EOF

[Peer]
# $client_name
PublicKey = $client_public
PresharedKey = $client_preshared
AllowedIPs = $client_ip/32
EOF

    read -p "是否为该客户端指定独立公网IP？(y/N) " custom_ip
    if [[ $custom_ip =~ ^[Yy]$ ]]; then
        read -p "输入自定义公网IP: " client_nat_ip
        if ! validate_ip "$client_nat_ip"; then
            return 1
        fi
        
        if ! grep -q "$client_nat_ip" "$PUBLIC_IP_FILE"; then
            echo "警告: 该IP不在公网IP池中"
            log "使用非池中公网IP: $client_nat_ip"
        fi
        
        rule_up="iptables -t nat -I POSTROUTING 1 -s $client_ip/32 -o $ext_if -j SNAT --to-source $client_nat_ip"
        rule_down="iptables -t nat -D POSTROUTING -s $client_ip/32 -o $ext_if -j SNAT --to-source $client_nat_ip"
        
        awk -v rule="$rule_up" '/PostUp =/{print; print "PostUp = " rule; next}1' "$tmp_conf" > "${tmp_conf}.new"
        mv "${tmp_conf}.new" "$tmp_conf"
        
        awk -v rule="$rule_down" '/PostDown =/{print; print "PostDown = " rule; next}1' "$tmp_conf" > "${tmp_conf}.new"
        mv "${tmp_conf}.new" "$tmp_conf"
        
        if ! eval "$rule_up"; then
            echo "错误: iptables规则添加失败"
            log "iptables规则添加失败"
            return 1
        fi
    fi

    # 保存配置
    chmod 600 "$tmp_conf"
    mv "$tmp_conf" "$CONFIG_DIR/$FIXED_IFACE.conf"

    # 生成客户端配置
    mkdir -p "$CLIENT_DIR/$FIXED_IFACE"
    client_file="$CLIENT_DIR/$FIXED_IFACE/$client_name.conf"
    
    read -p "输入客户端DNS服务器（默认 8.8.8.8,9.9.9.9）: " client_dns
    client_dns=${client_dns:-"8.8.8.8,9.9.9.9"}

    cat > "$client_file" <<EOF
[Interface]
PrivateKey = $client_private
Address = $client_ip/32
DNS = $client_dns

[Peer]
PublicKey = $(grep 'PrivateKey' "$CONFIG_DIR/$FIXED_IFACE.conf" | awk '{print $3}' | wg pubkey)
PresharedKey = $client_preshared
Endpoint = $(echo "$public_ip" | tr -d '\r'):$(grep ListenPort "$CONFIG_DIR/$FIXED_IFACE.conf" | awk '{print $3}')
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 15
EOF

    chmod 600 "$client_file"
    qrencode -t ansiutf8 < "$client_file"
    qrencode -o "${client_file}.png" < "$client_file"
    chmod 600 "${client_file}.png"

    # 动态加载配置
    if wg syncconf "$FIXED_IFACE" <(wg-quick strip "$FIXED_IFACE") 2>/dev/null; then
        echo "配置已动态加载"
        log "配置动态加载成功"
    else
        echo "警告: 动态加载失败，尝试重启接口..."
        log "动态加载失败，尝试重启"
        if ! systemctl restart "wg-quick@$FIXED_IFACE"; then
            echo "错误: 接口重启失败"
            log "接口重启失败"
            return 1
        fi
    fi

    echo "客户端 $client_name 添加成功！"
    echo "出口公网IP: ${client_nat_ip:-$public_ip}"
    echo "配置文件: $client_file"
    echo "二维码: ${client_file}.png"
    log "客户端添加成功: $client_name"
}

uninstall_wireguard() {
    read -p "确定要完全卸载WireGuard吗？(y/N) " confirm
    [[ ! $confirm =~ ^[Yy]$ ]] && return
    
    echo "正在卸载WireGuard..."
    log "开始卸载"
    
    systemctl stop "wg-quick@$FIXED_IFACE" 2>/dev/null
    rm -rf "$CONFIG_DIR" "$CLIENT_DIR"
    apt-get purge -y --auto-remove wireguard-tools iptables-persistent qrencode
    
    iptables -F
    iptables -t nat -F
    
    echo "WireGuard已完全卸载"
    log "卸载完成"
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
                iptables-save > /etc/iptables/rules.v4 2>/dev/null
                echo "配置已保存，再见！"
                log "脚本正常退出"
                break ;;
            *) echo "无效选项" ;;
        esac
    done
}

# 初始化
mkdir -p "$CLIENT_DIR/$FIXED_IFACE"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

main_menu
