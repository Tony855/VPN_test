#!/bin/bash
#
# https://github.com/Tony855/MySocks5
#
# 修改说明：
# 1. 全自动检测并配置所有可用公网IPv4地址，每个IP创建独立WireGuard接口
# 2. 子网改为10.29.29.1/24
# 3. 客户端配置自动适配多接口
# 4. 默认端口从51620开始递增
# 5. 自动生成多接口配置

exiterr()  { echo "Error: $1" >&2; exit 1; }
exiterr2() { exiterr "'apt-get install' failed."; }
exiterr3() { exiterr "'yum install' failed."; }
exiterr4() { exiterr "'zypper install' failed."; }

# 获取所有公网IPv4地址
get_all_public_ips() {
    ips=()
    # 检测所有非私有IP
    while read -r line; do
        if ! check_pvt_ip "$line"; then
            ips+=("$line")
        fi
    done < <(ip -4 addr | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
    
    # 如果未检测到，尝试通过外部服务获取
    if [ ${#ips[@]} -eq 0 ]; then
        find_public_ip
        [ -n "$get_public_ip" ] && ips+=("$get_public_ip")
    fi
    
    [ ${#ips[@]} -eq 0 ] && exiterr "无法检测到公网IP地址"
}

# 修改子网配置
WG_SUBNET="10.29.29.1/24"
WG_IPV6_SUBNET="fddd:2c4:2c4:2c4::1/64"

# 生成多接口配置
create_multiple_configs() {
    port=51620
    for idx in "${!ips[@]}"; do
        interface="wg${idx}"
        conf_file="/etc/wireguard/${interface}.conf"
        
        # 生成服务器配置
        cat << EOF > "$conf_file"
[Interface]
Address = $WG_SUBNET
PrivateKey = $(wg genkey)
ListenPort = $((port + idx))
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

EOF
        # 添加公网IP绑定
        echo "# PublicIP = ${ips[$idx]}" >> "$conf_file"
        chmod 600 "$conf_file"
        
        # 启用服务
        systemctl enable --now wg-quick@${interface}.service >/dev/null 2>&1
    done
}

# 修改客户端生成逻辑
new_client() {
    interface=$1
    client=$2
    octet=$((254 - $(grep -c '^# BEGIN_PEER' "/etc/wireguard/${interface}.conf")))
    conf_file="/etc/wireguard/${interface}.conf"
    
    key=$(wg genkey)
    psk=$(wg genpsk)
    public_ip=$(grep '# PublicIP' "$conf_file" | awk '{print $3}')
    port=$(grep 'ListenPort' "$conf_file" | awk '{print $3}')

    # 添加到服务端配置
    cat << EOF >> "$conf_file"
# BEGIN_PEER $client
[Peer]
PublicKey = $(wg pubkey <<< "$key")
PresharedKey = $psk
AllowedIPs = 10.29.29.$octet/32
# END_PEER $client
EOF

    # 生成客户端配置
    cat << EOF > "/root/${client}-${interface}.conf"
[Interface]
PrivateKey = $key
Address = 10.29.29.$octet/24
DNS = 8.8.8.8,8.8.4.4

[Peer]
PublicKey = $(grep 'PrivateKey' "$conf_file" | awk '{print $3}' | wg pubkey)
PresharedKey = $psk
Endpoint = ${public_ip}:${port}
AllowedIPs = 0.0.0.0/0,::/0
PersistentKeepalive = 25
EOF
    echo "客户端配置已生成: /root/${client}-${interface}.conf"
}

# 主安装流程
auto_install() {
    check_root
    check_shell
    check_os
    check_os_ver
    
    # 安装依赖
    if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
        apt-get update
        apt-get install -y wireguard qrencode iptables
    elif [[ "$os" == "centos" ]]; then
        yum install -y epel-release
        yum install -y wireguard-tools qrencode
    fi

    get_all_public_ips
    create_multiple_configs
    
    # 为每个接口创建示例客户端
    for idx in "${!ips[@]}"; do
        interface="wg${idx}"
        client="client${idx}"
        new_client "$interface" "$client"
    done
    
    echo "安装完成！创建的接口列表："
    for idx in "${!ips[@]}"; do
        echo "wg${idx} - 公网IP: ${ips[$idx]} 端口: $((51620 + idx))"
    done
}

# 卸载逻辑
uninstall() {
    for conf in /etc/wireguard/wg*.conf; do
        interface=$(basename "$conf" .conf)
        systemctl stop wg-quick@${interface}.service
        systemctl disable wg-quick@${interface}.service
        rm -f "/etc/systemd/system/wg-quick@${interface}.service"
    done
    rm -rf /etc/wireguard/
    echo "WireGuard 已完全卸载"
}

# 参数处理
case "$1" in
    --auto)
        auto_install
        ;;
    --uninstall)
        uninstall
        ;;
    *)
        echo "用法: $0 [--auto|--uninstall]"
        exit 1
        ;;
esac
