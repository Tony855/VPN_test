#!/bin/bash
#
# 全自动多IP WireGuard配置脚本
# 修改说明：
# 1. 包含必要的系统检测函数
# 2. 修复缺失的命令错误
# 3. 保留核心校验逻辑

exiterr()  { echo "Error: $1" >&2; exit 1; }
exiterr2() { exiterr "'apt-get install' failed."; }
exiterr3() { exiterr "'yum install' failed."; }
exiterr4() { exiterr "'zypper install' failed."; }

#====================== 核心校验函数 ======================#
check_root() {
    if [ "$(id -u)" != 0 ]; then
        exiterr "脚本必须使用 root 权限运行，请使用 'sudo bash $0'"
    fi
}

check_shell() {
    if grep -q "dash" /proc/$$/cmdline; then
        exiterr "请使用 bash 执行本脚本，不要用 sh"
    fi
}

check_os() {
    if grep -qs "ubuntu" /etc/os-release; then
        os="ubuntu"
    elif [[ -e /etc/debian_version ]]; then
        os="debian"
    elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
        os="centos"
    elif [[ -e /etc/fedora-release ]]; then
        os="fedora"
    else
        exiterr "不支持的操作系统"
    fi
}

check_os_ver() {
    if [[ "$os" == "ubuntu" ]]; then
        os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
        [ "$os_version" -lt 2004 ] && exiterr "需要 Ubuntu 20.04 或更高版本"
    elif [[ "$os" == "debian" ]]; then
        os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
        [ "$os_version" -lt 11 ] && exiterr "需要 Debian 11 或更高版本"
    elif [[ "$os" == "centos" ]]; then
        os_version=$(grep -shoE '[0-9]+' /etc/centos-release | head -1)
        [ "$os_version" -lt 8 ] && exiterr "需要 CentOS 8 或更高版本"
    fi
}

check_pvt_ip() {
    IPP_REGEX='^(10|127|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168|169\.254)\.'
    printf '%s' "$1" | tr -d '\n' | grep -Eq "$IPP_REGEX"
}

#====================== 主要功能函数 ======================#
get_all_public_ips() {
    ips=()
    # 检测非私有IP
    while read -r line; do
        if ! check_pvt_ip "$line"; then
            ips+=("$line")
        fi
    done < <(ip -4 addr | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
    
    # 通过外部服务获取公网IP
    if [ ${#ips[@]} -eq 0 ]; then
        find_public_ip
        [ -n "$get_public_ip" ] && ips+=("$get_public_ip")
    fi
    
    [ ${#ips[@]} -eq 0 ] && exiterr "未检测到有效公网IP"
}

find_public_ip() {
    get_public_ip=$(curl -4 -s icanhazip.com)
    check_ip "$get_public_ip" || exiterr "无法获取公网IP"
}

check_ip() {
    IP_REGEX='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
    printf '%s' "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}

#====================== WireGuard配置 ======================#
WG_SUBNET="10.29.29.1/24"
WG_IPV6_SUBNET="fddd:2c4:2c4:2c4::1/64"

create_multiple_configs() {
    port=51620
    for idx in "${!ips[@]}"; do
        interface="wg${idx}"
        conf_file="/etc/wireguard/${interface}.conf"
        
        # 生成服务端配置
        cat << EOF > "$conf_file"
[Interface]
Address = $WG_SUBNET
PrivateKey = $(wg genkey)
ListenPort = $((port + idx))
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
EOF
        # 记录公网IP
        echo "# PublicIP = ${ips[$idx]}" >> "$conf_file"
        chmod 600 "$conf_file"
        systemctl enable --now wg-quick@${interface}.service >/dev/null 2>&1
    done
}

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

#====================== 安装流程 ======================#
auto_install() {
    check_root
    check_shell
    check_os
    check_os_ver
    
    # 安装依赖
    if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
        apt-get update && apt-get install -y wireguard qrencode iptables
    elif [[ "$os" == "centos" ]]; then
        yum install -y epel-release && yum install -y wireguard-tools qrencode
    fi

    get_all_public_ips
    create_multiple_configs
    
    # 为每个接口创建示例客户端
    for idx in "${!ips[@]}"; do
        interface="wg${idx}"
        client="client${idx}"
        new_client "$interface" "$client"
    done
    
    echo "安装完成！接口列表："
    for idx in "${!ips[@]}"; do
        echo "wg${idx} - 公网IP: ${ips[$idx]} 端口: $((51620 + idx))"
    done
}

#====================== 卸载 ======================#
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

#====================== 主流程 ======================#
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
