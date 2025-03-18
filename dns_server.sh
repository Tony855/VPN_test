#!/bin/bash
# 支持 IPv6 的 DNS 缓存服务器一键安装脚本 (基于 Unbound)
# 作者：YourName | 版本：v1.3

set -e
trap 'echo -e "\n\033[31m安装中断！请检查错误或重试。\033[0m"; exit 1' SIGINT

# 定义颜色变量
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
RESET='\033[0m'

echo -e "${GREEN}\n=== 支持 IPv6 的 DNS 缓存服务器一键安装脚本 (Unbound) ===${RESET}"

# 检查 root 权限
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}错误：此脚本必须使用 root 权限运行！${RESET}" 
   exit 1
fi

# 检测系统类型
if grep -qi "debian\|ubuntu" /etc/os-release; then
    DISTRO="debian"
elif grep -qi "centos\|redhat\|rhel" /etc/os-release; then
    DISTRO="centos"
else
    echo -e "${RED}错误：不支持的系统！${RESET}"
    exit 1
fi

# 安装 Unbound
echo -e "${BLUE}\n[1/4] 安装 Unbound ...${RESET}"
if [[ $DISTRO == "debian" ]]; then
    apt update > /dev/null 2>&1
    apt install -y unbound unbound-anchor > /dev/null 2>&1
elif [[ $DISTRO == "centos" ]]; then
    yum install -y unbound > /dev/null 2>&1
fi

# 生成支持 IPv6 的优化配置
echo -e "${BLUE}\n[2/4] 生成配置文件 ...${RESET}"
CONF_FILE="/etc/unbound/unbound.conf"
BACKUP_FILE="${CONF_FILE}.bak.$(date +%s)"

# 备份原配置
if [[ -f $CONF_FILE ]]; then
    mv "$CONF_FILE" "$BACKUP_FILE"
    echo -e "${YELLOW}原配置文件已备份至：${BACKUP_FILE}${RESET}"
fi

# 写入新配置（IPv4/IPv6 双栈）
cat > "$CONF_FILE" << EOF
server:
    verbosity: 1
    interface: 0.0.0.0
    interface: ::0
    port: 53
    access-control: 127.0.0.0/8 allow
    access-control: ::1/128 allow
    access-control: 192.168.0.0/16 allow
    access-control: 10.0.0.0/8 allow
    access-control: fd00::/8 allow  # IPv6 私有网络
    access-control: 2401:c080:1c01:b45::/64 allow  # IPv6 公共网络
    prefetch: yes
    num-threads: $(nproc)
    cache-min-ttl: 3600
    cache-max-ttl: 86400
    msg-cache-size: 128m
    rrset-cache-size: 256m
    key-cache-size: 64m
    infra-cache-numhosts: 50000
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes
    hide-identity: yes
    hide-version: yes
    aggressive-nsec: yes

remote-control:
    control-enable: no

forward-zone:
    name: "."
    # IPv4 上游 DNS
    forward-addr: 8.8.8.8@853#dns.google     # Google DNS (DoT)
    forward-addr: 1.1.1.1@853#cloudflare-dns.com  # Cloudflare DNS (DoT)
    forward-addr: 9.9.9.9@853#dns.quad9.net    # quad9 DNS (DoT)
    
    # IPv6 上游 DNS
    forward-addr: 2001:4860:4860::8888@853#dns.google    # Google IPv6
    forward-addr: 2606:4700:4700::1111@853#cloudflare-dns.com  # Cloudflare IPv6
    forward-addr: 2620:fe::fe@853#dns.quad9.net    # quad9 IPv6
EOF

# 配置防火墙（IPv4 + IPv6）
echo -e "${BLUE}\n[3/4] 配置防火墙 ...${RESET}"
if systemctl status firewalld > /dev/null 2>&1; then
    firewall-cmd --permanent --add-port=53/udp --add-port=53/tcp > /dev/null 2>&1
    firewall-cmd --permanent --add-rich-rule='rule family="ipv6" port port="53" protocol="udp" accept' > /dev/null 2>&1
    firewall-cmd --permanent --add-rich-rule='rule family="ipv6" port port="53" protocol="tcp" accept' > /dev/null 2>&1
    firewall-cmd --reload > /dev/null 2>&1
elif command -v ufw > /dev/null 2>&1; then
    ufw allow 53/udp > /dev/null 2>&1
    ufw allow 53/tcp > /dev/null 2>&1
    ufw allow in from ::/0 to any port 53 proto udp > /dev/null 2>&1
    ufw allow in from ::/0 to any port 53 proto tcp > /dev/null 2>&1
    ufw reload > /dev/null 2>&1
fi

# 启动服务
echo -e "${BLUE}\n[4/4] 启动服务 ...${RESET}"
systemctl enable --now unbound > /dev/null 2>&1

# 修改系统 DNS 配置（IPv4 + IPv6）
echo -e "nameserver 127.0.0.1\nnameserver ::1" > /etc/resolv.conf
chattr +i /etc/resolv.conf 2>/dev/null || true

# 验证安装
echo -e "${GREEN}\n=== 安装完成！正在验证 ===${RESET}"
echo -e "${BLUE}测试 IPv4 解析...${RESET}"
if dig @127.0.0.1 google.com | grep -q "ANSWER SECTION"; then
    echo -e "${GREEN}IPv4 DNS 解析成功！${RESET}"
else
    echo -e "${RED}错误：IPv4 DNS 解析失败！${RESET}"
    exit 1
fi

echo -e "${BLUE}测试 IPv6 解析...${RESET}"
if dig @::1 google.com AAAA | grep -q "ANSWER SECTION"; then
    echo -e "${GREEN}IPv6 DNS 解析成功！${RESET}"
else
    echo -e "${RED}警告：IPv6 DNS 解析失败，请检查网络是否支持 IPv6！${RESET}"
fi

# 显示帮助信息
echo -e "\n${YELLOW}=== 使用说明 ===${RESET}"
echo -e "1. 监听地址："
echo -e "   - IPv4: 0.0.0.0:53"
echo -e "   - IPv6: ::0:53"
echo -e "2. 测试命令："
echo -e "   - IPv4: dig @127.0.0.1 www.facebook.com"
echo -e "   - IPv6: dig @::1 www.facebook.com AAAA"
echo -e "3. 上游 DNS 已启用 DNS-over-TLS (DoT)"
echo -e "4. 允许访问范围："
echo -e "   - IPv4: 本地/私有网络 (10.0.0.0/8, 192.168.0.0/16)"
echo -e "   - IPv6: ::1/128 和 fd00::/8 (私有网络)"
