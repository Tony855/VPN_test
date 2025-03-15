#!/bin/bash

# 检查root权限
if [ "$EUID" -ne 0 ]; then
    echo "请使用sudo或root用户运行此脚本"
    exit 1
fi

# 安装必要组件
export DEBIAN_FRONTEND=noninteractive
echo "安装依赖包..."
apt-get update
apt-get install -y wireguard-tools iptables iptables-persistent

# 配置iptables持久化自动保存
echo "配置iptables持久化..."
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

# 配置内核参数
echo "配置内核参数..."
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf

# 立即应用内核参数
sysctl -p

# 配置iptables规则
# 请根据实际情况替换eth0为你的公网接口名称
# 请根据实际情况替换wg0为你的WireGuard接口名称
echo "配置iptables规则..."
iptables -A FORWARD -i wg0 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# 保存iptables规则
echo "保存防火墙规则..."
iptables-save > /etc/iptables/rules.v4

# 启用WireGuard服务（需手动创建配置文件后生效）
echo "启用WireGuard服务..."
systemctl enable wg-quick@wg0

echo "安装完成！"
echo "请手动创建WireGuard配置文件：/etc/wireguard/wg0.conf"
echo "使用以下命令启动服务：systemctl start wg-quick@wg0"
