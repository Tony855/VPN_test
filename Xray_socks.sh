#!/bin/bash

DEFAULT_START_PORT=23049                         # 默认起始端口
DEFAULT_WS_PATH="/ws"                            # 默认ws路径
DEFAULT_UUID=$(cat /proc/sys/kernel/random/uuid) # 默认随机UUID
IP_ADDRESSES=($(hostname -I))                    # 获取本机所有IP地址

# 生成随机默认用户名和密码
generate_random_username() {
    echo "user_$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 6 | head -n 1)"
}

generate_random_password() {
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 12 | head -n 1
}

install_xray() {
    echo "安装 Xray..."
    apt-get install unzip -y || yum install unzip -y
    wget https://github.com/XTLS/Xray-core/releases/download/v25.1.1/Xray-linux-64.zip
    unzip Xray-linux-64.zip
    mv xray /usr/local/bin/xrayL
    chmod +x /usr/local/bin/xrayL
    
    # 创建日志目录并设置权限
    mkdir -p /var/log/xrayL
    chown nobody:nobody /var/log/xrayL
    chmod 700 /var/log/xrayL

    cat <<EOF >/etc/systemd/system/xrayL.service
[Unit]
Description=XrayL Service
After=network.target

[Service]
ExecStart=/usr/local/bin/xrayL -c /etc/xrayL/config.toml
Restart=on-failure
User=nobody
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable xrayL.service
    systemctl start xrayL.service
    echo "Xray 安装完成."
}

config_xray() {
    config_type=$1
    mkdir -p /etc/xrayL
    
    # 日志配置（JSON格式）
    config_content="[log]\n"
    config_content+="loglevel = \"info\"\n"
    config_content+="access = \"/var/log/xrayL/access.log\"\n"
    config_content+="format = \"json\"\n\n"

    if [ "$config_type" != "socks" ] && [ "$config_type" != "vmess" ]; then
        echo "类型错误！仅支持socks和vmess."
        exit 1
    fi

    read -p "起始端口 (默认 $DEFAULT_START_PORT): " START_PORT
    START_PORT=${START_PORT:-$DEFAULT_START_PORT}

    if [ "$config_type" == "socks" ]; then
        # 生成随机认证信息
        DEFAULT_SOCKS_USERNAME=$(generate_random_username)
        DEFAULT_SOCKS_PASSWORD=$(generate_random_password)
        
        read -p "SOCKS 账号 (默认 $DEFAULT_SOCKS_USERNAME): " SOCKS_USERNAME
        SOCKS_USERNAME=${SOCKS_USERNAME:-$DEFAULT_SOCKS_USERNAME}

        read -p "SOCKS 密码 (默认 $DEFAULT_SOCKS_PASSWORD): " SOCKS_PASSWORD
        SOCKS_PASSWORD=${SOCKS_PASSWORD:-$DEFAULT_SOCKS_PASSWORD}
    elif [ "$config_type" == "vmess" ]; then
        read -p "UUID (默认随机): " UUID
        UUID=${UUID:-$DEFAULT_UUID}
        read -p "WebSocket 路径 (默认 $DEFAULT_WS_PATH): " WS_PATH
        WS_PATH=${WS_PATH:-$DEFAULT_WS_PATH}
    fi

    for ((i = 0; i < ${#IP_ADDRESSES[@]}; i++)); do
        config_content+="[[inbounds]]\n"
        config_content+="port = $((START_PORT + i))\n"
        config_content+="protocol = \"$config_type\"\n"
        config_content+="tag = \"tag_$((i + 1))\"\n"
        config_content+="[inbounds.settings]\n"
        
        if [ "$config_type" == "socks" ]; then
            config_content+="auth = \"password\"\n"
            config_content+="udp = true\n"
            config_content+="ip = \"${IP_ADDRESSES[i]}\"\n"
            config_content+="[[inbounds.settings.accounts]]\n"
            config_content+="user = \"$SOCKS_USERNAME\"\n"
            config_content+="pass = \"$SOCKS_PASSWORD\"\n"
        elif [ "$config_type" == "vmess" ]; then
            config_content+="[[inbounds.settings.clients]]\n"
            config_content+="id = \"$UUID\"\n"
            config_content+="[inbounds.streamSettings]\n"
            config_content+="network = \"ws\"\n"
            config_content+="[inbounds.streamSettings.wsSettings]\n"
            config_content+="path = \"$WS_PATH\"\n\n"
        fi

        config_content+="[[outbounds]]\n"
        config_content+="sendThrough = \"${IP_ADDRESSES[i]}\"\n"
        config_content+="protocol = \"freedom\"\n"
        config_content+="tag = \"tag_$((i + 1))\"\n\n"

        config_content+="[[routing.rules]]\n"
        config_content+="type = \"field\"\n"
        config_content+="inboundTag = \"tag_$((i + 1))\"\n"
        config_content+="outboundTag = \"tag_$((i + 1))\"\n\n"
    done

    echo -e "$config_content" >/etc/xrayL/config.toml
    systemctl restart xrayL.service
    systemctl --no-pager status xrayL.service

    # 输出配置信息
    echo -e "\n\033[32m=== 配置已生成 ===\033[0m"
    echo "协议类型: $config_type"
    echo "起始端口: $START_PORT"
    echo "结束端口: $(($START_PORT + ${#IP_ADDRESSES[@]} - 1))"
    echo "有效IP列表: ${IP_ADDRESSES[*]}"
    
    if [ "$config_type" == "socks" ]; then
        echo -e "\033[33m认证信息:\033[0m"
        echo "用户名: $SOCKS_USERNAME"
        echo "密码: $SOCKS_PASSWORD"
    elif [ "$config_type" == "vmess" ]; then
        echo -e "\033[33mVmess配置:\033[0m"
        echo "UUID: $UUID"
        echo "WebSocket路径: $WS_PATH"
    fi
    
    echo -e "\n\033[36m访问日志路径: /var/log/xrayL/access.log\033[0m"
    echo "使用以下命令查看实时日志:"
    echo "tail -f /var/log/xrayL/access.log | jq -r '. | select(.msg == \"inbound connection accepted\") | .remoteAddr'"
}

stats_ips() {
    echo -e "\n\033[34m=== 连接统计功能 ===\033[0m"
    if ! command -v jq &> /dev/null; then
        echo "检测到系统未安装jq，正在自动安装..."
        apt-get install -y jq || yum install -y jq
    fi
    
    echo -e "\033[36m最近10个连接IP:\033[0m"
    tail -n 100 /var/log/xrayL/access.log | jq -r 'select(.msg == "inbound connection accepted") | .remoteAddr' | cut -d':' -f1 | sort | uniq -c | sort -nr | head -n 10
    
    echo -e "\n\033[36m历史连接TOP10:\033[0m"
    jq -r 'select(.msg == "inbound connection accepted") | .remoteAddr' /var/log/xrayL/access.log | cut -d':' -f1 | sort | uniq -c | sort -nr | head -n 10
}

main() {
    if [ "$1" == "stats" ]; then
        stats_ips
        exit 0
    fi

    [ -x "$(command -v xrayL)" ] || install_xray

    if [ $# -ge 1 ]; then
        config_type="$1"
    else
        read -p "请选择节点类型 (socks/vmess): " config_type
    fi

    case $config_type in
        "socks"|"vmess")
            config_xray "$config_type"
            ;;
        *)
            echo -e "\033[31m错误: 不支持的协议类型!\033[0m"
            echo "使用示例:"
            echo "$0          # 交互式配置"
            echo "$0 socks    # 快速配置SOCKS"
            echo "$0 vmess    # 快速配置VMess"
            echo "$0 stats    # 查看连接统计"
            exit 1
            ;;
    esac
}

main "$@"
