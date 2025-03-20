#!/bin/sh
# 安装依赖（增加依赖检查）
opkg update
opkg install redsocks iptables-mod-nat-extra ipset luci-base uhttpd-mod-lua || {
    echo "依赖安装失败，请检查网络连接或软件源配置"
    exit 1
}

# 创建UCI配置文件（增加注释和格式标准化）
cat > /etc/config/socks5client <<'EOF'
config global
    option enabled '0'  # 全局开关，0=禁用 1=启用

config device
    option enabled '1'
    option name 'MyPhone'
    option mac 'AA:BB:CC:DD:EE:FF'
    option socks_server 'proxy1.example.com'
    option socks_port '1080'
    option username 'user1'
    option password 'pass1'

config device
    option enabled '1'
    option name 'MyLaptop'
    option ipaddr '192.168.1.100'
    option socks_server 'proxy2.example.com'
    option socks_port '1080'
EOF

# 创建LuCI界面（优化错误处理）
mkdir -p /usr/lib/lua/luci/model/cbi/
cat > /usr/lib/lua/luci/model/cbi/socks5client.lua <<'EOF'
module("luci.model.cbi.socks5client", package.seeall)

local uci = require("luci.model.uci").cursor()

function get_devices()
    local devices = {}
    uci:foreach("socks5client", "device",
        function(s)
            if s[".type"] == "device" then
                table.insert(devices, s)
            end
        end)
    return devices
end

function validate_identifier(identifier)
    return identifier:match("^%d+%.%d+%.%d+%.%d+$") or identifier:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$")
end

function add_device(name, identifier, server, port, user, pass)
    if not validate_identifier(identifier) then
        return false, "标识符格式错误：需为IP或MAC地址"
    end
    
    local section = uci:section("socks5client", "device")
    uci:set("socks5client", section, "name", name)
    if identifier:match("^%d") then
        uci:set("socks5client", section, "ipaddr", identifier)
    else
        uci:set("socks5client", section, "mac", identifier:upper())
    end
    uci:set("socks5client", section, "socks_server", server)
    uci:set("socks5client", section, "socks_port", port)
    if user and pass then
        uci:set("socks5client", section, "username", user)
        uci:set("socks5client", section, "password", pass)
    end
    return uci:commit("socks5client")
end

function toggle_device(section_id, enable)
    uci:set("socks5client", section_id, "enabled", enable and "1" or "0")
    return uci:commit("socks5client")
end
EOF

# 初始化脚本优化（增加状态检查）
cat > /etc/init.d/socks5client <<'EOF'
#!/bin/sh /etc/rc.common

START=99
USE_PROCD=1

EXTRA_COMMANDS="status"
EXTRA_HELP="
    status  Check service status
"

validate_service() {
    if ! command -v redsocks >/dev/null; then
        echo "redsocks未安装"
        exit 1
    fi
}

status_service() {
    if pgrep -f socks5client-daemon >/dev/null; then
        echo "服务运行中"
        iptables -t nat -L SOCKS5CLIENT -n 2>/dev/null
    else
        echo "服务未运行"
    fi
}

start_service() {
    validate_service
    procd_open_instance
    procd_set_param command /sbin/socks5client-daemon
    procd_set_param respawn
    procd_close_instance
}

stop_service() {
    /sbin/socks5client-clean
    sleep 1  # 等待清理完成
    rm -f /var/run/socks5client.pid
}
EOF

# 守护进程优化（关键点改进）
cat > /sbin/socks5client-daemon <<'EOF'
#!/bin/sh
set -e  # 启用错误中断

# 初始化日志
LOG_FILE="/var/log/socks5client.log"
exec >$LOG_FILE 2>&1

# 网络配置获取
. /lib/functions/network.sh
network_flush_cache
network_find_wan NET_IF || {
    echo "无法获取WAN接口"
    exit 1
}
network_get_gateway NET_GW "$NET_IF" || {
    echo "无法获取网关地址"
    exit 1
}

# 常量定义
REDSOCKS_BIN="/usr/sbin/redsocks"
REDSOCKS_CONF="/var/run/redsocks.conf"
LOCK_FILE="/var/run/socks5client.lock"

# 单实例检查
[ -f "$LOCK_FILE" ] && {
    echo "另一个实例正在运行"
    exit 1
}
echo $$ > "$LOCK_FILE"
trap 'rm -f "$LOCK_FILE"' EXIT

generate_redsocks_conf() {
    local config=$1
    IFS='|' read -r ip port user pass <<EOF_CONFIG
$config
EOF_CONFIG

    cat > "$REDSOCKS_CONF.$port" <<EOC
base {
    log_debug = off;
    log_info = off;
    daemon = on;
    redirector = iptables;
}

redsocks {
    local_ip = 0.0.0.0;
    local_port = $port;
    ip = $ip;
    port = $port;
    type = socks5;
EOC

    [ -n "$user" ] && cat >> "$REDSOCKS_CONF.$port" <<EOC
    login = "$user";
    password = "$pass";
EOC

    echo "}" >> "$REDSOCKS_CONF.$port"
    $REDSOCKS_BIN -c "$REDSOCKS_CONF.$port" || {
        echo "redsocks启动失败，检查配置端口 $port"
        return 1
    }
}

setup_routing() {
    # 路由表管理
    grep -q '^200 socks5rt' /etc/iproute2/rt_tables || echo "200 socks5rt" >> /etc/iproute2/rt_tables
    
    # 清理旧规则
    ip rule del fwmark 0x1 2>/dev/null || true
    ip route flush table socks5rt 2>/dev/null || true
    
    # 主路由规则
    ip rule add fwmark 0x1 lookup socks5rt
    ip route replace default via "$NET_GW" dev "$NET_IF" table socks5rt
    
    # IPSET管理
    ipset create socks5_dst hash:ip timeout 600 2>/dev/null || ipset flush socks5_dst
    
    # 动态规则生成
    uci -X -p/var/state show socks5client | awk '
        /^socks5client\.@device\[[0-9]+\]\.enabled=1/ {
            sect=gensub(/^socks5client\.@device\[([0-9]+)\].*/, "\\1", 1)
            cmd="uci -q get socks5client.@device[" sect "].socks_server"
            cmd | getline server; close(cmd)
            cmd="uci -q get socks5client.@device[" sect "].socks_port"
            cmd | getline port; close(cmd)
            cmd="uci -q get socks5client.@device[" sect "].ipaddr"
            cmd | getline ip; close(cmd)
            cmd="uci -q get socks5client.@device[" sect "].mac"
            cmd | getline mac; close(cmd)
            cmd="uci -q get socks5client.@device[" sect "].username"
            cmd | getline user; close(cmd)
            cmd="uci -q get socks5client.@device[" sect "].password"
            cmd | getline pass; close(cmd)
            
            if(ip) { ips[ip]=server "|" port "|" user "|" pass }
            if(mac) { macs[toupper(mac)]=server "|" port "|" user "|" pass }
        }
        END {
            for(ip in ips) {
                split(ips[ip], s, "|")
                # 源地址规则
                system("iptables -t mangle -C SOCKS5CLIENT -s " ip " -j MARK --set-mark 1 2>/dev/null || iptables -t mangle -A SOCKS5CLIENT -s " ip " -j MARK --set-mark 1")
                system("iptables -t nat -C SOCKS5CLIENT -s " ip " -p tcp -j REDIRECT --to-port " s[2] " 2>/dev/null || iptables -t nat -A SOCKS5CLIENT -s " ip " -p tcp -j REDIRECT --to-port " s[2])
                
                # 目标地址规则
                system("iptables -t mangle -C SOCKS5CLIENT -m set --match-set socks5_dst dst -j MARK --set-mark 1 2>/dev/null || iptables -t mangle -A SOCKS5CLIENT -m set --match-set socks5_dst dst -j MARK --set-mark 1")
                system("iptables -t nat -C SOCKS5CLIENT -m set --match-set socks5_dst dst -p tcp -j REDIRECT --to-port " s[2] " 2>/dev/null || iptables -t nat -A SOCKS5CLIENT -m set --match-set socks5_dst dst -p tcp -j REDIRECT --to-port " s[2])
                
                # 生成redsocks配置
                system("generate_redsocks_conf \"" ips[ip] "\"")
            }
            for(mac in macs) {
                split(macs[mac], s, "|")
                system("iptables -t mangle -C SOCKS5CLIENT -m mac --mac-source " mac " -j MARK --set-mark 1 2>/dev/null || iptables -t mangle -A SOCKS5CLIENT -m mac --mac-source " mac " -j MARK --set-mark 1")
                system("iptables -t nat -C SOCKS5CLIENT -m mac --mac-source " mac " -p tcp -j REDIRECT --to-port " s[2] " 2>/dev/null || iptables -t nat -A SOCKS5CLIENT -m mac --mac-source " mac " -p tcp -j REDIRECT --to-port " s[2])
                system("generate_redsocks_conf \"" macs[mac] "\"")
            }
        }'
    
    # DNS处理（增加缓存清理）
    iptables -t nat -C SOCKS5CLIENT -p udp --dport 53 -j REDIRECT --to-port 5353 2>/dev/null || \
    iptables -t nat -A SOCKS5CLIENT -p udp --dport 53 -j REDIRECT --to-port 5353
    
    killall -HUP dnsmasq 2>/dev/null || true
    dnsmasq --server=/socks5_dst/#5353 --ipset=/socks5_dst/ --no-resolv 2>/dev/null
}

# 主循环（优化监控逻辑）
while :; do
    # 初始化链（增加存在性检查）
    for table in nat mangle; do
        iptables -t $table -N SOCKS5CLIENT 2>/dev/null || iptables -t $table -F SOCKS5CLIENT
        iptables -t $table -C PREROUTING -j SOCKS5CLIENT 2>/dev/null || iptables -t $table -A PREROUTING -j SOCKS5CLIENT
    done
    
    setup_routing
    
    # 监控配置变化（增加重试机制）
    inotifywait -e modify -q /etc/config/socks5client && {
        echo "检测到配置变化，重新加载服务"
        /etc/init.d/socks5client restart
        continue  # 继续监控
    }
    
    sleep 60 & wait $!  # 心跳检测
done
EOF

# 清理脚本增强
cat > /sbin/socks5client-clean <<'EOF'
#!/bin/sh
set -e

# 清理iptables规则
for table in nat mangle; do
    iptables -t $table -F SOCKS5CLIENT 2>/dev/null || true
    iptables -t $table -X SOCKS5CLIENT 2>/dev/null || true
done

# 清理路由规则
ip rule del fwmark 0x1 2>/dev/null || true
ip route flush table socks5rt 2>/dev/null || true
sed -i '/socks5rt/d' /etc/iproute2/rt_tables 2>/dev/null || true

# 清理ipset
ipset destroy socks5_dst 2>/dev/null || true

# 停止redsocks进程
killall redsocks 2>/dev/null || true
rm -f /var/run/redsocks.conf.*
EOF

# 权限设置
chmod 755 /sbin/socks5client-* /etc/init.d/socks5client

# 服务管理（增加启动验证）
if /etc/init.d/socks5client enable; then
    echo "服务已启用"
    if /etc/init.d/socks5client start; then
        echo "服务启动成功"
        sleep 2
        /etc/init.d/socks5client status
    else
        echo "服务启动失败，检查日志：/var/log/socks5client.log"
    fi
else
    echo "服务启用失败"
fi
