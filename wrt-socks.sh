#!/bin/sh
# 安装依赖
opkg update
opkg install redsocks iptables-mod-nat-extra ipset luci-base uhttpd-mod-lua

# 创建UCI配置文件 /etc/config/socks5client
cat > /etc/config/socks5client <<EOF
config global
    option enabled '0'

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

# 创建LuCI界面 /usr/lib/lua/luci/model/cbi/socks5client.lua
mkdir -p /usr/lib/lua/luci/model/cbi/
cat > /usr/lib/lua/luci/model/cbi/socks5client.lua <<EOF
module("luci.model.cbi.socks5client", package.seeall)

local uci = require("luci.model.uci").cursor()

function get_devices()
    local devices = {}
    uci:foreach("socks5client", "device",
        function(s) table.insert(devices, s) end)
    return devices
end

function add_device(name, identifier, server, port, user, pass)
    local section = uci:section("socks5client", "device")
    uci:set("socks5client", section, "name", name)
    if identifier:match("^%d+%.%d+%.%d+%.%d+$") then
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
    uci:save("socks5client")
    uci:commit("socks5client")
end

function toggle_device(section_id, enable)
    uci:set("socks5client", section_id, "enabled", enable and "1" or "0")
    uci:commit("socks5client")
end
EOF

# 创建初始化脚本 /etc/init.d/socks5client 
cat > /etc/init.d/socks5client <<EOF
#!/bin/sh /etc/rc.common

START=99
STOP=15

USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command /sbin/socks5client-daemon
    procd_set_param respawn
    procd_close_instance
}

stop_service() {
    /sbin/socks5client-clean
}
EOF

# 创建守护进程 /sbin/socks5client-daemon
cat > /sbin/socks5client-daemon <<'EOF'
#!/bin/sh

. /lib/functions/network.sh
network_flush_cache
network_find_wan NET_IF
network_get_gateway NET_GW "$NET_IF"

CONFIG_FILE="/etc/socks5client-rules.conf"
REDSOCKS_BIN="/usr/sbin/redsocks"
REDSOCKS_CONF="/var/run/redsocks.conf"

generate_redsocks_conf() {
    local config=$1
    local port=$(echo "$config" | cut -d'|' -f2)
    local ip=$(echo "$config" | cut -d'|' -f1)
    local user=$(echo "$config" | cut -d'|' -f3)
    local pass=$(echo "$config" | cut -d'|' -f4)

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

    if [ -n "$user" ]; then
        cat >> "$REDSOCKS_CONF.$port" <<EOC
    login = "$user";
    password = "$pass";
EOC
    fi

    cat >> "$REDSOCKS_CONF.$port" <<EOC
}
EOC
    $REDSOCKS_BIN -c "$REDSOCKS_CONF.$port"
}

setup_routing() {
    # 创建自定义路由表（如果不存在）
    grep -q '^200 socks5rt' /etc/iproute2/rt_tables || echo "200 socks5rt" >> /etc/iproute2/rt_tables
    
    # 主路由规则
    ip rule add fwmark 0x1 lookup socks5rt 2>/dev/null
    ip route replace default via "$NET_GW" dev "$NET_IF" table socks5rt
    
    # 初始化IPSET
    ipset create socks5_dst hash:ip timeout 600 2>/dev/null
    
    # 动态生成iptables规则
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
                print "iptables -t mangle -A SOCKS5CLIENT -s " ip " -j MARK --set-mark 1"
                print "iptables -t nat -A SOCKS5CLIENT -s " ip " -p tcp -j REDIRECT --to-port " s[2]
                print "iptables -t mangle -A SOCKS5CLIENT -m set --match-set socks5_dst dst -j MARK --set-mark 1"
                print "iptables -t nat -A SOCKS5CLIENT -m set --match-set socks5_dst dst -p tcp -j REDIRECT --to-port " s[2]
                generate_conf="generate_redsocks_conf \"" ips[ip] "\""
                print generate_conf
            }
            for(mac in macs) {
                split(macs[mac], s, "|") 
                print "iptables -t mangle -A SOCKS5CLIENT -m mac --mac-source " mac " -j MARK --set-mark 1"
                print "iptables -t nat -A SOCKS5CLIENT -m mac --mac-source " mac " -p tcp -j REDIRECT --to-port " s[2]
                print "iptables -t mangle -A SOCKS5CLIENT -m set --match-set socks5_dst dst -j MARK --set-mark 1"
                print "iptables -t nat -A SOCKS5CLIENT -m set --match-set socks5_dst dst -p tcp -j REDIRECT --to-port " s[2]
                generate_conf="generate_redsocks_conf \"" macs[mac] "\""
                print generate_conf
            }
        }' | sh
    
    # DNS处理规则
    iptables -t nat -A SOCKS5CLIENT -p udp --dport 53 -j REDIRECT --to-port 5353
    dnsmasq --server=/socks5_dst/#5353 --ipset=/socks5_dst/
}

while true; do
    # 初始化网络设置
    iptables -t nat -N SOCKS5CLIENT 2>/dev/null
    iptables -t mangle -N SOCKS5CLIENT 2>/dev/null
    iptables -t nat -A PREROUTING -j SOCKS5CLIENT
    iptables -t mangle -A PREROUTING -j SOCKS5CLIENT
    
    setup_routing
    
    # 监控配置文件变化
    inotifywait -e modify /etc/config/socks5client && {
        /etc/init.d/socks5client restart
        exit 0
    }
done
EOF

# 创建清理脚本 /sbin/socks5client-clean
cat > /sbin/socks5client-clean <<'EOF'
#!/bin/sh

iptables -t nat -F SOCKS5CLIENT
iptables -t mangle -F SOCKS5CLIENT
iptables -t nat -X SOCKS5CLIENT 2>/dev/null
iptables -t mangle -X SOCKS5CLIENT 2>/dev/null

ip rule del fwmark 0x1 2>/dev/null
ip route flush table socks5rt 2>/dev/null
sed -i '/socks5rt/d' /etc/iproute2/rt_tables 2>/dev/null

killall redsocks 2>/dev/null
rm -f /var/run/redsocks.conf.*
EOF

# 设置权限
chmod +x /sbin/socks5client-* /etc/init.d/socks5client

# 启用服务
/etc/init.d/socks5client enable
/etc/init.d/socks5client start
