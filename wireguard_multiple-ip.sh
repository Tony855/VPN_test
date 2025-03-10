#!/bin/bash
#
# https://github.com/Tony855/MySocks5
#
# Based on the work of Nyr and contributors at:
# https://github.com/Nyr/wireguard-install
#
# Copyright (c) 2022-2024 Lin Song <linsongui@gmail.com>
# Copyright (c) 2020-2023 Nyr
#
# Released under the MIT License, see the accompanying file LICENSE.txt
# or https://opensource.org/licenses/MIT

exiterr()  { echo "Error: $1" >&2; exit 1; }
exiterr2() { exiterr "'apt-get install' failed."; }
exiterr3() { exiterr "'yum install' failed."; }
exiterr4() { exiterr "'zypper install' failed."; }

check_ip() {
    IP_REGEX='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
    printf '%s' "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}

check_pvt_ip() {
    IPP_REGEX='^(10|127|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168|169\.254)\.'
    printf '%s' "$1" | tr -d '\n' | grep -Eq "$IPP_REGEX"
}

check_dns_name() {
    FQDN_REGEX='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    printf '%s' "$1" | tr -d '\n' | grep -Eq "$FQDN_REGEX"
}

check_root() {
    if [ "$(id -u)" != 0 ]; then
        exiterr "This installer must be run as root. Try 'sudo bash $0'"
    fi
}

check_shell() {
    if readlink /proc/$$/exe | grep -q "dash"; then
        exiterr 'This installer needs to be run with "bash", not "sh".'
    fi
}

check_kernel() {
    if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
        exiterr "The system is running an old kernel, which is incompatible with this installer."
    fi
}

check_os() {
    if grep -qs "ubuntu" /etc/os-release; then
        os="ubuntu"
        os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
    elif [[ -e /etc/debian_version ]]; then
        os="debian"
        os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
    elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
        os="centos"
        os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
    elif [[ -e /etc/fedora-release ]]; then
        os="fedora"
        os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
    elif [[ -e /etc/SUSE-brand && "$(head -1 /etc/SUSE-brand)" == "openSUSE" ]]; then
        os="openSUSE"
        os_version=$(tail -1 /etc/SUSE-brand | grep -oE '[0-9\\.]+')
    else
        exiterr "This installer seems to be running on an unsupported distribution.
Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS, Fedora and openSUSE."
    fi
}

check_os_ver() {
    if [[ "$os" == "ubuntu" && "$os_version" -lt 2004 ]]; then
        exiterr "Ubuntu 20.04 or higher is required to use this installer."
    fi
    if [[ "$os" == "debian" && "$os_version" -lt 11 ]]; then
        exiterr "Debian 11 or higher is required to use this installer."
    fi
    if [[ "$os" == "centos" && "$os_version" -lt 8 ]]; then
        exiterr "CentOS 8 or higher is required to use this installer."
    fi
}

check_container() {
    if systemd-detect-virt -cq 2>/dev/null; then
        exiterr "This system is running inside a container, which is not supported by this installer."
    fi
}

set_client_name() {
    if [[ "$unsanitized_client" == "auto" || -z "$unsanitized_client" ]]; then
        max_num=$(grep '^# BEGIN_PEER' "$WG_CONF" | cut -d' ' -f3 | grep -Eo '[0-9]+$' | sed 's/^0*//' | sort -nr | head -n1)
        [ -z "$max_num" ] && max_num=0
        next_num=$((10#$max_num + 1))
        client="router$(printf "%03d" "$next_num")"
    else
        client=$(sed 's/[^0-9a-zA-Z_-]//g' <<< "$unsanitized_client" | cut -c-15)
    fi
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case $1 in
            --auto)
                auto=1
                shift
                ;;
            --serverips)
                server_ips="$2"
                shift 2
                ;;
            --addclient)
                add_client=1
                unsanitized_client="$2"
                shift 2
                ;;
            --listclients)
                list_clients=1
                shift
                ;;
            --removeclient)
                remove_client=1
                unsanitized_client="$2"
                shift 2
                ;;
            --showclientqr)
                show_client_qr=1
                unsanitized_client="$2"
                shift 2
                ;;
            --uninstall)
                remove_wg=1
                shift
                ;;
            --serveraddr)
                server_addr="$2"
                shift 2
                ;;
            --port)
                base_port="$2"
                shift 2
                ;;
            --clientname)
                first_client_name="$2"
                shift 2
                ;;
            --dns1)
                dns1="$2"
                shift 2
                ;;
            --dns2)
                dns2="$2"
                shift 2
                ;;
            -y|--yes)
                assume_yes=1
                shift
                ;;
            -h|--help)
                show_usage
                ;;
            *)
                show_usage "Unknown parameter: $1"
                ;;
        esac
    done
}

check_args() {
    [ -z "$server_ips" ] && exiterr "Missing required parameter: --serverips"
    IFS=',' read -ra WG_INTERFACES <<< "$server_ips"
    for ip in "${WG_INTERFACES[@]}"; do
        ip_trim=$(echo "$ip" | xargs)
        check_ip "$ip_trim" || exiterr "Invalid IP: $ip_trim"
    done
    total_interfaces=${#WG_INTERFACES[@]}
    [ "$total_interfaces" -eq 0 ] && exiterr "No valid IPs provided"
}

install_pkgs() {
    if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
        export DEBIAN_FRONTEND=noninteractive
        (
            set -x
            apt-get -yqq update && apt-get -yqq install wireguard qrencode >/dev/null
        ) || exiterr2
    elif [[ "$os" == "centos" ]]; then
        (
            set -x
            yum -y -q install epel-release elrepo-release >/dev/null
            yum -y -q install kmod-wireguard wireguard-tools qrencode >/dev/null
        ) || exiterr3
    elif [[ "$os" == "fedora" ]]; then
        (
            set -x
            dnf install -y wireguard-tools qrencode >/dev/null
        ) || exiterr3
    elif [[ "$os" == "openSUSE" ]]; then
        (
            set -x
            zypper install -y wireguard-tools qrencode >/dev/null
        ) || exiterr4
    fi
}

create_server_config() {
    local idx=$1
    local ip=$2
    local port=$((base_port + idx))
    WG_CONF="/etc/wireguard/wg${idx}.conf"
    
    cat << EOF > "$WG_CONF"
[Interface]
Address = 10.25.25${idx}.1/24
PrivateKey = $(wg genkey)
ListenPort = $port
EOF
    chmod 600 "$WG_CONF"
}

create_firewall_rules() {
    local idx=$1
    local port=$((base_port + idx))
    if systemctl is-active --quiet firewalld.service; then
        firewall-cmd --add-port=$port/udp --permanent
        firewall-cmd --reload
    else
        iptables -A INPUT -p udp --dport $port -j ACCEPT
        iptables-save > /etc/iptables/rules.v4
    fi
}

generate_clients() {
    local idx=$1
    local ip=$2
    WG_CONF="/etc/wireguard/wg${idx}.conf"
    for client_num in {1..10}; do
        client="client${idx}-${client_num}"
        key=$(wg genkey)
        psk=$(wg genpsk)
        octet=$((client_num + 1))
        cat << EOF >> "$WG_CONF"
# BEGIN_PEER $client
[Peer]
PublicKey = $(wg pubkey <<< "$key")
PresharedKey = $psk
AllowedIPs = 10.25.25${idx}.${octet}/32
# END_PEER $client
EOF
        cat << EOF > "/root/${client}.conf"
[Interface]
Address = 10.25.25${idx}.${octet}/24
DNS = 8.8.8.8
PrivateKey = $key

[Peer]
PublicKey = $(grep PrivateKey "$WG_CONF" | cut -d' ' -f3 | wg pubkey)
PresharedKey = $psk
Endpoint = ${ip}:$((base_port + idx))
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF
    done
}

start_services() {
    for idx in $(seq 0 $((total_interfaces - 1))); do
        systemctl enable --now wg-quick@wg${idx}.service
    done
}

show_qr_codes() {
    for idx in $(seq 0 $((total_interfaces - 1))); do
        for client_num in {1..10}; do
            client="client${idx}-${client_num}"
            qrencode -t ansiutf8 < "/root/${client}.conf"
            echo "QR code for $client generated: /root/${client}.conf"
        done
    done
}

uninstall_wg() {
    for idx in $(seq 0 $((total_interfaces - 1))); do
        systemctl stop wg-quick@wg${idx}.service
        rm -f "/etc/wireguard/wg${idx}.conf"
    done
    rm -f /root/client*.conf
    apt-get remove --purge -y wireguard >/dev/null
}

main() {
    check_root
    check_args
    install_pkgs
    
    base_port=${base_port:-51620}
    for idx in $(seq 0 $((total_interfaces - 1))); do
        ip=${WG_INTERFACES[$idx]}
        create_server_config $idx $ip
        create_firewall_rules $idx
        generate_clients $idx $ip
    done
    
    start_services
    show_qr_codes
    echo "WireGuard setup complete with ${total_interfaces} interfaces!"
}

if [[ "$1" == "--uninstall" ]]; then
    uninstall_wg
    echo "WireGuard uninstalled"
    exit 0
fi

main "$@"
