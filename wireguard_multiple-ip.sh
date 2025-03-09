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
        exiterr "This installer seems to be running on an unsupported distribution."
    fi
}

check_os_ver() {
    case "$os" in
        ubuntu) [[ "$os_version" -lt 2004 ]] && exiterr "Ubuntu 20.04 or higher required." ;;
        debian) [[ "$os_version" -lt 11 ]] && exiterr "Debian 11 or higher required." ;;
        centos) [[ "$os_version" -lt 8 ]] && exiterr "CentOS 8 or higher required." ;;
    esac
}

check_container() {
    if systemd-detect-virt -cq 2>/dev/null; then
        exiterr "This system is running inside a container."
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
            --auto) auto=1; shift ;;
            --addclient) add_client=1; unsanitized_client="$2"; shift 2 ;;
            --listclients) list_clients=1; shift ;;
            --removeclient) remove_client=1; unsanitized_client="$2"; shift 2 ;;
            --showclientqr) show_client_qr=1; unsanitized_client="$2"; shift 2 ;;
            --uninstall) remove_wg=1; shift ;;
            --serveraddr) 
                server_addr="$2"
                shift 2
                ;;
            --port)
                if [ -e "$WG_CONF" ]; then
                    exiterr "Cannot modify port after initial setup."
                else
                    server_port="$2"
                fi
                shift 2 ;;
            --clientname) first_client_name="$2"; shift 2 ;;
            --dns1) dns1="$2"; shift 2 ;;
            --dns2) dns2="$2"; shift 2 ;;
            -y|--yes) assume_yes=1; shift ;;
            -h|--help) show_usage ;;
            *) show_usage "Unknown parameter: $1" ;;
        esac
    done
}

check_args() {
    if [ "$auto" != 0 ] && [ -e "$WG_CONF" ]; then
        exiterr "--auto cannot be used after initial setup."
    fi
    if [ "$((add_client + list_clients + remove_client + show_client_qr))" -gt 1 ]; then
        exiterr "Cannot specify multiple actions."
    fi
    if [ "$remove_wg" = 1 ] && [ "$((add_client + list_clients + remove_client + show_client_qr + auto))" -gt 0 ]; then
        exiterr "--uninstall cannot combine with other parameters."
    fi
    if [ -n "$server_addr" ] && { ! check_dns_name "$server_addr" && ! check_ip "$server_addr"; }; then
        exiterr "Invalid server address format."
    fi
}

update_endpoint() {
    if [ -n "$server_addr" ]; then
        sed -i "s|^# ENDPOINT .*|# ENDPOINT $server_addr|" "$WG_CONF"
        echo "Updated server endpoint to: $server_addr"
    fi
}

select_client_ip() {
    client_count=$(grep -c '^# BEGIN_PEER' "$WG_CONF")
    octet=$((254 - client_count))
    while : ; do
        [ "$octet" -eq 1 ] && octet=254 && client_count=0
        if ! grep -q "10.29.29.$octet/32" "$WG_CONF"; then
            break
        else
            ((client_count++))
            octet=$((254 - client_count))
        fi
        [ "$octet" -lt 2 ] && exiterr "IP pool exhausted!"
    done
}

new_client() {
    update_endpoint
    select_client_ip
    key=$(wg genkey)
    psk=$(wg genpsk)

    cat << EOF >> "$WG_CONF"
# BEGIN_PEER $client
[Peer]
PublicKey = $(wg pubkey <<< "$key")
PresharedKey = $psk
AllowedIPs = 10.29.29.$octet/32
# END_PEER $client
EOF

    get_export_dir
    cat << EOF > "${export_dir}router-${octet}.conf"
[Interface]
Address = 10.29.29.$octet/24
DNS = $dns
PrivateKey = $key

[Peer]
PublicKey = $(grep PrivateKey "$WG_CONF" | cut -d " " -f 3 | wg pubkey)
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $(grep '^# ENDPOINT' "$WG_CONF" | cut -d " " -f 3):$(grep ListenPort "$WG_CONF" | cut -d " " -f 3)
PersistentKeepalive = 25
EOF

    [ "$export_to_home_dir" = 1 ] && chown "$SUDO_USER:$SUDO_USER" "${export_dir}router-${octet}.conf"
    chmod 600 "${export_dir}router-${octet}.conf"
}

show_usage() {
    cat <<EOF
Usage: bash $0 [options]

Options:
  --addclient [client]       Add a new client
  --serveraddr [IP/DNS]      Server address (initial setup or update)
  --port [number]            Server port (initial setup only)
  --listclients              List existing clients
  --removeclient [client]    Remove a client
  --showclientqr [client]    Show QR code for a client
  --uninstall                Uninstall WireGuard
  -y, --yes                  Auto-confirm actions
  -h, --help                 Show this help
EOF
    exit 1
}

get_export_dir() {
    export_to_home_dir=0
    export_dir=~/
    if [ -n "$SUDO_USER" ] && getent group "$SUDO_USER" >/dev/null 2>&1; then
        user_home_dir=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
        if [ -d "$user_home_dir" ] && [ "$user_home_dir" != "/" ]; then
            export_dir="$user_home_dir/"
            export_to_home_dir=1
        fi
    fi
}

install_pkgs() {
    case "$os" in
        ubuntu|debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get -yqq update && apt-get -yqq install wireguard qrencode iptables >/dev/null ;;
        centos|fedora)
            yum -y -q install epel-release && yum -y -q install wireguard-tools qrencode >/dev/null ;;
        openSUSE)
            zypper install -y wireguard-tools qrencode >/dev/null ;;
    esac || exiterr "Package installation failed."
}

create_firewall_rules() {
    iptables -t nat -A POSTROUTING -s 10.29.29.0/24 -j MASQUERADE
    iptables -I INPUT -p udp --dport "$port" -j ACCEPT
    iptables -I FORWARD -s 10.29.29.0/24 -j ACCEPT
}

wgsetup() {
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    WG_CONF="/etc/wireguard/wg0.conf"

    auto=0
    assume_yes=0
    add_client=0
    list_clients=0
    remove_client=0
    show_client_qr=0
    remove_wg=0
    server_addr=""
    server_port="51620"

    parse_args "$@"
    check_args

    if [ "$add_client" = 1 ]; then
        set_client_name
        new_client
        echo "Client config generated: ${export_dir}router-${octet}.conf"
        exit 0
    fi

    if [[ ! -e "$WG_CONF" ]]; then
        install_pkgs
        detect_ip
        select_port
        create_server_config
        create_firewall_rules
        new_client
        systemctl enable --now wg-quick@wg0.service
        echo "WireGuard installation completed!"
    else
        show_usage
    fi
}

create_server_config() {
    cat << EOF > "$WG_CONF"
# ENDPOINT ${server_addr:-$(detect_ip)}

[Interface]
Address = 10.29.29.1/24
PrivateKey = $(wg genkey)
ListenPort = $server_port
EOF
}

wgsetup "$@"
exit 0
