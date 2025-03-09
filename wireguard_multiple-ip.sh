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
            --serverip)
                server_ip="$2"
                shift
                shift
                ;;
            --serverips)
                server_ips="$2"
                shift
                shift
                ;;
            --addclient)
                add_client=1
                unsanitized_client="$2"
                shift
                shift
                ;;
            --listclients)
                list_clients=1
                shift
                ;;
            --removeclient)
                remove_client=1
                unsanitized_client="$2"
                shift
                shift
                ;;
            --showclientqr)
                show_client_qr=1
                unsanitized_client="$2"
                shift
                shift
                ;;
            --uninstall)
                remove_wg=1
                shift
                ;;
            --serveraddr)
                server_addr="$2"
                shift
                shift
                ;;
            --port)
                server_port="$2"
                shift
                shift
                ;;
            --clientname)
                first_client_name="$2"
                shift
                shift
                ;;
            --dns1)
                dns1="$2"
                shift
                shift
                ;;
            --dns2)
                dns2="$2"
                shift
                shift
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
	if [ -n "$server_ip" ] && ! check_ip "$server_ip"; then
		exiterr "Invalid server IP specified: $server_ip"
	fi
	if [ -n "$server_ips" ]; then
		IFS=',' read -ra ips <<< "$server_ips"
		for ip in "${ips[@]}"; do
			if ! check_ip "$ip"; then
				exiterr "Invalid server IP in --serverips: $ip"
			fi
		done
	fi
	if [ "$auto" != 0 ] && [ -e "$WG_CONF" ] && [ "$add_client" = 0 ] && [ "$remove_client" = 0 ] && [ "$show_client_qr" = 0 ] && [ "$remove_wg" = 0 ]; then
    show_usage "Invalid parameter '--auto'. WireGuard is already set up on this server."
    fi
	if [ "$((add_client + list_clients + remove_client + show_client_qr))" -gt 1 ]; then
		show_usage "Specify only one of '--addclient', '--listclients', '--removeclient' or '--showclientqr'."
	fi
	if [ "$remove_wg" = 1 ]; then
		if [ "$((add_client + list_clients + remove_client + show_client_qr + auto))" -gt 0 ]; then
			show_usage "'--uninstall' cannot be specified with other parameters."
		fi
	fi
	if [ ! -e "$WG_CONF" ]; then
		st_text="You must first set up WireGuard before"
		[ "$add_client" = 1 ] && exiterr "$st_text adding a client."
		[ "$remove_client" = 1 ] && exiterr "$st_text removing a client."
		[ "$show_client_qr" = 1 ] && exiterr "$st_text showing QR code for a client."
		[ "$remove_wg" = 1 ] && exiterr "Cannot remove WireGuard because it has not been set up."
	fi
	if [ "$((add_client + remove_client + show_client_qr))" = 1 ] && [ -n "$first_client_name" ]; then
		show_usage "'--clientname' can only be specified when installing WireGuard."
	fi
	if [ -n "$server_addr" ] || [ -n "$server_port" ] || [ -n "$first_client_name" ]; then
		if [ -e "$WG_CONF" ]; then
			show_usage "WireGuard is already set up on this server."
		elif [ "$auto" = 0 ]; then
			show_usage "You must specify '--auto' when using these parameters."
		fi
	fi
	if [ "$add_client" = 1 ]; then
		set_client_name
		if [ -z "$client" ]; then
			exiterr "Invalid client name. Use one word only, no special characters except '-' and '_'."
		elif grep -q "^# BEGIN_PEER $client$" "$WG_CONF"; then
			exiterr "$client: Client already exists."
		fi
	fi
	if [ "$remove_client" = 1 ] || [ "$show_client_qr" = 1 ]; then
		set_client_name
		if [ -z "$client" ] || ! grep -q "^# BEGIN_PEER $client$" "$WG_CONF"; then
			exiterr "Invalid client name, or client does not exist."
		fi
	fi
	if [ -n "$server_addr" ] && { ! check_dns_name "$server_addr" && ! check_ip "$server_addr"; }; then
		exiterr "Invalid server address. Must be a FQDN or IPv4 address."
	fi
	if [ -n "$first_client_name" ]; then
		unsanitized_client="$first_client_name"
		set_client_name
		if [ -z "$client" ]; then
			exiterr "Invalid client name. Use one word only, no special characters except '-' and '_'."
		fi
	fi
	if [ -n "$server_port" ]; then
		if [[ ! "$server_port" =~ ^[0-9]+$ || "$server_port" -gt 65535 ]]; then
			exiterr "Invalid port. Must be between 1 and 65535."
		fi
	fi
	if [ -n "$dns1" ]; then
		if [ -e "$WG_CONF" ] && [ "$add_client" = 0 ]; then
			show_usage "Custom DNS server(s) can only be specified when installing WireGuard or adding a client."
		fi
	fi
	if { [ -n "$dns1" ] && ! check_ip "$dns1"; } || { [ -n "$dns2" ] && ! check_ip "$dns2"; }; then
		exiterr "Invalid DNS server(s)."
	fi
	if [ -z "$dns1" ] && [ -n "$dns2" ]; then
		show_usage "--dns2 cannot be specified without --dns1."
	fi
	if [ -n "$dns1" ] && [ -n "$dns2" ]; then
		dns="$dns1, $dns2"
	elif [ -n "$dns1" ]; then
		dns="$dns1"
	else
		dns="8.8.8.8, 8.8.4.4"
	fi
}

check_nftables() {
	if [ "$os" = "centos" ]; then
		if grep -qs "hwdsl2 VPN script" /etc/sysconfig/nftables.conf \
			|| systemctl is-active --quiet nftables 2>/dev/null; then
			exiterr "This system has nftables enabled, which is not supported."
		fi
	fi
}

install_wget() {
	if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
		if [ "$auto" = 0 ]; then
			echo "Wget is required to use this installer."
			read -n1 -r -p "Press any key to install Wget..."
		fi
		export DEBIAN_FRONTEND=noninteractive
		(
			set -x
			apt-get -yqq update || apt-get -yqq update
			apt-get -yqq install wget >/dev/null
		) || exiterr2
	fi
}

install_iproute() {
	if ! hash ip 2>/dev/null; then
		if [ "$auto" = 0 ]; then
			echo "iproute is required."
			read -n1 -r -p "Press any key to install iproute..."
		fi
		if [ "$os" = "debian" ] || [ "$os" = "ubuntu" ]; then
			export DEBIAN_FRONTEND=noninteractive
			(
				set -x
				apt-get -yqq update || apt-get -yqq update
				apt-get -yqq install iproute2 >/dev/null
			) || exiterr2
		elif [ "$os" = "openSUSE" ]; then
			(
				set -x
				zypper install iproute2 >/dev/null
			) || exiterr4
		else
			(
				set -x
				yum -y -q install iproute >/dev/null
			) || exiterr3
		fi
	fi
}

show_header() {
cat <<'EOF'

WireGuard Script
https://github.com/Tony855/MySocks5
EOF
}

show_header2() {
cat <<'EOF'

Welcome to this WireGuard server installer!
GitHub: https://github.com/Tony855/MySocks5

EOF
}

show_header3() {
cat <<'EOF'

Copyright (c) 2022-2024 Lin Song
Copyright (c) 2020-2023 Nyr
EOF
}

show_usage() {
	if [ -n "$1" ]; then
		echo "Error: $1" >&2
	fi
	show_header
	show_header3
cat 1>&2 <<EOF

Usage: bash $0 [options]

Options:

  --addclient [client name]      add a new client
  --serverip [server IP]         specify server IP for new client
  --serverips [IP1,IP2,...]      specify multiple server IPs during setup
  --dns1 [DNS IP]                primary DNS for new client (default: Google)
  --dns2 [DNS IP]                secondary DNS for new client
  --listclients                  list existing clients
  --removeclient [client name]   remove a client
  --showclientqr [client name]   show QR code for a client
  --uninstall                    remove WireGuard
  -y, --yes                      assume "yes" to prompts
  -h, --help                     show help

Install options:

  --auto                         auto install with default/custom options
  --serveraddr [DNS or IP]       server address (FQDN or IPv4)
  --port [number]                WireGuard port (default: 51620)
  --clientname [client name]     name for first client (default: client)
  --dns1 [DNS IP]                primary DNS for first client
  --dns2 [DNS IP]                secondary DNS for first client
EOF
	exit 1
}

show_welcome() {
	if [ "$auto" = 0 ]; then
		show_header2
		echo 'Answer a few questions to start setup.'
	else
		show_header
		op_text=default
		if [ -n "$server_addr" ] || [ -n "$server_port" ] \
			|| [ -n "$first_client_name" ] || [ -n "$dns1" ]; then
			op_text=custom
		fi
		echo "Starting WireGuard setup using $op_text options."
	fi
}

enter_server_address() {
	echo
	echo "Should clients connect via DNS name or IP?"
	printf "Use DNS name? [y/N] "
	read -r response
	case $response in
		[yY][eE][sS]|[yY])
			use_dns_name=1
			echo
			;;
		*)
			use_dns_name=0
			;;
	esac
	if [ "$use_dns_name" = 1 ]; then
		read -rp "Enter DNS name of this server: " server_addr_i
		until check_dns_name "$server_addr_i"; do
			echo "Invalid DNS name. Enter FQDN."
			read -rp "Enter DNS name: " server_addr_i
		done
		ip="$server_addr_i"
		show_dns_name_note "$ip"
	else
		detect_ip
		check_nat_ip
	fi
}

detect_ip() {
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		ip=$(ip -4 route get 1 | sed 's/ uid .*//' | awk '{print $NF;exit}' 2>/dev/null)
		if ! check_ip "$ip"; then
			find_public_ip
			ip_match=0
			if [ -n "$get_public_ip" ]; then
				ip_list=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
				while IFS= read -r line; do
					if [ "$line" = "$get_public_ip" ]; then
						ip_match=1
						ip="$line"
					fi
				done <<< "$ip_list"
			fi
			if [ "$ip_match" = 0 ]; then
				if [ "$auto" = 0 ]; then
					echo "Which IPv4 address should be used?"
					num_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
					ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | nl -s ') '
					read -rp "IPv4 address [1]: " ip_num
					until [[ -z "$ip_num" || "$ip_num" =~ ^[0-9]+$ && "$ip_num" -le "$num_of_ip" ]]; do
						echo "$ip_num: invalid."
						read -rp "IPv4 address [1]: " ip_num
					done
					[[ -z "$ip_num" ]] && ip_num=1
				else
					ip_num=1
				fi
				ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | sed -n "$ip_num"p)
			fi
		fi
	fi
	if ! check_ip "$ip"; then
		exiterr "Could not detect server IP."
	fi
}

check_nat_ip() {
	if check_pvt_ip "$ip"; then
		find_public_ip
		if ! check_ip "$get_public_ip"; then
			if [ "$auto" = 0 ]; then
				echo "This server is behind NAT. Enter public IPv4:"
				read -rp "Public IPv4: " public_ip
				until check_ip "$public_ip"; do
					echo "Invalid IP."
					read -rp "Public IPv4: " public_ip
				done
			else
				exiterr "Could not detect public IP."
			fi
		else
			public_ip="$get_public_ip"
		fi
	fi
}

show_config() {
	if [ "$auto" != 0 ]; then
		echo
		if [ -n "$server_addr" ]; then
			echo "Server address: $server_addr"
		else
			printf '%s' "Server IP: "
			[ -n "$public_ip" ] && echo "$public_ip" || echo "$ip"
		fi
		[ -n "$server_port" ] && port_text="$server_port" || port_text=51620
		[ -n "$first_client_name" ] && client_text="$client" || client_text=client
		echo "Port: UDP/$port_text"
		echo "Client name: $client_text"
		echo "Client DNS: $dns"
	fi
}

detect_ipv6() {
	ip6=""
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -ne 0 ]]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n 1p)
	fi
}

select_port() {
	if [ "$auto" = 0 ]; then
		echo
		echo "Enter port for WireGuard:"
		read -rp "Port [51620]: " port
		until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
			echo "$port: invalid."
			read -rp "Port [51620]: " port
		done
		[[ -z "$port" ]] && port=51620
	else
		[ -n "$server_port" ] && port="$server_port" || port=51620
	fi
}

enter_first_client_name() {
	if [ "$auto" = 0 ]; then
		echo
		echo "Enter name for first client:"
		read -rp "Name [client]: " unsanitized_client
		set_client_name
		[[ -z "$client" ]] && client=client
	else
		if [ -n "$first_client_name" ]; then
			unsanitized_client="$first_client_name"
			set_client_name
		else
			client=client
		fi
	fi
}

show_setup_ready() {
	if [ "$auto" = 0 ]; then
		echo
		echo "WireGuard installation is ready."
	fi
}

check_firewall() {
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
		elif [[ "$os" == "openSUSE" ]]; then
			firewall="firewalld"
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			firewall="iptables"
		fi
		if [[ "$firewall" == "firewalld" ]]; then
			echo "Note: firewalld will be installed."
		fi
	fi
}

confirm_setup() {
	if [ "$auto" = 0 ]; then
		printf "Continue? [Y/n] "
		read -r response
		case $response in
			[yY][eE][sS]|[yY]|'') ;;
			*) abort_and_exit ;;
		esac
	fi
}

show_start_setup() {
	echo
	echo "Installing WireGuard..."
}

install_pkgs() {
	if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
		export DEBIAN_FRONTEND=noninteractive
		(
			set -x
			apt-get -yqq update || apt-get -yqq update
			apt-get -yqq install wireguard qrencode $firewall >/dev/null
		) || exiterr2
	elif [[ "$os" == "centos" && "$os_version" -eq 9 ]]; then
		(
			set -x
			yum -y -q install epel-release >/dev/null
			yum -y -q install wireguard-tools qrencode $firewall >/dev/null
		) || exiterr3
	elif [[ "$os" == "centos" && "$os_version" -eq 8 ]]; then
		(
			set -x
			yum -y -q install epel-release elrepo-release >/dev/null
			yum -y -q --nobest install kmod-wireguard >/dev/null
			yum -y -q install wireguard-tools qrencode $firewall >/dev/null
		) || exiterr3
	elif [[ "$os" == "fedora" ]]; then
		(
			set -x
			dnf install -y wireguard-tools qrencode $firewall >/dev/null
		) || exiterr3
	elif [[ "$os" == "openSUSE" ]]; then
		(
			set -x
			zypper install -y wireguard-tools qrencode $firewall >/dev/null
		) || exiterr4
	fi
	[ ! -d /etc/wireguard ] && exiterr2
	if [[ "$firewall" == "firewalld" ]]; then
		(
			set -x
			systemctl enable --now firewalld.service >/dev/null
		)
	fi
	if [ $? -ne 0 ]; then
        exiterr "Failed to install required packages."
    fi
}


create_server_config() {
    cat << EOF > "$WG_CONF"
# Do not alter these lines
# ENDPOINT $([[ -n "$public_ip" ]] && echo "$public_ip" || echo "$ip")
# SERVER_IPS ${server_ips}

[Interface]
Address = 10.29.29.1/24$([[ -n "$ip6" ]] && echo ", fddd:2c4:2c4:2c4::1/64")
PrivateKey = $(wg genkey)
ListenPort = $port

EOF
    chmod 600 "$WG_CONF"
}

create_firewall_rules() {
	if systemctl is-active --quiet firewalld.service; then
		firewall-cmd -q --add-port="$port"/udp
		firewall-cmd -q --zone=trusted --add-source=10.29.29.0/24
		firewall-cmd -q --permanent --add-port="$port"/udp
		firewall-cmd -q --permanent --zone=trusted --add-source=10.29.29.0/24
		firewall-cmd -q --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.29.29.0/24 ! -d 10.29.29.0/24 -j MASQUERADE
		firewall-cmd -q --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.29.29.0/24 ! -d 10.29.29.0/24 -j MASQUERADE
		if [[ -n "$ip6" ]]; then
			firewall-cmd -q --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64
			firewall-cmd -q --permanent --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64
			firewall-cmd -q --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
			firewall-cmd -q --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
		fi
	else
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.29.29.0/24 ! -d 10.29.29.0/24 -j MASQUERADE
ExecStart=$iptables_path -I INPUT -p udp --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.29.29.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.29.29.0/24 ! -d 10.29.29.0/24 -j MASQUERADE
ExecStop=$iptables_path -D INPUT -p udp --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.29.29.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/wg-iptables.service
		if [[ -n "$ip6" ]]; then
			echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
ExecStart=$ip6tables_path -I FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
ExecStop=$ip6tables_path -D FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/wg-iptables.service
		fi
		echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/wg-iptables.service
		(
			set -x
			systemctl enable --now wg-iptables.service >/dev/null
		)
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

get_server_ip() {
    if [ -n "$server_ip" ]; then
        echo "$server_ip"
        return
    fi
    server_ips_line=$(grep '^# SERVER_IPS' "$WG_CONF" | cut -d ' ' -f 3-)
    if [ -n "$server_ips_line" ]; then
        IFS=',' read -ra server_ips <<< "$server_ips_line"
        num_ips=${#server_ips[@]}
        if [ "$num_ips" -gt 0 ]; then
            last_ip_index=$(grep '^# LAST_IP_INDEX' "$WG_CONF" | cut -d ' ' -f 3)
            current_index=$(( (last_ip_index + 1) % num_ips ))
            sed -i "/^# LAST_IP_INDEX/d" "$WG_CONF"
            echo "# LAST_IP_INDEX $current_index" >> "$WG_CONF"
            echo "${server_ips[$current_index]}"
            return
        fi
    fi
    grep '^# ENDPOINT' "$WG_CONF" | cut -d " " -f 3
}

new_client() {
	select_client_ip
	specify_ip=n
	if [ "$1" = "add_client" ] && [ "$add_client" = 0 ]; then
		echo
		read -rp "Specify internal IP for client? [y/N]: " specify_ip
		until [[ "$specify_ip" =~ ^[yYnN]*$ ]]; do
			echo "$specify_ip: invalid."
			read -rp "Specify IP? [y/N]: " specify_ip
		done
		if [[ ! "$specify_ip" =~ ^[yY]$ ]]; then
			echo "Using auto IP 10.29.29.$octet."
		fi
	fi
	if [[ "$specify_ip" =~ ^[yY]$ ]]; then
		echo
		read -rp "Enter IP for client (e.g. 10.29.29.X): " client_ip
		octet=$(printf '%s' "$client_ip" | cut -d "." -f 4)
		until [[ $client_ip =~ ^10\.29\.29\.([2-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$ ]] \
			&& ! grep AllowedIPs "$WG_CONF" | cut -d "." -f 4 | grep -q "^$octet$"; do
			if [[ ! $client_ip =~ ^10\.29\.29\.([2-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$ ]]; then
				echo "Invalid IP. Must be 10.29.29.2-254."
			else
				echo "IP already in use."
			fi
			read -rp "Enter IP for client: " client_ip
			octet=$(printf '%s' "$client_ip" | cut -d "." -f 4)
		done
	fi
	key=$(wg genkey)
	psk=$(wg genpsk)
	endpoint_ip=$(get_server_ip)
	cat << EOF >> "$WG_CONF"
# BEGIN_PEER $client
[Peer]
PublicKey = $(wg pubkey <<< "$key")
PresharedKey = $psk
AllowedIPs = 10.29.29.$octet/32$([[ -n "$ip6" ]] && echo ", fddd:2c4:2c4:2c4::$octet/128")
# CLIENT_OCTET $octet
# CLIENT_ENDPOINT $endpoint_ip
# END_PEER $client
EOF
	get_export_dir
	port=$(grep ListenPort "$WG_CONF" | cut -d " " -f 3)
	cat << EOF > "${export_dir}router-${octet}.conf"
[Interface]
Address = 10.29.29.$octet/24$([[ -n "$ip6" ]] && echo ", fddd:2c4:2c4:2c4::$octet/64")
DNS = $dns
PrivateKey = $key

[Peer]
PublicKey = $(grep PrivateKey "$WG_CONF" | cut -d " " -f 3 | wg pubkey)
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${endpoint_ip}:${port}
PersistentKeepalive = 25
EOF
	if [ "$export_to_home_dir" = 1 ]; then
		chown "$SUDO_USER:$SUDO_USER" "${export_dir}router-${octet}.conf"
	fi
	chmod 600 "${export_dir}router-${octet}.conf"
}

update_sysctl() {
	mkdir -p /etc/sysctl.d
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard-forward.conf
	[[ -n "$ip6" ]] && echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-wireguard-forward.conf
	sysctl -e -q -p /etc/sysctl.d/99-wireguard-forward.conf
}

start_wg_service() {
	systemctl enable --now wg-quick@wg0.service >/dev/null
}

show_client_qr_code() {
    get_export_dir
    octet=$(sed -n "/^# BEGIN_PEER $client$/,/^# END_PEER $client/p" "$WG_CONF" | grep '# CLIENT_OCTET' | awk '{print $3}')
    qrencode -t UTF8 < "${export_dir}router-${octet}.conf"
    echo -e '\xE2\x86\x91 QR code for client configuration.'
}

finish_setup() {
	echo
	echo "Finished! Client config: ${export_dir}router-${octet}.conf"
}

wgsetup() {

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

check_root
check_shell
check_kernel
check_os
check_os_ver
check_container

WG_CONF="/etc/wireguard/wg0.conf"

parse_args "$@"
check_args

if [ "$add_client" = 1 ]; then
	show_header
	new_client add_client
	start_wg_service
	show_client_qr_code
	print_client_added
	exit 0
fi

if [ "$list_clients" = 1 ]; then
	show_header
	check_clients
	show_clients
	print_client_total
	exit 0
fi

if [ "$remove_client" = 1 ]; then
	show_header
	confirm_remove_client
	if [[ "$remove" =~ ^[yY]$ ]]; then
		remove_client_wg
		print_client_removed
		exit 0
	else
		print_client_removal_aborted
		exit 1
	fi
fi

if [ "$show_client_qr" = 1 ]; then
	show_header
	check_client_conf
	show_client_qr_code
	exit 0
fi

if [ "$remove_wg" = 1 ]; then
	show_header
	confirm_remove_wg
	if [[ "$remove" =~ ^[yY]$ ]]; then
		remove_wg
		print_wg_removed
		exit 0
	else
		print_wg_removal_aborted
		exit 1
	fi
fi

if [[ ! -e "$WG_CONF" ]]; then
	check_nftables
	install_wget
	install_iproute
	show_welcome
	if [ "$auto" = 0 ]; then
		enter_server_address
	else
		if [ -n "$server_addr" ]; then
			ip="$server_addr"
		else
			detect_ip
			check_nat_ip
		fi
	fi
	show_config
	detect_ipv6
	select_port
	enter_first_client_name
	select_dns
	show_setup_ready
	check_firewall
	confirm_setup
	show_start_setup
	install_pkgs
	create_server_config
	update_sysctl
	create_firewall_rules
	update_rclocal
	new_client
	start_wg_service
	show_client_qr_code
	finish_setup
else
	show_header
	select_menu_option
	case "$option" in
		1)
			enter_client_name
			select_dns
			new_client
			start_wg_service
			show_client_qr_code
			exit 0
		;;
		2)
			check_clients
			show_clients
			exit 0
		;;
		3)
			check_clients
			select_client_to remove
			confirm_remove_client
			if [[ "$remove" =~ ^[yY]$ ]]; then
				remove_client_wg
				print_client_removed
				exit 0
			fi
			exit 1
		;;
		4)
			check_clients
			select_client_to "show QR"
			show_client_qr_code
			exit 0
		;;
		5)
			confirm_remove_wg
			if [[ "$remove" =~ ^[yY]$ ]]; then
				remove_wg
				print_wg_removed
				exit 0
			fi
			exit 1
		;;
		6)
			exit 0
		;;
	esac
fi
}

wgsetup "$@"
exit 0
