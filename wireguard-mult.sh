#!/bin/bash
#
# https://github.com/hwdsl2/wireguard-install
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
		exiterr "Ubuntu 20.04 or higher is required to use this installer.
This version of Ubuntu is too old and unsupported."
	fi
	if [[ "$os" == "debian" && "$os_version" -lt 11 ]]; then
		exiterr "Debian 11 or higher is required to use this installer.
This version of Debian is too old and unsupported."
	fi
	if [[ "$os" == "centos" && "$os_version" -lt 8 ]]; then
		exiterr "CentOS 8 or higher is required to use this installer.
This version of CentOS is too old and unsupported."
	fi
}

check_container() {
	if systemd-detect-virt -cq 2>/dev/null; then
		exiterr "This system is running inside a container, which is not supported by this installer."
	fi
}

set_client_name() {
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
}

# -------------------------- 参数解析（新增 --addclient-iface 参数） --------------------------
parse_args() {
	while [ "$#" -gt 0 ]; do
		case $1 in
			--auto)
				auto=1
				shift
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
				server_port="$2"
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
			--multi)
				multi_mode=1
				multi_cfg="$2"
				shift 2
				;;
			# 新增：指定接口添加客户端命令参数，要求后跟接口名和客户端名称
			--addclient-iface)
				add_client_iface=1
				iface_name="$2"
				client_for_iface="$3"
				shift 3
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
# -----------------------------------------------------------------------------------------

check_args() {
	# 如果启用了多接口模式，则原本禁用客户端管理，但允许--addclient-iface命令
	if [ "$multi_mode" = 1 ] && [ "$((add_client + list_clients + remove_client + show_client_qr))" -gt 0 ] && [ -z "$add_client_iface" ]; then
		show_usage "Client management functions are not supported in multi-mode. Use --addclient-iface to add a client to a specific interface."
	fi
	if [ "$auto" != 0 ] && [ -e "$WG_CONF" ]; then
		show_usage "Invalid parameter '--auto'. WireGuard is already set up on this server."
	fi
	if [ "$((add_client + list_clients + remove_client + show_client_qr))" -gt 1 ]; then
		show_usage "Invalid parameters. Specify only one of '--addclient', '--listclients', '--removeclient' or '--showclientqr'."
	fi
	if [ "$remove_wg" = 1 ]; then
		if [ "$((add_client + list_clients + remove_client + show_client_qr + auto))" -gt 0 ]; then
			show_usage "Invalid parameters. '--uninstall' cannot be specified with other parameters."
		fi
	fi
	if [ ! -e "$WG_CONF" ]; then
		st_text="You must first set up WireGuard before"
		[ "$add_client" = 1 ] && exiterr "$st_text adding a client."
		[ "$list_clients" = 1 ] && exiterr "$st_text listing clients."
		[ "$remove_client" = 1 ] && exiterr "$st_text removing a client."
		[ "$show_client_qr" = 1 ] && exiterr "$st_text showing QR code for a client."
		[ "$remove_wg" = 1 ] && exiterr "Cannot remove WireGuard because it has not been set up on this server."
	fi
	if [ "$((add_client + remove_client + show_client_qr))" = 1 ] && [ -n "$first_client_name" ]; then
		show_usage "Invalid parameters. '--clientname' can only be specified when installing WireGuard."
	fi
	if [ -n "$server_addr" ] || [ -n "$server_port" ] || [ -n "$first_client_name" ]; then
		if [ -e "$WG_CONF" ]; then
			show_usage "Invalid parameters. WireGuard is already set up on this server."
		elif [ "$auto" = 0 ]; then
			show_usage "Invalid parameters. You must specify '--auto' when using these parameters."
		fi
	fi
	if [ "$add_client" = 1 ]; then
		set_client_name
		if [ -z "$client" ]; then
			exiterr "Invalid client name. Use one word only, no special characters except '-' and '_'."
		elif grep -q "^# BEGIN_PEER $client$" "$WG_CONF"; then
			exiterr "$client: invalid name. Client already exists."
		fi
	fi
	if [ "$remove_client" = 1 ] || [ "$show_client_qr" = 1 ]; then
		set_client_name
		if [ -z "$client" ] || ! grep -q "^# BEGIN_PEER $client$" "$WG_CONF"; then
			exiterr "Invalid client name, or client does not exist."
		fi
	fi
	if [ -n "$server_addr" ] && { ! check_dns_name "$server_addr" && ! check_ip "$server_addr"; }; then
		exiterr "Invalid server address. Must be a fully qualified domain name (FQDN) or an IPv4 address."
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
			exiterr "Invalid port. Must be an integer between 1 and 65535."
		fi
	fi
	if [ -n "$dns1" ]; then
		if [ -e "$WG_CONF" ] && [ "$add_client" = 0 ]; then
			show_usage "Invalid parameters. Custom DNS server(s) can only be specified when installing WireGuard or adding a client."
		fi
	fi
	if { [ -n "$dns1" ] && ! check_ip "$dns1"; } \
		|| { [ -n "$dns2" ] && ! check_ip "$dns2"; }; then
		exiterr "Invalid DNS server(s)."
	fi
	if [ -z "$dns1" ] && [ -n "$dns2" ]; then
		show_usage "Invalid DNS server. --dns2 cannot be specified without --dns1."
	fi
	if [ -n "$dns1" ] && [ -n "$dns2" ]; then
		dns="$dns1, $dns2"
	elif [ -n "$dns1" ]; then
		dns="$dns1"
	else
		dns="8.8.8.8, 8.8.4.4"
	fi

	# 新增：如果使用--addclient-iface，则仅在多接口模式下允许此命令
	if [ "$add_client_iface" = 1 ]; then
		if [ "$multi_mode" != 1 ]; then
			show_usage "--addclient-iface can only be used in multi-mode."
		fi
		config_file="/etc/wireguard/${iface_name}.conf"
		if [ ! -f "$config_file" ]; then
			exiterr "Interface $iface_name not found: $config_file does not exist."
		fi
		if [ -z "$client_for_iface" ]; then
			exiterr "Client name must be provided with --addclient-iface."
		fi
	fi
}

check_nftables() {
	if [ "$os" = "centos" ]; then
		if grep -qs "hwdsl2 VPN script" /etc/sysconfig/nftables.conf \
			|| systemctl is-active --quiet nftables 2>/dev/null; then
			exiterr "This system has nftables enabled, which is not supported by this installer."
		fi
	fi
}

install_wget() {
	if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
		if [ "$auto" = 0 ]; then
			echo "Wget is required to use this installer."
			read -n1 -r -p "Press any key to install Wget and continue..."
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
			echo "iproute is required to use this installer."
			read -n1 -r -p "Press any key to install iproute and continue..."
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
https://github.com/hwdsl2/wireguard-install
EOF
}

show_header2() {
cat <<'EOF'

Welcome to this WireGuard server installer!
GitHub: https://github.com/hwdsl2/wireguard-install

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

  --addclient [client name]      add a new client (single interface mode)
  --dns1 [DNS server IP]         primary DNS server for new client (optional, default: Google Public DNS)
  --dns2 [DNS server IP]         secondary DNS server for new client (optional)
  --listclients                  list the names of existing clients (single interface mode)
  --removeclient [client name]   remove an existing client (single interface mode)
  --showclientqr [client name]   show QR code for an existing client (single interface mode)
  --uninstall                    remove WireGuard and delete all configuration
  -y, --yes                      assume "yes" as answer to prompts when removing a client or removing WireGuard
  -h, --help                     show this help message and exit

Install options (optional):

  --auto                         auto install WireGuard using default or custom options
  --serveraddr [DNS name or IP]  server address, must be a fully qualified domain name (FQDN) or an IPv4 address
  --port [number]                port for WireGuard (1-65535, default: 51820)
  --clientname [client name]     name for the first WireGuard client (default: client)
  --dns1 [DNS server IP]         primary DNS server for first client (default: Google Public DNS)
  --dns2 [DNS server IP]         secondary DNS server for first client

Multi-interface mode:

  --multi "[iface1]:[port1]:[public_ip1],[iface2]:[port2]:[public_ip2],..."
       Enable multi-interface mode. Each interface will be configured with its own configuration file.
       In this mode, the internal subnet for the first interface will be 10.29.10.0/24 (gateway 10.29.10.1),
       the second 10.29.11.0/24 (gateway 10.29.11.1), etc.

  --addclient-iface [iface] [client name]
       Add a new client to the specified interface in multi-mode.
EOF
	exit 1
}

show_welcome() {
	if [ "$auto" = 0 ]; then
		show_header2
		echo 'I need to ask you a few questions before starting setup.'
		echo 'You can use the default options and just press enter if you are OK with them.'
	else
		show_header
		op_text=default
		if [ -n "$server_addr" ] || [ -n "$server_port" ] \
			|| [ -n "$first_client_name" ] || [ -n "$dns1" ]; then
			op_text=custom
		fi
		echo
		echo "Starting WireGuard setup using $op_text options."
	fi
}

show_dns_name_note() {
cat <<EOF

Note: Make sure this DNS name '$1'
      resolves to the IPv4 address of this server.
EOF
}

enter_server_address() {
	echo
	echo "Do you want WireGuard VPN clients to connect to this server using a DNS name,"
	printf "e.g. vpn.example.com, instead of its IP address? [y/N] "
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
		read -rp "Enter the DNS name of this VPN server: " server_addr_i
		until check_dns_name "$server_addr_i"; do
			echo "Invalid DNS name. You must enter a fully qualified domain name (FQDN)."
			read -rp "Enter the DNS name of this VPN server: " server_addr_i
		done
		ip="$server_addr_i"
		show_dns_name_note "$ip"
	else
		detect_ip
		check_nat_ip
	fi
}

find_public_ip() {
	ip_url1="http://ipv4.icanhazip.com"
	ip_url2="http://ip1.dynupdate.no-ip.com"
	get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "$ip_url1" || curl -m 10 -4Ls "$ip_url1")")
	if ! check_ip "$get_public_ip"; then
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "$ip_url2" || curl -m 10 -4Ls "$ip_url2")")
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
					echo
					echo "Which IPv4 address should be used?"
					num_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
					ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
					read -rp "IPv4 address [1]: " ip_num
					until [[ -z "$ip_num" || "$ip_num" =~ ^[0-9]+$ && "$ip_num" -le "$num_of_ip" ]]; do
						echo "$ip_num: invalid selection."
						read -rp "IPv4 address [1]: " ip_num
					done
					[[ -z "$ip_num" ]] && ip_num=1
				else
					ip_num=1
				fi
				ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_num"p)
			fi
		fi
	fi
	if ! check_ip "$ip"; then
		echo "Error: Could not detect this server's IP address." >&2
		echo "Abort. No changes were made." >&2
		exit 1
	fi
}

check_nat_ip() {
	if check_pvt_ip "$ip"; then
		find_public_ip
		if ! check_ip "$get_public_ip"; then
			if [ "$auto" = 0 ]; then
				echo
				echo "This server is behind NAT. What is the public IPv4 address?"
				read -rp "Public IPv4 address: " public_ip
				until check_ip "$public_ip"; do
					echo "Invalid input."
					read -rp "Public IPv4 address: " public_ip
				done
			else
				echo "Error: Could not detect this server's public IP." >&2
				echo "Abort. No changes were made." >&2
				exit 1
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
			[ -n "$public_ip" ] && printf '%s\n' "$public_ip" || printf '%s\n' "$ip"
		fi
		[ -n "$server_port" ] && port_text="$server_port" || port_text=51820
		[ -n "$first_client_name" ] && client_text="$client" || client_text=client
		if [ -n "$dns1" ] && [ -n "$dns2" ]; then
			dns_text="$dns1, $dns2"
		elif [ -n "$dns1" ]; then
			dns_text="$dns1"
		else
			dns_text="Google Public DNS"
		fi
		echo "Port: UDP/$port_text"
		echo "Client name: $client_text"
		echo "Client DNS: $dns_text"
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
		echo "Which port should WireGuard listen to?"
		read -rp "Port [51820]: " port
		until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
			echo "$port: invalid port."
			read -rp "Port [51820]: " port
		done
		[[ -z "$port" ]] && port=51820
	else
		[ -n "$server_port" ] && port="$server_port" || port=51820
	fi
}

enter_custom_dns() {
	read -rp "Enter primary DNS server: " dns1
	until check_ip "$dns1"; do
		echo "Invalid DNS server."
		read -rp "Enter primary DNS server: " dns1
	done
	read -rp "Enter secondary DNS server (Enter to skip): " dns2
	until [ -z "$dns2" ] || check_ip "$dns2"; do
		echo "Invalid DNS server."
		read -rp "Enter secondary DNS server (Enter to skip): " dns2
	done
}

enter_first_client_name() {
	if [ "$auto" = 0 ]; then
		echo
		echo "Enter a name for the first client:"
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
		echo "WireGuard installation is ready to begin."
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
			echo
			echo "Note: firewalld, which is required to manage routing tables, will also be installed."
		fi
	fi
}

abort_and_exit() {
	echo "Abort. No changes were made." >&2
	exit 1
}

confirm_setup() {
	if [ "$auto" = 0 ]; then
		printf "Do you want to continue? [Y/n] "
		read -r response
		case $response in
			[yY][eE][sS]|[yY]|'')
				:
				;;
			*)
				abort_and_exit
				;;
		esac
	fi
}

show_start_setup() {
	echo
	echo "Installing WireGuard, please wait..."
}

install_pkgs() {
	if [[ "$os" == "ubuntu" ]]; then
		export DEBIAN_FRONTEND=noninteractive
		(
			set -x
			apt-get -yqq update || apt-get -yqq update
			apt-get -yqq install wireguard qrencode $firewall >/dev/null
		) || exiterr2
	elif [[ "$os" == "debian" ]]; then
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
			yum -y -q install wireguard-tools qrencode $firewall >/dev/null 2>&1
		) || exiterr3
		mkdir -p /etc/wireguard/
	elif [[ "$os" == "centos" && "$os_version" -eq 8 ]]; then
		(
			set -x
			yum -y -q install epel-release elrepo-release >/dev/null
			yum -y -q --nobest install kmod-wireguard >/dev/null 2>&1
			yum -y -q install wireguard-tools qrencode $firewall >/dev/null 2>&1
		) || exiterr3
		mkdir -p /etc/wireguard/
	elif [[ "$os" == "fedora" ]]; then
		(
			set -x
			dnf install -y wireguard-tools qrencode $firewall >/dev/null
		) || exiterr "'dnf install' failed."
		mkdir -p /etc/wireguard/
	elif [[ "$os" == "openSUSE" ]]; then
		(
			set -x
			zypper install -y wireguard-tools qrencode $firewall >/dev/null
		) || exiterr4
		mkdir -p /etc/wireguard/
	fi
	[ ! -d /etc/wireguard ] && exiterr2
	if [[ "$firewall" == "firewalld" ]]; then
		(
			set -x
			systemctl enable --now firewalld.service >/dev/null 2>&1
		)
	fi
}

remove_pkgs() {
	if [[ "$os" == "ubuntu" ]]; then
		(
			set -x
			rm -rf /etc/wireguard/
			apt-get remove --purge -y wireguard wireguard-tools >/dev/null
		)
	elif [[ "$os" == "debian" ]]; then
		(
			set -x
			rm -rf /etc/wireguard/
			apt-get remove --purge -y wireguard wireguard-tools >/dev/null
		)
	elif [[ "$os" == "centos" && "$os_version" -eq 9 ]]; then
		(
			set -x
			yum -y -q remove wireguard-tools >/dev/null
			rm -rf /etc/wireguard/
		)
	elif [[ "$os" == "centos" && "$os_version" -le 8 ]]; then
		(
			set -x
			yum -y -q remove kmod-wireguard wireguard-tools >/dev/null
			rm -rf /etc/wireguard/
		)
	elif [[ "$os" == "fedora" ]]; then
		(
			set -x
			dnf remove -y wireguard-tools >/dev/null
			rm -rf /etc/wireguard/
		)
	elif [[ "$os" == "openSUSE" ]]; then
		(
			set -x
			zypper remove -y wireguard-tools >/dev/null
			rm -rf /etc/wireguard/
		)
	fi
}

create_server_config() {
	cat << EOF > "$WG_CONF"
# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT $([[ -n "$public_ip" ]] && echo "$public_ip" || echo "$ip")

[Interface]
Address = 10.29.10.1/24$([[ -n "$ip6" ]] && echo ", fddd:2c4:2c4:2c4::1/64")
PrivateKey = $(wg genkey)
ListenPort = $port

EOF
	chmod 600 "$WG_CONF"
}

create_firewall_rules() {
	if systemctl is-active --quiet firewalld.service; then
		firewall-cmd -q --add-port="$port"/udp
		firewall-cmd -q --zone=trusted --add-source=10.29.10.0/24
		firewall-cmd -q --permanent --add-port="$port"/udp
		firewall-cmd -q --permanent --zone=trusted --add-source=10.29.10.0/24
		firewall-cmd -q --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.29.10.0/24 ! -d 10.29.10.0/24 -j MASQUERADE
		firewall-cmd -q --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.29.10.0/24 ! -d 10.29.10.0/24 -j MASQUERADE
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
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.29.10.0/24 ! -d 10.29.10.0/24 -j MASQUERADE
ExecStart=$iptables_path -I INPUT -p udp --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.29.10.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.29.10.0/24 ! -d 10.29.10.0/24 -j MASQUERADE
ExecStop=$iptables_path -D INPUT -p udp --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.29.10.0/24 -j ACCEPT
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
		systemctl enable --now wg-iptables.service >/dev/null 2>&1
	fi
}

# 新增：为多接口模式下添加客户端定义的函数 new_client_multi()
new_client_multi() {
    local config_file="$1"
    local client_name="$2"
    # 从指定配置文件中提取服务器内部IP和子网（假设为 /24）
    local addr_line
    addr_line=$(grep "^Address" "$config_file" | head -n1)
    if [ -z "$addr_line" ]; then
       exiterr "No Address line found in $config_file"
    fi
    local server_ip mask
    server_ip=$(echo "$addr_line" | awk '{print $3}' | cut -d '/' -f1)
    mask=$(echo "$addr_line" | awk '{print $3}' | cut -d '/' -f2)
    local base
    base=$(echo "$server_ip" | cut -d '.' -f 1-3)
    local octet=2
    while grep -q "AllowedIPs = ${base}.${octet}/32" "$config_file"; do
         octet=$((octet+1))
         if [ "$octet" -ge 255 ]; then
              exiterr "No available IP addresses in subnet ${base}.0/24"
         fi
    done
    local client_ip="${base}.${octet}"
    local key psk
    key=$(wg genkey)
    psk=$(wg genpsk)
    cat << EOF >> "$config_file"
# BEGIN_PEER ${client_name}
[Peer]
PublicKey = $(wg pubkey <<< "$key")
PresharedKey = $psk
AllowedIPs = ${client_ip}/32
# END_PEER ${client_name}
EOF

    get_export_dir
    local client_conf="${export_dir}${client_name}.conf"
    local server_priv
    server_priv=$(grep "PrivateKey" "$config_file" | head -n1 | awk '{print $3}')
    local server_pub
    server_pub=$(echo "$server_priv" | wg pubkey)
    local endpoint
    endpoint=$(grep '^# ENDPOINT' "$config_file" | awk '{print $2}')
    local listen_port
    listen_port=$(grep "ListenPort" "$config_file" | awk '{print $3}')
    cat << EOF > "$client_conf"
[Interface]
Address = ${client_ip}/24
DNS = $dns
PrivateKey = $key

[Peer]
PublicKey = $server_pub
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${endpoint}:${listen_port}
PersistentKeepalive = 25
EOF
    if [ "$export_to_home_dir" = 1 ]; then
        chown "$SUDO_USER:$SUDO_USER" "$client_conf"
    fi
    chmod 600 "$client_conf"
    echo "Client $client_name added to interface $(basename "$config_file" .conf)."
    echo "Configuration available in: $client_conf"
}

update_sysctl() {
	mkdir -p /etc/sysctl.d
	conf_fwd="/etc/sysctl.d/99-wireguard-forward.conf"
	conf_opt="/etc/sysctl.d/99-wireguard-optimize.conf"
	echo 'net.ipv4.ip_forward=1' > "$conf_fwd"
	if [[ -n "$ip6" ]]; then
		echo "net.ipv6.conf.all.forwarding=1" >> "$conf_fwd"
	fi
	base_url="https://github.com/hwdsl2/vpn-extras/releases/download/v1.0.0"
	conf_url="$base_url/sysctl-wg-$os"
	[ "$auto" != 0 ] && conf_url="${conf_url}-auto"
	wget -t 3 -T 30 -q -O "$conf_opt" "$conf_url" 2>/dev/null \
		|| curl -m 30 -fsL "$conf_url" -o "$conf_opt" 2>/dev/null \
		|| { /bin/rm -f "$conf_opt"; touch "$conf_opt"; }
	if modprobe -q tcp_bbr \
		&& printf '%s\n%s' "4.20" "$(uname -r)" | sort -C -V \
		&& [ -f /proc/sys/net/ipv4/tcp_congestion_control ]; then
cat >> "$conf_opt" <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
	fi
	sysctl -e -q -p "$conf_fwd"
	sysctl -e -q -p "$conf_opt"
}

update_rclocal() {
	ipt_cmd="systemctl restart wg-iptables.service"
	if ! grep -qs "$ipt_cmd" /etc/rc.local; then
		if [ ! -f /etc/rc.local ]; then
			echo '#!/bin/sh' > /etc/rc.local
		else
			if [ "$os" = "ubuntu" ] || [ "$os" = "debian" ]; then
				sed --follow-symlinks -i '/^exit 0/d' /etc/rc.local
			fi
		fi
cat >> /etc/rc.local <<EOF

$ipt_cmd
EOF
		if [ "$os" = "ubuntu" ] || [ "$os" = "debian" ]; then
			echo "exit 0" >> /etc/rc.local
		fi
		chmod +x /etc/rc.local
	fi
}

start_wg_service() {
	(
		set -x
		systemctl enable --now wg-quick@wg0.service >/dev/null 2>&1
	)
}

show_client_qr_code() {
	qrencode -t UTF8 < "$export_dir$client".conf
	echo -e '\xE2\x86\x91 That is a QR code containing the client configuration.'
}

finish_setup() {
	echo
	if ! modprobe -nq wireguard; then
		echo "Warning!"
		echo "Installation was finished, but the WireGuard kernel module could not load."
		echo "Reboot the system to load the most recent kernel."
	else
		echo "Finished!"
	fi
	echo
	echo "The client configuration is available in: $export_dir$client.conf"
	echo "New clients can be added by running this script again."
}

select_menu_option() {
	echo
	echo "WireGuard is already installed."
	echo
	echo "Select an option:"
	echo "   1) Add a new client"
	echo "   2) List existing clients"
	echo "   3) Remove an existing client"
	echo "   4) Show QR code for a client"
	echo "   5) Remove WireGuard"
	echo "   6) Exit"
	read -rp "Option: " option
	until [[ "$option" =~ ^[1-6]$ ]]; do
		echo "$option: invalid selection."
		read -rp "Option: " option
	done
}

show_clients() {
	grep '^# BEGIN_PEER' "$WG_CONF" | cut -d ' ' -f 3 | nl -s ') '
}

enter_client_name() {
	echo
	echo "Provide a name for the client:"
	read -rp "Name: " unsanitized_client
	[ -z "$unsanitized_client" ] && abort_and_exit
	set_client_name
	while [[ -z "$client" ]] || grep -q "^# BEGIN_PEER $client$" "$WG_CONF"; do
		if [ -z "$client" ]; then
			echo "Invalid client name. Use one word only, no special characters except '-' and '_'."
		else
			echo "$client: invalid name. Client already exists."
		fi
		read -rp "Name: " unsanitized_client
		[ -z "$unsanitized_client" ] && abort_and_exit
		set_client_name
	done
}

update_wg_conf() {
	wg addconf wg0 <(sed -n "/^# BEGIN_PEER $client/,/^# END_PEER $client/p" "$WG_CONF")
}

print_client_added() {
	echo
	echo "$client added. Configuration available in: $export_dir$client.conf"
}

print_check_clients() {
	echo
	echo "Checking for existing client(s)..."
}

check_clients() {
	num_of_clients=$(grep -c '^# BEGIN_PEER' "$WG_CONF")
	if [[ "$num_of_clients" = 0 ]]; then
		echo
		echo "There are no existing clients!"
		exit 1
	fi
}

print_client_total() {
	if [ "$num_of_clients" = 1 ]; then
		printf '\n%s\n' "Total: 1 client"
	elif [ -n "$num_of_clients" ]; then
		printf '\n%s\n' "Total: $num_of_clients clients"
	fi
}

select_client_to() {
	echo
	echo "Select the client to $1:"
	show_clients
	read -rp "Client: " client_num
	[ -z "$client_num" ] && abort_and_exit
	until [[ "$client_num" =~ ^[0-9]+$ && "$client_num" -le "$num_of_clients" ]]; do
		echo "$client_num: invalid selection."
		read -rp "Client: " client_num
		[ -z "$client_num" ] && abort_and_exit
	done
	client=$(grep '^# BEGIN_PEER' "$WG_CONF" | cut -d ' ' -f 3 | sed -n "$client_num"p)
}

confirm_remove_client() {
	if [ "$assume_yes" != 1 ]; then
		echo
		read -rp "Confirm $client removal? [y/N]: " remove
		until [[ "$remove" =~ ^[yYnN]*$ ]]; do
			echo "$remove: invalid selection."
			read -rp "Confirm $client removal? [y/N]: " remove
		done
	else
		remove=y
	fi
}

remove_client_conf() {
	get_export_dir
	wg_file="$export_dir$client.conf"
	if [ -f "$wg_file" ]; then
		echo "Removing $wg_file..."
		rm -f "$wg_file"
	fi
}

print_remove_client() {
	echo
	echo "Removing $client..."
}

remove_client_wg() {
	wg set wg0 peer "$(sed -n "/^# BEGIN_PEER $client$/,\$p" "$WG_CONF" | grep -m 1 PublicKey | cut -d " " -f 3)" remove
	sed -i "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/d" "$WG_CONF"
	remove_client_conf
}

print_client_removed() {
	echo
	echo "$client removed!"
}

print_client_removal_aborted() {
	echo
	echo "$client removal aborted!"
}

check_client_conf() {
	wg_file="$export_dir$client.conf"
	if [ ! -f "$wg_file" ]; then
		echo "Error: Cannot show QR code. Missing client config file $wg_file" >&2
		echo "       You may instead re-run this script and add a new client." >&2
		exit 1
	fi
}

print_client_conf() {
	echo
	echo "Configuration for '$client' is available in: $wg_file"
}

confirm_remove_wg() {
	if [ "$assume_yes" != 1 ]; then
		echo
		read -rp "Confirm WireGuard removal? [y/N]: " remove
		until [[ "$remove" =~ ^[yYnN]*$ ]]; do
			echo "$remove: invalid selection."
			read -rp "Confirm WireGuard removal? [y/N]: " remove
		done
	else
		remove=y
	fi
}

print_remove_wg() {
	echo
	echo "Removing WireGuard, please wait..."
}

disable_wg_service() {
	systemctl disable --now wg-quick@wg0.service
}

remove_sysctl_rules() {
	rm -f /etc/sysctl.d/99-wireguard-forward.conf /etc/sysctl.d/99-wireguard-optimize.conf
	if [ ! -f /usr/sbin/openvpn ] && [ ! -f /usr/sbin/ipsec ] \
		&& [ ! -f /usr/local/sbin/ipsec ]; then
		echo 0 > /proc/sys/net/ipv4/ip_forward
		echo 0 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
}

remove_rclocal_rules() {
	ipt_cmd="systemctl restart wg-iptables.service"
	if grep -qs "$ipt_cmd" /etc/rc.local; then
		sed --follow-symlinks -i "/^$ipt_cmd/d" /etc/rc.local
	fi
}

print_wg_removed() {
	echo
	echo "WireGuard removed!"
}

print_wg_removal_aborted() {
	echo
	echo "WireGuard removal aborted!"
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

auto=0
assume_yes=0
add_client=0
list_clients=0
remove_client=0
show_client_qr=0
remove_wg=0
public_ip=""
server_addr=""
server_port=""
first_client_name=""
unsanitized_client=""
client=""
dns=""
dns1=""
dns2=""

multi_mode=0
multi_cfg=""
add_client_iface=0
iface_name=""
client_for_iface=""

parse_args "$@"
check_args

# 如果启用多接口模式并指定了--addclient-iface，则为指定接口添加客户端
if [ "$multi_mode" = 1 ] && [ "$add_client_iface" = 1 ]; then
	config_file="/etc/wireguard/${iface_name}.conf"
	new_client_multi "$config_file" "$client_for_iface"
	systemctl restart wg-quick@${iface_name}.service
	exit 0
fi

# 多接口模式下自动配置接口
if [ "$multi_mode" = 1 ]; then
	IFS=',' read -r -a iface_list <<< "$multi_cfg"
	index=0
	for entry in "${iface_list[@]}"; do
		entry=$(echo "$entry" | xargs)
		iface=$(echo "$entry" | cut -d ':' -f1)
		port=$(echo "$entry" | cut -d ':' -f2)
		pub_ip=$(echo "$entry" | cut -d ':' -f3)
		subnet_octet=$((10 + index))
		SERVER_IP="10.29.${subnet_octet}.1"
		SUBNET="10.29.${subnet_octet}.0/24"
		echo "Configuring interface $iface: ListenPort=$port, PublicIP=$pub_ip, InternalSubnet=$SUBNET (Gateway $SERVER_IP)"
		CONFIG_PATH="/etc/wireguard/${iface}.conf"
		cat << EOF > "$CONFIG_PATH"
# ENDPOINT $pub_ip
[Interface]
Address = ${SERVER_IP}/24
PrivateKey = $(wg genkey)
ListenPort = $port

EOF
		chmod 600 "$CONFIG_PATH"
		create_firewall_rules_multi "$port" "$SUBNET"
		systemctl enable --now wg-quick@${iface}.service >/dev/null 2>&1
		echo "Interface $iface configured with config file $CONFIG_PATH."
		index=$((index+1))
	done
	echo "Multi-interface setup completed."
	exit 0
fi

if [ "$add_client" = 1 ]; then
	show_header
	new_client add_client
	update_wg_conf
	echo
	show_client_qr_code
	print_client_added
	exit 0
fi

if [ "$list_clients" = 1 ]; then
	show_header
	print_check_clients
	check_clients
	echo
	show_clients
	print_client_total
	exit 0
fi

if [ "$remove_client" = 1 ]; then
	show_header
	confirm_remove_client
	if [[ "$remove" =~ ^[yY]$ ]]; then
		print_remove_client
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
	echo
	get_export_dir
	check_client_conf
	show_client_qr_code
	print_client_conf
	exit 0
fi

if [ "$remove_wg" = 1 ]; then
	show_header
	confirm_remove_wg
	if [[ "$remove" =~ ^[yY]$ ]]; then
		print_remove_wg
		remove_firewall_rules
		disable_wg_service
		remove_sysctl_rules
		remove_rclocal_rules
		remove_pkgs
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
	if [ "$auto" = 0 ]; then
		select_dns
	fi
	show_setup_ready
	check_firewall
	confirm_setup
	show_start_setup
	install_pkgs
	create_server_config
	update_sysctl
	create_firewall_rules
	if [ "$os" != "openSUSE" ]; then
		update_rclocal
	fi
	new_client
	start_wg_service
	echo
	show_client_qr_code
	if [ "$auto" != 0 ] && check_dns_name "$server_addr"; then
		show_dns_name_note "$server_addr"
	fi
	finish_setup
else
	show_header
	select_menu_option
	case "$option" in
		1)
			enter_client_name
			select_dns
			new_client add_client
			update_wg_conf
			echo
			show_client_qr_code
			print_client_added
			exit 0
		;;
		2)
			print_check_clients
			check_clients
			echo
			show_clients
			print_client_total
			exit 0
		;;
		3)
			check_clients
			select_client_to remove
			confirm_remove_client
			if [[ "$remove" =~ ^[yY]$ ]]; then
				print_remove_client
				remove_client_wg
				print_client_removed
				exit 0
			else
				print_client_removal_aborted
				exit 1
			fi
		;;
		4)
			check_clients
			select_client_to "show QR code for"
			echo
			get_export_dir
			check_client_conf
			show_client_qr_code
			print_client_conf
			exit 0
		;;
		5)
			confirm_remove_wg
			if [[ "$remove" =~ ^[yY]$ ]]; then
				print_remove_wg
				remove_firewall_rules
				disable_wg_service
				remove_sysctl_rules
				remove_rclocal_rules
				remove_pkgs
				print_wg_removed
				exit 0
			else
				print_wg_removal_aborted
				exit 1
			fi
		;;
		6)
			exit 0
		;;
	esac
fi
}

wgsetup "$@"

exit 0
