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
	# Update endpoint before generating config
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

update_sysctl() {
	mkdir -p /etc/sysctl.d
	conf_fwd="/etc/sysctl.d/99-wireguard-forward.conf"
	conf_opt="/etc/sysctl.d/99-wireguard-optimize.conf"
	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > "$conf_fwd"
	if [[ -n "$ip6" ]]; then
		# Enable net.ipv6.conf.all.forwarding for the system
		echo "net.ipv6.conf.all.forwarding=1" >> "$conf_fwd"
	fi
	# Optimize sysctl settings such as TCP buffer sizes
	base_url="https://github.com/hwdsl2/vpn-extras/releases/download/v1.0.0"
	conf_url="$base_url/sysctl-wg-$os"
	[ "$auto" != 0 ] && conf_url="${conf_url}-auto"
	wget -t 3 -T 30 -q -O "$conf_opt" "$conf_url" 2>/dev/null \
		|| curl -m 30 -fsL "$conf_url" -o "$conf_opt" 2>/dev/null \
		|| { /bin/rm -f "$conf_opt"; touch "$conf_opt"; }
	# Enable TCP BBR congestion control if kernel version >= 4.20
	if modprobe -q tcp_bbr \
		&& printf '%s\n%s' "4.20" "$(uname -r)" | sort -C -V \
		&& [ -f /proc/sys/net/ipv4/tcp_congestion_control ]; then
cat >> "$conf_opt" <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
	fi
	# Apply sysctl settings
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
	# Enable and start the wg-quick service
	(
		set -x
		systemctl enable --now wg-quick@wg0.service >/dev/null 2>&1
	)
}

show_client_qr_code() {
    get_export_dir
    octet=$(sed -n "/^# BEGIN_PEER $client$/,/^# END_PEER $client/p" "$WG_CONF" | grep '# CLIENT_OCTET' | awk '{print $3}')
    qrencode -t UTF8 < "${export_dir}router-${octet}.conf"
    echo -e '\xE2\x86\x91 That is a QR code containing the client configuration.'
}

finish_setup() {
	echo
	# If the kernel module didn't load, system probably had an outdated kernel
	if ! modprobe -nq wireguard; then
		echo "Warning!"
		echo "Installation was finished, but the WireGuard kernel module could not load."
		echo "Reboot the system to load the most recent kernel."
	else
		echo "Finished!"
	fi
	echo
	echo "The client configuration is available in: ${export_dir}router-${octet}.conf"
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
	# Append new client configuration to the WireGuard interface
	wg addconf wg0 <(sed -n "/^# BEGIN_PEER $client/,/^# END_PEER $client/p" "$WG_CONF")
}

print_client_added() {
    echo
    echo "客户端配置已生成: ${export_dir}router-${octet}.conf"
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
    octet=$(sed -n "/^# BEGIN_PEER $client$/,/^# END_PEER $client/p" "$WG_CONF" | grep '# CLIENT_OCTET' | awk '{print $3}')
    wg_file="${export_dir}router-${octet}.conf"
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
	# The following is the right way to avoid disrupting other active connections:
	# Remove from the live interface
	wg set wg0 peer "$(sed -n "/^# BEGIN_PEER $client$/,\$p" "$WG_CONF" | grep -m 1 PublicKey | cut -d " " -f 3)" remove
	# Remove from the configuration file
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
    get_export_dir
    octet=$(sed -n "/^# BEGIN_PEER $client$/,/^# END_PEER $client/p" "$WG_CONF" | grep '# CLIENT_OCTET' | awk '{print $3}')
    wg_file="${export_dir}router-${octet}.conf"
    if [ ! -f "$wg_file" ]; then
        echo "Error: Cannot show QR code. Missing client config file $wg_file" >&2
        echo "       You may instead re-run this script and add a new client." >&2
        exit 1
    fi
}

print_client_conf() {
    get_export_dir
    octet=$(sed -n "/^# BEGIN_PEER $client$/,/^# END_PEER $client/p" "$WG_CONF" | grep '# CLIENT_OCTET' | awk '{print $3}')
    echo
    echo "Configuration for '$client' is available in: ${export_dir}router-${octet}.conf"
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
WG_CONF="/etc/wireguard/wg0.conf"

# 初始化变量
auto=0
assume_yes=0
add_client=0
list_clients=0
remove_client=0
show_client_qr=0
remove_wg=0
server_addr=""

parse_args "$@"
check_args

if [ "$add_client" = 1 ]; then
	set_client_name
	new_client
	echo "Client config generated: ${export_dir}router-${octet}.conf"
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

## Defer setup until we have the complete script
wgsetup "$@"

exit 0
