hardenKernel() {
    (

    echo "- lsmod" 
    echo "\`\`\`bash" 
    lsmod
    echo "\`\`\`" 

    # Harden networking stack to improve security and block OS enumeration via nmap
    echo "net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0" > /etc/sysctl.conf
    sysctl -p

    # Disable unneeded modules
	MOD="dccp sctp rds tipc bluetooth bnep btusb cpia2 firewire-core floppy n_hdlc net-pf-31 pcspkr soundcore thunderbolt usb-midi usb-storage uvcvideo v4l2_common"
	for disable in $MOD; do
		if ! grep -q "$disable" /etc/modprobe.d/blacklist.conf 2> /dev/null; then
			echo "install $disable /bin/true" >> /etc/modprobe.d/blacklist.conf
		fi
	done


    ) &
}