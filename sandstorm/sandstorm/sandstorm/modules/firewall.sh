makeFirewall () { 

    #
    ### Define variables
    #

    # if script over ssh
    if [ -n "$SSH_CONNECTION" ] || [ `head -c 3 /sys/hypervisor/uuid` == ec2 ]; then
        IS_RUNNING_OVER_SSH=true
    else
        IS_RUNNING_OVER_SSH=false
    fi

    # Define IPs for refence
    compDNS="10.120.0.53"
    teamDNS="172.16.1.5"
    compNTP="10.120.0.10"

    # Safe IPs
    patchSrv="10.120.0.9"
    chatSrv="10.120.0.11"
    injectSrv="10.120.0.20"
    ccsSrv="10.120.0.111"
    proxySrv="10.120.0.200"
    proxyPort="8080"
    dhcpSRV=""
    ldapSRV=""

    # Define subnets for reference
    compNet="10.120.0.0/16"
    teamNetA="10.0.0.0/8"
    teamNetB="172.16.10.0/24"
    teamNetC="172.16.15.0/24"

    # Create an array of subnets
    subnets=("$compNet" "$teamNetA" "$teamNetB" "$teamNetC")

    # ICMP types to allow
    safe_icmp_types=("0" "8" "11" "3")

    #
    ### Prep setup
    #

    # Move the binaries so redteam cant use them
    mv /sbin/iptables /sbin/eyepeetables
    mv /sbin/ip6tables /sbin/eyepeesixtables
    i="/sbin/eyepeetables"
    s="/sbin/eyepeesixtables"

    # flush ipv4
    $i iptables -P INPUT ACCEPT
    $i iptables -P FORWARD ACCEPT
    $i iptables -P OUTPUT ACCEPT
    $i iptables -t nat -F
    $i iptables -t mangle -F
    $i iptables -F
    $i iptables -X

    # flush/drop ipv6
    $s ip6tables -P INPUT DROP
    $s ip6tables -P FORWARD DROP
    $s ip6tables -P OUTPUT DROP
    $s ip6tables -t nat -F
    $s ip6tables -t mangle -F
    $s ip6tables -F
    $s ip6tables -X

    # get flags
    t=
    u=
    while getopts 't:u:' f; do
        case $f in
            t)
                t=$OPTARG
                ;;
            u)
                u=$OPTARG
                ;;
        esac
    done

    # if no flags passed, use 80,443,22,21,110
    if [ -z $t ]; then
        t="80,443,22,21,110"
    fi
    if [ -z $u ]; then
        u="53,63,123"
    fi


    # Allow loopback
    $i iptables -A INPUT -i lo -j ACCEPT 
    $i iptables -A OUTPUT -o lo -j ACCEPT 

    # Allow established and related connections
    $i iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    $i iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Iterate through the subnets array to apply iptables rules
    for subnet in "${subnets[@]}"; do
        for icmp_type in "${safe_icmp_types[@]}"; do
            # Allow safe ICMP types to the subnet
            $i iptables -A OUTPUT -p icmp --icmp-type ${icmp_type} -d $subnet -j ACCEPT

            # Allow safe ICMP types from the subnet
            $i iptables -A INPUT -p icmp --icmp-type ${icmp_type} -s $subnet -j ACCEPT
        done
    done

    #
    ### Drop quirky traffic
    #

    # Prevent stealthy scans/weird connections
    $i iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j DROP
    $i iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    $i iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
    $i iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
    $i iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
    $i iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
    $i iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP
    $i iptables -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j DROP
    $i iptables -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP

    # Drop invalid connections
    $i iptables -A INPUT -m state --state INVALID -j DROP
    $i iptables -A OUTPUT -m state --state INVALID -j DROP

    # Block overly large or fragmented icmp packets
    $i iptables -A INPUT -p icmp -m u32 ! --u32 "4&0x3FFF=0"   -j DROP
    $i iptables -A INPUT -p icmp -m length --length 1492:65535 -j DROP

    #
    ### Allow good traffic
    #

    # let the for loop work on comma separated lists
    IFS=,

    # Allow proxy
    $i iptables -A OUTPUT -p tcp -d $proxySrv --dport $proxyPort -j ACCEPT

    # Allow DHCP responses from a specific server only
    $i iptables -A INPUT -p udp --sport 67 --dport 68 -s $dhcpSRV -j ACCEPT

    # Allow LDAP requests to a specific server - Regular LDAP on port 389
    $i iptables -A OUTPUT -p tcp --dport 389 -d $ldapSRV -j ACCEPT

    # Allow LDAP requests to a specific server - Secure LDAP (LDAPS) on port 636
    $i iptables -A OUTPUT -p tcp --dport 636 -d $ldapSRV -j ACCEPT

    # Prevent DOS attacks and nmap scans (below scored services to prevent issue)
    $i iptables -A INPUT -p tcp -m state --state NEW -m recent --set
    $i iptables -A INPUT -p tcp -m state --state NEW -m recent --update --seconds 30 --hitcount 10 -j DROP

    # allow specified ports inbound
    for port in $t; do
        $i iptables -A INPUT -p tcp --dport $port -j ACCEPT
    done
    for port in $u; do
        $i iptables -A INPUT -p udp --dport $port -j ACCEPT
    done

    

    # Allowing basic outbound ports, http, https, ssh/sftp, ftp, pop3
    outTCP="80,443,22,21,110"
    webTCP="80,443"

    # Define internal IP ranges (Unless you are IANA, these should not change)
    internalIPs="192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"

    # Allow traffic to the safe IPs list
    for ip in $patchSrv $chatSrv $injectSrv $ccsSrv; do
        for port in $webTCP; do
            $i iptables -A OUTPUT -p tcp -d $ip --dport $port -j ACCEPT
        done
    done

    # Allow service traffic to teamNetA, teamNetB, and teamNetC
    for net in $teamNetA $teamNetB $teamNetC; do
        for port in $outTCP; do
            $i iptables -A OUTPUT -p tcp -d $net --dport $port -j ACCEPT
            #if running over ssh, allow ssh
            if [ "$IS_RUNNING_OVER_SSH" = true ]; then
                $i iptables -A INPUT -p tcp -s $net --dport 22 -j ACCEPT
            fi
        done
    done

    # Drop web traffic to internal IPs (This has the be below the previous two for loops)
    for ip in $internalIPs; do
        for port in $webTCP; do
            $i iptables -A OUTPUT -p tcp -d $ip --dport $port -j DROP
        done
    done

    # Allow all outbound web traffic to non-internal IPs
    for port in $webTCP; do
        $i iptables -A OUTPUT -p tcp --dport $port -j ACCEPT
    done

    # Allow outgoing DNS queries to compDNS
    $i iptables -A OUTPUT -p udp -d $compDNS --dport 53 -j ACCEPT

    # Allow outgoing DNS queries to teamDNS
    $i iptables -A OUTPUT -p udp -d $teamDNS --dport 53 -j ACCEPT

    # Allow outgoing NTP requests to compNTP
    $i iptables -A OUTPUT -p udp -d $compNTP --dport 123 -j ACCEPT

    #
    ### Configure default policy and enforce
    #

    # Setting default policy to drop
    $i iptables -P INPUT DROP 
    $i iptables -P OUTPUT DROP 
    $i iptables -P FORWARD DROP 

    # Flushing active connections
    # conntrack -F
}