fixDns () {
    cp /etc/resolv.conf{,.bak}
    cat /root/sandstorm/nameserver.txt > /etc/resolv.conf
}