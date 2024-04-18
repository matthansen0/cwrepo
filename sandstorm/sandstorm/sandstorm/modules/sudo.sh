breakSudo(){
    # Remove sudo permissions from everyone
    mkdir -p /quarantine/sudo
    cp -ra /etc/sudoers /etc/sudo.conf /etc/sudoers.d /quarantine/sudo
    echo >/etc/sudoers
    echo >/etc/sudo.conf
}