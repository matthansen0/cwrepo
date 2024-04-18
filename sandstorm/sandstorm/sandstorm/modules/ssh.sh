hardenSSH() {
    (
    # Make a keypair
    ssh-keygen -b 2048 -t rsa -f /root/.ssh/id_rsa -q -N ""

    # Make root login allowed
    sed -i 's/#\?\(PermitRootLogin\s*\).*$/\1 yes/' /etc/ssh/sshd_config

    # Prevent port forwarding through SSH
    sed -i 's/#\?\(AllowTcpForwarding\s*\).*$/\1 no/' /etc/ssh/sshd_config

    # Prevent obfuscation via compression
    sed -i 's/#\?\(Compression\s*\).*$/\1 no/' /etc/ssh/sshd_config

    # Enable verbose logging of connections
    sed -i 's/#\?\(LogLevel\s*\).*$/\1 verbose/' /etc/ssh/sshd_config

    # Disconnect after 3 failed connections
    sed -i 's/#\?\(MaxAuthTries\s*\).*$/\1 3/' /etc/ssh/sshd_config

    # Limit to 2 SSH sessions at once
    sed -i 's/#\?\(MaxSessions\s*\).*$/\1 2/' /etc/ssh/sshd_config

    # Disconnect inactive sessions
    sed -i 's/#\?\(TCPKeepAlive\s*\).*$/\1 no/' /etc/ssh/sshd_config

    # Prevent SSH from tunneling a graphical environment
    sed -i 's/#\?\(X11Forwarding\s*\).*$/\1 no/' /etc/ssh/sshd_config

    # Block obfuscation via agent forwarding
    sed -i 's/#\?\(AllowAgentForwarding\s*\).*$/\1 no/' /etc/ssh/sshd_config

    # Listen on IPv4 only
    sed -i '/.*ListenAddress.*::/d' /etc/ssh/sshd_config

    # Drop session if no login after 20 seconds
    sed -i 's/#\?\(LoginGraceTime\s*\).*$/\1 20/' /etc/ssh/sshd_config

    # Configure login banner
    sed -i 's/#\?\(Banner\s*\).*$/\1 \/etc\/issue/' /etc/ssh/sshd_config

    # Drop support for legacy sftp-server in favor of internal-sftp
    sed -i 's/#\?\(Subsystem\s*\).*$/\1 sftp internal-sftp/' /etc/ssh/sshd_config

    # Disable key auth
    sed -i 's/#\?\(PubkeyAuthentication\s*\).*$/\1 no/' /etc/ssh/sshd_config

    # Restart SSH to enable changes
    systemctl restart sshd


    ) &
}