configureAutologin(){
    # Check if the system uses systemd or upstart and set autologin accordingly
    if [ -x "$(command -v systemctl)" ]; then
        # SystemD-based
        sed -i 's/^ExecStart.*/ExecStart=-\/sbin\/agetty --autologin root --noclear %I $TERM/' /lib/systemd/system/getty@.service
    else
        # Upstart-based both possible ways (one will fail)
        sed -i 's/tty1/--autologin root tty1/' /etc/init/tty1.conf
        sed -i 's/mingetty/mingetty --autologin root/' /etc/init/tty.conf
    fi
}