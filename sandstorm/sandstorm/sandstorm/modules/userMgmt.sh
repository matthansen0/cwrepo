userMgmt(){
    # Investigate the two stage system here for users as their passwords are scored
    # https://github.com/DSU-DefSec/ace/blob/master/linux/pw.sh

    # back up /etc/passwd just in case
    cp /etc/passwd /etc/passwd.bak
    chmod 644 /etc/passwd.bak

    # create rbash if it doesn't exist
    if ! which rbash >/dev/null 2>&1; then
        ln -sf /bin/bash /bin/rbash
    fi

    # set rbash for non-root bash users
    head -1 /etc/passwd > /etc/pw
    sed -n '1!p' /etc/passwd | sed 's/\/bin\/bash/\/bin\/rbash/g' >> /etc/pw
    mv /etc/pw /etc/passwd
    chmod 644 /etc/passwd

    # Lock non-shell users
    # for u in $(cat /etc/passwd | grep -vE "/bin/.*sh" | cut -d":" -f1); do
    #     passwd -l $u >/dev/null 2>&1
    #     if [[ $? -ne 0 ]]; then
    #         echo "[-] Error locking password for $u"
    #     fi
    # done

}