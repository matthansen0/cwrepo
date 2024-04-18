verifyFiles() {
    chown root:root /etc/shadow
    chown root:root /etc/passwd
    chmod 640 /etc/shadow
    chmod 644 /etc/passwd

    (
    {
    # find / -xdev -perm -2000 -type f
    echo "- find / -xdev -perm -2000 -type f" 
    echo "\`\`\`bash" 
    find / -xdev -perm -2000 -type f
    echo "\`\`\`" 
    } | tee /quarantine/set-group-id
    ) &

    (
    {
    # getfacl -sR /etc/ /usr/ /root/
    echo "- getfacl -sR /etc/ /usr/ /root/" 
    echo "\`\`\`bash" 
    find getfacl -sR /etc/ /usr/ /root/
    echo "\`\`\`" 
    } | tee /quarantine/facl
    ) &

    (
    {
    # find / -xdev -perm -4000 -type f
    echo "- find / -xdev -perm -4000 -type f" 
    echo "\`\`\`bash" 
    find / -xdev -perm -4000 -type f
    echo "\`\`\`" 
    } | tee /quarantine/set-user-id
    ) &

    (
    {
    # getcap -r / 2>/dev/null
    echo "- getcap -r / 2>/dev/null" 
    echo "\`\`\`bash" 
    getcap -r / 2>/dev/null
    echo "\`\`\`" 
    } | tee /quarantine/cap-files
    ) &
}