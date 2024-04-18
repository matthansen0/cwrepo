purgeDots(){
    mv /{etc,quarintine}/profile.d 2>/dev/null
    mv /{etc,quarintine}/profile 2>/dev/null
    mv /{etc,quarintine}/environment 2>/dev/null
    for f in '.profile' '.bashrc' '.bash_login' '.bash_profile'; do
        find /home /root -name "$f" -exec rm {} \;
    done
    mkdir -p /rbin
    cp -a $(which id) $(which whoami) $(which ls) $(which pwd) $(which w) /rbin
    echo "PATH='/rbin'" > /etc/profile

    oldIFS=$IFS
    IFS='
    '

    for i in $(awk -F: '($3 > 999)' /etc/passwd)
    do 
        user=$(echo $i | cut -d ":" -f1)
        homedir=$(echo $i | cut -d ":" -f6)
        echo "PATH='/rbin'" > $homedir/.bashrc
    done

    IFS=$oldIFS
    
    echo 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PS1="\[$(tput setaf 216)\]\u\[$(tput setaf 220)\]@\[$(tput setaf 222)\]\h \[$(tput setaf 229)\]\w \[$(tput sgr0)\]$ "
' > /root/.profile
}