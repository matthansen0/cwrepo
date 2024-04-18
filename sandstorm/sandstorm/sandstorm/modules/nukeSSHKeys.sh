nukeSSHKeys () { 
    echo 'nuking ssh keys'

    for i in $(getent passwd)
    do 
        user=$(echo $i | cut -d ":" -f1)
        homedir=$(echo $i | cut -d ":" -f6)
        if [ -d "$homedir/.ssh" ]; then
            mkdir -p /quarantine/ssh/$user
            cp -ra $homedir/.ssh/* /quarantine/ssh/$user
            rm $homedir/.ssh/*
        fi
    done
}