breakTimers(){
    # get timers files
    mkdir -p /quarantine/scheduled-tasks/systemd/
    for i in $(systemctl list-unit-files --type timer --state enabled | grep .timer | awk '{print $1}')
    do
        systemctl stop $i
        systemctl disable $i
        cp $(systemctl show -p FragmentPath $i | awk -F= '{print $2}') /quarantine/scheduled-tasks/systemd/
    done
}