breakCron(){
    # Remove all crontabs for all users
    mkdir -p /quarantine/scheduled-tasks/cron
    for i in $(getent passwd | cut -d ":" -f1)
    do 
        crontab -u $i -l 2>/dev/null 1>/dev/null
        if [[ $? -eq 0 ]]; then
            mkdir -p /quarantine/scheduled-tasks/cron/$i
            crontab -u $i -l > /quarantine/scheduled-tasks/cron/$i/crontab  2>/dev/null
            crontab -u $i -r  2>/dev/null
        fi
    done
    find /etc/crontab /etc/anacrontab /var/spool/at /var/spool/cron /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly -type f -exec mv {} /quarantine/scheduled-tasks/cron \;
    service cron stop
    service crond stop
    service atd stop
}