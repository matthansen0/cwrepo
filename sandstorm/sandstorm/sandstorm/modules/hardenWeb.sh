hardenWeb(){
    for ini in $(find / -xdev -name "php.ini" 2>/dev/null); do
        echo "[+] Writing php.ini options to $ini..."
        echo "disable_functions = proc_open, popen, disk_free_space, diskfreespace, leak, tmpfile, exec, system, shell_exec, passthru, show_source, system, phpinfo, pcntl_alarm, pcntl_fork, pcntl_waitpid, pcntl_wait, pcntl_wifexited, pcntl_wifstopped, pcntl_wifsignaled, pcntl_wexitstatus, pcntl_wtermsig, pcntl_wstopsig, pcntl_signal, pcntl_signal_dispatch, pcntl_get_last_error, pcntl_strerror, pcntl_sigprocmask, pcntl_sigwaitinfo, pcntl_sigtimedwait, pcntl_exec, pcntl_getpriority, pcntl_setpriority, pcntl_wifcontinued, pcntl_signal_get_handler, pcntl_setpriority, pcntl_async_signals, error_log, link, symlink, syslog, ld, mail, stream_socket_sendto, stream_socket_client, fsockopen" >> $ini
        echo "max_execution_time = 3" >> $ini
        echo "register_globals = off" >> $ini
        echo "magic_quotes_gpc = on" >> $ini
        echo "allow_url_fopen = off" >> $ini
        echo "allow_url_include = off" >> $ini
        echo "display_errors = off" >> $ini
        echo "short_open_tag = off" >> $ini
        echo "session.cookie_httponly = 1" >> $ini
        echo "session.use_only_cookies = 1" >> $ini
        echo "session.cookie_secure = 1" >> $ini
    done
}