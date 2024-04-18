#!/bin/bash

mkdir -p /quarantine

# funny logging
{

# load modules
execdir="$(readlink -m $(dirname $0))"
for module in $execdir/modules/* ; do
    [[ -f $module ]] || break
    source "$module"
    echo "${HOSTNAME}: loaded $module"
done

fixDns

# check for psmisc conntrack iptables 
if [ -x "$(command -v apt-get)" ]; then
    apt update 
	apt install -y psmisc conntrack iptables || exit 1
elif [ -x "$(command -v yum)" ]; then
	yum install -y psmisc conntrack iptables || exit 1
else
    echo "${HOSTNAME}:This OS is not supported! Please review documentation!!!"
	exit 1
fi


# run modules and keep track of their PID and exit status
declare -A moduleStatuses
declare -A pids

asciiart &
pids["asciiart"]=$!

nukeSSHKeys &
pids["nukeSSHKeys"]=$!

makeFirewall &
pids["makeFirewall"]=$!

fixLDPreload &
pids["fixLDPreload"]=$!

breakCron &
pids["breakCron"]=$!

breakTimers &
pids["breakTimers"]=$!

breakSudo &
pids["breakSudo"]=$!

checkConnections &
pids["checkConnections"]=$!

runningProcs &
pids["runningProcs"]=$!

hardenKernel &
pids["hardenKernel"]=$!

hardenSSH &
pids["hardenSSH"]=$!

verifyFiles &
pids["verifyFiles"]=$!

configureAutologin &
pids["configureAutologin"]=$!

purgeDots &
pids["purgeDots"]=$!

hardenWeb &
pids["hardenWeb"]=$!

userMgmt &
pids["userMgmt"]=$!

echo "${HOSTNAME}: all modules started"

# wait for all modules to finish
for moduleName in "${!pids[@]}"; do
    wait ${pids[$moduleName]}
    moduleStatuses[$moduleName]=$?
done

echo "${HOSTNAME}: all modules done"

# print the exit status of all modules
for moduleName in "${!moduleStatuses[@]}"; do
    status=${moduleStatuses[$moduleName]}
    echo "${HOSTNAME}: $moduleName ($status)"
done

echo "${HOSTNAME}: If you have an interactive connection to this box, you NEED to run 'bash;exit' to refresh env vars."

} | tee /quarantine/sandstorm.log 2>&1
exit 0
