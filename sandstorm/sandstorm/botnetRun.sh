#!/bin/bash

execdir="$(readlink -m $(dirname $0))"

# prompt for master password
read -s -p "Enter master password for password db: " masterPassword 



echo "packaging sandstorm"
tar czf sandstorm.tar.gz ./sandstorm



# 20 char random filename
TMP_PASSLIST_FILE="/tmp/.orig_$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 20 | head -n 1)"

# if botnetPassList.gpg does not exist, use initialPasswordList.txt
if [ ! -f botnetPassList.gpg ]; then
  echo "using initialPasswordList"
  cp initialPasswordList.txt $TMP_PASSLIST_FILE
else
  echo "decrypting botnetPassList.gpg"
  gpg --pinentry-mode=loopback --passphrase $masterPassword -o $TMP_PASSLIST_FILE -d botnetPassList.gpg
  if [ $? -ne 0 ]; then
    echo "failed to decrypt botnetPassList.gpg"
    exit 1
  fi
fi


declare -a ip_password_array

while IFS=' ' read -r ip password; do
    # Add IP and password to the array
    ip_password_array+=("$ip $password")
done < $TMP_PASSLIST_FILE


# roll passwords
TMP_PASSLIST_FILE_NEW="/tmp/.new_$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 20 | head -n 1)"
regeneratePassList () {
  echo "generating new random passwords"
  echo -n > $TMP_PASSLIST_FILE_NEW
  for host_pass in "${ip_password_array[@]}"
  do
    host=$(echo $host_pass | cut -d" " -f1)
    ROOT_PW=$(echo "$(date +%N)$RANDOM" | sha256sum | cut -d" " -f1 | cut -c -12)
    echo "$host $ROOT_PW" >> $TMP_PASSLIST_FILE_NEW
  done
}




rollPasswords () {
  regeneratePassList
  echo "rolling passwords"
  for host_pass in "${ip_password_array[@]}"
  do
    host=$(echo $host_pass | cut -d" " -f1)
    password=$(echo $host_pass | cut -d" " -f2)
    new_password=$(cat $TMP_PASSLIST_FILE_NEW | grep $host | cut -d" " -f2)
    echo "rolling password for ${host}"
    {
      sshpass -p${password} ssh -o LogLevel=error -o ConnectTimeout=3 -o StrictHostKeyChecking=no root@${host} "echo -e \"${new_password}\n${new_password}\" | passwd"
      if [ $? -ne 0 ]; then
        echo "failed to change password for ${host}"
        # overwrite the password in the new password list with the old password
        sed -i "s/${new_password}/${password}/" $TMP_PASSLIST_FILE_NEW 
      fi
    } &
  done
  wait
  echo "passwords rolled"
  cat $TMP_PASSLIST_FILE_NEW 



  # encrypt
  gpg -c --pinentry-mode=loopback --passphrase $masterPassword $TMP_PASSLIST_FILE_NEW
  mv ${TMP_PASSLIST_FILE_NEW}.gpg botnetPassList.gpg


  # grab newly set password list
  ip_password_array=()
  while IFS=' ' read -r ip password; do
      # Add IP and password to the array
      ip_password_array+=("$ip $password")
  done < $TMP_PASSLIST_FILE_NEW

  # cleanup
  rm $TMP_PASSLIST_FILE_NEW
  rm $TMP_PASSLIST_FILE
}

rollPasswords

# running the botnet
echo "running botnet"
mkdir -p ${execdir}/logs
for host_pass in "${ip_password_array[@]}"
do
  host=$(echo $host_pass | cut -d" " -f1)
  password=$(echo $host_pass | cut -d" " -f2)
  echo "starting task on ${host}"
  {
    echo "deploying sandstorm on ${host}"
    sshpass -p${password} scp -o LogLevel=error -o ConnectTimeout=3 sandstorm.tar.gz root@${host}:/root

    echo "extracting sandstorm on ${host}"
    sshpass -p${password} ssh -o LogLevel=error -o ConnectTimeout=3 root@${host} "rm -rf sandstorm && tar xzf sandstorm.tar.gz"

    echo "running sandstorm"
    sshpass -p${password} ssh -o LogLevel=error -o ConnectTimeout=3 root@${host} "cd sandstorm && ./sandstorm.sh &> /dev/null ; exit"

    echo "Done with ${host}. Grabbing log file"
    sshpass -p${password} scp -o LogLevel=error -o ConnectTimeout=3 root@${host}:/quarantine/sandstorm.log ${execdir}/logs/${host}_$(date +%Y%m%d%H%M%S).log && \
    echo ${execdir}/logs/${host}_$(date +%Y%m%d%H%M%S).log
  } &
done

# wait for all backgrounded processes to finish
wait


echo "All tasks completed."