
    #Backup Firewall
    mkdir C:\firewall
    netsh advfirewall export C:\firewall\ORIGINAL_FW.wfw
    Write-Host "[OK] " -ForegroundColor Green -NoNewLine 
    Write-Host "Firewall backed up" -ForegroundColor Green 

    if ($global:config.IsDomainController -eq 1) {
        $tcpports = "53,88,389,25,587,123"
        $udpports = "53,88,389,25,587,123"
    }
    else{
        # THIS ALLOWS ALL WEB, FTP, AND RDP TRAFFIC
        $tcpports = "80,443,21,3389,123"
        $udpports = "80,443,21,3389,123"
    }



    #Enables and Sets Firewall Logging to File
    #This could be broken out into 3 seperate logs for allowed, blocked, and ignored if desired.
    Set-NetFirewallProfile -LogFileName C:\firewall\firewall.log -LogAllowed True -LogBlocked True -LogIgnored True -LogMaxSizeKilobytes 32767

    #Sets Firewall to block all profiles and disables Firewall while rules are being made
    Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultInboundAction block -DefaultOutboundAction block -Enabled false

    #Disables all firewall rules
    Disable-NetFirewallRule -All

    #Set Allowed Rules
    New-NetFirewallRule -DisplayName "Allow Update" -Direction Outbound -Program "C:\tools\malwarebytes.exe" -Action Allow
    New-NetFirewallRule -DisplayName "Allow Ping" -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow
    New-NetFirewallRule -DisplayName "Allow Ping" -Direction Outbound -Protocol ICMPv4 -Action Allow
    New-NetFirewallRule -DisplayName "Allow Update" -Direction Outbound -Program "C:\Windows\system32\wusa.exe" -Action Allow
    New-NetFirewallRule -DisplayName "Allow SNMP" -Direction Inbound -Protocol UDP -LocalPort 161 -Action Allow
    New-NetFirewallRule -DisplayName "Allow SNMP" -Direction Outbound -Protocol UDP -RemotePort 161 -Action Allow

    # Allow Zabbix Agent and comms from the server, needs to be changed to binary level firewall
    New-NetFirewallRule -DisplayName "Zabbix" -Direction Inbound -Protocol UDP -LocalPort 10050 -Action Allow
    New-NetFirewallRule -DisplayName "Zabbix" -Direction Outbound -Protocol UDP -RemotePort 10051 -Action Allow

    # Allow Splunk forwarder, needs to be changed to binary level firewall
    New-NetFirewallRule -DisplayName "Splunk Forwarder" -Direction Inbound -Protocol UDP -LocalPort 9997 -Action Allow
    New-NetFirewallRule -DisplayName "Splunk Forwarder" -Direction Outbound -Protocol UDP -RemotePort 9997 -Action Allow


    Enable-NetFirewallRule -DisplayName "Core Networking - DNS (UDP-Out)"
    Enable-NetFirewallRule -DisplayName "Core Networking - Group Policy (LSASS-Out)"
    Enable-NetFirewallRule -DisplayName "Core Networking - Group Policy (NP-Out)"
    Enable-NetFirewallRule -DisplayName "Core networking - Group Policy (TCP-Out)"
    if ($global:config.IsDomainController -eq 1) {
        Enable-NetFirewallRule -DisplayGroup "Active Directory Domain Services" -Direction Inbound
        Enable-NetFirewallRule -DisplayGroup "DNS Service" -Direction Inbound
        Enable-NetFirewallRule -DisplayGroup "DFS Management" -Direction Inbound
        Enable-NetFirewallRule -DisplayGroup "DFS Replication" -Direction Inbound
        Enable-NetFirewallRule -DisplayGroup "Kerberos Key Distribution Center" -Direction Inbound
        Enable-NetFirewallRule -DisplayName "Active Directory Domain Controller (TCP-Out)"
        Enable-NetFirewallRule -DisplayName "Active Directory Domain Controller (UDP-Out)"
    }
    if ($tcpports) {
        New-NetFirewallRule -DisplayName "Allow TCP Ports" -Direction Inbound -Protocol TCP -LocalPort $tcpports.split(',') -Action Allow
        New-NetFirewallRule -DisplayName "Allow TCP Ports" -Direction Outbound -Protocol TCP -RemotePort $tcpports.split(',') -Action Allow
    }
    if ($udpports) {
        New-NetFirewallRule -DisplayName "Allow UDP Ports" -Direction Inbound -Protocol UDP -LocalPort $udpports.split(',') -Action Allow
        New-NetFirewallRule -DisplayName "Allow UDP Ports" -Direction Outbound -Protocol UDP -RemotePort $udpports.split(',') -Action Allow
    }

    #Turn on Firewall
    Set-NetFirewallProfile -Enabled True

    #Notify when a service starts listening for inbound connections
    Set-NetFirewallProfile -NotifyOnListen True

    Write-Host "[OK] " -ForegroundColor Green -NoNewLine 


