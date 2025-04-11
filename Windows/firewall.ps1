param (
    [int[]]$tcpin,
    [int[]]$tcpout,
    [int[]]$udpin,
    [int[]]$udpout
)


## Create directory for backup
$firewallDir = "C:\firewall"
New-Item -ItemType Directory -Path $firewallDir

## Export current rules
$firewallBackup = "$firewallDir\original_fw.wfw"
netsh advfirewall export $firewallBackup

## Set default allow action for all profiles
Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultInboundAction Allow -DefaultOutboundAction Allow

## Disable all profiles
Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled False

## Disable all current rules
Get-NetFirewallRule | Disable-NetFirewallRule

## Delete all current rules
Get-NetFirewallRule | Remove-NetFirewallRule


#saveSinnoh 
New-NetFirewallRule -DisplayName "tcp_22_in" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow
New-NetFirewallRule -DisplayName "tcp_22_out" -Direction Outbound -Protocol TCP -RemotePort 22 -Action Allow
New-NetFirewallRule -DisplayName "tcp_3389_out" -Direction Outbound -Protocol TCP -RemotePort 3389 -Action Allow
New-NetFirewallRule -DisplayName "tcp_3389_in" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow
New-NetFirewallRule -DisplayName "udp_3389_in" -Direction Inbound -Protocol UDP -LocalPort 3389 -Action Allow
New-NetFirewallRule -DisplayName "tcp_5985_in" -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow
New-NetFirewallRule -DisplayName "tcp_5985_out" -Direction Outbound -Protocol TCP -RemotePort 5985 -Action Allow
New-NetFirewallRule -DisplayName "CCS-Out" -Direction Outbound -Protocol TCP -RemotePort 80,443 -Program "%systemdrive%\CCS\CCSClient.exe" -Action Allow


function add-fwRule {
    param (
        [string]$Direction,
        [string]$Protocol,
        [int[]]$Ports
    )

    foreach ($port in $Ports) {
        $ruleName = "~${Protocol}_${Direction}_${port}"
        Write-Host "`nCreating rule: $ruleName" -ForegroundColor Cyan

        try {
            $params = @{
                DisplayName         = $ruleName
                Direction           = $Direction
                Action              = 'Allow'
                Protocol            = $Protocol
                Profile             = 'Any'
                EdgeTraversalPolicy = 'Block'
                Enabled             = 'True'
                Verbose             = $true
            }

            if ($Direction -eq 'Inbound') {
                $params['LocalPort'] = $port
            } elseif ($Direction -eq 'Outbound') {
                $params['RemotePort'] = $port
            }

            New-NetFirewallRule @params
        }
        catch {
            Write-Error "Failed to create rule '$ruleName': $_"
        }
    }
}

## params
if ($tcpin)   { add-fwRule -Direction 'Inbound'  -Protocol 'TCP' -Ports $tcpin }
if ($tcpout)  { add-fwRule -Direction 'Outbound' -Protocol 'TCP' -Ports $tcpout }
if ($udpin)   { add-fwRule -Direction 'Inbound'  -Protocol 'UDP' -Ports $udpin }
if ($udpout)  { add-fwRule -Direction 'Outbound' -Protocol 'UDP' -Ports $udpout }


## Notify when a service starts listening for inbound connections
Set-NetFirewallProfile -NotifyOnListen True

## Define settings for log
Set-NetFirewallProfile -LogAllowed True -LogBlocked True -LogIgnored True -LogMaxSizeKilobytes 32767

## Set default block action for all profiles
Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultInboundAction Block -DefaultOutboundAction Block

## Enable all profiles
Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True