
Write-Output "=====================Hardening==========================="

try {
    # Set DNS server forwarders
    # Removes any old Forwarders

    # Should be changed to write old possibly malicious forwarders to a findings file
    get-dnsserverforwarder | remove-dnsserverforwarder
        
    # Adds DNS forwarder
    Add-DnsServerForwarder -IPAddress  1.1.1.1 -PassThru
    
    Write-Host "[OK] " -ForegroundColor Green -NoNewLine 
    Write-Host "DNS Forwarders configured" -ForegroundColor Green
}
catch {
    Write-Host "[SKIP] " -ForegroundColor Red -NoNewLine 
    Write-Host "Skipping DNS config, not a DNS Server" -ForegroundColor Yellow
}
    


# Starts Windows Updates and sets registry 
Set-Service -Name wuauserv -StartupType Automatic -Status Running
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v AUOptions /t REG_DWORD /d 4 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 4 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /v ElevateNonAdmins /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoWindowsUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\Internet Communication Management\Internet Communication" /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate /v DisableWindowsUpdateAccess /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V IncludeRecommendedUpdates /T REG_DWORD /D 1 /F
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /V ScheduledInstallTime /T REG_DWORD /D 22 /F
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferFeatureUpdates" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferQualityUpdates" /t REG_DWORD /d 0 /f

# Delete Shares and Set Registry Keys related to shares
# This needs to be rewritten so that it doesn't delete shares without documenting them.
net share C$ /delete 
net share Admin$ /delete
REG ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /f /v AutoShareServer /t REG_DWORD /d 0
REG ADD HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters /f /v AutoShareWks /t REG_DWORD /d 0
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy /f /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0
Write-Host "[OK] " -ForegroundColor Green -NoNewLine 
Write-Host "Shares deleted and registry keys added" -ForegroundColor Green

# Disable SMBv1
# This needs to be rewritten so that it logs the SMBv1 status before disabling it.
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force

# Remove Password Filters
# This needs to be rewritten so that it logs the password filters before removing them, maybe save them to quarantine?
Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages" -Recurse
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name "Notification Packages" -Value "scecli" -Type REG_MULTI_SZ

# Prevent Zerologon
# This needs to be rewritten so that it logs the Zerologon vulnerability status before disabling it.
Remove-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'FullSecureChannelProtection' -Force
New-Item -path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'FullSecureChannelProtection' -Value 1 -ItemType "DWORD" -Force 

# More SMB tings
#Minimum SMB version
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB2 /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v SMB2 /t REG_DWORD /d 2 /f

# Security Signature
reg add "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f

#harden the SMB
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v RejectUnencryptedAccess /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AnnounceServer /t REG_DWORD /d 0 /f

# Disable print spooler
# This needs to be rewritten so that it logs the print spooler status before disabling it.
Get-Service -Name Spooler | Stop-Service -Force
Set-Service -Name Spooler -StartupType Disabled -Status Stopped
Get-Service -Name RemoteRegistry | Stop-Service -Force
Set-Service -Name RemoteRegistry -StartupType Disabled -Status Stopped -Confirm $false

## Disable WinRM
## This needs to be rewritten so that it logs the WinRM status before disabling it.
#Disable-PSRemoting -Force
#Get-Service -Name WinRM | Stop-Service -Force
#Set-Service -Name WinRM -StartupType Disabled -Status Stopped -Confirm $false
#Remove-Item -Path WSMan:\Localhost\listener\listener* -Recurse
#Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system -Name LocalAccountTokenFilterPolicy -Value 0

    
# Remove startup scripts
####
#
# Oh my god just take me out back and put me down, this is so bad. We lose so much evidence in this block alone.
# This needs to be rewritten so that it logs/saves the startup scripts before removing them.
#
####
remove-item -Force 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*'
remove-item -Force 'C:\autoexec.bat'
remove-item -Force "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*"
remove-item -Force "C:\Windows\System32\GroupPolicy\Machine\Scripts\Startup"
remove-item -Force "C:\Windows\System32\GroupPolicy\Machine\Scripts\Shutdown"
remove-item -Force "C:\Windows\System32\GroupPolicy\User\Scripts\Logon"
remove-item -Force "C:\Windows\System32\GroupPolicy\User\Scripts\Logoff"

reg delete HKLM\Software\Microsoft\Windows\CurrentVersion\Run /VA /F
reg delete HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce /VA /F 
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /VA /F
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce /VA /F

# Enable TLS 1.2
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'Enabled' -value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'Enabled' -value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'TLS 1.2 has been enabled.'

#Select Default Action Array Action 3 = Remove
Set-MpPreference -ThreatIDDefaultAction_Ids "0000000000" -ThreatIDDefaultAction_Actions "3"
#Signature Scanning?
Set-MpPreference -SignatureScheduleDay Everyday -SignatureScheduleTime 120 -CheckForSignaturesBeforeRunningScan $true -DisableArchiveScanning $false -DisableAutoExclusions $false -DisableBehaviorMonitoring $false -DisableBlockAtFirstSeen $false -DisableCatchupFullScan $false -DisableCatchupQuickScan $false -DisableEmailScanning $false -DisableIOAVProtection $false -DisableIntrusionPreventionSystem $false -DisablePrivacyMode $false -DisableRealtimeMonitoring $false -DisableRemovableDriveScanning $false -DisableRestorePoint $false -DisableScanningMappedNetworkDrivesForFullScan $false -DisableScanningNetworkFiles $false -DisableScriptScanning $false -HighThreatDefaultAction Remove -LowThreatDefaultAction Quarantine -MAPSReporting 0 -ModerateThreatDefaultAction Quarantine -PUAProtection Enabled -QuarantinePurgeItemsAfterDelay 1 -RandomizeScheduleTaskTimes $false -RealTimeScanDirection 0 -RemediationScheduleDay 0 -RemediationScheduleTime 100 -ReportingAdditionalActionTimeOut 5 -ReportingCriticalFailureTimeOut 6 -ReportingNonCriticalTimeOut 7 -ScanAvgCPULoadFactor 50 -ScanOnlyIfIdleEnabled $false -ScanPurgeItemsAfterDelay 15 -ScanScheduleDay 0 -ScanScheduleQuickScanTime 200 -ScanScheduleTime 200 -SevereThreatDefaultAction Remove -SignatureAuGracePeriod 30 -SignatureUpdateCatchupInterval 1 -SignatureUpdateInterval 1 -SubmitSamplesConsent 2 -UILockdown $false -UnknownThreatDefaultAction Quarantine -Force

#Start Defender
start-service WinDefend
#Set Defender Policies
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d 3 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableGenericRePorts" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "LocalSettingOverrideSpynetReporting" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d 0 /f
    
#disable features
dism /online /disable-feature /featurename:TFTP /NoRestart
dism /online /disable-feature /featurename:TelnetClient /NoRestart
dism /online /disable-feature /featurename:TelnetServer /NoRestart
dism /online /disable-feature /featurename:"SMB1Protocol" /NoRestart

#Disable Powershell Remoting
Disable-PSRemoting -Force
Get-Service -Name WinRM | Stop-Service -Force
Set-Service -Name WinRM -StartupType Disabled -Status Stopped -Confirm $false
 
#remove sticky keys
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /f
TAKEOWN /F C:\Windows\System32\sethc.exe /A
ICACLS C:\Windows\System32\sethc.exe /grant administrators:F
Remove-Item C:\Windows\System32\sethc.exe -Force

#Delete utility manager (backdoor)
TAKEOWN /F C:\Windows\System32\Utilman.exe /A
ICACLS C:\Windows\System32\Utilman.exe /grant administrators:F
Remove-Item C:\Windows\System32\Utilman.exe -Force

#Delete on screen keyboard (backdoor)
TAKEOWN /F C:\Windows\System32\osk.exe /A
ICACLS C:\Windows\System32\osk.exe /grant administrators:F
Remove-Item C:\Windows\System32\osk.exe -Force

#Delete narrator (backdoor)
TAKEOWN /F C:\Windows\System32\Narrator.exe /A
ICACLS C:\Windows\System32\Narrator.exe /grant administrators:F
Remove-Item C:\Windows\System32\Narrator.exe -Force

#Delete magnify (backdoor)
TAKEOWN /F C:\Windows\System32\Magnify.exe /A
ICACLS C:\Windows\System32\Magnify.exe /grant administrators:F
Remove-Item C:\Windows\System32\Magnify.exe -Force

#Delete ScheduledTasks
Get-ScheduledTask | Unregister-ScheduledTask -Confirm:$false

#Disable Guest user
net user Guest /active:no

#Set Data Execution Prevention (DEP) to be always on
bcdedit.exe /set "{current}" nx AlwaysOn

#Make sure DEP is allowed (Triple Negative)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /t REG_DWORD /d 0 /f

#Only privileged groups can add or delete printer drivers
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f

#Don't execute autorun commands
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f
 
#Don't allow empty password login
reg ADD "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f
 
#Only local sessions can control the CD/Floppy
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateCDRoms /t REG_DWORD /d 1 /f
     
#Don't automatically logon as admin remotely
reg ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f

#audit policies
#Enable logging for EVERYTHING
auditpol /set /category:* /success:enable
auditpol /set /category:* /failure:enable
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"IPsec Main Mode" /success:enable /failure:enable
auditpol /set /subcategory:"IPsec Quick Mode" /success:enable /failure:enable
auditpol /set /subcategory:"IPsec Extended Mode" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
auditpol /set /subcategory:"Network Policy Server" /success:enable /failure:enable
auditpol /set /subcategory:"User / Device Claims" /success:enable /failure:enable
auditpol /set /subcategory:"Group Membership" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"Kernel Object" /success:enable /failure:enable
auditpol /set /subcategory:"SAM" /success:enable /failure:enable
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
auditpol /set /subcategory:"Central Policy Staging" /success:enable /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Other Privilege Use Events" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable
auditpol /set /subcategory:"DPAPI Activity" /success:enable /failure:enable
auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable
auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:enable
auditpol /set /subcategory:"Token Right Adjusted Events" /success:enable /failure:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Other Policy Change Events" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Replication" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed Directory Service Replication" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable

#Flush DNS Lookup Cache
ipconfig /flushdns

#Enable UAC popups if software trys to make changes
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f
  
#Require admin authentication for operations that requires elevation of privileges
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V ConsentPromptBehaviorAdmin /T REG_DWORD /D 1 /F
#Does not allow user to run elevates privileges
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V ConsentPromptBehaviorUser /T REG_DWORD /D 0 /F
#Built-in administrator account is placed into Admin Approval Mode, admin approval is required for administrative tasks
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V FilterAdministratorToken /T REG_DWORD /D 1 /F
#https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/932a34b5-48e7-44c0-b6d2-a57aadef1799
#WHY?
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /V EnableVirtualization /T REG_DWORD /D 1 /F 
  
#Disable Multiple Avenues for Backdoors
reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f
reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\Keyboard Response" /v Flags /t REG_SZ /d 122 /f
reg ADD "HKU\.DEFAULT\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 58 /f

#Don't allow Windows Search and Cortana to search cloud sources (OneDrive, SharePoint, etc.)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d 0 /f
#Disable Cortana
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
#Disable Cortana when locked
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d 0 /f
#Disable location permissions for windows search
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
#Don't let windows search the web
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
#Don't let windows search the web
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /V HideFileExt /T REG_DWORD /D 0 /F
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\HideFileExt" /v "CheckedValue" /t REG_DWORD /d 0 /f
reg ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /F


sc.exe config trustedinstaller start= auto
DISM /Online /Cleanup-Image /RestoreHealth
sfc /scannow