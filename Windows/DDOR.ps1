# Distributed denial of redteam (hopefully)

# imports $IPS 
. $PSScriptRoot\Config.ps1
$psExecPath = "$PSScriptRoot\PsExec.exe"






#"c[n]" = @{
#        "Username" = $u;
#        "Password" = $p;
# }
$credentials = @{ }

$numberOfBatches = Read-Host "Enter the number of creds"

for ($i = 1; $i -le $numberOfBatches; $i++) {
    $u = Read-Host "Enter the $($i)st batch of usernames"
    $p = Read-Host "Enter the password for $u"
    
    $credentials["c$i"] = @{
        "Username" = $u;
        "Password" = $p
    }

}

#Write-Output $credentials


foreach ($ip in $IPS) {
    $selectedCredential = Read-Host "Enter the credential name (c1, c2, ..., cn) for IP $ip"

    if ($credentials.ContainsKey($selectedCredential)) {
        $username = $credentials[$selectedCredential]["Username"]
        $password = $credentials[$selectedCredential]["Password"]
        
        Write-Output "For IP $ip, using credential $selectedCredential. Username: $username, Password: $password"
        # Here is where the calls to psexec go
        # Here's their format, lol
        # & $psexecPath \\$ip -u $username -p $password -c -d -f C:\Users\Administrator\Downloads\init.ps1 -lo C:\lol.log
        & $psexecPath \\$ip -u $username -p $password -c -d -f "$PSScriptRoot\windowtint.ps1" "C:\Users\Administrator\Downloads\windowtint.ps1" -lo "C:\DDOR.log"
        & $psexecPath \\$ip -u $username -p $password -c -d -f "$PSScriptRoot\windowtint.ps1" "C:\Users\Administrator\Downloads\firewall.ps1" -lo "C:\DDOR.ps1"

        & $psexecPath \\$ip -u $username -p $password -h -s -d powershell.exe -ExecutionPolicy Bypass -File "C:\Users\Administrator\Downloads\windowTint.ps1" -lo "C:\DDOR.log"
        & $psexecPath \\$ip -u $username -p $password -h -s -d powershell.exe -ExecutionPolicy Bypass -File "C:\Users\Administrator\Downloads\firewall.ps1" -lo "C:\DDOR.log"

    

    
    

    } else {
        Write-Output "Credential $selectedCredential not found."
    }
}