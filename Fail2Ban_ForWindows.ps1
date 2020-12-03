# https://github.com/dm3942/Fail2Ban-For-Windows
# dm3942

$IPAddresses = @{}

$query = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
     *[System[
        Provider[@Name='Microsoft-Windows-Security-Auditing']
        and (Level=0) and (EventID=4625)
      ]]
    </Select>
  </Query>
</QueryList>
"@

$startTime = Get-Date
$lastIPaddr = "127.0.0.1"
$outbuff = ""

While (1) { # while (Get-Date) -lt $startTime.AddSeconds(20)) # run for 20 seconds
    $avent = Get-WinEvent -FilterXml $query -MaxEvents 1
    if($avent.Properties.Count -gt 19) {
        $IPaddr = $avent.Properties[19].Value
        try { 
            $IPAddresses.Add($IPaddr,$IPaddr) 
            Write-Host -ForegroundColor Red "$IPaddr  New attacker, time to block. $(Get-Date)"
            Write-Host "    Creating rule"
            New-NetFirewallRule -Profile Any -DisplayName "Block $(Get-Date (Get-Date) -UFormat '%Y%m%d%H%M%S') $IPaddr" -RemoteAddress $IPaddr -Enabled True -Direction Inbound -Action Block | % { Write-Host "    -> ", $_.DisplayName, "-", $_.Status }
            Write-Host "    Rule created"
        } catch [Exception] {
            if($lastIPaddr -ne $IPaddr) {
                $lastIPaddr = $IPaddr
                Write-Host -ForegroundColor Green "$IPaddr  existing attacker, rule already exists. $(Get-Date)"
            }
            Sleep -Milliseconds 200
        }
    }
}

