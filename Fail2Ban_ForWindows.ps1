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

$lastcleanup = Get-Date

While (1) { # while (Get-Date) -lt $startTime.AddSeconds(20)) # run for 20 seconds
    $avent = Get-WinEvent -FilterXml $query -MaxEvents 1
    if($avent.Properties.Count -gt 19) {
        $IPaddr = $avent.Properties[19].Value
        try {
            # Show IP Address 
            $IPAddresses.Add($IPaddr,$IPaddr) 
            Write-Host -ForegroundColor Red "$IPaddr  New attacker, time to block. $(Get-Date)"
            Write-Host "    Creating rule"

            # Check for local subnet
            $skipplocal = $false
            Get-NetIPAddress | where IPv4Address -ne $null | select IPAddress | % {
                if( ($_.IPAddress -like "$($IPaddr.Substring(0,$IPaddr.LastIndexOf('.')))*")  ) {
                    "    Local address skipping rule creation. "
                    $skipplocal = $true
                }
            }

            # Create Firewall Rule
            if(-not $skipplocal) {
                New-NetFirewallRule -Profile Any -DisplayName "Fail2Ban Block $(Get-Date (Get-Date) -UFormat '%Y%m%d%H%M%S') $IPaddr" -RemoteAddress $IPaddr -Enabled True -Direction Inbound -Action Block | % { Write-Host "    -> ", $_.DisplayName, "-", $_.Status }
                Write-Host "    Rule created"
            }
        } catch [Exception] {
            # Show IP address
            if($lastIPaddr -ne $IPaddr) {
                $lastIPaddr = $IPaddr
                Write-Host -ForegroundColor Green "$IPaddr  existing attacker, rule already exists. No new events found. $(Get-Date)"
            }
            Sleep -Milliseconds 1000
        }
    }

    # Every hour, clean up old rules
    if ( ((Get-Date)-$lastcleanup).Hour -gt 1) 
    {
        Write-Host -ForegroundColor DarkGreen "Cleaning up old rules. $(Get-Date)"
        $yesterdays = Get-Date (Get-Date).AddDays(-1) -UFormat '%Y%m%d' 
        Get-NetFirewallRule -DisplayName "Fail2Ban Block $($yesterdays)*" | Remove-NetFirewallRule 
        $lastcleanup = Get-Date
    }
}

