# https://github.com/dm3942/Fail2Ban-For-Windows
# dm3942

function CleanUpOldRules() {
    # Remove rules more than 5 days old
    $yesterdays = Get-Date (Get-Date).AddDays(-5) -UFormat '%Y%m%d_%H' 
    Write-Host -ForegroundColor DarkGreen "Cleaning up rules that are more than 5 days old. Match: 'Fail2Ban Block*' $(Get-Date)"
    Get-NetFirewallRule -DisplayName "Fail2Ban Block*" | Sort-Object -Property DisplayName | % {
        try {
            $firewallStringDate = $_.DisplayName.SubString("Fail2Ban Block ".Length, 13)
            $firewallCreationDate = [datetime]::ParseExact($firewallStringDate, 'yyyyMMdd_HHmm', $null)
            if($firewallCreationDate -lt (Get-Date).AddDays(-1)) { # Is the rule more than a day old?
                "   Removing: $($_.DisplayName)"
                $_ | Remove-NetFirewallRule
            } else {
                "   Keeping: $($_.DisplayName)"
            }
        } catch [Exception] {
            ""
        }
    }
}

CleanUpOldRules

$query = @"
    <QueryList>
        <Query Id="0" Path="Security">
        <Select Path="Security">*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and 
            (Task=12544) and 
            (band(Keywords,4503599627370496)) and 
            (EventID=4625) and 
            TimeCreated[timediff(@SystemTime) &lt;= 3600000]]]
        </Select>
        </Query>
    </QueryList>
"@

$startTime = Get-Date
$lastIPaddr = "127.0.0.1"
$lastEventCheck = (Get-Date).AddMinutes(-30) # Upon startup review the last 30 minutes of logs
$lastcleanup = Get-Date
$IPAddresses = @{} # Cache known bad IP addresses

While (1) { # while ( (Get-Date) -lt $startTime.AddSeconds(20)) # run for 20 seconds
    $createRule = $false
    #Write-Host -NoNewline "."
    try {
        # Check for the latest events
        $aevent = @()
        $aevent += Get-WinEvent -FilterXml $query -ErrorAction SilentlyContinue #  Where object causes xmlfilter with time filter to fail. ATM don't use | Where-Object TimeCreated -gt $lastEventCheck
        #$aevent.Count
        $createRule = $true
    } catch [Exception] {
        #Write-Host -ForegroundColor Green "No failed logon attempts found."
    }
    $lastEventCheck = Get-Date


    # If this event has the source IP address details
    if($createRule) {
        $aevent | % {
            $avent = $_ 
            if ($avent.Properties.Count -gt 19) {
                # Get source IP address from the Event
                $IPaddr = $avent.Properties[19].Value
                $userID = $avent.Properties[5].Value
                $userDomain = $avent.Properties[6].Value
                $workstation = $avent.Properties[13].Value

                # Try to create a firewall rule to block 
                try {
                    $IPAddresses.Add($IPaddr,$IPaddr) # Raise except and jump to Catch if the IP address already exists.

                    Write-Host -ForegroundColor Red "$IPaddr  New attacker $userDomain\$userID $workstation, time to block. $(Get-Date)"
                    Write-Host "    Creating rule"

                    # Don't block if it comes from the same subnet
                    $skipplocal = $false
                    Get-NetIPAddress | where IPv4Address -ne $null | select IPAddress | % {
                        if( ($_.IPAddress -like "$($IPaddr.Substring(0,$IPaddr.LastIndexOf('.')))*")  ) {
                            "    Failed login $userDomain\$userID $workstation came from local address $($IPaddr). Skipping rule creation. "
                            $skipplocal = $true
                        }
                    }

                    # Create Firewall Rule
                    if(-not $skipplocal) {
                        # Check existing rules
                        $existing = Get-NetFirewallRule -DisplayName "Fail2Ban Block*" | Get-NetFirewallAddressFilter |  Where-Object RemoteAddress -eq $IPaddr
                        If($existing.Count -eq 0) {
                            New-NetFirewallRule -Profile Any -DisplayName "Fail2Ban Block $(Get-Date (Get-Date) -UFormat '%Y%m%d_%H%M%S') $IPaddr" -RemoteAddress $IPaddr -Enabled True -Direction Inbound -Action Block | % { Write-Host "    -> ", $_.DisplayName, "-", $_.Status }
                            Write-Host "    Rule created"
                            $lastRuleCreated = Get-Date
                        } else {
                            Write-Host "    Rule already exists"
                        }
                    }
                } catch [Exception] {
                    # Show IP address
                    if($lastIPaddr -ne $IPaddr) {
                        $lastIPaddr = $IPaddr
                        Write-Host -ForegroundColor Green "$IPaddr $userDomain\$userID $workstation. Event already processed. Firewall rule previously created/processed. $(Get-Date)"
                        Write-Host "    Event time: $($avent.TimeCreated)"
                    }
                }
            } else {
                Write-Host -ForegroundColor Red "----------- !!ERROR!! ----------------- Missing Properties for rule creation. $(Get-Date)"
                Write-Host -ForegroundColor Red $avent
            }
        }
    }

    # Every 5 hours, clean up old rules, from the day before
    if ( (Get-Date) -gt $lastcleanup.AddHours(5) ) 
    {
        $IPAddresses = @{} # Reset bad IP address cache
        CleanUpOldRules
        $lastcleanup = Get-Date
    }

    Sleep -Milliseconds 1000

    # TO DO find a way to better align the time shift since the last query.
    $query = @"
        <QueryList>
            <Query Id="0" Path="Security">
            <Select Path="Security">*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and 
                (Task=12544) and 
                (band(Keywords,4503599627370496)) and 
                (EventID=4625) and 
                TimeCreated[timediff(@SystemTime) &lt;= 5000]]]
            </Select>
            </Query>
        </QueryList>
"@
}

