<#
.Synopsis
  Remove or disable stale computer accounts. There is a restore option for disabled accounts. 
.DESCRIPTION
  This scripts looks for stale computers accounts:
  - lastLogon more than $cutoffAge days ago
  - AND pwdLastSet more than $cutoffAge days ago.
  There are four possible behaviors specified with the $staleAction parameter.
  1. "nothing"; this will just run an inventory. 
  2. "disable"; disable and move account to a specific OU
  3. "restore": enable a previously disabled account and move it back.
  4. "delete" : permanently delete a computer account.
   
  Use the $DN and $wildcard parameters to select relevant computers. The $skipNonWindows
  flags selects only accounts belonging to Windows machines. This is useful to skip
  non-windows accounts (Linux), cluster accounts, and non-initialized accounts. 
  
  As a final safeguard, confirmation is needed for actual deletion. Override using 
  the -Confirm flag. 

  The script is limited to the single domain that your account is member of. 
.EXAMPLE
  # check all computers in the domain, but do nothing.
  .\Remove-StaleComputerAccounts.ps1
.EXAMPLE
  # select single computer account, and remove if stale. Write to a specific file. 
  $verbosepreference="continue"
  .\Remove-StaleComputerAccounts.ps1 -wildcard "server1$" -accountsFile "c:\temp\server1-account.csv" -staleAction delete
.EXAMPLE
  # Select all stale server accounts for an application, disable them if stale, and skip confirmation prompts.
  .\Remove-StaleComputerAccounts.ps1 -wildcard "foobar*" -staleAction disable -Confirm:$false -verbose
.EXAMPLE
  # Restore the foobar accounts from the previous action...
  .\Remove-StaleComputerAccounts.ps1 -wildcard "foobar*" -staleAction restore -verbose
  .NOTES
    Version:        1.0 : Initial version
    Author:         Willem Kasdorp, Microsoft. 
    Creation Date:  5/8/2018
    Last modified:
#>

[CmdletBinding(ConfirmImpact='high', SupportsShouldProcess)]
Param(
    # Toplevel Distinghuished Name to search. Defaults to the domain.
    [ValidateScript({Get-ADObject -SearchBase $_ -SearchScope base -Filter *})] 
    [String] $dn = $((Get-ADDomain).DistinguishedName),

    # Target OU for disabled accounts.
    [ValidateScript({Get-ADOrganizationalUnit -Identity $_})] 
    [String] $disabledOU,

    # Wildcard filter for computer name. Use this to select individual accounts of subsets. 
    # When specifying a single computer account, be sure to include the terminating $ sign.
    [string] $wildcard = "*",

    # Number of days indicating a stale computer account. Allow for a 14-day fudge offset.
    [int] $cutoffAge = 90,

    # select only Windows computers, meaning: skip Linux and other accounts. These machines
    # possibly do not change their password or log on, but could be still active. 
    [Switch] $skipNonWindows = $true,

    # disabled computer accounts are disabled for a reason, and should probably not be removed.
    [switch] $skipDisabled = $true,
     
    # determine action when stale accounts are encountered.
    [ValidateSet("delete", "disable", "nothing", "restore")]
    [string] $staleAction = "nothing",

    # Output file with the computer accounts matching DN and filter. 
    [string] $accountsFile = ".\aad-ds-stale-computer-accounts.csv" 
)

Write-Verbose "- searching in toplevel DN: '$dn'"
Write-Verbose "- matching pattern for computer samaccountname: '$($wildcard)'"
Write-Verbose "- flagging computer account with LastLogon and PasswordAge both older than '$cutoffAge' days"
Write-Verbose "- Process Windows-only accounts (skipping Linux and empty accounts): $skipNonWindows"
Write-Verbose "- Stale action: $staleAction"
Write-Verbose "- Target OU for disabled computer accounts: '$($disabledOU)'"
Write-Verbose "- Do not delete disabled computer accounts: $skipDisabled"

#
# some input validation
#
if (-not $skipDisabled) 
{
    Write-Warning "- WARNING: will remove disabled accounts if they are stale."
}
if ($staleAction -eq "disable" -and -not $disabledOU)
{
    throw "If the required action is to 'disable' you must specify an existing destination OU for the disabled computer account."
}
if ($staleAction -eq "restore" -and -not $disabledOU)
{
    throw "If the required action is to 'restore' you must specify an existing destination OU with disabled computer accounts."
}
if ($staleAction -eq "restore")
{
    #
    # for disabled accounts we already know where to look, so just limit the search to that. 
    #
    $dn = $disabledOU
    Write-Verbose "- Action is 'restore', so setting the DN equal to the disabled OU: $disabledOU"
}

#
# Query for the computer account, filter the samAccountname attribute on the wildcard, and skip non-windows if needed. 
#
$totalaccounts = 0
$propertyset = @("pwdLastSet,operatingsystem,whenCreated,samaccountname,lastlogonTimestamp,lastknownParent".split(','))
Get-ADComputer -SearchBase $dn -SearchScope Subtree -Filter * -Properties $propertyset -PipelineVariable computer |
    Where-Object { $computer.samaccountname -like $wildcard } | 
    Where-Object { -not $skipNonWindows -or $computer.operatingsystem -like "*Windows*" } |
    ForEach-Object {
        #
        # show a progress bar.
        #
        $totalaccounts++
        Write-Progress -Activity "Getting properties for computer accounts in DN: $dn" -Status "Processing object nr: $totalaccounts" 
        Write-Verbose "- Processing $($computer.samaccountname)"
        
        #
        # determine if the account is stale. 
        #
        $passwordAge = [datetime]::FromFileTimeUtc($computer.pwdLastSet)
        $pwdDaysOld = (New-TimeSpan -Start $passwordAge -End $(Get-Date)).Days
        if ($computer.lastlogonTimestamp -gt 0)
        {
            $lastLogon = [datetime]::FromFileTimeUtc($computer.lastLogonTimeStamp)
            $logonDaysOld = (New-TimeSpan -Start $lastLogon -End $(Get-Date)).Days
        } else {
            $lastLogon = -1
            $logonDaysOld = -1
        }
        $shouldDisableOrRemove = $pwdDaysOld -gt $cutoffAge -and (($logonDaysOld -gt $cutoffAge) -or $logonDaysOld -lt 0)

        #
        # Restore, disable, or remove the account. If we need to restore computer accounts from the disabled 
        # objects OU, try that first. 
        #
        $actionTaken = "nothing"
        if ($staleAction -eq "restore")
        {
            $parentDN = $computer.distinguishedname -replace '^.+?,(CN|OU|DC.+)','$1'
            $shouldRestore = -not $computer.enabled -and $computer.lastknownparent -ne $null -and $parentDN -eq $disabledOU
            if ($shouldRestore)
            {
                #
                # all criteria for restore are met; now ask permission. If approved, read the lastKnowParent that we set
                # when the account was disabled, move it there and enable it. 
                #
                if ($PSCmdlet.ShouldProcess("$($computer.samaccountname)", "Restore and enable the disabled computer account"))
                {
                    Write-Verbose "--- Recovery approved, going ahead"
                    try {
                        $lastKnownParent = $computer.lastknownParent
                        Write-Verbose "--- restoring $($computer.samaccountname) to '$($lastKnownParent)' because it is disabled and is a child of '$($disabledOU)'"                 
                        $description = "Moved and Enabled on $(Get-Date)."
                        Set-ADComputer -Identity $computer -enabled:$true -Description $description -Clear @("lastknownParent")
                        Move-ADObject -Identity $computer -TargetPath $lastKnownParent 
                        $actionTaken = "restore"
                    } catch {
                        Write-Warning "Caught exception '$($_.Exception.Message)' while moving and enabling $($computer.samaccountname)"
                    } 
                } else {
                    Write-Verbose "--- recovery DENIED, no action."
                }                     
            } else {
                Write-Verbose "-- computer account $($computer.samaccountname) will not be restored."
                $actionTaken = "nothing" 
            }
        } elseif ($shouldDisableOrRemove) {
            #
            # The account is stale. It either needs to be moved/disabled or deleted directly.
            # if it is disabled already and $skipDisabled: take no action. Somebody did this on purpose. 
            #
            Write-Verbose "-- computer account $($computer.samaccountname) is stale."
            if ($staleAction -eq "delete" -and -not $computer.enabled -and $skipDisabled)
            {
                Write-Verbose "-- computer account $($computer.samaccountname) is stale but disabled already, and will not be deleted."
            } elseif ($staleAction -eq "delete") {
                #
                # before we delete the account, log why. 
                #
                if (-not $computer.enabled -and -not $skipDisabled) 
                {
                    Write-Verbose "-- computer account $($computer.samaccountname) is stale, and will be removed even though it is disabled already"
                } else {
                    Write-Verbose "-- computer account $($computer.samaccountname) is stale and will be removed."
                }
                
                #
                # User gets popup to confirm deletion. To avoid this, specify on the commandline: -Confirm:$false
                #
                if ($PSCmdlet.ShouldProcess("$($computer.samaccountname)", "DELETE the stale computer account"))
                {
                    Write-Verbose "--- Removal approved, going ahead"
                    Try {
                        #
                        # note the specific syntax to remove child objects of the computer as well. These could be
                        # Hyper-V SCPs, printer queues, etc. 
                        #
                        $computer | Remove-ADObject -Recursive -confirm:$false -ErrorAction Stop | Out-Null
                        $actionTaken = "deleted"
                    } catch {
                        Write-Warning "Caught exception '$($_.Exception.Message)' while deleting $($computer.samaccountname)"
                    }
                } else {
                    Write-Verbose "--- deletion DENIED, no action."
                }       
            } elseif ($staleAction -eq "disable") {
                #
                # Account is stale, and should be disabled. Ask for confirmation first. Store the current parent DN
                # so that we can easily restore it later. Move it to an OU for disabled computers. 
                #
                if ($computer.enabled) {
                    if ($PSCmdlet.ShouldProcess("$($computer.samaccountname)", "DISABLE and move the stale computer account account"))
                    {
                        Write-Verbose "--- Disabling approved, going ahead"
                        try {
                            Write-Verbose "-- Disabling computer account and moving to: '$disabledOU'"
                            $lastKnownParent = $computer.distinguishedname -replace '^.+?,(CN|OU|DC.+)','$1'
                            $description = "Disabled on $(Get-Date)."
                            Set-ADComputer -Identity $computer -enabled:$false -Description $description -Replace @{lastKnownParent=$lastKnownParent}
                            Move-ADObject -Identity $computer -TargetPath $disabledOU 
                            $actionTaken = "disabled"
                        } catch {
                            Write-Warning "Caught exception '$($_.Exception.Message)' while disabling and moving $($computer.samaccountname)"
                        }   
                    } else {
                        Write-Verbose "--- disabling DENIED, no action."
                    }
                } else {
                    Write-Verbose "-- computer account $($computer.samaccountname) is stale but disabled already: no action."
                    $actionTaken = "nothing" 
                }
            } elseif ($staleAction -eq "nothing") {
                $actionTaken = "nothing"
            }
        }
        
        #
        # log what we found and did (or did not)
        #
        [PSCustomObject] @{
            dn = $computer.distinguishedname
            samAccountname = $computer.samaccountname
            os = $computer.operatingsystem
            accountEnabled = $computer.enabled
            whenCreated = $computer.whenCreated
            passwordAge = $passwordAge
            passwordDaysOld = $pwdDaysOld
            lastLogon = $lastLogon
            logonDaysOld = $logonDaysOld
            isStale = $shouldDisableOrRemove
            actionTaken = $actionTaken
        }
    } | Export-Csv $accountsFile -NoTypeInformation -Force

Write-Host "Wrote computer account information to: $accountsFile" -ForegroundColor Yellow
