#
# full disclosure: original is here: https://github.com/cyberark/RiskySPN/blob/master/Find-PotentiallyCrackableAccounts.ps1 
#

#
# Get domain and preferred DC. Warn about limitations.
#
if ($domain.ChildDomains.Count -ne 0)
{
    Write-Warning "This script does not properly handle cross-domain privileged users in the same forest"
}
$dc = Get-ADDomainController -DomainName $domain.DNSRoot -Service GlobalCatalog -Discover

#
# get all priviliged users as defined by group membership.
#
$groupList = @(
    "Administrators", 
    "Domain Admins",
    "Account Operators", 
    "Backup Operators", 
    "Print Operators", 
    "Server Operators", 
    "Group Policy Creator Owners", 
    "Schema Admins",
    "Enterprise Admins",
    "dnsadmins"
)
$privilegedUsers = @()
Write-Verbose "- expanding important groups" 
foreach ($groupname in $grouplist)
{
    $groupExists = (Get-ADObject -Server $dc -Filter { samaccountname -eq $groupname } -Properties samaccountname) -ne $null
    if ($groupExists)
    {
        Write-Verbose "-- expanding $groupname"
        $group = Get-ADGroup -server $dc -Identity $groupname 
        $privilegedUsers += Get-ADGroupMember -server $dc -Identity $group -Recursive | Where-Object { $_.objectclass -eq "user" }
    } else {
        Write-Verbose "-- skipping $groupname because it does not exist in domain $($domain.DNSRoot)"
    }    
}
$privilegedUsers = $privilegedUsers.samaccountname | Sort-Object -Unique

#
# query all users with SPN, check if they are privileged, write info
#
Write-Verbose "- now querying for all user accounts having an SPN"
$usercount = 0
Get-ADUser -server $dc -filter { serviceprincipalname -like "*" } -Properties @("serviceprincipalname") -PipelineVariable user | ForEach-Object {
    $usercount++
    Write-Progress -Activity "Searching for potential Kerberoast victims" -Status "User with SPN #$($usercount)"
    
    $isPriviliged = $privilegedUsers -contains $user.samaccountname
    $spnlist = $user.serviceprincipalname -join ','
    [pscustomobject]@{
        domain = $domain.DNSRoot
        samaccountname = $user.SamAccountName
        isPriviliged = $isPriviliged
        enabled = $user.enabled
        spnlist = $spnlist        
    }
}
