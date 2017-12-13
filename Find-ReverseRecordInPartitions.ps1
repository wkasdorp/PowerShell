# 
# Quick hack to look for PTR records directly in partitions. Assumes single domain forest,
# but accepts full list of parent DNs if needed. 
#
Param
(
    [Parameter(Mandatory=$true)]
    [string]$ipaddress,
    [Parameter(Mandatory=$false)]
    [string[]]$partitionlist = @(
        "DC=ForestDNSZones,$((Get-ADRootDSE).rootDomainNamingContext)",
        "DC=DomainDNSZones,$((Get-ADRootDSE).defaultNamingContext)",
        "CN=System,$((Get-ADRootDSE).defaultNamingContext)"
    )
)

function get_and_show_ad_object($dn)
{
    $object = $null
    try {
        $object = Get-ADObject -Filter * -SearchScope Base -SearchBase $dn -Properties whencreated
    } catch {}
    if ($object -ne $null)
    {
        $object | select distinguishedname,whencreated
    }
}

Write-Host "Looking through the following partitions partitions for a PTR record of $ipaddress :" -ForegroundColor Cyan
$partitionlist | Write-Host -ForegroundColor Cyan

$octets = $ipaddress -split '\.'
$list=@()
foreach ($dn in $partitionlist)
{
    # try class-C
    $recorddn = "DC=$($octets[3]),DC=$($octets[2]).$($octets[1]).$($octets[0]).in-addr.arpa,CN=MicrosoftDNS,$dn"
    $list += get_and_show_ad_object -dn $recorddn

    # try class-B
    $recorddn = "DC=$($octets[3]).$($octets[2]),DC=$($octets[1]).$($octets[0]).in-addr.arpa,CN=MicrosoftDNS,$dn"
    $list += get_and_show_ad_object -dn $recorddn

    # try class-A
    $recorddn = "DC=$($octets[3]).$($octets[2]).$($octets[1]),DC=$($octets[0]).in-addr.arpa,CN=MicrosoftDNS,$dn"
    $list += get_and_show_ad_object -dn $recorddn
}
if ($list)
{
    $list
} else {
    Write-Host "No PTR record found." -ForegroundColor Cyan
}
