<#
.Synopsis
    Search the forest looking for active USN bubbles.
.DESCRIPTION
    An Active Directory USN bubble happens when a DC is restored with an 
    image-like restore method, such as a snapshot, copying a VMDK, breaking 
    a disk mirror, etc. This is less common now (2016) than it used to be. 
    Modern hypervisors such as Windows 2012 or ESX 5.1 and higher will try 
    to prevent the problem for compatible Windows versions: 2012+. 

    After such an event, the local USN on a DC will be lower than the one in 
    the UTD vectors of the other DC's hosting the same NCs, which means that 
    these won't replicate any changes from the problem DC until the USN 
    exceeds the value stored in the remote UTD: USN bubble. Modern versions 
    of Windows will also detect this problem and generate event ID 2095. 
    Read more in https://support.microsoft.com/en-us/kb/875495. 

    It is possible for an USN bubble to go undetected. This happens when the 
    USN exceeds the one in the UTD vector without any intermediate 
    replication attempt. At this point you have irrevocably inconsistent AD 
    databases. This script will only detect active USN bubbles. You can find 
    exceeded USN bubbles only be comparing data between DCs. Call Microsoft 
    Support to help you with this. 

    The script requires all DCs in the forest to be online and accessible. 
    It will check each DC before proceeding, and will remove unreachable DCs 
    from consideration. The script has been tested with 50 DCs. Large 
    forests are expected to be slow because the current version contains an 
    NxN algorithm. 
.INPUTS
    None.  
.OUTPUTS
    PSObjects with the USN administration. 
.PARAMETER exportfile
    export the data to an XML export file
.PARAMETER importfile
    import the data from an XML export file
.EXAMPLE
    .\Find-USNBubbles | out-gridview
    Normal usage, showing the output in a GUI. 
.EXAMPLE
    .\Find-USNBubbles -verbose -exportfile usnbubble.xml
    Show what is happening in excruciating detail (handy for 
    troubleshooting) and save the results to an XML output file. Import 
    using Import-CLIXML for your own analysis, or using the -importfile 
    parameter. They can even be combined. 
.EXAMPLE
    .\Find-USNBubbles -importfile usnbubble.xml
    Import a previously saved export. Can be used to have the analysis done
    by someone else. 
.NOTES
    Version:        0.1 : first version
                    0.2 : get local USN last to avoid false positives. 
                    0.3 : removed dependency on Test-NetConnection
    Author:         Willem Kasdorp, Microsoft. 
    Creation Date:  1/2/2016
    Last modified:  3/2/2016
#>

#requires -version 3

[CmdletBinding()]
Param
(
    [Parameter(Mandatory=$false)]
    [string]$exportfile,

    [Parameter(Mandatory=$false)]
    [string]$importfile
)

#
# global hash to convert Invocation ID guids to DC names. 
#
$invocationID2fqdn = @{}

#
# Helper function to check if a TCP port is open by using a TCP socket connection. The default 
# tcp handshake timeout is 5000 ms. To modify this, I use an async connection.
#
function Test-TCPPort
{
    Param (
        [string]$computername,
        [int]$port,
        [int]$timeout=1500
    )

    $tcpsocket = New-Object System.Net.Sockets.TcpClient
    
    $result = $false
    Try
    {
        $connection = $tcpsocket.BeginConnect($computername, $port, $null, $null)
        $connection.AsyncWaitHandle.WaitOne($timeout,$false) | Out-Null
        Write-Verbose "-- TCP connection state to $computername on port $port : $($tcpsocket.Connected)"
        $result = $tcpsocket.Connected
    }
    Catch
    {
        Write-Verbose "-- TCP connection to $computername on port $port failed, exception $_"
        $result = $false
    }
    Finally
    {
        $tcpsocket.Dispose()
    }
    $result
}

#
# helper function to convert an array of [byte] to a GUID string. 
#
Function Convert-Octet2GUIDString
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [byte[]]$octet
    )

    if ($octet.Count -ne 16) 
    {
        throw "Invalid octet length"
    }

    "{0:x2}{1:x2}{2:x2}{3:x2}-{4:x2}{5:x2}-{6:x2}{7:x2}-{8:x2}{9:x2}-{10:x2}{11:x2}{12:x2}{13:x2}{14:x2}{15:x2}" -f 
        $octet[3], $octet[2], $octet[1], $octet[0], 
        $octet[5], $octet[4], 
        $octet[7], $octet[6],
        $octet[8], $octet[9],  
        $octet[10], $octet[11], $octet[12], $octet[13], $octet[14], $octet[15]
}

#
# This function returns a list of all DC's in the forest, using FQDN. It gets this
# information from the Config partition, in the CN=Sites container. Because some servers
# here may not be real DC's (demoted, ADC, MSMQ,...), each server object is also
# checked for the existence of an NTDS Settings object. That should be a DC.
# 
# returns an (extensible) list of DCs in a PSobject.
#
function Get-ForestDCs
{
    [CmdletBinding()]
    param ()
     
    $objRootDSE = New-Object System.DirectoryServices.DirectoryEntry('LDAP://rootDSE') 
    $objSites = New-Object System.DirectoryServices.DirectoryEntry('LDAP://CN=Sites,' + $objRootDSE.configurationNamingContext) 

    $strFilter = "(&(objectCategory=Server)(dNSHostName=*))" 
    $objSearcher = New-Object System.DirectoryServices.DirectorySearcher 
    $objSearcher.SearchRoot = $objSites 
    $objSearcher.PageSize = 1000 
    $objSearcher.Filter = $strFilter 
    $objSearcher.SearchScope = "Subtree" 

    @("dNSHostname", "distinguishedName") | ForEach-Object { 
        [void] $objSearcher.PropertiesToLoad.Add($_) 
    }

    Write-Verbose "-- getting list of all Server objects in the config partition"
    $colResults = $objSearcher.FindAll() 

    #
    # read NTDS Settings for all DCs, fill the invocation ID conversion hash. 
    #
    Write-Verbose "-- getting details of the NTDS object of each server" 
    foreach ($objResult in $colResults) 
    {
        $objItem = $objResult.Properties 
        $objNTDS = New-Object System.DirectoryServices.DirectoryEntry('LDAP://CN=NTDS Settings,' + $objItem.distinguishedname) 
        if ($objNTDS.name) {
            if ($objNTDS.InvocationID) 
            {
                Write-Verbose "--- found NTDS object for $($objItem.dnshostname)"
                $invocationID = Convert-Octet2GUIDString -octet ($objNTDS | Select-Object -ExpandProperty invocationid)
                $invocationID2fqdn.Add($invocationID, [string]$objItem.dnshostname)   
                #
                # push the DC data in the pipeline. 
                #
                [PSCustomObject] @{
                    dnshostname = [string]$objItem.dnshostname
                    invocationID = $invocationID
                    NCList = $objNTDS."msDS-HasMasterNCs"
                }
            } else {
                Write-Warning "--- No invocation ID found for $($objItem.dnshostname). This could be an RODC or a recent DC. For now, it's ignored"
            }
        } 
    } 
    $objSearcher.Dispose()
} 

#
# we only want to talk to DCs that have an open LDAP port. This function extends the PSObject with that information.
#
function Check-LdapOnline
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true, ValueFromPipeLine=$true)]
        [PSObject]$computer
    )

    BEGIN {}
    PROCESS
    {
        Write-Verbose "-- testing connection to $($computer.dnshostname) with PING and a TCP connection to port 389"
        $result = Test-TCPPort -ComputerName $computer.dnshostname -port 389
        #
        # Extend the incoming computer object, and push it back into the pipeline.
        #
        $computer | Add-Member -MemberType NoteProperty -Name ldaponline -Value $result -PassThru -Force
    }
    END{}
}

#
# execute repadmin for all DCs and for all NCs to find the UTD vectors containing the remote USN that we need. 
# Output: new objects for each DC/NC combination. 
#
function Get-RemoteUSN
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true, ValueFromPipeLine=$true)]
        [PSObject]$computer
    )

    BEGIN 
    {
        if (-not (Get-Command repadmin.exe -ErrorAction SilentlyContinue))
        {
            Throw "REPADMIN.EXE not found in path. Please install the RSAT for Domain Services"
        }
    }

    PROCESS 
    {
        #
        # skip the DC if we got no LDAP tcp response from the DC. 
        #
        if (-not $computer.ldaponline)
        {
            return
        }
       
        #
        # loop over NCs of the DC, get the utdvec for each
        #
        Write-Verbose "-- getting repadmin info for $($computer.dnshostname)"
        foreach ($nc in $computer.nclist)
        {
            Write-Verbose "--- repadmin /showutdvec $($computer.dnshostname) $nc /nocache"
            $repadmin = repadmin /showutdvec $computer.dnshostname $nc /nocache

            #
            # loop over all output lines of repadmin, extract invocation ID and USN. A line looks like this.
            # "bad8c4dc-535b-404c-8d86-18d009731a93 @ USN     32775 @ Time 2014-12-02 20:59:10"
            #
            # All guids not in the hash should be retired invocation IDs or DCs that no longer exist. We ignore them. 
            #
            $repadmin | ForEach-Object {
                if ($_ -match "([\w-]+)\s+@\s+USN\s+(\d+)")
                {
                    # Write-Verbose "----$_"
                    $invocationID = $matches[1]
                    $usn = $matches[2]
                    if ($fqdn = $invocationID2fqdn[$invocationID])
                    {
                        Write-Verbose "---- found matching invocation ID $fqdn, $invocationID, $usn" 
                        #
                        # Push the new data in the pipeline. The incoming objects are discarded
                        #
                        [PSCustomObject]@{
                            dc = $computer.dnshostname
                            nc = $nc
                            remotedc = $fqdn
                            usn = $usn
                        }
                    }
                }
            }
        }
    }

    END {}
}

#
# Read the local USN of the remote DC, add it to the incoming PSObject. 
#
function Get-LocalUSN
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true, ValueFromPipeLine=$true)]
        [PSObject]$dc
    )

    BEGIN {}
    PROCESS 
    {
        #
        # At this stage, assume the DC is alive; connect to its RootDSE and get the current USN.
        # Extend the incoming DC object with property currentusn.
        #
        Write-Verbose "-- reading the current USN from $($dc.dnshostname) by connecting to its RootDSE" 
        $objRootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($dc.dnshostname)/RootDSE")
        $dc | Add-Member -MemberType NoteProperty -Name currentusn -Value ([string]$objRootDSE.highestCommittedUSN[0])
        $objRootDSE.Dispose()

        #
        # put it back in the pipeline.
        #
        $dc
    }
    END {}
}

#
# This function tries to find remote USNs that are higher than the current USN; that would be an active USN bubble. 
# It loops over all DCs, all the NCs it holds, and for that it loops over all other DCs with the same NCs 
# to look for these bubbles.
#
# output: new PSObjects for each DC/NC combination containing the USN administration. 
#
function Find-USNBubble
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        $dclist,

        [Parameter(Mandatory=$true)]
        $usnlist
    )

    #
    # N x N algorithm, will be slow in large forest. 
    #
    foreach ($dc in $dclist)
    {
        if (-not $dc.ldaponline)
        {
            continue
        }
        Write-Verbose "--- analyzing $($dc.dnshostname) for USN bubbles"
        foreach ($nc in $dc.nclist)
        {
            Write-Verbose "---- analyzing $nc"
            $highestusn = 0
            $status = [PSCustomObject]@{ 
                dnshostname          = $dc.dnshostname
                nc                   = $nc
                localusn             = $dc.currentusn
                highestusn           = 0
                dc_highestusn        = "<self>"             # this will happen when an NC exists on only one DC
                isbubble             = $false
            } 
    
            foreach ($item in $usnlist)
            {
                #
                # select only relevant records: other DC, same NC, remoteDC refers to self.
                #
                if ($dc.dnshostname -eq $item.dc)
                {
                    continue
                }
                if ($nc -ne $item.nc)
                {
                    continue
                }
                if ($dc.dnshostname -ne $item.remotedc)
                {
                    continue
                }

                #
                # find highest remote USN, record the DC where it happened. 
                # For now we select only the first one found. There will very likely be more than one DC
                # with the same highest remote USN! Not that this matters. 
                #
                if ($item.usn -gt $highestusn)
                {
                    Write-Verbose "----- found new highest USN $($item.usn) on $($item.dc)"
                    $highestusn = $item.usn
                    $status.highestusn = $highestusn
                    $status.dc_highestusn = $item.dc
                    if ($item.usn -gt $dc.currentusn)
                    { 
                        Write-Verbose "------ FOUND USN BUBBLE on remote DC $($item.dc): $($item.usn) > $($dc.currentusn)"
                        $status.isbubble = $true
                    }
                }
            }
            #
            # Here we write the output objects.
            #
            $status
        }
    }
}

#
# If there is an import file it will contain all DC data. Use this to recalculate the USN bubble. 
# Note that we do not import the overview. 
#
if ($importfile)
{
    Write-Verbose "-- reading USN data from importfile $($importfile)" 
    $import = Import-Clixml -Path $importfile
    $dclist = $import.dclist
    $usnlist = $import.usnlist
    $onlinelist = $import.onlinelist
    $invocationID2fqdn = $import.invocationID2fqdn
} else {
    #
    # get all DCs first with some relevant data. Check if they are talking LDAP.
    #
    Write-Verbose "-- Generating list of DC's, verifying if they are online"
    $dclist = Get-ForestDCs | Check-LdapOnline

    #
    # once complete, check the UTD Vectors, skipping the unreachable DCs. Same for local USNs.
    # Note: do NOT combine pipelines; the first needs to finish fully before starting the next. 
    #
    Write-Verbose "-- Getting the UTDVectors for all DCs that are online"
    $usnlist = $dclist | Get-RemoteUSN 

    Write-Verbose "-- Getting the local USN for all DCs that are online"
    $onlinelist = $dclist | Where-Object { $_.ldaponline } | Get-LocalUSN
}

#
# try to find USN bubbles, retain and show the results
#
$overview = Find-USNBubble -dclist $onlinelist -usnlist $usnlist
$overview 

#
# Export all global variables. Handy for testing and transporting data from/to environments.
# you can create a fake bubble by editing the export file, and importing it. 
#
if ($exportfile)
{
    $export = [PSCustomObject]@{ 
        dclist = $dclist
        usnlist = $usnlist
        overview = $overview
        onlinelist = $onlinelist
        invocationID2fqdn = $invocationID2fqdn
    }
    Write-Verbose "-- writing dclist, usnlist, overview and invocation ID mapping to $exportfile"
    $export | Export-Clixml -Path $exportfile -Force
}
