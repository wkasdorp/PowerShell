<#
.Synopsis
   Validate a folder structure for Onedrive and/or Sharepoint sync compatibility.
.DESCRIPTION
   I wrote this because I have a very large file set that I want to sync with
   Onedrive for Business, and I know it has many incompatibilities that would
   lead to sync errors. Rather than relying on the many qualities of the 
   Onedrive sync I wanted to resolve incompatililities before setting up sync.
   
   This script scans a folder structure looking for known problems: path length,
   illegal characters, forbidden words, and optionally for the file size as well.
   Note that only the first error of any path is reported. After you repair
   it there may be other problems, so rerun the tool until it reports zero problems. 

   No guarantee: Onedrive/Sharepoint is rather picky and there may be other problematic 
   cases. If you encounter one, let me know. 
.OUTPUTS
   Output are PSObjects with Path and Status. Meaning of Status:
       OK             : file is fine. These files are not shown by default. 
       TooLong        : file is too long to sync, possibly after moving. See parameter DestinationPath.
       TooLarge       : file is too large. This check is not done by default. Max size is 10 GB. 
       IllegalChar    : file contains an illegal character, one of #%<>"|?*/ 
       InvalidName    : Path element contains a reserved word, like LPT1, NUL, COM and similar.
       PeriodProblem  : Path element ends with period, or starts with double period. 
       IllegalSpace   : Path element starting or ending in a whitespace character.
       Exception      : An error occurred while reading; usually the path is too long. 
.EXAMPLE
   .\Scan-OnedriveFilesForProblems.ps1
.EXAMPLE
   .\Scan-OnedriveFilesForProblems.ps1 -SourcePath 'c:\users\foobar\Work Folders' -DestinationPath 'c:\users\foobar\Onedrive - Microsoft' 
.NOTES
    Version:        1.0 : first version
    Author:         Willem Kasdorp, Microsoft. 
    Creation Date:  6/8/2016
    Last modified:  6/14/2016
#>

#requires -version 3

[CmdletBinding()]
Param
(
    # Specify path to Source folder to be checked. If not specified the path for Onedrive for Business
    # will be read from registry.
    [Parameter(Mandatory=$false)]
    [string]$SourcePath="",

    # This is the path where you are planning to move the folder structure. It is used to calculate
    # the maximum allowable path length. Note: no actual move is done!
    [Parameter(Mandatory=$false)]
    [string]$DestinationPath="",

    # Specify if file size should be checked. Default is not to check because the check is I/O intensive. 
    # Limit is 10 GB.
    [Parameter(Mandatory=$false)]
    [switch]$CheckSize=$false,

    # Output files that are OK for those people that want a complete report. 
    [Parameter(Mandatory=$false)]
    [switch]$IncludeOKFiles=$false
)

#
# this is a bit simpleminded; there could be more than one if you link to multiple tenants (BusinessX).
#
$OnedriveRegkey = "HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts\Business1"

#
# Get the source path
#
if (-not $SourcePath)
{
    $SourcePath = (Get-ItemProperty $OnedriveRegkey -ErrorAction SilentlyContinue).userfolder
    if (-not $SourcePath)
    {
        throw "SourcePath not specified and Onedrive for Business configuration not found in registry on this machine."
    }
}

#
# Calculate maximum length for current path IF moved to a new destination. 
#
$MaxPathLength = if ($DestinationPath) { 256 + $SourcePath.Length - $DestinationPath.Length } else { 256 } 

#
# function to check the path according to rules here: https://support.microsoft.com/en-us/kb/3125202 
#
Function IsValidOnedrivePath 
{  
    Param ([string]$path, [int]$MaxPathLength=256) 

    $ForbiddenWords = @(    
        '.files', '~$', '._', '.laccdb', '.tmp', '.tpm', 'thumbs.db', 'EhThumbs.db', 
        'Desktop.ini', '.DS_Store', 'Icon', '.lock', 'CON', 'PRN', 'AUX', 'NUL', 
        'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 
        'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    )
    
    if ($path.Length -ge $MaxPathLength)
    {
        return "TooLong"
    }
    if ($path -match '[#%<>"|?*/]')
    {
        return "IllegalChar"
    }

    foreach ($element in $path.Split([system.io.path]::DirectorySeparatorChar))
    {
        if ($ForbiddenWords -contains $element)
        {
            return "InvalidName"
        }
        #
        # path element starts or ends in whitespace.
        #
        if ($element -match '(^\s)|(\s$)')
        {
            return "InvalidSpace"
        }
        #
        # path element starts with double period, or ends with a period.
        #
        if ($element -match '(^\.\.)|(\.$)')
        {
            return "PeriodProblem"
        }
    }
    
    if ($CheckSize)
    {
        if ((Get-Item $path).length -gt 10GB)
        {
            return "TooLarge"
        }
    }
    "OK"
}

#
# The tricky bit here is to catch all errors generated by Get-Childitem while it's 
# traversing the tree. Adding (note the +) errors to a dedicated variable does the trick. 
#
$badfiles = 0
$FileError = @()
Get-ChildItem -Path $SourcePath -Recurse -ErrorAction SilentlyContinue -ErrorVariable +FileError | ForEach-Object {
    $PathState = IsValidOnedrivePath -path $_.FullName -MaxPathLength $MaxPathLength
    if ($PathState -ne "OK") 
    { 
        $badfiles++
        [PSCustomObject] @{
            Path = $_.FullName
            Status = $PathState
        }
    } elseif ($IncludeOKFiles) {
        [PSCustomObject] @{
            Path = $_.FullName
            Status = "OK"
        }
    }
}
foreach ($err in $FileError)
{
    $badfiles++
    [PSCustomObject] @{
        Path = $err.TargetObject
        Status = "Exception"
    }
}

#
# show summary outside the pipeline. 
#
Write-Host "Encountered $badfiles problematic files or folders" -ForegroundColor Cyan 
