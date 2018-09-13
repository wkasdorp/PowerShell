<#
.Synopsis
Inventory Log Analytics workspaces and their connected resources.
.DESCRIPTION
The goal is to find which resources are connected to which OMS workspace. The script
does this by collecting all RM objects for each subscription in scope (wildcard), and
checking of the object reports to a workspace. The VMs get special treatment in the code. 

The output will allow you to determine deviations:
- cross region associations;
- VMs without OMS registration;
- VMs without an OMS agent extension
- which namespaces are heavily used, and which are not.
.EXAMPLE  
 .\Inventory-OMSConnections.ps1 -subscriptionwildcard "*PROD*" -verbose
.EXAMPLE  
 .\Inventory-OMSConnections.ps1 -subscriptionwildcard "*" -objectTypeWildcard "*VirtualMachine*" -verbose
.NOTES
    Version:        1.0 : Original Version
    Author:         Willem Kasdorp, Microsoft. 
    Creation Date:  9/13/2018
    Last modified:
#>

#
# we need a certain minimum version of the AzureRM modules for this to work. 
#
#Requires -Modules @{ ModuleName="AzureRM.Insights"; RequiredVersion="5.1.3" }

[CmdletBinding()]
Param(
    # use this wildcard to select subscriptions
    [String] $subscriptionWildcard = "*",
    # put this to $false to receive the status of all objects.
    [switch] $showOnlyConnectedObjects = $false,
    # specify the object type wildcard;
    [string] $objectTypeWildcard = "*",
    # output file in CSV format.
    [string] $outputfileName = ".\oms-connections.csv"
)

#
# Don't check types that are cannot have OMS extensions. This is an optimization to save time. 
# This list is incomplete, and simply derived from all diagnostic objects queries
# 'Get-AzureRmDiagnosticSetting' that gave exceptions. 
#
$typeNoWorkspace = @(  
    "Microsoft.AAD/DomainServices",
    "Microsoft.Automation/automationAccounts/configurations",
    "Microsoft.Automation/automationAccounts/runbooks",
    "Microsoft.BatchAI/workspaces",
    "Microsoft.BotService/botServices",
    "Microsoft.CertificateRegistration/certificateOrders",
    "Microsoft.ClassicCompute/domainNames",
    "Microsoft.ClassicNetwork/virtualNetworks",
    "Microsoft.ClassicStorage/storageAccounts",
    "Microsoft.Compute/availabilitySets",
    "Microsoft.Compute/disks",
    "Microsoft.Compute/images",
    "Microsoft.Compute/restorePointCollections",
    "Microsoft.Compute/snapshots",
    "Microsoft.Compute/virtualMachines/extensions",
    "Microsoft.ContainerRegistry/registries/replications",
    "Microsoft.ContainerRegistry/registries/webhooks",
    "Microsoft.ContainerService/containerServices",
    "Microsoft.Databricks/workspaces",
    "Microsoft.DevTestLab/labs",
    "Microsoft.DevTestLab/labs/virtualMachines",
    "Microsoft.DevTestLab/schedules",
    "Microsoft.DomainRegistration/domains",
    "microsoft.insights/actiongroups",
    "microsoft.insights/activityLogAlerts",
    "microsoft.insights/alertrules",
    "microsoft.insights/metricalerts",
    "microsoft.insights/scheduledqueryrules",
    "microsoft.insights/webtests",
    "Microsoft.MachineLearning/commitmentPlans",
    "Microsoft.MachineLearning/Workspaces",
    "Microsoft.MachineLearningCompute/operationalizationClusters",
    "Microsoft.MachineLearningExperimentation/accounts",
    "Microsoft.MachineLearningExperimentation/accounts/workspaces",
    "Microsoft.MachineLearningExperimentation/accounts/workspaces/projects",
    "Microsoft.MachineLearningModelManagement/accounts",
    "Microsoft.Network/applicationSecurityGroups",
    "Microsoft.Network/ddosProtectionPlans",
    "Microsoft.Network/localNetworkGateways",
    "Microsoft.Network/routeTables",
    "Microsoft.OperationsManagement/solutions",
    "Microsoft.Portal/dashboards",
    "Microsoft.PowerBI/workspaceCollections",
    "Microsoft.Scheduler/jobcollections",
    "Microsoft.Solutions/applicationDefinitions",
    "Microsoft.VisualStudio/account",
    "Microsoft.Web/certificates",
    "Microsoft.Web/connections",
    "Microsoft.Web/hostingEnvironments"
)

#
# Read all L.A. workspaces, needed to translate workspace IDs to friendly names.
# Note that associations can be cross-subscription.
#
Write-Verbose "- Reading all Log Analytics workspaces in all subscriptions that we can reach."
$workspacesObjects = @()
Get-AzureRmSubscription |  ForEach-Object {
    $subscription= $_
    $subscriptionname = $subscription.Name
    Set-AzureRmContext -SubscriptionId $subscription.SubscriptionId -ErrorAction stop | Out-Null
    Write-Verbose "-- Processing subscription $($subscription.Name)"     
    $workspacesObjects += Get-AzureRmOperationalInsightsWorkspace | Add-Member -NotePropertyName "subscription" -NotePropertyValue $subscriptionname -PassThru
} 
Write-Verbose "- found the following workspaces:"
$workspacesObjects | ft subscription,name,Location | Out-String | Write-Verbose

#
# for each specified subscriptions, read all objects and try to get OMS workspace information.
# This may differ per object type, unfortunately.
#
Write-Verbose "- Now reading all RM objects trying to extract which OMS namespace that they report to."
Write-Verbose "- Selecting subscriptions with pattern '$subscriptionwildcard'."
Get-AzureRmSubscription | Where-Object { $_.name -like $subscriptionwildcard } | ForEach-Object {
    $subscription= $_
    $subscriptionname = $subscription.Name
    Set-AzureRmContext -SubscriptionId $subscription.SubscriptionId -ErrorAction stop | Out-Null
    Write-Verbose "-- Processing subscription $($subscription.Name)"
    
    Get-AzureRmResource -PipelineVariable resource | ForEach-Object {
        #
        # Optimization: skip object that cannot have a workspace
        #
        if ($resource.ResourceType -in $typeNoWorkspace)
        {
            # Write-Verbose "--- Skipping '$($resource.Name)' of type '$($resource.ResourceType)', it cannot have a workspace."
            return
        }

        #
        # skip object types that we do not care about.
        #
        if ($resource.ResourceType -notlike $objectTypeWildcard)
        {
            # Write-Verbose "--- Skipping '$($resource.Name)' of type '$($resource.ResourceType)', its type does not match wildcard '$objectTypeWildcard'"
            return
        }      

        $diagSetting = $null
        $workspaceID = ""
        $customerID = ""
        $connected = ""
        $workspaceName = ""
        $workspaceRegion = ""

        #
        # WK: special cases for WinVM, LinuxVM.. 
        #
        if ($resource.ResourceType -eq "Microsoft.Compute/virtualMachines")
        {
            #
            # get the reference to the OMS placeholder object, if it exits.
            #
            Write-Verbose "--- processing VM: $($resource.name)"
            $vm = Get-AzureRmVm -ResourceGroupName $resource.ResourceGroupName -Name $resource.Name -WarningAction SilentlyContinue
            $omsExtensions = @($vm.Extensions | Where-Object { $_.VirtualMachineExtensionType -in @("oms","MicrosoftMonitoringAgent","OmsAgentForLinux") })
            $omsObjectID = ""
            if ($omsExtensions.Count -eq 0)
            {
                $connected = "no extension"
            } elseif ($omsExtensions.Count -eq 1) {
                $omsObjectID = $omsExtensions[0].Id
                $connected = "yes"
            } else {
                Write-Warning "--- Found VM $($vm.Name) with more than one (count = $($omsExtensions.Count)) OMS extension?!"
                $omsObjectID = $omsExtensions[0].Id
                $connected = "multiple!"
            }

            #
            # from the OMS placeholder ref, get the customerID.
            # Note: not all the attributes have the same usage accross objects.
            # 
            if ($omsObjectID)
            {
                $omsObject = Get-AzureRmResource -ResourceId $omsObjectID
                $customerID = $omsObject.Properties.settings.workspaceId
                Write-Verbose "---- Read the OMS object of the VM; customerID = $customerID"
            }
        } else {
            #
            # Not a VM, assume basic diagnostic settings.
            #
            try 
            {
                #
                # we can have multiple connections, for instance to a storage account and l.a. workspace ...
                # this happens for Application Gateways, for instance.
                # Implicit assumption here: there is at most 1 setting with a Workspace ID.
                #
                Get-AzureRmDiagnosticSetting -ResourceId $resource.ResourceID -ErrorAction Stop -WarningAction SilentlyContinue -PipelineVariable diagSetting | ForEach-Object {
                    if ($diagSetting.WorkspaceId)
                    {
                        $workspaceID = $diagSetting.WorkspaceId
                        $connected = "yes"

                        #
                        # from the workspace ID, which is really an object ID, get the workspace, and from the workspace
                        # get the customer ID (GUID identification)
                        #
                        $workspaceObject = $null
                        $workspaceObject = $workspacesObjects | Where-Object { $_.ResourceID -eq $diagSetting.WorkspaceId }
                        if ($workspaceObject -ne $null) {
                            $customerID = $workspaceObject.CustomerID
                            $workspaceRegion = $workspaceObject.Location
                        } else {
                            Write-Warning "---- object $($resource.Name): cannot find corresponding workspace for: $($diagSetting.WorkspaceId)"
                            $customerID = "workspace not found!"
                        }
                        Write-Verbose "---- found object $($resource.Name) of type '$($resource.ResourceType)' connected to $customerID"
                    } else {
                        $connected = "no"
                    }
                }
             } catch {
                $connected = "exception"
             }
        }
        
        #
        # from the customerID, get the correct workspace and some attributes. 
        #
        if ($customerID)
        {
            $workspaceObject = $null
            $workspaceObject = $workspacesObjects | Where-Object { $_.CustomerId -eq $customerID }
            if ($workspaceObject)
            {
                $workspaceName = $workspaceObject.Name
                $workspaceRegion = $workspaceObject.Location
            } else {
                $workspaceName = "<unknown>"
            }
        }

        #
        # summarize findings into the pipeline.
        #
        if (-not $showOnlyConnectedObjects -or $connected -eq "yes")
        {
            [pscustomobject] @{
                subscription = $subscriptionname
                RG = $resource.ResourceGroupName
                objectName = $resource.Name
                objectRegion = $resource.Location
                objectType = $resource.ResourceType
                connected = $connected
                customerID = $customerID
                workspaceName = $workspaceName
                workspaceRegion = $workspaceRegion
            }
        }
    }
} | Export-Csv -NoTypeInformation -Path $outputfileName

Write-Host "Wrote summary information to '$outputfileName'" -ForegroundColor Yellow
