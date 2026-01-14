<#
.SYNOPSIS
    Active Directory Cleanup and Audit Tool

.DESCRIPTION
    This script audits Active Directory for:
    - Inactive user accounts (no login for specified days)
    - Disabled accounts that can be archived
    - Empty security groups
    - Stale computer accounts
    - Users with passwords that never expire
    - Accounts with no email address
    Generates a detailed report and can optionally take action on findings.

.PARAMETER InactiveDays
    Number of days of inactivity to flag accounts (default: 90)

.PARAMETER StaleComputerDays
    Number of days for computer accounts to be considered stale (default: 90)

.PARAMETER LogPath
    Path where reports will be saved

.PARAMETER TakeAction
    Switch to enable automatic actions (disable, move to archive OU)

.PARAMETER ArchiveOU
    OU path where disabled accounts should be moved

.PARAMETER WhatIf
    Shows what actions would be taken without executing them

.EXAMPLE
    .\Project3-ADCleanup.ps1 -InactiveDays 90
    
.EXAMPLE
    .\Project3-ADCleanup.ps1 -TakeAction -ArchiveOU "OU=Disabled,DC=domain,DC=com" -WhatIf

.NOTES
    Author: Ranim Hassine
    Date: 2026-01-14
    
    IMPORTANT: Always run with -WhatIf first to review actions before making changes!
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [int]$InactiveDays = 90,
    
    [Parameter(Mandatory=$false)]
    [int]$StaleComputerDays = 90,
    
    [Parameter(Mandatory=$false)]
    [int]$DisabledAccountDays = 180,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\Logs\ADCleanup",
    
    [Parameter(Mandatory=$false)]
    [switch]$TakeAction,
    
    [Parameter(Mandatory=$false)]
    [string]$ArchiveOU = "OU=Archived,DC=Domain,DC=local",
    
    [Parameter(Mandatory=$false)]
    [string[]]$ExcludedOUs = @("OU=Service Accounts,DC=domain,DC=com")
)

#Requires -Modules ActiveDirectory

# Function to write log entries
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info','Warning','Error','Success')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        'Info'    { Write-Host $logMessage -ForegroundColor Cyan }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
        'Success' { Write-Host $logMessage -ForegroundColor Green }
    }
    
    $logFile = Join-Path $LogPath "ADCleanup_$(Get-Date -Format 'yyyyMMdd').log"
    $logMessage | Out-File -FilePath $logFile -Append
}

# Function to check if account is in excluded OU
function Test-ExcludedOU {
    param(
        [string]$DistinguishedName,
        [string[]]$ExcludedList
    )
    
    foreach ($ou in $ExcludedList) {
        if ($DistinguishedName -like "*$ou*") {
            return $true
        }
    }
    return $false
}

# Function to find inactive users
function Find-InactiveUsers {
    param(
        [int]$Days,
        [string[]]$ExcludedOUs
    )
    
    Write-Log "Searching for users inactive for more than $Days days..." -Level Info
    
    $cutoffDate = (Get-Date).AddDays(-$Days)
    $inactiveUsers = @()
    
    $users = Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonDate, EmailAddress, Department, Manager, DistinguishedName, PasswordNeverExpires, PasswordLastSet
    
    foreach ($user in $users) {
        # Skip excluded OUs
        if (Test-ExcludedOU -DistinguishedName $user.DistinguishedName -ExcludedList $ExcludedOUs) {
            continue
        }
        
        # Check if never logged in or last logon is old
        if ($null -eq $user.LastLogonDate -or $user.LastLogonDate -lt $cutoffDate) {
            $daysSinceLogon = if ($user.LastLogonDate) { 
                (New-TimeSpan -Start $user.LastLogonDate -End (Get-Date)).Days 
            } else { 
                "Never" 
            }
            
            $inactiveUsers += [PSCustomObject]@{
                Username = $user.SamAccountName
                Name = $user.Name
                EmailAddress = $user.EmailAddress
                Department = $user.Department
                LastLogon = if ($user.LastLogonDate) { $user.LastLogonDate.ToString('yyyy-MM-dd') } else { "Never" }
                DaysSinceLogon = $daysSinceLogon
                PasswordNeverExpires = $user.PasswordNeverExpires
                DistinguishedName = $user.DistinguishedName
            }
        }
    }
    
    Write-Log "Found $($inactiveUsers.Count) inactive users" -Level Warning
    return $inactiveUsers
}

# Function to find disabled accounts
function Find-DisabledAccounts {
    param(
        [int]$Days,
        [string[]]$ExcludedOUs
    )
    
    Write-Log "Searching for accounts disabled more than $Days days ago..." -Level Info
    
    $cutoffDate = (Get-Date).AddDays(-$Days)
    $disabledAccounts = @()
    
    $users = Get-ADUser -Filter {Enabled -eq $false} -Properties WhenChanged, EmailAddress, Department, DistinguishedName
    
    foreach ($user in $users) {
        # Skip excluded OUs and already archived accounts
        if (Test-ExcludedOU -DistinguishedName $user.DistinguishedName -ExcludedList $ExcludedOUs) {
            continue
        }
        
        if ($user.DistinguishedName -like "*Archived*") {
            continue
        }
        
        if ($user.WhenChanged -lt $cutoffDate) {
            $daysSinceDisabled = (New-TimeSpan -Start $user.WhenChanged -End (Get-Date)).Days
            
            $disabledAccounts += [PSCustomObject]@{
                Username = $user.SamAccountName
                Name = $user.Name
                EmailAddress = $user.EmailAddress
                Department = $user.Department
                DisabledDate = $user.WhenChanged.ToString('yyyy-MM-dd')
                DaysSinceDisabled = $daysSinceDisabled
                DistinguishedName = $user.DistinguishedName
            }
        }
    }
    
    Write-Log "Found $($disabledAccounts.Count) disabled accounts ready for archiving" -Level Warning
    return $disabledAccounts
}

# Function to find empty groups
function Find-EmptyGroups {
    Write-Log "Searching for empty security groups..." -Level Info
    
    $emptyGroups = @()
    $groups = Get-ADGroup -Filter {GroupCategory -eq 'Security'} -Properties Members, Description, WhenCreated
    
    foreach ($group in $groups) {
        $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
        
        if ($members.Count -eq 0) {
            $emptyGroups += [PSCustomObject]@{
                GroupName = $group.Name
                Description = $group.Description
                DistinguishedName = $group.DistinguishedName
                CreatedDate = $group.WhenCreated.ToString('yyyy-MM-dd')
                DaysSinceCreation = (New-TimeSpan -Start $group.WhenCreated -End (Get-Date)).Days
            }
        }
    }
    
    Write-Log "Found $($emptyGroups.Count) empty security groups" -Level Warning
    return $emptyGroups
}

# Function to find stale computers
function Find-StaleComputers {
    param(
        [int]$Days
    )
    
    Write-Log "Searching for stale computer accounts (inactive for $Days days)..." -Level Info
    
    $cutoffDate = (Get-Date).AddDays(-$Days)
    $staleComputers = @()
    
    $computers = Get-ADComputer -Filter {Enabled -eq $true} -Properties LastLogonDate, OperatingSystem, Description, DistinguishedName
    
    foreach ($computer in $computers) {
        if ($null -eq $computer.LastLogonDate -or $computer.LastLogonDate -lt $cutoffDate) {
            $daysSinceLogon = if ($computer.LastLogonDate) { 
                (New-TimeSpan -Start $computer.LastLogonDate -End (Get-Date)).Days 
            } else { 
                "Never" 
            }
            
            $staleComputers += [PSCustomObject]@{
                ComputerName = $computer.Name
                OperatingSystem = $computer.OperatingSystem
                Description = $computer.Description
                LastLogon = if ($computer.LastLogonDate) { $computer.LastLogonDate.ToString('yyyy-MM-dd') } else { "Never" }
                DaysSinceLogon = $daysSinceLogon
                DistinguishedName = $computer.DistinguishedName
            }
        }
    }
    
    Write-Log "Found $($staleComputers.Count) stale computer accounts" -Level Warning
    return $staleComputers
}

# Function to find accounts with password issues
function Find-PasswordIssues {
    Write-Log "Searching for accounts with password issues..." -Level Info
    
    $passwordIssues = @()
    $users = Get-ADUser -Filter {Enabled -eq $true} -Properties PasswordNeverExpires, PasswordLastSet, DistinguishedName
    
    foreach ($user in $users) {
        $issues = @()
        
        if ($user.PasswordNeverExpires) {
            $issues += "Password Never Expires"
        }
        
        if ($null -eq $user.PasswordLastSet) {
            $issues += "Password Never Set"
        }
        elseif ($user.PasswordLastSet -lt (Get-Date).AddDays(-180)) {
            $issues += "Password Over 180 Days Old"
        }
        
        if ($issues.Count -gt 0) {
            $passwordIssues += [PSCustomObject]@{
                Username = $user.SamAccountName
                Name = $user.Name
                Issues = $issues -join ", "
                PasswordLastSet = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString('yyyy-MM-dd') } else { "Never" }
                DistinguishedName = $user.DistinguishedName
            }
        }
    }
    
    Write-Log "Found $($passwordIssues.Count) accounts with password issues" -Level Warning
    return $passwordIssues
}

# Function to find accounts without email
function Find-AccountsWithoutEmail {
    Write-Log "Searching for user accounts without email addresses..." -Level Info
    
    $noEmailAccounts = @()
    $users = Get-ADUser -Filter {Enabled -eq $true} -Properties EmailAddress, Department, Title, DistinguishedName
    
    foreach ($user in $users) {
        if ([string]::IsNullOrWhiteSpace($user.EmailAddress)) {
            $noEmailAccounts += [PSCustomObject]@{
                Username = $user.SamAccountName
                Name = $user.Name
                Department = $user.Department
                Title = $user.Title
                DistinguishedName = $user.DistinguishedName
            }
        }
    }
    
    Write-Log "Found $($noEmailAccounts.Count) accounts without email addresses" -Level Warning
    return $noEmailAccounts
}

# Function to generate HTML report
function New-HTMLReport {
    param(
        [hashtable]$Data,
        [string]$OutputPath
    )
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Active Directory Cleanup Report - $(Get-Date -Format 'yyyy-MM-dd')</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #2c3e50; text-align: center; }
        h2 { color: #34495e; border-bottom: 2px solid #e74c3c; padding-bottom: 5px; margin-top: 30px; }
        .summary { background-color: #fff3cd; padding: 15px; border-radius: 5px; margin-bottom: 20px; border-left: 5px solid #ffc107; }
        .summary-item { margin: 10px 0; }
        .count { font-weight: bold; color: #e74c3c; font-size: 1.2em; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; background-color: white; }
        th { background-color: #e74c3c; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f5f5f5; }
        .section { background-color: white; padding: 20px; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .recommendation { background-color: #d1ecf1; padding: 10px; border-radius: 5px; margin-top: 10px; border-left: 5px solid #0c5460; }
        .timestamp { text-align: center; color: #7f8c8d; margin-top: 20px; }
        .action-taken { color: #27ae60; font-weight: bold; }
        .action-recommended { color: #f39c12; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Active Directory Cleanup Report</h1>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="summary-item">Report Generated: <strong>$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</strong></div>
        <div class="summary-item">Inactive Users: <span class="count">$($Data.InactiveUsers.Count)</span></div>
        <div class="summary-item">Disabled Accounts Ready for Archive: <span class="count">$($Data.DisabledAccounts.Count)</span></div>
        <div class="summary-item">Empty Security Groups: <span class="count">$($Data.EmptyGroups.Count)</span></div>
        <div class="summary-item">Stale Computer Accounts: <span class="count">$($Data.StaleComputers.Count)</span></div>
        <div class="summary-item">Password Issues: <span class="count">$($Data.PasswordIssues.Count)</span></div>
        <div class="summary-item">Accounts Without Email: <span class="count">$($Data.NoEmailAccounts.Count)</span></div>
        <div class="summary-item"><strong>Total Issues Found: <span class="count">$($Data.InactiveUsers.Count + $Data.DisabledAccounts.Count + $Data.EmptyGroups.Count + $Data.StaleComputers.Count + $Data.PasswordIssues.Count + $Data.NoEmailAccounts.Count)</span></strong></div>
    </div>
"@

    # Inactive Users Section
    if ($Data.InactiveUsers.Count -gt 0) {
        $html += @"
    <div class="section">
        <h2>Inactive User Accounts ($($Data.InactiveUsers.Count))</h2>
        <p>Users who haven't logged in for more than $InactiveDays days.</p>
        <table>
            <tr>
                <th>Username</th>
                <th>Name</th>
                <th>Email</th>
                <th>Department</th>
                <th>Last Logon</th>
                <th>Days Inactive</th>
            </tr>
"@
        foreach ($user in $Data.InactiveUsers) {
            $html += "<tr><td>$($user.Username)</td><td>$($user.Name)</td><td>$($user.EmailAddress)</td><td>$($user.Department)</td><td>$($user.LastLogon)</td><td>$($user.DaysSinceLogon)</td></tr>"
        }
        $html += @"
        </table>
        <div class="recommendation">
            <strong>Recommendation:</strong> Review these accounts with department managers. Consider disabling accounts that are no longer needed. For accounts that haven't logged in for 120+ days, consider moving to a "To Be Deleted" OU.
        </div>
    </div>
"@
    }

    # Disabled Accounts Section
    if ($Data.DisabledAccounts.Count -gt 0) {
        $html += @"
    <div class="section">
        <h2>Disabled Accounts Ready for Archiving ($($Data.DisabledAccounts.Count))</h2>
        <p>Accounts that have been disabled for more than $DisabledAccountDays days.</p>
        <table>
            <tr>
                <th>Username</th>
                <th>Name</th>
                <th>Email</th>
                <th>Department</th>
                <th>Disabled Date</th>
                <th>Days Disabled</th>
            </tr>
"@
        foreach ($account in $Data.DisabledAccounts) {
            $html += "<tr><td>$($account.Username)</td><td>$($account.Name)</td><td>$($account.EmailAddress)</td><td>$($account.Department)</td><td>$($account.DisabledDate)</td><td>$($account.DaysSinceDisabled)</td></tr>"
        }
        $html += @"
        </table>
        <div class="recommendation">
            <strong>Recommendation:</strong> Move these accounts to an Archive OU or delete them if they're no longer needed. Ensure mailbox data has been backed up before deletion.
        </div>
    </div>
"@
    }

    # Empty Groups Section
    if ($Data.EmptyGroups.Count -gt 0) {
        $html += @"
    <div class="section">
        <h2>Empty Security Groups ($($Data.EmptyGroups.Count))</h2>
        <p>Security groups with no members.</p>
        <table>
            <tr>
                <th>Group Name</th>
                <th>Description</th>
                <th>Created Date</th>
                <th>Days Since Creation</th>
            </tr>
"@
        foreach ($group in $Data.EmptyGroups) {
            $html += "<tr><td>$($group.GroupName)</td><td>$($group.Description)</td><td>$($group.CreatedDate)</td><td>$($group.DaysSinceCreation)</td></tr>"
        }
        $html += @"
        </table>
        <div class="recommendation">
            <strong>Recommendation:</strong> Review the purpose of these groups. If no longer needed, delete them. If they're placeholder groups for future use, document their purpose in the Description field.
        </div>
    </div>
"@
    }

    # Stale Computers Section
    if ($Data.StaleComputers.Count -gt 0) {
        $html += @"
    <div class="section">
        <h2>Stale Computer Accounts ($($Data.StaleComputers.Count))</h2>
        <p>Computer accounts that haven't connected for more than $StaleComputerDays days.</p>
        <table>
            <tr>
                <th>Computer Name</th>
                <th>Operating System</th>
                <th>Description</th>
                <th>Last Logon</th>
                <th>Days Inactive</th>
            </tr>
"@
        foreach ($computer in $Data.StaleComputers) {
            $html += "<tr><td>$($computer.ComputerName)</td><td>$($computer.OperatingSystem)</td><td>$($computer.Description)</td><td>$($computer.LastLogon)</td><td>$($computer.DaysSinceLogon)</td></tr>"
        }
        $html += @"
        </table>
        <div class="recommendation">
            <strong>Recommendation:</strong> Verify these computers are decommissioned or offline. Disable accounts for computers that are no longer in use. Delete accounts for computers that have been permanently removed.
        </div>
    </div>
"@
    }

    # Password Issues Section
    if ($Data.PasswordIssues.Count -gt 0) {
        $html += @"
    <div class="section">
        <h2>Password Policy Issues ($($Data.PasswordIssues.Count))</h2>
        <p>Accounts with password-related concerns.</p>
        <table>
            <tr>
                <th>Username</th>
                <th>Name</th>
                <th>Issues</th>
                <th>Password Last Set</th>
            </tr>
"@
        foreach ($issue in $Data.PasswordIssues) {
            $html += "<tr><td>$($issue.Username)</td><td>$($issue.Name)</td><td>$($issue.Issues)</td><td>$($issue.PasswordLastSet)</td></tr>"
        }
        $html += @"
        </table>
        <div class="recommendation">
            <strong>Recommendation:</strong> Review accounts with "Password Never Expires" - this should only be set for service accounts. Force password resets for accounts with old passwords.
        </div>
    </div>
"@
    }

    # No Email Section
    if ($Data.NoEmailAccounts.Count -gt 0) {
        $html += @"
    <div class="section">
        <h2>Accounts Without Email Addresses ($($Data.NoEmailAccounts.Count))</h2>
        <p>Active user accounts missing email addresses.</p>
        <table>
            <tr>
                <th>Username</th>
                <th>Name</th>
                <th>Department</th>
                <th>Title</th>
            </tr>
"@
        foreach ($account in $Data.NoEmailAccounts) {
            $html += "<tr><td>$($account.Username)</td><td>$($account.Name)</td><td>$($account.Department)</td><td>$($account.Title)</td></tr>"
        }
        $html += @"
        </table>
        <div class="recommendation">
            <strong>Recommendation:</strong> Update user accounts with correct email addresses. If these are service accounts, consider moving them to a dedicated OU.
        </div>
    </div>
"@
    }

    $html += @"
    <div class="timestamp">
        Report generated by AD Cleanup Tool
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Log "HTML report generated: $OutputPath" -Level Success
}

# Function to export to CSV
function Export-ToCSV {
    param(
        [hashtable]$Data,
        [string]$BasePath
    )
    
    if ($Data.InactiveUsers.Count -gt 0) {
        $csvPath = Join-Path $BasePath "InactiveUsers_$(Get-Date -Format 'yyyyMMdd').csv"
        $Data.InactiveUsers | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Log "Exported inactive users to: $csvPath" -Level Success
    }
    
    if ($Data.DisabledAccounts.Count -gt 0) {
        $csvPath = Join-Path $BasePath "DisabledAccounts_$(Get-Date -Format 'yyyyMMdd').csv"
        $Data.DisabledAccounts | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Log "Exported disabled accounts to: $csvPath" -Level Success
    }
    
    if ($Data.EmptyGroups.Count -gt 0) {
        $csvPath = Join-Path $BasePath "EmptyGroups_$(Get-Date -Format 'yyyyMMdd').csv"
        $Data.EmptyGroups | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Log "Exported empty groups to: $csvPath" -Level Success
    }
    
    if ($Data.StaleComputers.Count -gt 0) {
        $csvPath = Join-Path $BasePath "StaleComputers_$(Get-Date -Format 'yyyyMMdd').csv"
        $Data.StaleComputers | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Log "Exported stale computers to: $csvPath" -Level Success
    }
    
    if ($Data.PasswordIssues.Count -gt 0) {
        $csvPath = Join-Path $BasePath "PasswordIssues_$(Get-Date -Format 'yyyyMMdd').csv"
        $Data.PasswordIssues | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Log "Exported password issues to: $csvPath" -Level Success
    }
    
    if ($Data.NoEmailAccounts.Count -gt 0) {
        $csvPath = Join-Path $BasePath "NoEmailAccounts_$(Get-Date -Format 'yyyyMMdd').csv"
        $Data.NoEmailAccounts | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Log "Exported accounts without email to: $csvPath" -Level Success
    }
}

# Function to take cleanup actions
function Invoke-CleanupActions {
    param(
        [hashtable]$Data
    )
    
    $actionsLog = @()
    
    # Disable inactive users
    if ($Data.InactiveUsers.Count -gt 0 -and $TakeAction) {
        Write-Log "Processing inactive users for action..." -Level Info
        
        foreach ($user in $Data.InactiveUsers) {
            if ($PSCmdlet.ShouldProcess($user.Username, "Disable inactive user account")) {
                try {
                    Disable-ADAccount -Identity $user.Username -ErrorAction Stop
                    $actionsLog += "Disabled user: $($user.Username)"
                    Write-Log "Disabled user: $($user.Username)" -Level Success
                }
                catch {
                    Write-Log "Failed to disable $($user.Username): $_" -Level Error
                }
            }
        }
    }
    
    # Move disabled accounts to archive
    if ($Data.DisabledAccounts.Count -gt 0 -and $TakeAction) {
        Write-Log "Processing disabled accounts for archiving..." -Level Info
        
        # Verify archive OU exists
        try {
            Get-ADOrganizationalUnit -Identity $ArchiveOU -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Log "Archive OU does not exist: $ArchiveOU" -Level Error
            Write-Log "Skipping archive operations" -Level Warning
            return $actionsLog
        }
        
        foreach ($account in $Data.DisabledAccounts) {
            if ($PSCmdlet.ShouldProcess($account.Username, "Move to archive OU")) {
                try {
                    Move-ADObject -Identity $account.DistinguishedName -TargetPath $ArchiveOU -ErrorAction Stop
                    $actionsLog += "Archived user: $($account.Username)"
                    Write-Log "Moved $($account.Username) to archive OU" -Level Success
                }
                catch {
                    Write-Log "Failed to move $($account.Username): $_" -Level Error
                }
            }
        }
    }
    
    return $actionsLog
}

# Main script execution
try {
    # Create log directory if it doesn't exist
    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    
    Write-Log "===== AD Cleanup Tool Started =====" -Level Info
    Write-Log "Inactive Days Threshold: $InactiveDays" -Level Info
    Write-Log "Stale Computer Days Threshold: $StaleComputerDays" -Level Info
    Write-Log "Disabled Account Days Threshold: $DisabledAccountDays" -Level Info
    
    if ($TakeAction) {
        Write-Log "ACTION MODE: Changes will be made to AD" -Level Warning
    }
    else {
        Write-Log "REPORT MODE: No changes will be made" -Level Info
    }
    
    # Collect all data
    $reportData = @{
        InactiveUsers = Find-InactiveUsers -Days $InactiveDays -ExcludedOUs $ExcludedOUs
        DisabledAccounts = Find-DisabledAccounts -Days $DisabledAccountDays -ExcludedOUs $ExcludedOUs
        EmptyGroups = Find-EmptyGroups
        StaleComputers = Find-StaleComputers -Days $StaleComputerDays
        PasswordIssues = Find-PasswordIssues
        NoEmailAccounts = Find-AccountsWithoutEmail
    }
    
    # Calculate totals
    $totalIssues = $reportData.InactiveUsers.Count + $reportData.DisabledAccounts.Count + 
                   $reportData.EmptyGroups.Count + $reportData.StaleComputers.Count + 
                   $reportData.PasswordIssues.Count + $reportData.NoEmailAccounts.Count
    
    Write-Log "===== Audit Results =====" -Level Info
    Write-Log "Total Issues Found: $totalIssues" -Level $(if ($totalIssues -gt 0) { 'Warning' } else { 'Success' })
    
    # Generate reports
    $reportPath = Join-Path $LogPath "ADCleanupReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    New-HTMLReport -Data $reportData -OutputPath $reportPath
    
    # Export to CSV
    Export-ToCSV -Data $reportData -BasePath $LogPath
    
    # Take actions if enabled
    if ($TakeAction) {
        $actions = Invoke-CleanupActions -Data $reportData
        Write-Log "Actions taken: $($actions.Count)" -Level Success
        $actions | ForEach-Object { Write-Log $_ -Level Success }
    }
    
    Write-Log "===== AD Cleanup Tool Completed =====" -Level Success
    Write-Log "Report saved to: $reportPath" -Level Info
}
catch {
    Write-Log "Critical error in main script: $_" -Level Error
    exit 1
}
