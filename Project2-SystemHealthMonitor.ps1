<#
.SYNOPSIS
    System Health Monitoring Script for Active Directory Environment

.DESCRIPTION
    This script monitors the health of all computers in Active Directory by checking:
    - Disk space usage
    - Critical services status
    - Event log errors
    - Network connectivity
    - CPU and memory usage
    Generates an HTML report and sends email alerts if issues are found.

.PARAMETER LogPath
    Path where log files and reports will be saved

.PARAMETER DiskSpaceThreshold
    Percentage of free disk space that triggers a warning (default: 15%)

.PARAMETER SendEmail
    Switch to enable email notifications

.PARAMETER EmailTo
    Email address to send the report to

.PARAMETER SMTPServer
    SMTP server for sending emails

.EXAMPLE
    .\Project2-SystemHealthMonitor.ps1 -SendEmail -EmailTo "admin@M365x99325588.onmicrosoft.com"

.NOTES
    Author: Ranim Hassine
    Date: 2026-01-14
    
    Schedule this script to run daily using Task Scheduler:
    Action: powershell.exe
    Arguments: -ExecutionPolicy Bypass -File "C:\Scripts\Project2-SystemHealthMonitor.ps1"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\Logs\SystemHealth",
    
    [Parameter(Mandatory=$false)]
    [int]$DiskSpaceThreshold = 15,
    
    [Parameter(Mandatory=$false)]
    [switch]$SendEmail,
    
    [Parameter(Mandatory=$false)]
    [string]$EmailTo = "admin@M365x99325588.onmicrosoft.com",
    
    [Parameter(Mandatory=$false)]
    [string]$EmailFrom = "systemhealth@domain.com",
    
    [Parameter(Mandatory=$false)]
    [string]$SMTPServer = "smtp.Domain.local",
    
    [Parameter(Mandatory=$false)]
    [string[]]$CriticalServices = @('Spooler', 'W32Time', 'Winmgmt', 'NTDS'),
    
    [Parameter(Mandatory=$false)]
    [int]$EventLogHours = 24
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
    
    $logFile = Join-Path $LogPath "SystemHealth_$(Get-Date -Format 'yyyyMMdd').log"
    $logMessage | Out-File -FilePath $logFile -Append
}

# Function to check disk space
function Test-DiskSpace {
    param(
        [string]$ComputerName,
        [int]$Threshold
    )
    
    $diskInfo = @()
    
    try {
        $disks = Get-WmiObject Win32_LogicalDisk -ComputerName $ComputerName -Filter "DriveType=3" -ErrorAction Stop
        
        foreach ($disk in $disks) {
            $freeSpacePercent = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)
            $freeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
            $totalSpaceGB = [math]::Round($disk.Size / 1GB, 2)
            
            $status = if ($freeSpacePercent -lt $Threshold) { "Critical" } 
                      elseif ($freeSpacePercent -lt ($Threshold + 10)) { "Warning" } 
                      else { "OK" }
            
            $diskInfo += [PSCustomObject]@{
                Drive = $disk.DeviceID
                TotalGB = $totalSpaceGB
                FreeGB = $freeSpaceGB
                FreePercent = $freeSpacePercent
                Status = $status
            }
        }
        
        return $diskInfo
    }
    catch {
        Write-Log "Failed to check disk space on $ComputerName : $_" -Level Error
        return $null
    }
}

# Function to check services
function Test-Services {
    param(
        [string]$ComputerName,
        [string[]]$ServiceNames
    )
    
    $serviceInfo = @()
    
    try {
        foreach ($serviceName in $ServiceNames) {
            $service = Get-Service -Name $serviceName -ComputerName $ComputerName -ErrorAction SilentlyContinue
            
            if ($service) {
                $status = if ($service.Status -eq 'Running') { "OK" } else { "Critical" }
                
                $serviceInfo += [PSCustomObject]@{
                    ServiceName = $service.Name
                    DisplayName = $service.DisplayName
                    Status = $service.Status
                    StartType = $service.StartType
                    HealthStatus = $status
                }
            }
            else {
                $serviceInfo += [PSCustomObject]@{
                    ServiceName = $serviceName
                    DisplayName = "Not Found"
                    Status = "N/A"
                    StartType = "N/A"
                    HealthStatus = "Warning"
                }
            }
        }
        
        return $serviceInfo
    }
    catch {
        Write-Log "Failed to check services on $ComputerName : $_" -Level Error
        return $null
    }
}

# Function to check event logs
function Test-EventLogs {
    param(
        [string]$ComputerName,
        [int]$Hours
    )
    
    $eventInfo = @{
        Errors = 0
        Warnings = 0
        CriticalErrors = @()
    }
    
    try {
        $startTime = (Get-Date).AddHours(-$Hours)
        
        # Check System log
        $systemErrors = Get-EventLog -LogName System -ComputerName $ComputerName -EntryType Error -After $startTime -ErrorAction SilentlyContinue
        $eventInfo.Errors += $systemErrors.Count
        
        # Check Application log
        $appErrors = Get-EventLog -LogName Application -ComputerName $ComputerName -EntryType Error -After $startTime -ErrorAction SilentlyContinue
        $eventInfo.Errors += $appErrors.Count
        
        # Get top 5 critical errors
        $allErrors = $systemErrors + $appErrors | Sort-Object TimeGenerated -Descending | Select-Object -First 5
        
        foreach ($error in $allErrors) {
            $eventInfo.CriticalErrors += [PSCustomObject]@{
                TimeGenerated = $error.TimeGenerated
                Source = $error.Source
                EventID = $error.EventID
                Message = $error.Message.Substring(0, [Math]::Min(150, $error.Message.Length)) + "..."
            }
        }
        
        return $eventInfo
    }
    catch {
        Write-Log "Failed to check event logs on $ComputerName : $_" -Level Error
        return $null
    }
}

# Function to test connectivity
function Test-ComputerConnectivity {
    param(
        [string]$ComputerName
    )
    
    $result = Test-Connection -ComputerName $ComputerName -Count 2 -Quiet
    return $result
}

# Function to get system performance
function Get-SystemPerformance {
    param(
        [string]$ComputerName
    )
    
    try {
        $cpu = Get-WmiObject Win32_Processor -ComputerName $ComputerName -ErrorAction Stop | 
               Measure-Object -Property LoadPercentage -Average | 
               Select-Object -ExpandProperty Average
        
        $os = Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop
        $memoryUsedPercent = [math]::Round((($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize) * 100, 2)
        
        return [PSCustomObject]@{
            CPUUsage = [math]::Round($cpu, 2)
            MemoryUsedPercent = $memoryUsedPercent
            UptimeDays = [math]::Round(((Get-Date) - $os.ConvertToDateTime($os.LastBootUpTime)).TotalDays, 2)
        }
    }
    catch {
        Write-Log "Failed to get performance data from $ComputerName : $_" -Level Error
        return $null
    }
}

# Function to generate HTML report
function New-HTMLReport {
    param(
        [array]$Results,
        [string]$OutputPath
    )
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>System Health Report - $(Get-Date -Format 'yyyy-MM-dd')</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1 { color: #2c3e50; text-align: center; }
        h2 { color: #34495e; border-bottom: 2px solid #3498db; padding-bottom: 5px; }
        .summary { background-color: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .computer-section { background-color: white; padding: 15px; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        table { border-collapse: collapse; width: 100%; margin-bottom: 15px; }
        th { background-color: #3498db; color: white; padding: 10px; text-align: left; }
        td { padding: 8px; border-bottom: 1px solid #ddd; }
        tr:hover { background-color: #f5f5f5; }
        .status-ok { color: #27ae60; font-weight: bold; }
        .status-warning { color: #f39c12; font-weight: bold; }
        .status-critical { color: #e74c3c; font-weight: bold; }
        .timestamp { text-align: center; color: #7f8c8d; margin-top: 20px; }
        .offline { background-color: #ffebee; }
    </style>
</head>
<body>
    <h1>System Health Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Report Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p><strong>Total Computers:</strong> $($Results.Count)</p>
        <p><strong>Online:</strong> $($Results | Where-Object {$_.Online} | Measure-Object | Select-Object -ExpandProperty Count)</p>
        <p><strong>Offline:</strong> $($Results | Where-Object {-not $_.Online} | Measure-Object | Select-Object -ExpandProperty Count)</p>
        <p><strong>Issues Found:</strong> $($Results | Where-Object {$_.IssuesFound} | Measure-Object | Select-Object -ExpandProperty Count)</p>
    </div>
"@

    foreach ($computer in $Results) {
        $cssClass = if (-not $computer.Online) { "offline" } else { "" }
        
        $html += @"
    <div class="computer-section $cssClass">
        <h2>$($computer.ComputerName)</h2>
"@
        
        if (-not $computer.Online) {
            $html += "<p class='status-critical'>OFFLINE - Unable to connect to this computer</p>"
        }
        else {
            # Performance Section
            if ($computer.Performance) {
                $html += @"
        <h3>Performance</h3>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>CPU Usage</td><td>$($computer.Performance.CPUUsage)%</td></tr>
            <tr><td>Memory Usage</td><td>$($computer.Performance.MemoryUsedPercent)%</td></tr>
            <tr><td>Uptime (Days)</td><td>$($computer.Performance.UptimeDays)</td></tr>
        </table>
"@
            }
            
            # Disk Space Section
            if ($computer.DiskSpace) {
                $html += @"
        <h3>Disk Space</h3>
        <table>
            <tr><th>Drive</th><th>Total (GB)</th><th>Free (GB)</th><th>Free %</th><th>Status</th></tr>
"@
                foreach ($disk in $computer.DiskSpace) {
                    $statusClass = switch ($disk.Status) {
                        'OK' { 'status-ok' }
                        'Warning' { 'status-warning' }
                        'Critical' { 'status-critical' }
                    }
                    $html += "<tr><td>$($disk.Drive)</td><td>$($disk.TotalGB)</td><td>$($disk.FreeGB)</td><td>$($disk.FreePercent)%</td><td class='$statusClass'>$($disk.Status)</td></tr>"
                }
                $html += "</table>"
            }
            
            # Services Section
            if ($computer.Services) {
                $html += @"
        <h3>Critical Services</h3>
        <table>
            <tr><th>Service</th><th>Display Name</th><th>Status</th><th>Health</th></tr>
"@
                foreach ($service in $computer.Services) {
                    $statusClass = if ($service.HealthStatus -eq 'OK') { 'status-ok' } else { 'status-critical' }
                    $html += "<tr><td>$($service.ServiceName)</td><td>$($service.DisplayName)</td><td>$($service.Status)</td><td class='$statusClass'>$($service.HealthStatus)</td></tr>"
                }
                $html += "</table>"
            }
            
            # Event Logs Section
            if ($computer.EventLogs) {
                $html += @"
        <h3>Event Logs (Last $EventLogHours Hours)</h3>
        <p><strong>Total Errors:</strong> $($computer.EventLogs.Errors)</p>
"@
                if ($computer.EventLogs.CriticalErrors.Count -gt 0) {
                    $html += @"
        <table>
            <tr><th>Time</th><th>Source</th><th>Event ID</th><th>Message</th></tr>
"@
                    foreach ($event in $computer.EventLogs.CriticalErrors) {
                        $html += "<tr><td>$($event.TimeGenerated)</td><td>$($event.Source)</td><td>$($event.EventID)</td><td>$($event.Message)</td></tr>"
                    }
                    $html += "</table>"
                }
            }
        }
        
        $html += "</div>"
    }
    
    $html += @"
    <div class="timestamp">
        Report generated by System Health Monitor Script
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Log "HTML report generated: $OutputPath" -Level Success
}

# Main script execution
try {
    # Create log directory if it doesn't exist
    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    
    Write-Log "===== System Health Monitor Started =====" -Level Info
    
    # Get all computers from AD
    $computers = Get-ADComputer -Filter * -Properties OperatingSystem, LastLogonDate | 
                 Where-Object { $_.Enabled -eq $true } |
                 Select-Object -ExpandProperty Name
    
    Write-Log "Found $($computers.Count) computers in Active Directory" -Level Info
    
    $results = @()
    $issueCount = 0
    
    foreach ($computer in $computers) {
        Write-Log "Checking $computer..." -Level Info
        
        $computerResult = [PSCustomObject]@{
            ComputerName = $computer
            Online = $false
            IssuesFound = $false
            DiskSpace = $null
            Services = $null
            EventLogs = $null
            Performance = $null
        }
        
        # Test connectivity
        if (Test-ComputerConnectivity -ComputerName $computer) {
            $computerResult.Online = $true
            Write-Log "$computer is online" -Level Success
            
            # Get performance data
            $computerResult.Performance = Get-SystemPerformance -ComputerName $computer
            
            # Check disk space
            $diskSpace = Test-DiskSpace -ComputerName $computer -Threshold $DiskSpaceThreshold
            $computerResult.DiskSpace = $diskSpace
            
            if ($diskSpace | Where-Object { $_.Status -ne 'OK' }) {
                $computerResult.IssuesFound = $true
                $issueCount++
                Write-Log "$computer has disk space issues" -Level Warning
            }
            
            # Check services
            $services = Test-Services -ComputerName $computer -ServiceNames $CriticalServices
            $computerResult.Services = $services
            
            if ($services | Where-Object { $_.HealthStatus -ne 'OK' }) {
                $computerResult.IssuesFound = $true
                $issueCount++
                Write-Log "$computer has service issues" -Level Warning
            }
            
            # Check event logs
            $eventLogs = Test-EventLogs -ComputerName $computer -Hours $EventLogHours
            $computerResult.EventLogs = $eventLogs
            
            if ($eventLogs.Errors -gt 50) {
                $computerResult.IssuesFound = $true
                $issueCount++
                Write-Log "$computer has $($eventLogs.Errors) errors in event logs" -Level Warning
            }
        }
        else {
            Write-Log "$computer is offline" -Level Error
            $issueCount++
        }
        
        $results += $computerResult
    }
    
    # Generate HTML report
    $reportPath = Join-Path $LogPath "SystemHealthReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    New-HTMLReport -Results $results -OutputPath $reportPath
    
    # Send email if enabled and issues found
    if ($SendEmail -and $issueCount -gt 0) {
        $subject = "System Health Alert - $issueCount Issues Found"
        $body = @"
System Health Monitoring has detected $issueCount issues across your environment.

Summary:
- Total Computers Checked: $($results.Count)
- Online: $($results | Where-Object {$_.Online} | Measure-Object | Select-Object -ExpandProperty Count)
- Offline: $($results | Where-Object {-not $_.Online} | Measure-Object | Select-Object -ExpandProperty Count)
- Computers with Issues: $($results | Where-Object {$_.IssuesFound} | Measure-Object | Select-Object -ExpandProperty Count)

Please review the attached HTML report for detailed information.

Report Location: $reportPath
"@
        
        try {
            Send-MailMessage -To $EmailTo -From $EmailFrom -Subject $subject -Body $body -SmtpServer $SMTPServer -Attachments $reportPath -ErrorAction Stop
            Write-Log "Alert email sent to $EmailTo" -Level Success
        }
        catch {
            Write-Log "Failed to send email: $_" -Level Error
        }
    }
    
    Write-Log "===== System Health Monitor Completed =====" -Level Info
    Write-Log "Total Issues Found: $issueCount" -Level $(if ($issueCount -gt 0) { 'Warning' } else { 'Success' })
}
catch {
    Write-Log "Critical error in main script: $_" -Level Error
    exit 1
}
