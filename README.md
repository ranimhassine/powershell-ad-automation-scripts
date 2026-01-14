# PowerShell Automation Projects - Interview Preparation
## Three Complete Active Directory Automation Scripts

This package contains three professional PowerShell scripts designed to help you prepare for your automation interview and demonstrate your skills in a real Active Directory environment.

---

## Table of Contents
1. [Project 1: User Onboarding Automation](#project-1-user-onboarding-automation)
2. [Project 2: System Health Monitor](#project-2-system-health-monitor)
3. [Project 3: AD Cleanup Tool](#project-3-ad-cleanup-tool)
4. [Prerequisites](#prerequisites)
5. [Setup Instructions](#setup-instructions)
6. [Best Practices](#best-practices)
7. [Interview Tips](#interview-tips)

---

## Project 1: User Onboarding Automation

### Overview
Automates the complete process of creating new user accounts in Active Directory, including:
- Creating AD accounts with proper configuration
- Setting temporary passwords with forced change at first login
- Creating home directories with proper permissions
- Adding users to department groups
- Setting manager relationships
- Sending welcome emails with credentials
- Comprehensive logging

### Features Demonstrated
✅ CSV file handling (Import-Csv)
✅ Error handling (Try-Catch blocks)
✅ Parameter validation
✅ Password generation and security
✅ NTFS permission management
✅ Email automation (Send-MailMessage)
✅ Logging functionality
✅ Statistics and reporting
✅ WhatIf support for safe testing

### Usage

#### Basic Usage
```powershell
.\Project1-UserOnboarding.ps1 -CsvPath "C:\NewUsers.csv"
```
<img width="987" height="128" alt="Pasted image 20260114144852" src="https://github.com/user-attachments/assets/b700f275-7e9a-4377-9c7b-224dc3c3a0a8" />
<img width="600" height="79" alt="Pasted image 20260114150439" src="https://github.com/user-attachments/assets/2f81871d-a18a-41c3-b5b2-b0029abc0ce0" />


#### Test Mode (Shows what would happen)
```powershell
.\Project1-UserOnboarding.ps1 -CsvPath "C:\NewUsers.csv" -WhatIf
```

#### Custom Configuration
```powershell
.\Project1-UserOnboarding.ps1 `
    -CsvPath "C:\NewUsers.csv" `
    -LogPath "C:\Logs\UserOnboarding" `
    -UsersOU "OU=Employees,DC=domain,DC=com" `
    -HomeDirectoryRoot "\\fileserver\home$" `
    -SMTPServer "mail.domain.com" `
    -EmailFrom "hr@domain.com"
```

### CSV File Format
Create a CSV file with the following columns:
```csv
FirstName,LastName,Username,Email,Department,Title,Manager
John,Doe,jdoe,jdoe@domain.com,IT,Systems Administrator,jsmith
Jane,Smith,jsmith,jsmith@domain.com,IT,IT Manager,
```
<img width="974" height="184" alt="Pasted image 20260114150646" src="https://github.com/user-attachments/assets/99faa5b1-c0e0-467e-a7eb-89c4c8378376" />


**Note:** A sample CSV file (`sample-users.csv`) is included.

### Before Running
1. Update the script parameters for your environment:
   - Domain name
   - Users OU path
   - Home directory path
   - SMTP server
   - Email addresses

2. Create department groups in AD (e.g., "IT-Users", "Sales-Users")

3. Test with `-WhatIf` first!

### Output
- Log file: `C:\Logs\UserOnboarding\UserOnboarding_YYYYMMDD.log`
- Statistics summary at the end
- Email confirmation to each new user

---
<img width="634" height="257" alt="Pasted image 20260114150556" src="https://github.com/user-attachments/assets/6de1c57b-613a-4b7c-bd65-e3aa21d409d4" />


## Project 2: System Health Monitor

### Overview
Comprehensive monitoring solution that checks all computers in your Active Directory environment for:
- Disk space usage with configurable thresholds
- Critical service status
- Event log errors (last 24 hours)
- Network connectivity
- CPU and memory usage
- System uptime

Generates a beautiful HTML report and can send email alerts.

### Features Demonstrated
✅ Remote system monitoring (Get-WmiObject)
✅ Multiple data collection methods
✅ HTML report generation with CSS styling
✅ Email notifications
✅ Performance metric collection
✅ Event log analysis
✅ Service monitoring
✅ Parallel processing considerations
✅ Professional reporting

### Usage

#### Basic Usage
```powershell
.\Project2-SystemHealthMonitor.ps1
```
<img width="922" height="372" alt="Pasted image 20260114153033" src="https://github.com/user-attachments/assets/b5ef3d7d-4e9b-48d7-a7c7-0131711de054" />

#### With Email Alerts
```powershell
.\Project2-SystemHealthMonitor.ps1 `
    -SendEmail `
    -EmailTo "admin@domain.com" `
    -SMTPServer "mail.domain.com"
```

#### Custom Configuration
```powershell
.\Project2-SystemHealthMonitor.ps1 `
    -LogPath "C:\Reports\SystemHealth" `
    -DiskSpaceThreshold 10 `
    -SendEmail `
    -EmailTo "it-team@domain.com" `
    -CriticalServices @('Spooler', 'W32Time', 'Winmgmt', 'NTDS', 'DNS') `
    -EventLogHours 48
```

### Configurable Parameters
- **DiskSpaceThreshold**: % of free space that triggers warning (default: 15%)
- **CriticalServices**: Array of service names to monitor
- **EventLogHours**: Number of hours to check in event logs (default: 24)
- **EmailTo**: Recipient for alert emails
- **SMTPServer**: Your mail server

### Output
- HTML Report: `C:\Logs\SystemHealth\SystemHealthReport_YYYYMMDD_HHMMSS.html`
- Log file: `C:\Logs\SystemHealth\SystemHealth_YYYYMMDD.log`
- Email alert (if enabled and issues found)

### Scheduling
Schedule this script to run daily using Task Scheduler:

```powershell
# Create scheduled task
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -File C:\Scripts\Project2-SystemHealthMonitor.ps1 -SendEmail -EmailTo admin@domain.com"

$trigger = New-ScheduledTaskTrigger -Daily -At 6:00AM

$principal = New-ScheduledTaskPrincipal -UserId "DOMAIN\ServiceAccount" -LogonType Password

Register-ScheduledTask -TaskName "Daily System Health Check" `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Description "Monitors system health across all AD computers"
```

---

## Project 3: AD Cleanup Tool

### Overview
Comprehensive Active Directory auditing and cleanup tool that identifies:
- Inactive user accounts (no login for X days)
- Disabled accounts ready for archiving
- Empty security groups
- Stale computer accounts
- Password policy violations
- Accounts missing email addresses

Generates detailed reports and can optionally take action on findings.

### Features Demonstrated
✅ Advanced AD queries with filters
✅ Date calculations and comparisons
✅ Multiple report types (HTML + CSV)
✅ Safe testing with -WhatIf parameter
✅ Conditional action execution
✅ OU exclusion logic
✅ Comprehensive HTML reporting
✅ Data export to CSV
✅ Automated remediation options

### Usage

#### Audit Mode (Read-Only)
```powershell
.\Project3-ADCleanup.ps1 -InactiveDays 90
```
<img width="955" height="455" alt="Pasted image 20260114162851" src="https://github.com/user-attachments/assets/841afef3-8fe8-4a37-acd2-0bde0719c52c" />

#### Test Actions (See what would happen)
```powershell
.\Project3-ADCleanup.ps1 `
    -InactiveDays 90 `
    -TakeAction `
    -ArchiveOU "OU=Archived,DC=domain,DC=com" `
    -WhatIf
```

#### Execute Actions (Make actual changes)
```powershell
.\Project3-ADCleanup.ps1 `
    -InactiveDays 90 `
    -StaleComputerDays 120 `
    -DisabledAccountDays 180 `
    -TakeAction `
    -ArchiveOU "OU=Archived,DC=domain,DC=com" `
    -ExcludedOUs @("OU=Service Accounts,DC=domain,DC=com", "OU=Test,DC=domain,DC=com")
```

### Configurable Parameters
- **InactiveDays**: Days of inactivity to flag users (default: 90)
- **StaleComputerDays**: Days for computers to be considered stale (default: 90)
- **DisabledAccountDays**: Days before disabled accounts are archived (default: 180)
- **TakeAction**: Enable automatic actions
- **ArchiveOU**: Where to move disabled accounts
- **ExcludedOUs**: OUs to skip during processing

### Actions Taken (when -TakeAction is enabled)
1. **Inactive Users**: Disables accounts
2. **Disabled Accounts**: Moves to archive OU
3. **Other findings**: Report only (manual review required)

### Output
- HTML Report: `C:\Logs\ADCleanup\ADCleanupReport_YYYYMMDD_HHMMSS.html`
- CSV Exports (one per category):
  - InactiveUsers_YYYYMMDD.csv
  - DisabledAccounts_YYYYMMDD.csv
  - EmptyGroups_YYYYMMDD.csv
  - StaleComputers_YYYYMMDD.csv
  - PasswordIssues_YYYYMMDD.csv
  - NoEmailAccounts_YYYYMMDD.csv
- Log file: `C:\Logs\ADCleanup\ADCleanup_YYYYMMDD.log`

### Safety Features
- **WhatIf Support**: Test before executing
- **OU Exclusions**: Protect service accounts and special OUs
- **Detailed Logging**: Track all actions
- **CSV Export**: Review findings before taking action
- **Configurable Thresholds**: Adjust to your environment

---

## Prerequisites

### Required Modules
```powershell
# Check if Active Directory module is available
Get-Module -ListAvailable -Name ActiveDirectory

# If not installed, add RSAT tools:
# Windows 10/11: Settings > Apps > Optional Features > RSAT: Active Directory DS Tools
# Windows Server: Install-WindowsFeature -Name RSAT-AD-PowerShell
```

### Required Permissions
- **Project 1**: User creation rights, group membership management
- **Project 2**: Read access to all computers, WMI query rights
- **Project 3**: Read access to AD, optional write access for actions

### Environment Requirements
- PowerShell 5.1 or higher
- Active Directory environment
- Network connectivity to target computers
- SMTP server (for email functionality)

---

## Setup Instructions

### 1. Initial Setup
```powershell
# Create directory structure
New-Item -Path "C:\Scripts" -ItemType Directory -Force
New-Item -Path "C:\Logs" -ItemType Directory -Force

# Copy scripts to C:\Scripts
Copy-Item "*.ps1" -Destination "C:\Scripts"
```

### 2. Configure Your Environment
Edit each script and update these variables for your domain:
- Domain name
- OU paths
- SMTP server
- Email addresses
- File share paths

### 3. Create Test OU
```powershell
# Create a test OU for safe testing
New-ADOrganizationalUnit -Name "TestUsers" -Path "DC=domain,DC=com"
New-ADOrganizationalUnit -Name "TestComputers" -Path "DC=domain,DC=com"
New-ADOrganizationalUnit -Name "Archived" -Path "DC=domain,DC=com"
```

### 4. Test Each Script
```powershell
# Test Project 1 with sample CSV
.\Project1-UserOnboarding.ps1 -CsvPath ".\sample-users.csv" -WhatIf

# Test Project 2 (read-only, safe)
.\Project2-SystemHealthMonitor.ps1

# Test Project 3 (read-only, safe)
.\Project3-ADCleanup.ps1
```

---

## Best Practices

### When Testing
1. **Always use -WhatIf first** to see what would happen
2. **Test in a non-production OU** before running against real users
3. **Start with small datasets** (1-2 test accounts)
4. **Review logs carefully** after each run
5. **Have a backup plan** before making bulk changes

### For Production Use
1. **Schedule monitoring scripts** to run automatically
2. **Archive logs regularly** but keep at least 90 days
3. **Review reports weekly** to catch issues early
4. **Document all changes** in change management system
5. **Test after AD schema changes** or updates

### Security Considerations
1. **Never store passwords in scripts** - use secure methods
2. **Use service accounts** with minimal required permissions
3. **Encrypt sensitive data** in transit and at rest
4. **Audit script execution** for compliance
5. **Review logs** for unauthorized changes

---

## Interview Tips

### Topics to Discuss
When presenting these scripts in your interview, be prepared to discuss:

1. **Error Handling**
   - How you use Try-Catch blocks
   - Recovery strategies for failures
   - Logging all errors

2. **Security**
   - How you handle credentials
   - Why you use SecureString
   - Permission management

3. **Scalability**
   - How scripts handle large environments
   - Performance optimization techniques
   - Parallel processing considerations

4. **Maintainability**
   - Why you use functions
   - Parameter validation
   - Code organization

5. **Logging & Auditing**
   - Log file structure
   - Retention policies
   - What gets logged and why

### Demo Scenarios
Practice these demonstrations:

1. **Project 1**: Show onboarding 5 users from CSV
2. **Project 2**: Run health check and explain the HTML report
3. **Project 3**: Run audit and walk through findings

### Questions You Might Get
- "How would you handle 1000 users instead of 10?"
- "What if the email server is down?"
- "How do you ensure the script doesn't disable critical accounts?"
- "What would you add to make this production-ready?"
- "How would you automate this to run daily?"

### Improvements to Mention
Show you're thinking ahead:
- Add parallel processing for faster execution
- Implement database logging
- Create a web dashboard
- Add approval workflows
- Integrate with ticketing system
- Add Microsoft Teams notifications
- Implement configuration files
- Add retry logic for transient failures

---

## Troubleshooting

### Common Issues

**Issue**: "Access Denied" errors
**Solution**: Ensure you have proper AD permissions and run as administrator

**Issue**: "Cannot find path" errors
**Solution**: Create required directories, update paths in scripts

**Issue**: "Module not found"
**Solution**: Install RSAT tools and import ActiveDirectory module

**Issue**: Email not sending
**Solution**: Verify SMTP server, check firewall, test with telnet

**Issue**: Scripts run slow on large domains
**Solution**: Add filtering, use specific OUs instead of whole domain

---

## Additional Resources

### PowerShell Learning
- Microsoft Learn: PowerShell Documentation
- PowerShell Gallery: Community modules
- Reddit: r/PowerShell community

### Active Directory
- Active Directory cmdlets reference
- AD best practices guide
- Group Policy management

### Testing
- Pester: PowerShell testing framework
- PSScriptAnalyzer: Code quality tool

---

## License and Usage

These scripts are provided for educational and interview preparation purposes. 
Test thoroughly in a lab environment before using in production.

**Author**: Your Name
**Date**: 2026-01-14
**Version**: 1.0

---

## Next Steps

1. ✅ Read through all three scripts
2. ✅ Update configuration values for your environment
3. ✅ Test each script with -WhatIf
4. ✅ Run in test OU with sample data
5. ✅ Review logs and reports
6. ✅ Document your testing process
7. ✅ Prepare talking points for interview
8. ✅ Practice explaining the code

Good luck with your interview! 🚀
