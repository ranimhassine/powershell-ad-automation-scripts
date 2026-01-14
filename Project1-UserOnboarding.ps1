<#
.SYNOPSIS
    Automated User Onboarding Script for Active Directory

.DESCRIPTION
    This script automates the process of creating new user accounts in Active Directory.
    It reads user data from a CSV file, creates AD accounts, sets up home directories,
    assigns group memberships, and sends welcome emails.

.PARAMETER CsvPath
    Path to the CSV file containing user information

.PARAMETER LogPath
    Path where log files will be saved (default: C:\Logs\UserOnboarding)

.PARAMETER WhatIf
    Shows what would happen if the script runs without actually making changes

.EXAMPLE
    .\Project1-UserOnboarding.ps1 -CsvPath "C:\NewUsers.csv"

.NOTES
    Author: Ranim Hassine
    Date: 2026-01-14
    
    CSV Format Required:
    FirstName,LastName,Username,Email,Department,Title,Manager
    John,Doe,jdoe,jdoe@domain.com,IT,Systems Admin,jsmith
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [string]$CsvPath,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\Logs\UserOnboarding",
    
    [Parameter(Mandatory=$false)]
    [string]$Domain = $env:USERDNSDOMAIN,
    
    [Parameter(Mandatory=$false)]
    [string]$UsersOU = "OU=Users,DC=domain,DC=com",
    
    [Parameter(Mandatory=$false)]
    [string]$HomeDirectoryRoot = "\\server\home$",
    
    [Parameter(Mandatory=$false)]
    [string]$SMTPServer = "smtp.domain.com",
    
    [Parameter(Mandatory=$false)]
    [string]$EmailFrom = "it-admin@domain.com"
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
    
    # Color coding for console output
    switch ($Level) {
        'Info'    { Write-Host $logMessage -ForegroundColor Cyan }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
        'Success' { Write-Host $logMessage -ForegroundColor Green }
    }
    
    # Write to log file
    $logFile = Join-Path $LogPath "UserOnboarding_$(Get-Date -Format 'yyyyMMdd').log"
    $logMessage | Out-File -FilePath $logFile -Append
}

# Function to generate random password
function New-RandomPassword {
    param(
        [int]$Length = 12
    )
    
    $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*'
    $password = -join ((1..$Length) | ForEach-Object { $characters[(Get-Random -Maximum $characters.Length)] })
    
    # Ensure password meets complexity requirements
    if ($password -notmatch '[A-Z]') { $password = $password.Replace($password[0], [char](Get-Random -Minimum 65 -Maximum 90)) }
    if ($password -notmatch '[a-z]') { $password = $password.Replace($password[1], [char](Get-Random -Minimum 97 -Maximum 122)) }
    if ($password -notmatch '[0-9]') { $password = $password.Replace($password[2], [char](Get-Random -Minimum 48 -Maximum 57)) }
    if ($password -notmatch '[!@#$%^&*]') { $password = $password.Replace($password[3], '!') }
    
    return $password
}

# Function to send welcome email
function Send-WelcomeEmail {
    param(
        [string]$ToEmail,
        [string]$Username,
        [string]$TempPassword,
        [string]$FirstName
    )
    
    $subject = "Welcome to the Organization - Account Created"
    $body = @"
Dear $FirstName,

Welcome to the organization! Your user account has been created successfully.

Account Details:
Username: $Username
Temporary Password: $TempPassword
Domain: $Domain

IMPORTANT: You will be required to change your password at first login.

To access your account:
1. Press Ctrl+Alt+Delete on any domain computer
2. Click "Sign in"
3. Enter your username and temporary password
4. Follow the prompts to create a new password

Password Requirements:
- Minimum 8 characters
- Must contain uppercase and lowercase letters
- Must contain at least one number
- Must contain at least one special character

If you have any questions or need assistance, please contact the IT Help Desk.

Best regards,
IT Department
"@

    try {
        Send-MailMessage -To $ToEmail -From $EmailFrom -Subject $subject -Body $body -SmtpServer $SMTPServer -ErrorAction Stop
        Write-Log "Welcome email sent to $ToEmail" -Level Success
        return $true
    }
    catch {
        Write-Log "Failed to send email to $ToEmail : $_" -Level Error
        return $false
    }
}

# Function to create home directory
function New-HomeDirectory {
    param(
        [string]$Username,
        [string]$HomeRoot
    )
    
    $homePath = Join-Path $HomeRoot $Username
    
    try {
        if (-not (Test-Path $homePath)) {
            New-Item -Path $homePath -ItemType Directory -Force -ErrorAction Stop | Out-Null
            
            # Set NTFS permissions
            $acl = Get-Acl $homePath
            $permission = "$Domain\$Username","FullControl","ContainerInherit,ObjectInherit","None","Allow"
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
            $acl.SetAccessRule($accessRule)
            Set-Acl -Path $homePath -AclObject $acl
            
            Write-Log "Home directory created: $homePath" -Level Success
            return $homePath
        }
        else {
            Write-Log "Home directory already exists: $homePath" -Level Warning
            return $homePath
        }
    }
    catch {
        Write-Log "Failed to create home directory for $Username : $_" -Level Error
        return $null
    }
}

# Main script execution
try {
    # Create log directory if it doesn't exist
    if (-not (Test-Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    
    Write-Log "===== User Onboarding Script Started =====" -Level Info
    Write-Log "CSV File: $CsvPath" -Level Info
    
    # Verify CSV file exists
    if (-not (Test-Path $CsvPath)) {
        Write-Log "CSV file not found: $CsvPath" -Level Error
        exit 1
    }
    
    # Import user data from CSV
    $users = Import-Csv -Path $CsvPath
    Write-Log "Loaded $($users.Count) users from CSV" -Level Info
    
    # Statistics
    $stats = @{
        Total = $users.Count
        Success = 0
        Failed = 0
        Skipped = 0
    }
    
    # Process each user
    foreach ($user in $users) {
        Write-Log "Processing user: $($user.FirstName) $($user.LastName)" -Level Info
        
        # Validate required fields
        if ([string]::IsNullOrWhiteSpace($user.Username) -or 
            [string]::IsNullOrWhiteSpace($user.Email) -or
            [string]::IsNullOrWhiteSpace($user.FirstName) -or
            [string]::IsNullOrWhiteSpace($user.LastName)) {
            Write-Log "Missing required fields for user, skipping..." -Level Warning
            $stats.Skipped++
            continue
        }
        
        try {
            # Check if user already exists
            $existingUser = Get-ADUser -Filter "SamAccountName -eq '$($user.Username)'" -ErrorAction SilentlyContinue
            if ($existingUser) {
                Write-Log "User $($user.Username) already exists, skipping..." -Level Warning
                $stats.Skipped++
                continue
            }
            
            # Generate temporary password
            $tempPassword = New-RandomPassword
            $securePassword = ConvertTo-SecureString $tempPassword -AsPlainText -Force
            
            # Prepare user properties
            $userParams = @{
                Name = "$($user.FirstName) $($user.LastName)"
                GivenName = $user.FirstName
                Surname = $user.LastName
                SamAccountName = $user.Username
                UserPrincipalName = "$($user.Username)@$Domain"
                EmailAddress = $user.Email
                DisplayName = "$($user.FirstName) $($user.LastName)"
                Description = $user.Title
                Department = $user.Department
                Title = $user.Title
                Path = $UsersOU
                AccountPassword = $securePassword
                Enabled = $true
                ChangePasswordAtLogon = $true
                PasswordNeverExpires = $false
                CannotChangePassword = $false
            }
            
            # Create AD user
            if ($PSCmdlet.ShouldProcess("$($user.Username)", "Create AD User")) {
                New-ADUser @userParams -ErrorAction Stop
                Write-Log "AD account created: $($user.Username)" -Level Success
                
                # Add to groups based on department
                if (-not [string]::IsNullOrWhiteSpace($user.Department)) {
                    $groupName = "$($user.Department)-Users"
                    $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
                    
                    if ($group) {
                        Add-ADGroupMember -Identity $groupName -Members $user.Username -ErrorAction Stop
                        Write-Log "Added to group: $groupName" -Level Success
                    }
                    else {
                        Write-Log "Group not found: $groupName" -Level Warning
                    }
                }
                
                # Set manager if specified
                if (-not [string]::IsNullOrWhiteSpace($user.Manager)) {
                    $manager = Get-ADUser -Filter "SamAccountName -eq '$($user.Manager)'" -ErrorAction SilentlyContinue
                    if ($manager) {
                        Set-ADUser -Identity $user.Username -Manager $manager -ErrorAction Stop
                        Write-Log "Manager set: $($user.Manager)" -Level Success
                    }
                    else {
                        Write-Log "Manager not found: $($user.Manager)" -Level Warning
                    }
                }
                
                # Create home directory
                $homePath = New-HomeDirectory -Username $user.Username -HomeRoot $HomeDirectoryRoot
                if ($homePath) {
                    Set-ADUser -Identity $user.Username -HomeDirectory $homePath -HomeDrive "H:" -ErrorAction Stop
                    Write-Log "Home directory mapped to H: drive" -Level Success
                }
                
                # Send welcome email
                Send-WelcomeEmail -ToEmail $user.Email -Username $user.Username -TempPassword $tempPassword -FirstName $user.FirstName
                
                $stats.Success++
                Write-Log "User onboarding completed: $($user.Username)" -Level Success
            }
        }
        catch {
            Write-Log "Failed to create user $($user.Username) : $_" -Level Error
            $stats.Failed++
        }
        
        Write-Log "---" -Level Info
    }
    
    # Summary report
    Write-Log "===== User Onboarding Script Completed =====" -Level Info
    Write-Log "Total Users: $($stats.Total)" -Level Info
    Write-Log "Successfully Created: $($stats.Success)" -Level Success
    Write-Log "Failed: $($stats.Failed)" -Level Error
    Write-Log "Skipped: $($stats.Skipped)" -Level Warning
}
catch {
    Write-Log "Critical error in main script: $_" -Level Error
    exit 1
}
