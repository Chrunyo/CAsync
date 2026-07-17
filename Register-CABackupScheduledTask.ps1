#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Registers the CA backup script as a Windows Scheduled Task.

.DESCRIPTION
    Creates (or replaces) a scheduled task that runs
    Backup-CertificationAuthority.ps1 on a daily schedule, elevated, using the
    account you specify. The task is configured to run whether or not the user
    is logged on and with highest privileges (required for certutil -backup and
    event-source registration).

.PARAMETER TaskName
    Name of the scheduled task. Default 'Backup Certification Authority'.

.PARAMETER BackupRoot
    Root folder passed to the backup script (a new subfolder is created per run).

.PARAMETER PasswordPath
    Path to the DPAPI-protected PFX password file created by
    New-CABackupCredential.ps1 (generated under the SAME account specified by
    -RunAsUser).

.PARAMETER ScriptPath
    Full path to Backup-CertificationAuthority.ps1. Defaults to the copy next to
    this registration script.

.PARAMETER At
    Time of day to run the daily backup. Default 02:00.

.PARAMETER RunAsUser
    The account the task runs under (e.g. 'DOMAIN\svc-cabackup' or
    'NT AUTHORITY\SYSTEM'). Must have CA backup rights.

.PARAMETER RetentionCount
    Optional retention count forwarded to the backup script (0 = keep all).

.EXAMPLE
    .\Register-CABackupScheduledTask.ps1 -BackupRoot 'D:\CABackups' `
        -PasswordPath 'C:\CABackup\pfx.cred' -RunAsUser 'NT AUTHORITY\SYSTEM' -RetentionCount 30

.NOTES
    For a domain service account you will be prompted for its password (used by
    Windows to store the task credential; it is NOT the PFX password). SYSTEM and
    gMSA accounts do not prompt.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TaskName = 'Backup Certification Authority',

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$BackupRoot,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$PasswordPath,

    [Parameter()]
    [string]$ScriptPath = (Join-Path $PSScriptRoot 'Backup-CertificationAuthority.ps1'),

    [Parameter()]
    [datetime]$At = '02:00',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RunAsUser = 'NT AUTHORITY\SYSTEM',

    [Parameter()]
    [ValidateRange(0, [int]::MaxValue)]
    [int]$RetentionCount = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ScriptPath)) {
    throw "Backup script not found: $ScriptPath"
}
$ScriptPath = (Resolve-Path -LiteralPath $ScriptPath).Path

# Build the PowerShell argument string the task will execute.
$psArgs = @(
    '-NoProfile'
    '-NonInteractive'
    '-ExecutionPolicy', 'Bypass'
    '-File', "`"$ScriptPath`""
    '-BackupRoot', "`"$BackupRoot`""
    '-ExportPrivateKey'
    '-PasswordPath', "`"$PasswordPath`""
)
if ($RetentionCount -gt 0) { $psArgs += @('-RetentionCount', $RetentionCount) }

$action = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') `
    -Argument ($psArgs -join ' ')

$trigger = New-ScheduledTaskTrigger -Daily -At $At

$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
    -DontStopOnIdleEnd -ExecutionTimeLimit (New-TimeSpan -Hours 2) `
    -MultipleInstances IgnoreNew

# Decide logon type / credentials based on the account.
$builtIn = @('NT AUTHORITY\SYSTEM', 'SYSTEM', 'NT AUTHORITY\LOCAL SERVICE', 'NT AUTHORITY\NETWORK SERVICE')
$isGmsa  = $RunAsUser.TrimEnd('$').Length -lt $RunAsUser.Length  # ends with '$'

if ($PSCmdlet.ShouldProcess($TaskName, 'Register scheduled task')) {

    $principalParams = @{ UserId = $RunAsUser; RunLevel = 'Highest' }

    if ($builtIn -contains $RunAsUser.ToUpper() -or $RunAsUser.ToUpper() -eq 'SYSTEM') {
        $principalParams.LogonType = 'ServiceAccount'
        $principal = New-ScheduledTaskPrincipal @principalParams
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
            -Settings $settings -Principal $principal -Force | Out-Null
    }
    elseif ($isGmsa) {
        $principalParams.LogonType = 'Password'  # gMSA: Windows retrieves the password
        $principal = New-ScheduledTaskPrincipal @principalParams
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
            -Settings $settings -Principal $principal -Force | Out-Null
    }
    else {
        # Standard domain/local account: prompt for the logon password.
        $cred = Get-Credential -UserName $RunAsUser -Message "Password for scheduled task account '$RunAsUser'"
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
            -Settings $settings -RunLevel Highest `
            -User $cred.UserName -Password $cred.GetNetworkCredential().Password -Force | Out-Null
    }

    Write-Host "Scheduled task '$TaskName' registered. Runs daily at $($At.ToString('HH:mm')) as '$RunAsUser'." -ForegroundColor Green
    Write-Host "Test it now with: Start-ScheduledTask -TaskName '$TaskName'" -ForegroundColor Cyan
}
