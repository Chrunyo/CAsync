#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Restores a Windows (AD CS) Certification Authority from a backup set created
    by Backup-CertificationAuthority.ps1.

.DESCRIPTION
    Restores a CA from a single backup subfolder (e.g.
    CABackup_20260622_143000). The restore is performed with 'certutil.exe' and
    mirrors the backup:

      * Configuration data is re-imported from CertSvc-Configuration.reg into
        HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration.
      * The CA database and the CA certificate + private key are restored with
        'certutil -restore' from the password-protected PKCS#12 (.p12).

    The Certificate Services service (CertSvc) is stopped for the duration of the
    restore and started again afterwards (unless -NoServiceStart is supplied).

    This operation is DESTRUCTIVE: it overwrites the current CA database, key,
    and configuration. It prompts for confirmation unless -Force is supplied.

    All activity is logged to a text log file and to the Windows Application
    event log (source 'CABackup'), consistent with the backup script.

.PARAMETER BackupFolder
    The specific backup subfolder to restore from (must contain the .p12 /
    database files produced by certutil -backup).

.PARAMETER Password
    PKCS#12 password as a SecureString (interactive use). Mutually exclusive with
    -PasswordPath.

.PARAMETER PasswordPath
    Path to the DPAPI-protected password file created by New-CABackupCredential.ps1.

.PARAMETER SkipConfiguration
    Do not import CertSvc-Configuration.reg (restore database + key only).

.PARAMETER SkipDatabaseAndKey
    Do not run certutil -restore (import configuration only).

.PARAMETER NoServiceStart
    Leave CertSvc stopped after the restore (e.g. for further manual steps).

.PARAMETER LogDirectory
    Directory for the text log file. Defaults to a 'Logs' subfolder under the
    parent of -BackupFolder.

.PARAMETER EventLogSource
    Application event-log source name. Default 'CABackup'.

.PARAMETER Force
    Suppress the confirmation prompt.

.EXAMPLE
    .\Restore-CertificationAuthority.ps1 -BackupFolder 'D:\CABackups\CABackup_20260622_143000' -PasswordPath 'C:\CABackup\pfx.cred'

.EXAMPLE
    $pw = Read-Host -AsSecureString 'PFX password'
    .\Restore-CertificationAuthority.ps1 -BackupFolder 'D:\CABackups\CABackup_20260622_143000' -Password $pw -WhatIf

.NOTES
    Must run elevated on the CA host. The AD CS role must already be installed.
    For a bare-metal rebuild, install the CA role first (matching the original CA
    name), then run this script. Always validate restores in a lab first.
#>

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'StoredPassword')]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$BackupFolder,

    [Parameter(Mandatory, ParameterSetName = 'SecurePassword')]
    [ValidateNotNull()]
    [securestring]$Password,

    [Parameter(Mandatory, ParameterSetName = 'StoredPassword')]
    [ValidateNotNullOrEmpty()]
    [string]$PasswordPath,

    [Parameter()]
    [switch]$SkipConfiguration,

    [Parameter()]
    [switch]$SkipDatabaseAndKey,

    [Parameter()]
    [switch]$NoServiceStart,

    [Parameter()]
    [string]$LogDirectory,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$EventLogSource = 'CABackup',

    [Parameter()]
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Helpers ---------------------------------------------------------------

$script:LogFile = $null
$script:EventSourceReady = $false

function Initialize-EventSource {
    [CmdletBinding()]
    param([string]$Source)

    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
            New-EventLog -LogName 'Application' -Source $Source -ErrorAction Stop
        }
        $script:EventSourceReady = $true
    }
    catch {
        $script:EventSourceReady = $false
        Write-Warning "Could not register/verify event source '$Source': $($_.Exception.Message). Continuing with file logging only."
    }
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Level = 'Information',

        [Parameter()]
        [int]$EventId = 1000
    )

    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line  = '{0} [{1}] {2}' -f $stamp, $Level.ToUpper().PadRight(11), $Message

    switch ($Level) {
        'Error'   { Write-Host $line -ForegroundColor Red }
        'Warning' { Write-Host $line -ForegroundColor Yellow }
        default   { Write-Host $line }
    }

    if ($script:LogFile) {
        try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 }
        catch { Write-Warning "Failed to write to log file '$($script:LogFile)': $($_.Exception.Message)" }
    }

    if ($script:EventSourceReady) {
        try {
            Write-EventLog -LogName 'Application' -Source $EventLogSource `
                -EntryType $Level -EventId $EventId -Message $Message -ErrorAction Stop
        }
        catch { Write-Warning "Failed to write to event log: $($_.Exception.Message)" }
    }
}

function ConvertTo-PlainText {
    [CmdletBinding()]
    [OutputType([string])]
    param([securestring]$Secure)

    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try   { return [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

#endregion --------------------------------------------------------------------

#region Main ------------------------------------------------------------------

$exitCode      = 0
$plainPassword = $null
$serviceWasRunning = $false

try {
    # --- Resolve / validate the backup folder --------------------------------
    if (-not (Test-Path -LiteralPath $BackupFolder)) {
        throw "Backup folder not found: $BackupFolder"
    }
    $BackupFolder = (Resolve-Path -LiteralPath $BackupFolder).Path

    # --- Logging targets ------------------------------------------------------
    if (-not $LogDirectory) {
        $LogDirectory = Join-Path (Split-Path -Path $BackupFolder -Parent) 'Logs'
    }
    if (-not (Test-Path -LiteralPath $LogDirectory)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }
    $script:LogFile = Join-Path $LogDirectory ('CARestore_{0}.log' -f (Get-Date).ToString('yyyyMMdd'))

    Initialize-EventSource -Source $EventLogSource
    Write-Log -Message "===== CA restore started (host: $env:COMPUTERNAME, user: $env:USERNAME, source: $BackupFolder) =====" -EventId 3000

    # --- Pre-flight checks ----------------------------------------------------
    $certSvc = Get-Service -Name 'CertSvc' -ErrorAction SilentlyContinue
    if (-not $certSvc) {
        throw "The Certificate Services service (CertSvc) is not installed. Install the AD CS / CA role before restoring."
    }

    $regFile = Join-Path $BackupFolder 'CertSvc-Configuration.reg'
    $hasConfig = Test-Path -LiteralPath $regFile
    $p12 = @(Get-ChildItem -LiteralPath $BackupFolder -Recurse -File -Filter '*.p12' -ErrorAction SilentlyContinue)
    $dbFiles = @(Get-ChildItem -LiteralPath $BackupFolder -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in '.edb', '.dat' })

    if (-not $SkipConfiguration -and -not $hasConfig) {
        Write-Log -Message "CertSvc-Configuration.reg not found in backup; configuration will NOT be imported." -Level Warning -EventId 1001
    }
    if (-not $SkipDatabaseAndKey -and (-not $p12 -and -not $dbFiles)) {
        throw "No database or .p12 files found in '$BackupFolder'; cannot restore database/key. Check the backup folder."
    }

    # --- Resolve the PKCS#12 password ----------------------------------------
    if (-not $SkipDatabaseAndKey) {
        if ($PSCmdlet.ParameterSetName -eq 'StoredPassword') {
            if (-not (Test-Path -LiteralPath $PasswordPath)) { throw "Password file not found: $PasswordPath" }
            $cred = Import-Clixml -LiteralPath $PasswordPath
            if ($cred -isnot [securestring]) {
                throw "Password file '$PasswordPath' did not contain a SecureString. Recreate it with New-CABackupCredential.ps1."
            }
            $plainPassword = ConvertTo-PlainText -Secure $cred
        }
        else {
            $plainPassword = ConvertTo-PlainText -Secure $Password
        }
        if ([string]::IsNullOrEmpty($plainPassword)) {
            throw "The private-key (PKCS#12) password resolved to an empty value."
        }
    }

    # --- Confirmation ---------------------------------------------------------
    $confirmMsg = "This OVERWRITES the current CA database, private key, and configuration on '$env:COMPUTERNAME' from '$BackupFolder'."
    if (-not $Force -and -not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, $confirmMsg)) {
        Write-Log -Message "Restore cancelled by operator / ShouldProcess; no changes made." -Level Warning
        return
    }

    # --- Stop the CA service --------------------------------------------------
    $serviceWasRunning = ($certSvc.Status -eq 'Running')
    if ($serviceWasRunning) {
        Write-Log -Message "Stopping CertSvc..."
        Stop-Service -Name 'CertSvc' -Force
        (Get-Service -Name 'CertSvc').WaitForStatus('Stopped', (New-TimeSpan -Seconds 60))
        Write-Log -Message "CertSvc stopped."
    }
    else {
        Write-Log -Message "CertSvc was not running (status: $($certSvc.Status))."
    }

    # --- 1) Import configuration ---------------------------------------------
    if (-not $SkipConfiguration -and $hasConfig) {
        Write-Log -Message "Importing CA configuration from '$regFile'..."
        $regOut = & reg.exe import $regFile 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "reg.exe import of CA configuration failed (exit $LASTEXITCODE): $regOut"
        }
        Write-Log -Message "CA configuration imported."
    }
    elseif ($SkipConfiguration) {
        Write-Log -Message "Skipping configuration import (-SkipConfiguration)."
    }

    # --- 2) Restore database + certificate/private key ------------------------
    # certutil syntax: certutil [-f] [-p Password] -restore BackupDirectory
    if (-not $SkipDatabaseAndKey) {
        Write-Log -Message "Running certutil restore from '$BackupFolder'..."
        $restoreArgs  = @('-f', '-p', $plainPassword, '-restore', $BackupFolder)
        $restoreOut   = & certutil.exe @restoreArgs 2>&1
        $restoreCode  = $LASTEXITCODE

        foreach ($l in ($restoreOut | Where-Object { "$_".Trim() })) {
            Write-Log -Message ("  certutil: {0}" -f $l)
        }
        if ($restoreCode -ne 0) {
            throw "certutil -restore failed with exit code $restoreCode."
        }
        Write-Log -Message "Database and key restored successfully."
    }
    else {
        Write-Log -Message "Skipping database/key restore (-SkipDatabaseAndKey)."
    }

    # --- 3) Start the CA service ----------------------------------------------
    if ($NoServiceStart) {
        Write-Log -Message "Leaving CertSvc stopped (-NoServiceStart)." -Level Warning -EventId 1001
    }
    elseif ($serviceWasRunning -or -not $NoServiceStart) {
        Write-Log -Message "Starting CertSvc..."
        Start-Service -Name 'CertSvc'
        (Get-Service -Name 'CertSvc').WaitForStatus('Running', (New-TimeSpan -Seconds 60))
        Write-Log -Message "CertSvc started."
    }

    Write-Log -Message "===== CA restore completed successfully from: $BackupFolder =====" -EventId 3001
}
catch {
    $exitCode = 1
    $msg = "CA restore FAILED: $($_.Exception.Message)"
    if ($script:LogFile -or $script:EventSourceReady) {
        Write-Log -Message $msg -Level Error -EventId 3002
        Write-Log -Message ("Stack: {0}" -f $_.ScriptStackTrace) -Level Error -EventId 3002
    }
    else {
        Write-Error $msg
    }

    # Best-effort: bring the service back if we stopped it.
    if ($serviceWasRunning -and -not $NoServiceStart) {
        try {
            Write-Log -Message "Attempting to restart CertSvc after failure..." -Level Warning -EventId 1001
            Start-Service -Name 'CertSvc' -ErrorAction Stop
        }
        catch {
            Write-Log -Message "Could not restart CertSvc: $($_.Exception.Message)" -Level Error -EventId 3002
        }
    }
}
finally {
    if ($plainPassword) {
        $plainPassword = $null
        [System.GC]::Collect()
    }
}

exit $exitCode

#endregion --------------------------------------------------------------------
