#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Performs a complete backup of a Windows (AD CS) Certification Authority.

.DESCRIPTION
    Creates a full backup of a Windows Certification Authority (CA) into a new,
    timestamped subfolder under the supplied backup root. Each run produces an
    independent, self-contained backup set containing:

      * The CA database (all issued/revoked/pending requests and CA log files)
        and the CA certificate + private key, exported by 'certutil.exe -backup'
        into a password-protected PKCS#12 (.p12) file.
      * The CA configuration, exported from the registry key
        HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration
        (which 'certutil -backup' does NOT include) so the CA can be fully
        reconstructed on a clean host.
      * A human-readable dump of the CA registry configuration for reference.

    'certutil.exe' is used as the backup engine, as recommended for AD CS.
    A full 'certutil -backup' requires the target directory to be empty, which
    is guaranteed here because a brand-new subfolder is created on every run.

    All activity is logged to a rolling text log file and to the Windows
    Application event log (source 'CABackup'), making it suitable for running
    unattended as a Windows Scheduled Task.

    The PKCS#12 private-key password must be supplied. For unattended scheduled
    execution, store it once with New-CABackupCredential.ps1 (DPAPI-protected,
    bound to the account that will run the task) and pass it via -PasswordPath.

.PARAMETER BackupRoot
    Root directory under which a new timestamped backup subfolder is created on
    every run (e.g. C:\CABackups\CABackup_20260622_143000).

.PARAMETER Password
    The password used to protect the exported private key (PKCS#12). Supply as a
    SecureString. Mutually exclusive with -PasswordPath. Mainly for interactive
    use.

.PARAMETER PasswordPath
    Path to a DPAPI-protected password file created with New-CABackupCredential.ps1.
    Use this for unattended/scheduled execution. The file can only be read by the
    same Windows account and machine that created it.

.PARAMETER LogDirectory
    Directory for the text log file. Defaults to a 'Logs' subfolder under
    -BackupRoot. Created if it does not exist.

.PARAMETER EventLogSource
    Event source name used for the Application event log. Defaults to 'CABackup'.

.PARAMETER RetentionCount
    If greater than 0, after a successful backup only the newest <RetentionCount>
    backup subfolders are kept; older ones are deleted. Default 0 (keep all).

.PARAMETER KeepDatabaseLog
    Pass to preserve the CA database log files (certutil 'KeepLog'). Default is to
    truncate the logs after a successful full backup.

.EXAMPLE
    .\Backup-CertificationAuthority.ps1 -BackupRoot 'D:\CABackups' -PasswordPath 'C:\CABackup\pfx.cred'

    Unattended full backup using a stored DPAPI password file. Intended form for
    a scheduled task.

.EXAMPLE
    $pw = Read-Host -AsSecureString 'PFX password'
    .\Backup-CertificationAuthority.ps1 -BackupRoot 'D:\CABackups' -Password $pw -RetentionCount 14

    Interactive backup keeping only the 14 most recent backup sets.

.NOTES
    Must run elevated (Administrator) and on the CA host itself, under an account
    that has CA backup rights (typically a local/Enterprise admin or a delegated
    "Backup files and directories" privilege holder).
#>

[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'StoredPassword')]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$BackupRoot,

    [Parameter(Mandatory, ParameterSetName = 'SecurePassword')]
    [ValidateNotNull()]
    [securestring]$Password,

    [Parameter(Mandatory, ParameterSetName = 'StoredPassword')]
    [ValidateNotNullOrEmpty()]
    [string]$PasswordPath,

    [Parameter()]
    [string]$LogDirectory,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$EventLogSource = 'CABackup',

    [Parameter()]
    [ValidateRange(0, [int]::MaxValue)]
    [int]$RetentionCount = 0,

    [Parameter()]
    [switch]$KeepDatabaseLog
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Helpers ---------------------------------------------------------------

# Script-scoped state used by Write-Log.
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
        # Non-fatal: fall back to file-only logging. Registering a source needs
        # admin rights; if it fails we still keep the text log.
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

    # Console
    switch ($Level) {
        'Error'       { Write-Host $line -ForegroundColor Red }
        'Warning'     { Write-Host $line -ForegroundColor Yellow }
        default       { Write-Host $line }
    }

    # Text log
    if ($script:LogFile) {
        try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 }
        catch { Write-Warning "Failed to write to log file '$($script:LogFile)': $($_.Exception.Message)" }
    }

    # Application event log
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

function Get-CaName {
    # Returns the CA common name from the registry, or $null if undetermined.
    [CmdletBinding()]
    param()

    $output = & certutil.exe -getreg 'CA\CommonName' 2>&1
    if ($LASTEXITCODE -eq 0) {
        $match = $output | Select-String -Pattern 'CommonName\s+REG_SZ\s*=\s*(.+)$'
        if ($match) { return $match.Matches[0].Groups[1].Value.Trim() }
    }
    return $null
}

#endregion --------------------------------------------------------------------

#region Main ------------------------------------------------------------------

$exitCode = 0
$plainPassword = $null
$targetDir = $null

try {
    # --- Resolve logging targets early so even setup errors are captured ------
    if (-not $LogDirectory) { $LogDirectory = Join-Path $BackupRoot 'Logs' }
    if (-not (Test-Path -LiteralPath $LogDirectory)) {
        New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null
    }
    $script:LogFile = Join-Path $LogDirectory ('CABackup_{0}.log' -f (Get-Date).ToString('yyyyMMdd'))

    Initialize-EventSource -Source $EventLogSource

    Write-Log -Message "===== CA backup started (host: $env:COMPUTERNAME, user: $env:USERNAME) =====" -EventId 2000

    # --- Pre-flight checks ----------------------------------------------------
    $certSvc = Get-Service -Name 'CertSvc' -ErrorAction SilentlyContinue
    if (-not $certSvc) {
        throw "The Active Directory Certificate Services service (CertSvc) is not installed on this host. This script must run on the CA server."
    }
    Write-Log -Message "CertSvc service detected (status: $($certSvc.Status))."

    $caName = Get-CaName
    if ($caName) { Write-Log -Message "Target CA common name: $caName" }
    else { Write-Log -Message "Could not determine CA common name; continuing." -Level Warning -EventId 1001 }

    # --- Resolve the PKCS#12 password ----------------------------------------
    if ($PSCmdlet.ParameterSetName -eq 'StoredPassword') {
        if (-not (Test-Path -LiteralPath $PasswordPath)) {
            throw "Password file not found: $PasswordPath"
        }
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

    # --- Create the new, empty target subfolder -------------------------------
    if (-not (Test-Path -LiteralPath $BackupRoot)) {
        New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null
    }
    $stamp     = (Get-Date).ToString('yyyyMMdd_HHmmss')
    $targetDir = Join-Path $BackupRoot ("CABackup_{0}" -f $stamp)

    if (Test-Path -LiteralPath $targetDir) {
        throw "Target backup folder already exists (unexpected): $targetDir"
    }

    if (-not $PSCmdlet.ShouldProcess($targetDir, 'Create CA backup')) {
        Write-Log -Message "Run cancelled by -WhatIf/ShouldProcess; no backup performed." -Level Warning
        return
    }

    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    Write-Log -Message "Created backup folder: $targetDir"

    # --- 1) Full CA backup (database + certificate + private key) -------------
    # certutil syntax: certutil [-f] [-p Password] -backup BackupDirectory [KeepLog]
    $certutilArgs = @('-f', '-p', $plainPassword, '-backup', $targetDir)
    if ($KeepDatabaseLog) { $certutilArgs += 'KeepLog' }

    Write-Log -Message "Running certutil full backup into '$targetDir'..."
    $backupOutput = & certutil.exe @certutilArgs 2>&1
    $backupCode   = $LASTEXITCODE

    # Log certutil output verbatim (it never echoes the password).
    foreach ($line in ($backupOutput | Where-Object { "$_".Trim() })) {
        Write-Log -Message ("  certutil: {0}" -f $line)
    }

    if ($backupCode -ne 0) {
        throw "certutil -backup failed with exit code $backupCode."
    }

    # Verify the backup actually produced files.
    $produced = Get-ChildItem -LiteralPath $targetDir -Recurse -File -ErrorAction SilentlyContinue
    if (-not $produced) {
        throw "certutil reported success but the backup folder is empty: $targetDir"
    }
    $dbFiles  = @($produced | Where-Object { $_.Extension -in '.edb', '.dat' })
    $p12Files = @($produced | Where-Object { $_.Extension -eq '.p12' })
    Write-Log -Message ("Database backup files: {0}; private-key (.p12) files: {1}." -f $dbFiles.Count, $p12Files.Count)
    if ($p12Files.Count -eq 0) {
        Write-Log -Message "No .p12 (private key) file was produced. Verify the account has key backup rights." -Level Warning -EventId 1001
    }

    # --- 2) Configuration data (registry export) ------------------------------
    $regKey  = 'HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
    $regFile = Join-Path $targetDir 'CertSvc-Configuration.reg'
    Write-Log -Message "Exporting CA configuration from registry to '$regFile'..."
    $regOutput = & reg.exe export $regKey $regFile /y 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "reg.exe export of CA configuration failed (exit $LASTEXITCODE): $regOutput"
    }
    Write-Log -Message "CA configuration exported successfully."

    # Human-readable configuration dump (reference only, not used for restore).
    $regDumpFile = Join-Path $targetDir 'CertSvc-Configuration.txt'
    $regDump = & certutil.exe -getreg 'CA' 2>&1
    if ($LASTEXITCODE -eq 0) {
        $regDump | Out-File -LiteralPath $regDumpFile -Encoding UTF8
        Write-Log -Message "Saved human-readable CA registry dump to '$regDumpFile'."
    }
    else {
        Write-Log -Message "Could not produce human-readable CA registry dump (non-fatal)." -Level Warning -EventId 1001
    }

    # --- 3) Retention cleanup -------------------------------------------------
    if ($RetentionCount -gt 0) {
        $allBackups = @(Get-ChildItem -LiteralPath $BackupRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like 'CABackup_*' } |
            Sort-Object -Property Name -Descending)

        if ($allBackups.Count -gt $RetentionCount) {
            $toRemove = $allBackups | Select-Object -Skip $RetentionCount
            foreach ($old in $toRemove) {
                if ($PSCmdlet.ShouldProcess($old.FullName, 'Remove old CA backup (retention)')) {
                    try {
                        Remove-Item -LiteralPath $old.FullName -Recurse -Force
                        Write-Log -Message "Retention: removed old backup '$($old.Name)'."
                    }
                    catch {
                        Write-Log -Message "Retention: failed to remove '$($old.Name)': $($_.Exception.Message)" -Level Warning -EventId 1001
                    }
                }
            }
        }
        else {
            Write-Log -Message "Retention: $($allBackups.Count) backup set(s) present; nothing to prune (keep $RetentionCount)."
        }
    }

    Write-Log -Message "===== CA backup completed successfully: $targetDir =====" -EventId 2001
}
catch {
    $exitCode = 1
    $msg = "CA backup FAILED: $($_.Exception.Message)"
    if ($script:LogFile -or $script:EventSourceReady) {
        Write-Log -Message $msg -Level Error -EventId 2002
        Write-Log -Message ("Stack: {0}" -f $_.ScriptStackTrace) -Level Error -EventId 2002
    }
    else {
        Write-Error $msg
    }

    # Leave a marker so an incomplete folder is obvious to operators.
    if ($targetDir -and (Test-Path -LiteralPath $targetDir)) {
        try {
            $marker = Join-Path $targetDir 'BACKUP_FAILED.txt'
            Set-Content -LiteralPath $marker -Value $msg -Encoding UTF8
        }
        catch { }
    }
}
finally {
    # Best-effort scrub of the plaintext password from memory.
    if ($plainPassword) {
        $plainPassword = $null
        [System.GC]::Collect()
    }
}

exit $exitCode

#endregion --------------------------------------------------------------------
