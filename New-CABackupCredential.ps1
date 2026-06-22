#Requires -Version 5.1

<#
.SYNOPSIS
    Stores the CA backup private-key (PKCS#12) password as a DPAPI-protected file.

.DESCRIPTION
    Prompts for the password used to protect the CA private key during
    'certutil -backup', then writes it to disk as a SecureString via
    Export-Clixml. Windows DPAPI encrypts it so the file can ONLY be decrypted
    by the same user account on the same computer that created it.

    IMPORTANT: Run this script while logged on AS THE ACCOUNT that the scheduled
    backup task will run under, and ON THE CA SERVER. If the task runs as
    'SYSTEM' or a gMSA, generating the file under that identity requires running
    this helper in that context (e.g. via PsExec -s for SYSTEM).

.PARAMETER Path
    Destination file path for the protected password (e.g. C:\CABackup\pfx.cred).

.PARAMETER Password
    Optional pre-supplied SecureString. If omitted, you are prompted securely.

.EXAMPLE
    .\New-CABackupCredential.ps1 -Path 'C:\CABackup\pfx.cred'

.NOTES
    Protect the containing folder with restrictive NTFS permissions; even though
    the file is DPAPI-encrypted, defense in depth is appropriate for PKI assets.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Path,

    [Parameter()]
    [securestring]$Password
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $Password) {
    $Password = Read-Host -AsSecureString -Prompt 'Enter the CA private-key (PKCS#12) backup password'
    $confirm  = Read-Host -AsSecureString -Prompt 'Confirm the password'

    $bstr1 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    $bstr2 = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirm)
    try {
        $p1 = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr1)
        $p2 = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr2)
        if ($p1 -ne $p2) { throw 'Passwords do not match.' }
        if ([string]::IsNullOrEmpty($p1)) { throw 'Password cannot be empty.' }
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr1)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2)
    }
}

$folder = Split-Path -Path $Path -Parent
if ($folder -and -not (Test-Path -LiteralPath $folder)) {
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
}

if ($PSCmdlet.ShouldProcess($Path, 'Write DPAPI-protected password file')) {
    $Password | Export-Clixml -LiteralPath $Path -Force
    Write-Host "Password stored (DPAPI, bound to '$env:USERNAME' on '$env:COMPUTERNAME'): $Path" -ForegroundColor Green
    Write-Host "Tighten NTFS permissions on this file before relying on it." -ForegroundColor Yellow
}
