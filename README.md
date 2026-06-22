# Windows Certification Authority Backup

A PowerShell 5.x solution that performs a complete, unattended backup of a
Windows (AD CS) Certification Authority using `certutil.exe`, runs as a Windows
Scheduled Task, and logs to both a text file and the Windows Application event
log.

## What gets backed up

Each run creates a **new timestamped subfolder** (`CABackup_yyyyMMdd_HHmmss`)
under the backup root, so every backup is independent and self-contained. A full
`certutil -backup` requires an empty target directory — using a fresh subfolder
each time guarantees that.

| Item | Mechanism | File(s) in the backup folder |
|------|-----------|------------------------------|
| CA database (all requests: issued, revoked, pending, failed) + DB logs | `certutil -backup` | `*.edb` / `*.dat`, `DataBase\` |
| CA certificate **and private key pair** | `certutil -backup` (PKCS#12) | `*.p12` |
| CA **configuration data** | registry export (`reg export`) | `CertSvc-Configuration.reg` |
| Human-readable config (reference) | `certutil -getreg CA` | `CertSvc-Configuration.txt` |

> `certutil -backup` does **not** include the CA configuration registry hive, so
> it is exported separately. Both are needed to rebuild a CA on a clean host.

## Files

| File | Purpose |
|------|---------|
| `Backup-CertificationAuthority.ps1` | The backup script (run by the scheduled task). |
| `Restore-CertificationAuthority.ps1` | Restores a CA from a backup set (config + database + key). |
| `New-CABackupCredential.ps1` | Stores the PKCS#12 private-key password as a DPAPI-protected file for unattended use. |
| `Register-CABackupScheduledTask.ps1` | Registers the daily scheduled task. |

## Requirements

- Windows Server with the **AD CS / Certification Authority** role (the `CertSvc` service).
- PowerShell **5.1**.
- Run **elevated** (Administrator) under an account with CA backup rights.

## Setup

Run all steps **on the CA server**.

### 1. Store the private-key password (as the task's run-as account)

The DPAPI-protected file can only be read back by the **same account on the same
machine** that created it. Create it under the identity the scheduled task will
use.

```powershell
# Running interactively as the service account:
.\New-CABackupCredential.ps1 -Path 'C:\CABackup\pfx.cred'
```

If the task will run as **SYSTEM**, generate the file in the SYSTEM context, e.g.:

```cmd
psexec -s -i powershell.exe -File C:\...\New-CABackupCredential.ps1 -Path C:\CABackup\pfx.cred
```

Then restrict NTFS permissions on `C:\CABackup\pfx.cred`.

### 2. Register the scheduled task

```powershell
.\Register-CABackupScheduledTask.ps1 `
    -BackupRoot   'D:\CABackups' `
    -PasswordPath 'C:\CABackup\pfx.cred' `
    -RunAsUser    'NT AUTHORITY\SYSTEM' `
    -At           02:00 `
    -RetentionCount 30
```

- For a **domain service account** pass e.g. `-RunAsUser 'CONTOSO\svc-cabackup'`; you'll be prompted for its logon password.
- For a **gMSA** pass `-RunAsUser 'CONTOSO\svc-cabackup$'`.

### 3. Test

```powershell
Start-ScheduledTask -TaskName 'Backup Certification Authority'
```

## Logging

- **Text log:** `<BackupRoot>\Logs\CABackup_yyyyMMdd.log` (override with `-LogDirectory`).
- **Application event log:** source `CABackup`. Key event IDs:
  - `2000` start, `2001` success, `2002` failure
  - `1001` warnings, `1000` informational

Query failures with:

```powershell
Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName='CABackup'; Level=2 }
```

## Manual / interactive run

```powershell
# Prompt for the password instead of using a stored file:
$pw = Read-Host -AsSecureString 'PFX password'
.\Backup-CertificationAuthority.ps1 -BackupRoot 'D:\CABackups' -Password $pw

# Preview only (no changes):
.\Backup-CertificationAuthority.ps1 -BackupRoot 'D:\CABackups' -PasswordPath 'C:\CABackup\pfx.cred' -WhatIf
```

## Restore

Use `Restore-CertificationAuthority.ps1`. The AD CS / CA role must already be
installed (for a bare-metal rebuild, install the role first, matching the
original CA name). The script stops `CertSvc`, imports the configuration
(`CertSvc-Configuration.reg`), runs `certutil -restore` for the database + key,
then restarts the service. It is **destructive** and prompts for confirmation
unless `-Force` is given.

```powershell
# Preview first (no changes):
.\Restore-CertificationAuthority.ps1 -BackupFolder 'D:\CABackups\CABackup_20260622_143000' `
    -PasswordPath 'C:\CABackup\pfx.cred' -WhatIf

# Perform the restore:
.\Restore-CertificationAuthority.ps1 -BackupFolder 'D:\CABackups\CABackup_20260622_143000' `
    -PasswordPath 'C:\CABackup\pfx.cred'
```

Useful switches: `-SkipConfiguration`, `-SkipDatabaseAndKey`, `-NoServiceStart`,
`-Force`. Restore logs go to `<parent>\Logs\CARestore_yyyyMMdd.log` and the
`CABackup` event source (event IDs `3000` start / `3001` success / `3002` fail).

Always validate restores in a lab before relying on them.

## Notes & trade-offs

- The PKCS#12 password is passed to `certutil` via `-p`. It is never written to
  the logs, and the in-memory plaintext is cleared after use. On a privileged CA
  host this is the standard, reliable approach.
- The CA service does **not** need to be stopped for a full backup.
- Retention (`-RetentionCount`) prunes oldest `CABackup_*` folders only after a
  successful backup. Default `0` keeps everything.
