# Windows Certification Authority Backup

A PowerShell 5.x solution that performs a complete, unattended backup of a
Windows (AD CS) Certification Authority using `certutil.exe`, runs as a Windows
Scheduled Task, and logs to both a text file and the Windows Application event
log.

## What gets backed up

Each run creates a **new timestamped subfolder** (`CABackup_yyyyMMdd_HHmmss`)
under the backup root, so every backup is independent and self-contained. A
`certutil` backup requires an empty target directory — using a fresh subfolder
each time guarantees that.

| Item | Mechanism | File(s) in the backup folder |
|------|-----------|------------------------------|
| CA database (all requests: issued, revoked, pending, failed) + DB logs | `certutil -backupDB` (or `-backup`) | `*.edb` / `*.dat`, `DataBase\` |
| CA certificate **and private key pair** *(only with `-ExportPrivateKey`)* | `certutil -backup` (PKCS#12) | `*.p12` |
| CA **configuration data** | registry export (`reg export`) | `CertSvc-Configuration.reg` |
| Human-readable config (reference) | `certutil -getreg CA` | `CertSvc-Configuration.txt` |

> The certutil backup does **not** include the CA configuration registry hive, so
> it is exported separately. Both are needed to rebuild a CA on a clean host.

### Private-key export is optional (`-ExportPrivateKey`)

By default the backup script performs a **database-only** backup
(`certutil -backupDB`) and needs **no password**. Pass **`-ExportPrivateKey`** to
additionally export the CA certificate + private key into a password-protected
PKCS#12 (`.p12`) via `certutil -backup`; in that mode a password is required
(supply `-Password` or `-PasswordPath`).

| Mode | Switch | certutil | Produces `.p12` | Password |
|------|--------|----------|-----------------|----------|
| Database-only (default) | *(none)* | `-backupDB` | no | not required |
| Full (DB + private key) | `-ExportPrivateKey` | `-backup` | yes | **required** |

The scheduled task registered by `Register-CABackupScheduledTask.ps1` runs in
**full** mode (it always passes `-ExportPrivateKey` together with the stored
`-PasswordPath`).

## Files

| File | Purpose |
|------|---------|
| `Backup-CertificationAuthority.ps1` | The backup script (run by the scheduled task). |
| `Restore-CertificationAuthority.ps1` | Restores a CA from a backup set (config + database + key). |
| `New-CABackupCredential.ps1` | Stores the PKCS#12 private-key password as a DPAPI-protected file for unattended use. |
| `Register-CABackupScheduledTask.ps1` | Registers the daily scheduled task. |
| `New-CAConfigurationReport.ps1` | Generates a self-contained HTML report of the CA configuration (server, services, registry) from the backup set and the live server. |

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
# Database-only backup (default) — no password needed:
.\Backup-CertificationAuthority.ps1 -BackupRoot 'D:\CABackups'

# Full backup including the private key; prompt for the password:
$pw = Read-Host -AsSecureString 'PFX password'
.\Backup-CertificationAuthority.ps1 -BackupRoot 'D:\CABackups' -ExportPrivateKey -Password $pw

# Full backup using a stored DPAPI password file:
.\Backup-CertificationAuthority.ps1 -BackupRoot 'D:\CABackups' -ExportPrivateKey -PasswordPath 'C:\CABackup\pfx.cred'

# Preview only (no changes):
.\Backup-CertificationAuthority.ps1 -BackupRoot 'D:\CABackups' -ExportPrivateKey -PasswordPath 'C:\CABackup\pfx.cred' -WhatIf
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

## Configuration report

`New-CAConfigurationReport.ps1` produces a single, self-contained **HTML report**
documenting the CA for operational, audit and disaster-recovery reference. It
combines two sources:

- **Backup data** — a `CABackup_*` folder: the exported configuration registry
  (`CertSvc-Configuration.reg`), its human-readable dump
  (`CertSvc-Configuration.txt`, embedded verbatim), and the file inventory
  (database, `.p12`, sizes/dates). This captures the CA state *as backed up*.
- **Live server** (when run on the CA host) — Windows identification (name,
  domain, OS, build, hardware, network), the `CertSvc` service and its related
  services, AD CS role features, CA identity/type, signing certificate,
  CRL/AIA/CDP publishing, crypto provider, certificate templates, and a **full
  structured dump of the CA registry** (`...\CertSvc\Configuration`).

The script is **read-only** (it makes no changes and never touches the private
key, so no password is needed) and degrades gracefully — any unavailable source
is marked as such instead of failing the whole report.

```powershell
# Newest backup set + live CA config; report written into that backup folder:
.\New-CAConfigurationReport.ps1 -BackupRoot 'D:\CABackups'

# A specific backup set plus live data, to a chosen path:
.\New-CAConfigurationReport.ps1 -BackupFolder 'D:\CABackups\CABackup_20260622_143000' `
    -OutputPath 'C:\Temp\CA-Report.html'

# From an archived backup only (e.g. on an admin workstation), no live queries:
.\New-CAConfigurationReport.ps1 -BackupFolder 'D:\Archive\CABackup_20260101_020000' -SkipLiveData
```

Run **elevated on the CA host** for the richest live output. The default output
file is `CA-Configuration-Report_<host>_<timestamp>.html` inside the backup
folder (or the current directory when no backup is given).

## Notes & trade-offs

- With `-ExportPrivateKey`, the PKCS#12 password is passed to `certutil` via
  `-p`. It is never written to the logs, and the in-memory plaintext is cleared
  after use. On a privileged CA host this is the standard, reliable approach.
  Without the switch no password is used at all.
- The CA service does **not** need to be stopped for a backup (database-only or full).
- Retention (`-RetentionCount`) prunes oldest `CABackup_*` folders only after a
  successful backup. Default `0` keeps everything.
