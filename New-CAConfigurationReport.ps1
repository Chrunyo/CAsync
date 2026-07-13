#Requires -Version 5.1

<#
.SYNOPSIS
    Produces a self-contained HTML report describing the technical configuration
    of a Windows (AD CS) Certification Authority, combining data from a backup
    set with the live server configuration.

.DESCRIPTION
    Generates a single, self-contained HTML document that documents a Windows
    Certification Authority (CA) for operational, audit and disaster-recovery
    reference. It draws on two sources:

      * The BACKUP data produced by Backup-CertificationAuthority.ps1 (a
        CABackup_* folder): the exported CA configuration registry
        (CertSvc-Configuration.reg), its human-readable dump
        (CertSvc-Configuration.txt), and the inventory of database / PKCS#12
        files. This captures the CA state as it was when backed up.

      * The LIVE server configuration (when the script is run on the CA host):
        Windows identification, hardware, network, the CertSvc service and its
        related services, the AD CS role features, the CA identity, certificate,
        CRL/AIA/CDP publishing, cryptographic provider, certificate templates,
        and a full structured dump of the CA registry
        (HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration).

    Every section degrades gracefully: if a data source is unavailable (for
    example the script is run off-box, or a certutil query fails), that section
    is marked as unavailable rather than aborting the whole report. The report
    never touches or exports the private key and needs no password.

    The report is written as a single .html file with inline CSS (no external
    dependencies), suitable for archiving next to the backup set.

.PARAMETER BackupFolder
    A specific backup subfolder to document (e.g.
    D:\CABackups\CABackup_20260622_143000). If omitted and -BackupRoot is given,
    the newest CABackup_* folder under the root is used. If neither is given the
    report is built from live server data only.

.PARAMETER BackupRoot
    Root folder containing CABackup_* subfolders. Used to auto-select the newest
    backup set when -BackupFolder is not supplied.

.PARAMETER OutputPath
    Full path of the HTML file to create. Defaults to
    'CA-Configuration-Report_<host>_<timestamp>.html' inside the backup folder
    (if one was resolved) or the current directory.

.PARAMETER SkipLiveData
    Build the report from the backup set only, without querying the live server.
    Useful when generating documentation from an archived backup on another host.

.EXAMPLE
    .\New-CAConfigurationReport.ps1 -BackupRoot 'D:\CABackups'

    Documents the newest backup set combined with the live CA configuration and
    writes the HTML report into that backup folder.

.EXAMPLE
    .\New-CAConfigurationReport.ps1 -BackupFolder 'D:\CABackups\CABackup_20260622_143000' `
        -OutputPath 'C:\Temp\CA-Report.html'

    Documents a specific backup set plus live data at a chosen output path.

.EXAMPLE
    .\New-CAConfigurationReport.ps1 -BackupFolder 'D:\Archive\CABackup_20260101_020000' -SkipLiveData

    Builds a report purely from an archived backup (e.g. on an admin workstation).

.NOTES
    Run elevated on the CA host for the richest live output (some registry and
    certutil queries require administrative rights). The script is read-only:
    it makes no changes to the CA, the registry, or the backup set.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$BackupFolder,

    [Parameter()]
    [string]$BackupRoot,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$SkipLiveData
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Helpers ---------------------------------------------------------------

$script:CertSvcConfigPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'

function Write-Status {
    # Lightweight console progress (the report itself is the real output).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Message,
        [ValidateSet('Information', 'Warning')][string]$Level = 'Information'
    )
    if ($Level -eq 'Warning') { Write-Host "  ! $Message" -ForegroundColor Yellow }
    else { Write-Host "  - $Message" }
}

function ConvertTo-HtmlText {
    # HTML-encode arbitrary text (SecurityElement handles & < > " ' safely and
    # is always available, unlike System.Web on Server Core).
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return '' }
    return [System.Security.SecurityElement]::Escape([string]$Value)
}

function Format-RegistryValue {
    # Render a registry value (from the live provider) as a readable string,
    # decoding multi-strings and binary data.
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object]$Value, [string]$Kind)

    if ($null -eq $Value) { return '(null)' }

    switch ($Kind) {
        'MultiString' {
            if ($Value -is [System.Array]) { return (($Value | ForEach-Object { [string]$_ }) -join "`n") }
            return [string]$Value
        }
        'Binary' {
            $bytes = [byte[]]$Value
            if ($bytes.Length -eq 0) { return '(empty)' }
            $hex = ($bytes | ForEach-Object { $_.ToString('x2') }) -join ' '
            if ($hex.Length -gt 512) { $hex = $hex.Substring(0, 512) + ' ...' }
            return $hex
        }
        { $_ -in 'DWord', 'QWord' } {
            return ('{0} (0x{1:x})' -f $Value, $Value)
        }
        default {
            if ($Value -is [System.Array]) { return (($Value | ForEach-Object { [string]$_ }) -join "`n") }
            return [string]$Value
        }
    }
}

function Get-RegistryRows {
    # Recursively read a registry key into rows of { Key; Name; Type; Value }.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $rows = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $Path)) { return $rows }

    $keys = @(Get-Item -LiteralPath $Path)
    $keys += @(Get-ChildItem -LiteralPath $Path -Recurse -ErrorAction SilentlyContinue)

    foreach ($key in $keys) {
        # Present the key path relative to the CertSvc Configuration root.
        $relative = $key.Name -replace '^HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration', 'Configuration'
        $names = @($key.GetValueNames())
        if ($names.Count -eq 0) {
            $rows.Add([pscustomobject]@{ Key = $relative; Name = '(no values)'; Type = ''; Value = '' })
            continue
        }
        foreach ($name in ($names | Sort-Object)) {
            $displayName = if ([string]::IsNullOrEmpty($name)) { '(Default)' } else { $name }
            try {
                $kind  = $key.GetValueKind($name).ToString()
                $value = $key.GetValue($name, $null, 'DoNotExpandEnvironmentNames')
            }
            catch {
                $kind = 'Unknown'; $value = '(unreadable)'
            }
            $rows.Add([pscustomobject]@{
                Key   = $relative
                Name  = $displayName
                Type  = $kind
                Value = (Format-RegistryValue -Value $value -Kind $kind)
            })
        }
    }
    return $rows
}

function Get-CATypeName {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][object]$Value)

    switch ([string]$Value) {
        '0' { 'Enterprise Root CA' }
        '1' { 'Enterprise Subordinate CA' }
        '3' { 'Standalone Root CA' }
        '4' { 'Standalone Subordinate CA' }
        default { "Unknown ($Value)" }
    }
}

function Invoke-CertUtil {
    # Run a certutil query and return its text output, or $null on failure.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string[]]$Arguments)

    try {
        $out = & certutil.exe @Arguments 2>&1
        if ($LASTEXITCODE -ne 0) { return $null }
        return ($out | Out-String)
    }
    catch { return $null }
}

#region HTML building ---------------------------------------------------------

function New-Section {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$BodyHtml
    )
    return @"
<section id="$Id">
  <h2>$(ConvertTo-HtmlText $Title)</h2>
  $BodyHtml
</section>
"@
}

function New-KeyValueTable {
    # Build a two-column table from an ordered dictionary / hashtable of label => value.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Data)

    if ($Data.Count -eq 0) { return '<p class="muted">No data.</p>' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<table class="kv"><tbody>')
    foreach ($k in $Data.Keys) {
        $v = ConvertTo-HtmlText $Data[$k]
        $v = $v -replace "`r?`n", '<br>'
        [void]$sb.Append(('<tr><th>{0}</th><td>{1}</td></tr>' -f (ConvertTo-HtmlText $k), $v))
    }
    [void]$sb.Append('</tbody></table>')
    return $sb.ToString()
}

function New-ObjectTable {
    # Build a multi-column table from a collection of objects and a column list.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][string[]]$Columns
    )

    if ($null -eq $Rows -or $Rows.Count -eq 0) { return '<p class="muted">No data.</p>' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="tablewrap"><table class="grid"><thead><tr>')
    foreach ($c in $Columns) { [void]$sb.Append('<th>' + (ConvertTo-HtmlText $c) + '</th>') }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($row in $Rows) {
        [void]$sb.Append('<tr>')
        foreach ($c in $Columns) {
            $cell = if ($null -ne $row -and $row.PSObject.Properties[$c]) { $row.$c } else { '' }
            $cell = ConvertTo-HtmlText $cell
            $cell = $cell -replace "`r?`n", '<br>'
            [void]$sb.Append('<td>' + $cell + '</td>')
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    return $sb.ToString()
}

function New-PreBlock {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '<p class="muted">Not available.</p>' }
    return '<pre>' + (ConvertTo-HtmlText $Text.TrimEnd()) + '</pre>'
}

function New-Note {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Text, [ValidateSet('info', 'warn')][string]$Kind = 'info')
    return ('<p class="note {0}">{1}</p>' -f $Kind, (ConvertTo-HtmlText $Text))
}

#endregion --------------------------------------------------------------------

#region Data collection -------------------------------------------------------

function Get-ServerIdentity {
    [CmdletBinding()] param()
    $data = [ordered]@{}
    try {
        $cs  = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $os  = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue

        $fqdn = try { [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName } catch { $env:COMPUTERNAME }

        $data['Computer name']        = $cs.Name
        $data['Fully qualified name'] = $fqdn
        $data['Domain / workgroup']   = $cs.Domain
        $data['Domain member']        = if ($cs.PartOfDomain) { 'Yes' } else { 'No (workgroup)' }
        $data['Domain role']          = switch ([int]$cs.DomainRole) {
            0 { 'Standalone workstation' } 1 { 'Member workstation' }
            2 { 'Standalone server' }      3 { 'Member server' }
            4 { 'Backup domain controller' } 5 { 'Primary domain controller' }
            default { "Role $($cs.DomainRole)" }
        }
        $data['Operating system']  = $os.Caption
        $data['OS version / build'] = ('{0} (build {1})' -f $os.Version, $os.BuildNumber)
        $data['OS architecture']   = $os.OSArchitecture
        $data['Install date']      = if ($os.InstallDate) { $os.InstallDate.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
        $data['Last boot']         = if ($os.LastBootUpTime) { $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
        $data['Registered owner']  = $os.RegisteredUser
        $data['OS serial number']  = $os.SerialNumber
        $data['Manufacturer / model'] = ('{0} / {1}' -f $cs.Manufacturer, $cs.Model)
        if ($bios) { $data['BIOS serial'] = $bios.SerialNumber }
        $data['Logical processors'] = $cs.NumberOfLogicalProcessors
        $data['Physical memory']    = ('{0:N1} GB' -f ($cs.TotalPhysicalMemory / 1GB))
        $data['Time zone']          = try { (Get-TimeZone).DisplayName } catch { '' }
        $data['Report host time']   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')
    }
    catch {
        $data['Error'] = "Could not read server identity: $($_.Exception.Message)"
    }
    return $data
}

function Get-NetworkRows {
    [CmdletBinding()] param()
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration `
            -Filter 'IPEnabled = TRUE' -ErrorAction Stop
        foreach ($a in $adapters) {
            $rows.Add([pscustomobject]@{
                Adapter     = $a.Description
                'IP address(es)' = (@($a.IPAddress) -join "`n")
                'Subnet'    = (@($a.IPSubnet) -join "`n")
                Gateway     = (@($a.DefaultIPGateway) -join "`n")
                'DNS servers' = (@($a.DNSServerSearchOrder) -join "`n")
                MAC         = $a.MACAddress
                DHCP        = if ($a.DHCPEnabled) { 'Yes' } else { 'No (static)' }
            })
        }
    }
    catch { }
    return $rows.ToArray()
}

function Get-ServiceRows {
    [CmdletBinding()] param()
    # CA-relevant services; only those actually installed are reported.
    $names = [ordered]@{
        'CertSvc'     = 'Active Directory Certificate Services'
        'CertPropSvc' = 'Certificate Propagation'
        'W3SVC'       = 'World Wide Web Publishing (Web Enrollment / CES / CEP)'
        'WMSVC'       = 'Web Management Service'
        'IISADMIN'    = 'IIS Admin Service'
        'RpcSs'       = 'Remote Procedure Call (RPC)'
        'NTDS'        = 'Active Directory Domain Services'
        'DNS'         = 'DNS Server'
    }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($svcName in $names.Keys) {
        $cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$svcName'" -ErrorAction SilentlyContinue
        if (-not $cim) { continue }
        $rows.Add([pscustomobject]@{
            Service      = $svcName
            'Display name' = $cim.DisplayName
            State        = $cim.State
            'Start mode' = $cim.StartMode
            'Runs as'    = $cim.StartName
            Path         = $cim.PathName
        })
    }
    return $rows.ToArray()
}

function Get-AdcsFeatureRows {
    [CmdletBinding()] param()
    $rows = New-Object System.Collections.Generic.List[object]
    if (-not (Get-Command -Name Get-WindowsFeature -ErrorAction SilentlyContinue)) { return $rows.ToArray() }
    try {
        $features = Get-WindowsFeature -Name 'ADCS-*' -ErrorAction Stop
        foreach ($f in $features) {
            $rows.Add([pscustomobject]@{
                Feature      = $f.Name
                'Display name' = $f.DisplayName
                Installed    = if ($f.Installed) { 'Yes' } else { 'No' }
            })
        }
    }
    catch { }
    return $rows.ToArray()
}

function Get-CaSummary {
    # Reads key CA settings from the live registry into a decoded summary.
    [CmdletBinding()] param()
    $data = [ordered]@{}
    if (-not (Test-Path -LiteralPath $script:CertSvcConfigPath)) {
        $data['Status'] = 'CertSvc Configuration registry key not present on this host.'
        return @{ Summary = $data; CaName = $null }
    }

    $root = Get-Item -LiteralPath $script:CertSvcConfigPath
    $active = $root.GetValue('Active', $null)
    if ([string]::IsNullOrEmpty($active)) {
        $data['Status'] = 'No active CA configured (Active value empty).'
        return @{ Summary = $data; CaName = $null }
    }

    $caPath = Join-Path $script:CertSvcConfigPath $active
    $data['Active CA (config name)'] = $active
    if (Test-Path -LiteralPath $caPath) {
        $ca  = Get-Item -LiteralPath $caPath
        $get = { param($n) $ca.GetValue($n, $null) }

        $data['Common name']      = & $get 'CommonName'
        $data['CA type']          = Get-CATypeName (& $get 'CAType')
        $data['CA certificate hash'] = & $get 'CACertHash'
        $vpu = & $get 'ValidityPeriodUnits'; $vp = & $get 'ValidityPeriod'
        if ($null -ne $vpu -or $vp) { $data['Certificate validity period'] = ('{0} {1}' -f $vpu, $vp).Trim() }
        $cpu = & $get 'CRLPeriodUnits'; $cp = & $get 'CRLPeriod'
        if ($null -ne $cpu -or $cp) { $data['Base CRL period'] = ('{0} {1}' -f $cpu, $cp).Trim() }
        $opu = & $get 'CRLOverlapUnits'; $op = & $get 'CRLOverlapPeriod'
        if ($op) { $data['CRL overlap'] = ('{0} {1}' -f $opu, $op).Trim() }
        $dpu = & $get 'CRLDeltaPeriodUnits'; $dp = & $get 'CRLDeltaPeriod'
        if ($dp) {
            $delta = ('{0} {1}' -f $dpu, $dp).Trim()
            $data['Delta CRL period'] = if ($dpu -eq 0) { "$delta (disabled)" } else { $delta }
        }
        $crlUrls = & $get 'CRLPublicationURLs'
        if ($crlUrls) { $data['CRL publication URLs (CDP)'] = (@($crlUrls) -join "`n") }
        $aiaUrls = & $get 'CACertPublicationURLs'
        if ($aiaUrls) { $data['CA cert publication URLs (AIA)'] = (@($aiaUrls) -join "`n") }

        # Cryptographic provider (CSP / KSP) subkey.
        $cspPath = Join-Path $caPath 'CSP'
        if (Test-Path -LiteralPath $cspPath) {
            $csp = Get-Item -LiteralPath $cspPath
            $prov = $csp.GetValue('Provider', $null)
            if ($prov) { $data['Crypto provider'] = $prov }
            $hash = $csp.GetValue('HashAlgorithm', $null)
            $cngHash = $csp.GetValue('CNGHashAlgorithm', $null)
            if ($cngHash) { $data['Hash algorithm'] = $cngHash }
            elseif ($null -ne $hash) { $data['Hash algorithm (ID)'] = $hash }
            $klen = $csp.GetValue('KeyLength', $null)
            if ($null -ne $klen) { $data['Key length (bits)'] = $klen }
        }
    }
    else {
        $data['Status'] = "Active CA '$active' has no configuration subkey."
    }
    return @{ Summary = $data; CaName = $active }
}

function Get-CaCertificateRows {
    # CA signing certificate(s) from the local machine store, matched by CACertHash.
    [CmdletBinding()] param([string]$CommonName)
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        $store = @(Get-ChildItem -Path 'Cert:\LocalMachine\My' -ErrorAction Stop)
        $matched = if ($CommonName) {
            @($store | Where-Object { $_.Subject -match [regex]::Escape($CommonName) })
        } else { @() }
        if ($matched.Count -eq 0) { $matched = $store }

        foreach ($c in $matched) {
            $sigAlg = try { $c.SignatureAlgorithm.FriendlyName } catch { '' }
            $keySize = try { $c.PublicKey.Key.KeySize } catch { '' }
            $rows.Add([pscustomobject]@{
                Subject       = $c.Subject
                Issuer        = $c.Issuer
                Thumbprint    = $c.Thumbprint
                Serial        = $c.SerialNumber
                'Valid from'  = $c.NotBefore.ToString('yyyy-MM-dd')
                'Valid to'    = $c.NotAfter.ToString('yyyy-MM-dd')
                'Signature alg' = $sigAlg
                'Key size'    = $keySize
            })
        }
    }
    catch { }
    return $rows.ToArray()
}

function Get-BackupInventory {
    # Inventory of the backup set and its captured configuration artifacts.
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Folder)

    $result = [ordered]@{
        Summary   = [ordered]@{}
        FileRows  = @()
        RegDumpText = $null
        HasRegExport = $false
    }

    $files = @(Get-ChildItem -LiteralPath $Folder -Recurse -File -ErrorAction SilentlyContinue)
    $p12   = @($files | Where-Object { $_.Extension -eq '.p12' })
    $db    = @($files | Where-Object { $_.Extension -in '.edb', '.dat' })
    $reg   = $files | Where-Object { $_.Name -eq 'CertSvc-Configuration.reg' } | Select-Object -First 1
    $txt   = $files | Where-Object { $_.Name -eq 'CertSvc-Configuration.txt' } | Select-Object -First 1
    $failMarker = $files | Where-Object { $_.Name -eq 'BACKUP_FAILED.txt' } | Select-Object -First 1

    $result.Summary['Backup folder']     = $Folder
    $result.Summary['Created (folder)']   = (Get-Item -LiteralPath $Folder).CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
    $result.Summary['Total files']        = $files.Count
    $result.Summary['Total size']         = ('{0:N2} MB' -f ((($files | Measure-Object -Property Length -Sum).Sum) / 1MB))
    $result.Summary['Database file(s)']   = if ($db.Count) { (@($db | ForEach-Object { $_.Name }) -join ', ') } else { '(none found)' }
    $result.Summary['Private key (.p12)'] = if ($p12.Count) { (@($p12 | ForEach-Object { $_.Name }) -join ', ') } else { '(none found)' }
    $result.Summary['Config registry export'] = if ($reg) { $reg.Name } else { '(none found)' }
    $result.Summary['Config human dump']  = if ($txt) { $txt.Name } else { '(none found)' }
    if ($failMarker) { $result.Summary['WARNING'] = 'BACKUP_FAILED.txt present — this backup set is incomplete.' }

    $result.HasRegExport = [bool]$reg
    if ($txt) {
        try { $result.RegDumpText = Get-Content -LiteralPath $txt.FullName -Raw -ErrorAction Stop } catch { }
    }

    $result.FileRows = @($files | Sort-Object FullName | ForEach-Object {
        [pscustomobject]@{
            File     = $_.FullName.Substring($Folder.Length).TrimStart('\')
            Size     = ('{0:N1} KB' -f ($_.Length / 1KB))
            Modified = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        }
    })
    return $result
}

#endregion --------------------------------------------------------------------

#endregion --------------------------------------------------------------------

#region Main ------------------------------------------------------------------

try {
    Write-Status "Certification Authority configuration report"

    # --- Resolve the backup folder (optional) --------------------------------
    if (-not $BackupFolder -and $BackupRoot) {
        if (-not (Test-Path -LiteralPath $BackupRoot)) { throw "BackupRoot not found: $BackupRoot" }
        $newest = Get-ChildItem -LiteralPath $BackupRoot -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like 'CABackup_*' } |
            Sort-Object -Property Name -Descending | Select-Object -First 1
        if (-not $newest) { throw "No CABackup_* folders found under: $BackupRoot" }
        $BackupFolder = $newest.FullName
        Write-Status "Auto-selected newest backup: $($newest.Name)"
    }

    $backup = $null
    if ($BackupFolder) {
        if (-not (Test-Path -LiteralPath $BackupFolder)) { throw "Backup folder not found: $BackupFolder" }
        $BackupFolder = (Resolve-Path -LiteralPath $BackupFolder).Path
        Write-Status "Reading backup set: $BackupFolder"
        $backup = Get-BackupInventory -Folder $BackupFolder
    }
    else {
        Write-Status "No backup folder supplied; using live data only." -Level Warning
    }

    # --- Collect live data ----------------------------------------------------
    $live = $SkipLiveData -eq $false
    $serverIdentity = [ordered]@{}
    $networkRows = @(); $serviceRows = @(); $featureRows = @()
    $caResult = @{ Summary = [ordered]@{}; CaName = $null }
    $caCertRows = @(); $caInfoText = $null; $templatesText = $null; $regRows = @()

    if ($live) {
        Write-Status "Collecting server identification..."
        $serverIdentity = Get-ServerIdentity
        $networkRows    = @(Get-NetworkRows)

        Write-Status "Collecting service configuration..."
        $serviceRows = @(Get-ServiceRows)
        $featureRows = @(Get-AdcsFeatureRows)

        Write-Status "Collecting CA configuration and registry..."
        $caResult   = Get-CaSummary
        $caCertRows = @(Get-CaCertificateRows -CommonName ([string]$caResult.CaName))
        $regRows    = @(Get-RegistryRows -Path $script:CertSvcConfigPath)

        $caInfoText    = Invoke-CertUtil -Arguments @('-cainfo')
        $templatesText = Invoke-CertUtil -Arguments @('-CATemplates')
    }
    else {
        Write-Status "Skipping live data (-SkipLiveData)." -Level Warning
    }

    # --- Resolve output path --------------------------------------------------
    if (-not $OutputPath) {
        $stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
        $fileName = ('CA-Configuration-Report_{0}_{1}.html' -f $env:COMPUTERNAME, $stamp)
        $dir = if ($BackupFolder) { $BackupFolder } else { (Get-Location).Path }
        $OutputPath = Join-Path $dir $fileName
    }
    $outDir = Split-Path -Path $OutputPath -Parent
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }

    # --- Build HTML sections --------------------------------------------------
    Write-Status "Rendering HTML report..."
    $sections = New-Object System.Collections.Generic.List[string]

    # Report metadata / overview
    $overview = [ordered]@{
        'Report generated'   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        'Generated by'       = ('{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME)
        'Report host'        = $env:COMPUTERNAME
        'Live data included' = if ($live) { 'Yes' } else { 'No (backup only)' }
        'Backup set'         = if ($BackupFolder) { $BackupFolder } else { '(none)' }
    }
    $sections.Add((New-Section -Title 'Report overview' -Id 'overview' -BodyHtml (New-KeyValueTable $overview)))

    # Server identity
    if ($live) {
        $body = New-KeyValueTable $serverIdentity
        $body += '<h3>Network configuration</h3>'
        $body += New-ObjectTable -Rows $networkRows -Columns @('Adapter', 'IP address(es)', 'Subnet', 'Gateway', 'DNS servers', 'MAC', 'DHCP')
        $sections.Add((New-Section -Title 'Windows server identification' -Id 'server' -BodyHtml $body))

        # Services
        $svcBody = New-ObjectTable -Rows $serviceRows -Columns @('Service', 'Display name', 'State', 'Start mode', 'Runs as', 'Path')
        if ($featureRows.Count) {
            $svcBody += '<h3>AD CS role features</h3>'
            $svcBody += New-ObjectTable -Rows $featureRows -Columns @('Feature', 'Display name', 'Installed')
        }
        $sections.Add((New-Section -Title 'Related services configuration' -Id 'services' -BodyHtml $svcBody))
    }

    # CA identity & certificate
    if ($live) {
        $caBody = New-KeyValueTable $caResult.Summary
        $caBody += '<h3>CA signing certificate(s)</h3>'
        $caBody += New-ObjectTable -Rows $caCertRows -Columns @('Subject', 'Issuer', 'Thumbprint', 'Serial', 'Valid from', 'Valid to', 'Signature alg', 'Key size')
        $sections.Add((New-Section -Title 'Certification Authority — identity & certificate' -Id 'ca' -BodyHtml $caBody))
    }

    # Live registry (the primary focus)
    if ($live) {
        $regBody = New-Note 'Full structured dump of HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration (live server).'
        $regBody += New-ObjectTable -Rows $regRows -Columns @('Key', 'Name', 'Type', 'Value')
        $sections.Add((New-Section -Title 'CA registry configuration (live)' -Id 'registry-live' -BodyHtml $regBody))
    }

    # certutil detail
    if ($live -and ($caInfoText -or $templatesText)) {
        $cuBody = '<h3>certutil -cainfo</h3>' + (New-PreBlock $caInfoText)
        $cuBody += '<h3>certutil -CATemplates (published certificate templates)</h3>' + (New-PreBlock $templatesText)
        $sections.Add((New-Section -Title 'CA details (certutil)' -Id 'certutil' -BodyHtml $cuBody))
    }

    # Backup set
    if ($backup) {
        $bBody = New-KeyValueTable $backup.Summary
        if ($backup.HasRegExport) {
            $bBody += New-Note 'CertSvc-Configuration.reg is present — the CA configuration hive can be re-imported during restore.'
        }
        else {
            $bBody += New-Note 'No CertSvc-Configuration.reg found in this backup set — configuration would not be restorable from it.' -Kind 'warn'
        }
        $bBody += '<h3>Backup file inventory</h3>'
        $bBody += New-ObjectTable -Rows $backup.FileRows -Columns @('File', 'Size', 'Modified')
        $bBody += '<h3>Captured CA configuration (CertSvc-Configuration.txt)</h3>'
        $bBody += New-Note 'Human-readable certutil -getreg CA dump captured at backup time (represents CA state when backed up).'
        $bBody += New-PreBlock $backup.RegDumpText
        $sections.Add((New-Section -Title 'Backup set — captured CA configuration' -Id 'backup' -BodyHtml $bBody))
    }

    # --- Assemble document ----------------------------------------------------
    $caHeading = if ($caResult.CaName) { ConvertTo-HtmlText $caResult.CaName }
                 elseif ($backup -and $backup.RegDumpText) { 'CA (from backup)' }
                 else { 'Certification Authority' }

    $nav = New-Object System.Text.StringBuilder
    [void]$nav.Append('<nav class="toc"><strong>Contents</strong><ul>')
    foreach ($s in $sections) {
        if ($s -match 'id="([^"]+)">\s*<h2>([^<]+)</h2>') {
            [void]$nav.Append(('<li><a href="#{0}">{1}</a></li>' -f $Matches[1], $Matches[2]))
        }
    }
    [void]$nav.Append('</ul></nav>')

    $css = @'
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{font-family:Segoe UI,-apple-system,Arial,sans-serif;margin:0;background:#f4f5f7;color:#1c2733;line-height:1.45}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
header.rpt{background:#12324f;color:#fff;padding:28px 24px;border-radius:0 0 8px 8px}
header.rpt h1{margin:0 0 4px;font-size:22px}
header.rpt .sub{opacity:.85;font-size:13px}
nav.toc{background:#fff;border:1px solid #dfe3e8;border-radius:8px;padding:14px 18px;margin:20px 0}
nav.toc ul{margin:8px 0 0;padding-left:18px;columns:2;font-size:14px}
nav.toc a{color:#12324f;text-decoration:none}
nav.toc a:hover{text-decoration:underline}
section{background:#fff;border:1px solid #dfe3e8;border-radius:8px;padding:18px 22px;margin:0 0 20px}
h2{margin:0 0 14px;font-size:18px;color:#12324f;border-bottom:2px solid #e6eaf0;padding-bottom:8px}
h3{font-size:14px;color:#334;margin:22px 0 8px;text-transform:uppercase;letter-spacing:.03em}
table{border-collapse:collapse;width:100%;font-size:13px}
table.kv th{text-align:left;width:32%;vertical-align:top;color:#4a5b6b;font-weight:600;padding:6px 12px 6px 0;border-bottom:1px solid #eef1f4}
table.kv td{padding:6px 0;border-bottom:1px solid #eef1f4;word-break:break-word}
.tablewrap{overflow-x:auto}
table.grid th{background:#eef2f6;text-align:left;padding:8px 10px;border:1px solid #dfe3e8;color:#334;position:sticky;top:0}
table.grid td{padding:7px 10px;border:1px solid #eef1f4;vertical-align:top;word-break:break-word}
table.grid tr:nth-child(even) td{background:#fafbfc}
pre{background:#0f1b26;color:#d6e2ee;padding:14px;border-radius:6px;overflow-x:auto;font-size:12px;line-height:1.4;white-space:pre-wrap;word-break:break-word}
.muted{color:#8a97a4;font-style:italic}
.note{border-left:4px solid #2d6cdf;background:#eef4ff;padding:8px 12px;border-radius:0 4px 4px 0;font-size:13px;margin:8px 0}
.note.warn{border-left-color:#d98324;background:#fff6ec}
footer.rpt{text-align:center;color:#8a97a4;font-size:12px;padding:18px}
@media(max-width:720px){nav.toc ul{columns:1}table.kv th{width:42%}}
@media print{body{background:#fff}section,nav.toc{border:none;box-shadow:none}header.rpt{border-radius:0}}
'@

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CA Configuration Report — $caHeading</title>
<style>$css</style>
</head>
<body>
<header class="rpt">
  <h1>Certification Authority Configuration Report</h1>
  <div class="sub">$caHeading &nbsp;&middot;&nbsp; Host: $(ConvertTo-HtmlText $env:COMPUTERNAME) &nbsp;&middot;&nbsp; Generated $(ConvertTo-HtmlText ((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')))</div>
</header>
<div class="wrap">
$($nav.ToString())
$([string]::Join("`n", $sections.ToArray()))
</div>
<footer class="rpt">Generated by New-CAConfigurationReport.ps1 &middot; read-only documentation of AD CS configuration</footer>
</body>
</html>
"@

    Set-Content -LiteralPath $OutputPath -Value $html -Encoding UTF8
    Write-Host ""
    Write-Host "Report written to: $OutputPath" -ForegroundColor Green
    Write-Output $OutputPath

    # Reset the exit code: guarded certutil queries may have left $LASTEXITCODE
    # non-zero even though the report was produced successfully.
    exit 0
}
catch {
    Write-Error "Failed to generate CA configuration report: $($_.Exception.Message)"
    exit 1
}

#endregion --------------------------------------------------------------------
