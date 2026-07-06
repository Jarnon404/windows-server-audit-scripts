#requires -Version 5.1
<#
.SYNOPSIS
Public-safe Windows Server audit and inventory script.

.DESCRIPTION
Collects local or remote Windows Server inventory, update, security, service,
network, firewall, Defender and optional SQL-related information into HTML and
supporting output files.

This public version has been sanitized for GitHub:
- no customer names
- no tenant identifiers
- no internal hostnames
- no private IP addresses
- no credentials or secrets
- no generated audit reports

.NOTES
Run from an elevated PowerShell session when possible.
#>

$ErrorActionPreference = "Stop"

# ---------------- TARGET COMPUTER: kysy alussa ----------------
$TargetComputer = Read-Host "Enter target computer (FQDN/hostname). Empty = local computer"
if ([string]::IsNullOrWhiteSpace($TargetComputer)) { $TargetComputer = $env:COMPUTERNAME }

# ---------------- SETTINGS ----------------
$ComputerName = $TargetComputer
$Stamp = Get-Date -Format "ddMMyyyy-HHmmss"

# UUSI: yhteinen ALKUprefix kaikille output-tiedostoille (kone+pvm+aika)
$NamePrefix = "{0}-{1}" -f $ComputerName, $Stamp

# MUUTOS: raportit kansioon AuditReports\<computer name>
$OutDir   = Join-Path (Join-Path $PWD "AuditReports") $ComputerName

# UUSI: raportti alkaa prefixillä
$HtmlPath = Join-Path $OutDir ("{0}-Windows-Server-Audit.html" -f $NamePrefix)

$MaxFirewallRules   = 300
$MaxDefenderThreats = 50
$MaxInstalledApps   = 500

$SqlInstance = "localhost" # HUOM: Etäkohteessa tämä tarkoittaa kohdekoneen localhostia, kun ajetaan Invoke-Commandilla

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# ---------------- HELPERS: SAFE RUN ----------------
function Try-Run {
  param([Parameter(Mandatory=$true)][scriptblock]$Script, $Default = $null)
  try { & $Script } catch { $Default }
}

# UUSI: etäajo wrapper (WinRM). Jos WinRM ei ole käytössä, palauttaa Default eikä kaada scriptiä.
function Try-InvokeRemote {
  param(
    [Parameter(Mandatory=$true)][string]$ComputerName,
    [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
    $Default = $null
  )
  try {
    Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock -ErrorAction Stop
  } catch {
    $Default
  }
}

# UUSI: Onko kohde etä?
$IsRemote = -not ($ComputerName -ieq $env:COMPUTERNAME -or $ComputerName -ieq "localhost" -or $ComputerName -ieq ".")

# UUSI: CIM-sessio (DCOM). Toimii monessa ympäristössä ilman WinRM:ää.
$cim = $null
if ($IsRemote) {
  $cim = Try-Run {
    $so = New-CimSessionOption -Protocol Dcom
    New-CimSession -ComputerName $ComputerName -SessionOption $so -ErrorAction Stop
  } $null
}

# UUSI: ajoloki + virheloki (alkuprefixillä)
$RunLog   = Join-Path $OutDir ("{0}-run.log" -f $NamePrefix)
$ErrorLog = Join-Path $OutDir ("{0}-error.txt" -f $NamePrefix)

# UUSI: CSS-fixi DataTablesin hakukenttien + headerin näkyvyyteen
$FixCss = @'
/* ---------------------------
   DataTables: header + filters fix (ScrollX clone aware)
   --------------------------- */

/* 1) Header cell + cloned header (ScrollX) */
table.dataTable thead th,
table.dataTable thead td,
.dataTables_wrapper .dataTables_scrollHead table.dataTable thead th,
.dataTables_wrapper .dataTables_scrollHead table.dataTable thead td {
  background: #f3f4f6 !important;
  color: #111 !important;
  font-weight: 600 !important;
  white-space: nowrap !important;
  padding: 8px 10px !important;
  vertical-align: middle !important;
}

/* 2) DataTables puts the actual title into spans */
table.dataTable thead th .dt-column-title,
table.dataTable thead th .dt-column-order,
.dataTables_wrapper .dataTables_scrollHead table.dataTable thead th .dt-column-title,
.dataTables_wrapper .dataTables_scrollHead table.dataTable thead th .dt-column-order {
  color: #111 !important;
}

/* 3) Make sure header content isn't clipped/hidden */
table.dataTable thead th,
.dataTables_wrapper .dataTables_scrollHead table.dataTable thead th {
  overflow: visible !important;
}

/* 4) Filter inputs/selects in header */
table.dataTable thead th input,
table.dataTable thead th select {
  width: 100% !important;
  box-sizing: border-box !important;
  color: #111 !important;
  background: #fff !important;
  border: 1px solid #999 !important;
  border-radius: 4px !important;
  height: 30px !important;
  line-height: 30px !important;
  padding: 0 8px !important;
}

/* Placeholder */
table.dataTable thead th input::placeholder {
  color: #666 !important;
  opacity: 1 !important;
}

/* 5) Global search + length dropdown */
.dataTables_filter input,
.dataTables_wrapper .dataTables_length select,
.dtsp-searchPane input,
.dtsp-searchPane select,
.dtsb-searchBuilder input,
.dtsb-searchBuilder select {
  color: #111 !important;
  background: #fff !important;
  border-color: #999 !important;
}

/* 6) If ScrollX squeezes columns, help it a bit */
.dataTables_wrapper .dataTables_scrollHeadInner,
.dataTables_wrapper .dataTables_scrollHeadInner table {
  width: 100% !important;
}

/* Optional: make very narrow columns readable */
table.dataTable thead th {
  min-width: 70px; /* prevents microscopic headers like in your screenshot */
}
'@

try {
  Try-Run { Start-Transcript -Path $RunLog -Append | Out-Null } $null | Out-Null

  # ---------------- PSWriteHTML ----------------
  if (-not (Get-Module -ListAvailable -Name PSWriteHTML)) {
    Install-Module PSWriteHTML -Scope CurrentUser -Force -AllowClobber
  }
  Import-Module PSWriteHTML -Force

  # ---------------- HELPERS ----------------
  function Join-Arr {
    param($Value)
    if ($null -eq $Value) { return "" }
    if ($Value -is [System.Array]) { return (@($Value) | Where-Object { $_ }) -join ", " }
    return [string]$Value
  }

  function Convert-ToFlatTableData {
    param([Parameter(Mandatory=$true)]$Data)

    $items = @($Data)
    if ($items.Count -eq 0) { return @() }

    $out = foreach ($row in $items) {
      if ($null -eq $row) { continue }

      $props = $row.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' -or $_.MemberType -eq 'Property' }
      $ht = [ordered]@{}

      foreach ($p in $props) {
        $v = $p.Value

        if ($null -eq $v) { $ht[$p.Name] = ""; continue }

        if ($v -is [System.Array]) {
          $ht[$p.Name] = ( @($v) | ForEach-Object { if ($_ -eq $null) { "" } else { [string]$_ } } | Where-Object { $_ } ) -join ", "
          continue
        }

        if ($v -is [datetime]) {
          $ht[$p.Name] = $v.ToString("yyyy-MM-dd HH:mm:ss")
          continue
        }

        switch ($v.GetType().FullName) {
          "System.String"  { $ht[$p.Name] = $v; break }
          "System.Int16"   { $ht[$p.Name] = $v; break }
          "System.Int32"   { $ht[$p.Name] = $v; break }
          "System.Int64"   { $ht[$p.Name] = $v; break }
          "System.UInt16"  { $ht[$p.Name] = $v; break }
          "System.UInt32"  { $ht[$p.Name] = $v; break }
          "System.UInt64"  { $ht[$p.Name] = $v; break }
          "System.Double"  { $ht[$p.Name] = $v; break }
          "System.Decimal" { $ht[$p.Name] = $v; break }
          "System.Boolean" { $ht[$p.Name] = $v; break }
          default          { $ht[$p.Name] = [string]$v; break }
        }
      }

      [pscustomobject]$ht
    }

    @($out)
  }

  function New-NiceTable {
    param(
      [Parameter(Mandatory=$true)] $Data,
      [int] $PageLength = 25,
      [switch] $HideFooter
    )

    $arr = Convert-ToFlatTableData -Data $Data
    if ($null -eq $arr -or $arr.Count -eq 0) {
      New-HTMLText -Text "Ei dataa." -FontSize 12
      return
    }

    $btn = @(
      'copyHtml5',
      'csvHtml5',
      'excelHtml5',
      'pdfHtml5',
      'print',
      'pageLength',
      'searchBuilder',
      'searchPanes',
      'columnVisibility'
    )

    $common = @{
      DataTable          = $arr
      ScrollX            = $true
      Filtering          = $true
      FilteringLocation  = 'Top'
      PagingLength       = $PageLength
      Buttons            = $btn
    }

    if ($HideFooter) { New-HTMLTable @common -HideFooter }
    else { New-HTMLTable @common }
  }

  function New-FlatTable {
    param(
      [Parameter(Mandatory=$true)] $DataTable,
      [switch] $HideFooter
    )

    $flat = Convert-ToFlatTableData -Data $DataTable
    if ($HideFooter) { New-HTMLTable -DataTable $flat -HideFooter }
    else { New-HTMLTable -DataTable $flat }
  }

  function Test-IsAdmin {
    try {
      $id = [Security.Principal.WindowsIdentity]::GetCurrent()
      $p  = New-Object Security.Principal.WindowsPrincipal($id)
      return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
  }

  # UUSI: reboot pending myös etänä (WinRM)
  function Get-RebootPending {
    param([string]$ComputerName, [switch]$Remote)

    if ($Remote) {
      return Try-InvokeRemote -ComputerName $ComputerName -Default ([pscustomobject]@{Pending=$false;Reasons="(ei saatu etänä)"}) -ScriptBlock {
        $pending = $false
        $reasons = @()
        $paths = @(
          "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
          "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        )

        foreach ($p in $paths) {
          if (Test-Path $p) { $pending = $true; $reasons += (Split-Path $p -Leaf) }
        }

        try {
          $pf = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction Stop
          if ($pf -and $pf.PendingFileRenameOperations) { $pending = $true; $reasons += "PendingFileRenameOperations" }
        } catch {}

        [pscustomobject]@{ Pending=$pending; Reasons=($reasons | Sort-Object -Unique) -join ", " }
      }
    }

    $pending = $false
    $reasons = @()

    $paths = @(
      "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
      "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    )

    foreach ($p in $paths) {
      if (Test-Path $p) {
        $pending = $true
        $reasons += (Split-Path $p -Leaf)
      }
    }

    $pf = Try-Run { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction Stop } $null
    if ($pf -and $pf.PendingFileRenameOperations) {
      $pending = $true
      $reasons += "PendingFileRenameOperations"
    }

    [pscustomobject]@{
      Pending = $pending
      Reasons = ($reasons | Sort-Object -Unique) -join ", "
    }
  }

  # UUSI: viimeisin hotfix etänä (WinRM)
  function Get-LastHotFix {
    param([string]$ComputerName, [switch]$Remote)
    if ($Remote) {
      return Try-InvokeRemote -ComputerName $ComputerName -Default $null -ScriptBlock {
        Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 HotFixID, Description, InstalledOn
      }
    }
    Try-Run {
      Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 HotFixID, Description, InstalledOn
    } $null
  }

  # UUSI: Listening ports etänä (WinRM) jos onnistuu
  function Get-ListeningPorts {
    param([string]$ComputerName, [switch]$Remote)

    if ($Remote) {
      return Try-InvokeRemote -ComputerName $ComputerName -Default @() -ScriptBlock {
        if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) { return @() }

        $list = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
          Select-Object LocalAddress, LocalPort, OwningProcess -Unique |
          Sort-Object LocalPort, LocalAddress

        foreach ($c in $list) {
          $pname = ""
          try { $pname = (Get-Process -Id $c.OwningProcess -ErrorAction Stop).ProcessName } catch {}
          [pscustomobject]@{
            LocalAddress  = [string]$c.LocalAddress
            LocalPort     = $c.LocalPort
            ProcessId     = $c.OwningProcess
            ProcessName   = $pname
          }
        }
      }
    }

    if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) { return @() }
    Try-Run {
      $list = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, OwningProcess -Unique |
        Sort-Object LocalPort, LocalAddress

      foreach ($c in $list) {
        $pname = Try-Run { (Get-Process -Id $c.OwningProcess -ErrorAction Stop).ProcessName } ""
        [pscustomobject]@{
          LocalAddress  = [string]$c.LocalAddress
          LocalPort     = $c.LocalPort
          ProcessId     = $c.OwningProcess
          ProcessName   = $pname
        }
      }
    } @()
  }

  function Get-FileHashes {
    param([Parameter(Mandatory=$true)][string[]]$Paths)
    $rows = @()
    foreach ($p in $Paths) {
      if ($p -and (Test-Path $p)) {
        $h = Try-Run { Get-FileHash -Path $p -Algorithm SHA256 } $null
        if ($h) {
          $rows += [pscustomobject]@{
            File      = (Split-Path $p -Leaf)
            Algorithm = $h.Algorithm
            Hash      = $h.Hash
          }
        }
      }
    }
    $rows
  }

  $Now = Get-Date

  # ---------------- EXEC CONTEXT ----------------
  $isAdmin = Test-IsAdmin
  $execContext = @(
    [pscustomobject]@{ Kenttä="Käyttäjä"; Arvo=("{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME) }
    [pscustomobject]@{ Kenttä="Admin-oikeudet"; Arvo=$isAdmin }
    [pscustomobject]@{ Kenttä="PowerShell"; Arvo=("$($PSVersionTable.PSVersion)") }
    [pscustomobject]@{ Kenttä="Host"; Arvo=("$($Host.Name) $($Host.Version)") }
    [pscustomobject]@{ Kenttä="Arkkitehtuuri"; Arvo=$env:PROCESSOR_ARCHITECTURE }
    [pscustomobject]@{ Kenttä="ScriptPath"; Arvo=($MyInvocation.MyCommand.Path) }
    [pscustomobject]@{ Kenttä="WorkingDir"; Arvo=$PWD.Path }
    [pscustomobject]@{ Kenttä="Kohde"; Arvo=$ComputerName }
    [pscustomobject]@{ Kenttä="Etäajo"; Arvo=$IsRemote }
    [pscustomobject]@{ Kenttä="CIM (DCOM) sessio"; Arvo=([bool]$cim) }
  )

  $reboot     = Get-RebootPending -ComputerName $ComputerName -Remote:$IsRemote
  $lastHotfix = Get-LastHotFix   -ComputerName $ComputerName -Remote:$IsRemote

  # ---------------- KERUU: PERUS (CIM sessiolla jos etä) ----------------
  $os    = if ($cim) { Try-Run { Get-CimInstance Win32_OperatingSystem -CimSession $cim } $null } else { Try-Run { Get-CimInstance Win32_OperatingSystem } $null }
  $bios  = if ($cim) { Try-Run { Get-CimInstance Win32_BIOS          -CimSession $cim } $null } else { Try-Run { Get-CimInstance Win32_BIOS } $null }
  $cpu   = if ($cim) { Try-Run { Get-CimInstance Win32_Processor     -CimSession $cim } $null } else { Try-Run { Get-CimInstance Win32_Processor } $null }
  $cs    = if ($cim) { Try-Run { Get-CimInstance Win32_ComputerSystem -CimSession $cim } $null } else { Try-Run { Get-CimInstance Win32_ComputerSystem } $null }
  $disks = if ($cim) { Try-Run { Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -CimSession $cim } @() } else { Try-Run { Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" } @() }
  $net   = if ($cim) { Try-Run { Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true" -CimSession $cim } @() } else { Try-Run { Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true" } @() }

  # ---------------- APPS (REGISTRY) ----------------
  # Etänä: yritetään Invoke-Commandilla. Paikallisesti: kuten ennen.
  $apps = if ($IsRemote) {
    Try-InvokeRemote -ComputerName $ComputerName -Default @() -ScriptBlock {
      $MaxInstalledApps = $using:MaxInstalledApps
      $sources = @(
        @{ Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"; Scope="Machine" },
        @{ Path="HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"; Scope="Machine" },
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"; Scope="User" }
      )

      $list = foreach ($s in $sources) {
        Get-ItemProperty $s.Path -ErrorAction SilentlyContinue |
          Where-Object { $_.DisplayName } |
          Select-Object @{n="Scope";e={$s.Scope}}, DisplayName, DisplayVersion, Publisher, InstallDate
      }

      $list | Sort-Object DisplayName, Scope -Unique | Select-Object -First $MaxInstalledApps
    }
  } else {
    Try-Run {
      $sources = @(
        @{ Path="HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"; Scope="Machine" },
        @{ Path="HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"; Scope="Machine" },
        @{ Path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"; Scope="User" }
      )

      $list = foreach ($s in $sources) {
        Get-ItemProperty $s.Path -ErrorAction SilentlyContinue |
          Where-Object { $_.DisplayName } |
          Select-Object @{n="Scope";e={$s.Scope}}, DisplayName, DisplayVersion, Publisher, InstallDate
      }

      $list | Sort-Object DisplayName, Scope -Unique | Select-Object -First $MaxInstalledApps
    } @()
  }

  # ---------------- KERUU: AD ----------------
  $adInfo = if ($IsRemote) {
    Try-InvokeRemote -ComputerName $ComputerName -Default $null -ScriptBlock { Get-ComputerInfo | Select-Object CsDomain, CsDomainRole, CsPartOfDomain }
  } else {
    Try-Run { Get-ComputerInfo | Select-Object CsDomain, CsDomainRole, CsPartOfDomain } $null
  }

  $adModuleAvailable = $false
  $adComputer = $null
  $adGroups   = @()
  Try-Run {
    Import-Module ActiveDirectory -ErrorAction Stop
    $adModuleAvailable = $true
    $adComputer = Get-ADComputer -Identity $ComputerName -Properties DistinguishedName, OperatingSystem, OperatingSystemVersion, LastLogonDate, whenCreated
    $adGroups = Get-ADPrincipalGroupMembership -Identity $adComputer | Select-Object Name, DistinguishedName
  } $null | Out-Null

  # ---------------- KERUU: ROOLIT/FEATURET ----------------
  $features = @()

  if ($IsRemote) {
    $features = Try-InvokeRemote -ComputerName $ComputerName -Default @() -ScriptBlock {
      if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        Import-Module ServerManager -ErrorAction SilentlyContinue | Out-Null
        Get-WindowsFeature |
          Where-Object { $_.Installed -eq $true } |
          Select-Object DisplayName, Name, FeatureType, Path
      } else {
        Get-WindowsCapability -Online |
          Where-Object { $_.State -eq "Installed" } |
          Select-Object @{n="DisplayName";e={$_.Name}}, @{n="Name";e={$_.Name}}, @{n="FeatureType";e={"Capability"}}, @{n="Path";e={""}}
      }
    }
  } else {
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
      $features = Try-Run {
        Import-Module ServerManager -ErrorAction Stop
        Get-WindowsFeature |
          Where-Object { $_.Installed -eq $true } |
          Select-Object DisplayName, Name, FeatureType, Path
      } @()
    } else {
      $features = Try-Run {
        Get-WindowsCapability -Online |
          Where-Object { $_.State -eq "Installed" } |
          Select-Object @{n="DisplayName";e={$_.Name}}, @{n="Name";e={$_.Name}}, @{n="FeatureType";e={"Capability"}}, @{n="Path";e={""}}
      } @()
    }
  }

  # UUSI: nimeä features-dumpit alkuprefixillä
  $featuresCsv  = Join-Path $OutDir ("{0}-windows-features.csv" -f $NamePrefix)
  $featuresJson = Join-Path $OutDir ("{0}-windows-features.json" -f $NamePrefix)
  if ($features -and @($features).Count -gt 0) {
    $features | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $featuresCsv
    $features | ConvertTo-Json -Depth 6 | Out-File -Encoding UTF8 $featuresJson
  }

  # ---------------- KERUU: IIS ----------------
  $iisInstalled = $false
  $iisSites     = @()
  $iisAppPools  = @()
  $iisBindings  = @()

  if ($IsRemote) {
    $iisData = Try-InvokeRemote -ComputerName $ComputerName -Default $null -ScriptBlock {
      try {
        Import-Module WebAdministration -ErrorAction Stop
        $sites = Get-ChildItem IIS:\Sites | Select-Object Name, State, PhysicalPath
        $pools = Get-ChildItem IIS:\AppPools | Select-Object Name, State, managedRuntimeVersion, managedPipelineMode
        $bind  = Get-ChildItem IIS:\Sites | ForEach-Object {
          $siteName = $_.Name
          (Get-WebBinding -Name $siteName) | ForEach-Object {
            [pscustomobject]@{ Site=$siteName; Protocol=$_.protocol; Binding=$_.bindingInformation }
          }
        }
        [pscustomobject]@{ Installed=$true; Sites=$sites; Pools=$pools; Bindings=$bind }
      } catch {
        [pscustomobject]@{ Installed=$false; Sites=@(); Pools=@(); Bindings=@() }
      }
    }
    if ($iisData) {
      $iisInstalled = [bool]$iisData.Installed
      $iisSites     = @($iisData.Sites)
      $iisAppPools  = @($iisData.Pools)
      $iisBindings  = @($iisData.Bindings)
    }
  } else {
    Try-Run {
      Import-Module WebAdministration -ErrorAction Stop
      $iisInstalled = $true
      $iisSites = Get-ChildItem IIS:\Sites | Select-Object Name, State, PhysicalPath
      $iisAppPools = Get-ChildItem IIS:\AppPools | Select-Object Name, State, managedRuntimeVersion, managedPipelineMode
      $iisBindings = Get-ChildItem IIS:\Sites | ForEach-Object {
        $siteName = $_.Name
        (Get-WebBinding -Name $siteName) | ForEach-Object {
          [pscustomobject]@{
            Site     = $siteName
            Protocol = $_.protocol
            Binding  = $_.bindingInformation
          }
        }
      }
    } $null | Out-Null
  }

  # ---------------- KERUU: SQL ----------------
  $sqlServices = if ($IsRemote) {
    Try-InvokeRemote -ComputerName $ComputerName -Default @() -ScriptBlock {
      Get-Service | Where-Object {
        $_.Name -match '^MSSQL' -or $_.Name -match '^SQLAgent' -or $_.Name -match '^MSOLAP' -or $_.Name -match '^SQLBrowser'
      } | Select-Object Name, DisplayName, Status, StartType
    }
  } else {
    Try-Run {
      Get-Service | Where-Object {
        $_.Name -match '^MSSQL' -or $_.Name -match '^SQLAgent' -or $_.Name -match '^MSOLAP' -or $_.Name -match '^SQLBrowser'
      } | Select-Object Name, DisplayName, Status, StartType
    } @()
  }

  $sqlSummary   = @()
  $sqlDatabases = @()
  if ($IsRemote) {
    $sqlOut = Try-InvokeRemote -ComputerName $ComputerName -Default $null -ScriptBlock {
      $SqlInstance = $using:SqlInstance
      if (Get-Module -ListAvailable -Name SqlServer) {
        try {
          Import-Module SqlServer -ErrorAction Stop
          $sum = Invoke-Sqlcmd -ServerInstance $SqlInstance -Query @"
SELECT
  @@SERVERNAME AS ServerName,
  SERVERPROPERTY('ProductVersion') AS ProductVersion,
  SERVERPROPERTY('ProductLevel')   AS ProductLevel,
  SERVERPROPERTY('Edition')        AS Edition,
  SERVERPROPERTY('IsClustered')    AS IsClustered
"@
          $dbs = Invoke-Sqlcmd -ServerInstance $SqlInstance -Query @"
SELECT
  name,
  state_desc,
  recovery_model_desc,
  create_date
FROM sys.databases
ORDER BY name
"@
          [pscustomobject]@{ Summary=$sum; Databases=$dbs }
        } catch { $null }
      } else { $null }
    }
    if ($sqlOut) {
      $sqlSummary   = @($sqlOut.Summary)
      $sqlDatabases = @($sqlOut.Databases)
    }
  } else {
    if (Get-Module -ListAvailable -Name SqlServer) {
      Try-Run {
        Import-Module SqlServer -ErrorAction Stop
        $sqlSummary = Invoke-Sqlcmd -ServerInstance $SqlInstance -Query @"
SELECT
  @@SERVERNAME AS ServerName,
  SERVERPROPERTY('ProductVersion') AS ProductVersion,
  SERVERPROPERTY('ProductLevel')   AS ProductLevel,
  SERVERPROPERTY('Edition')        AS Edition,
  SERVERPROPERTY('IsClustered')    AS IsClustered
"@
        $sqlDatabases = Invoke-Sqlcmd -ServerInstance $SqlInstance -Query @"
SELECT
  name,
  state_desc,
  recovery_model_desc,
  create_date
FROM sys.databases
ORDER BY name
"@
      } $null | Out-Null
    }
  }

  # ---------------- KERUU: PAIKALLISET KÄYTTÄJÄT/RYHMÄT ----------------
  $localUsers = if ($IsRemote) {
    Try-InvokeRemote -ComputerName $ComputerName -Default @() -ScriptBlock {
      if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordRequired, UserMayChangePassword
      } else {
        Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" |
          Select-Object Name, Disabled, Lockout, PasswordChangeable, PasswordRequired
      }
    }
  } else {
    Try-Run {
      if (Get-Command Get-LocalUser -ErrorAction SilentlyContinue) {
        Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordRequired, UserMayChangePassword
      } else {
        Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" |
          Select-Object Name, Disabled, Lockout, PasswordChangeable, PasswordRequired
      }
    } @()
  }

  # ---------------- KERUU: PAIKALLISET RYHMÄT + JÄSENET ----------------
  $localGroups       = @()
  $localGroupMembers = @()
  $localGroupsSource = ""

  if ($IsRemote) {

    # 1) Yritä ensin WinRM (Invoke-Command) kuten ennen
    $lg = Try-InvokeRemote -ComputerName $ComputerName -Default $null -ScriptBlock {
      if (-not (Get-Command Get-LocalGroup -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ Groups=@(); Members=@(); Source="WinRM(Get-LocalGroup): cmdlet puuttuu" }
      }

      $groups = Get-LocalGroup | Select-Object Name, Description

      $members = Get-LocalGroup | ForEach-Object {
        $group = $_.Name
        try {
          Get-LocalGroupMember -Group $group -ErrorAction Stop |
            Select-Object @{n="Group";e={$group}}, Name, ObjectClass, PrincipalSource
        } catch { }
      }

      [pscustomobject]@{ Groups=@($groups); Members=@($members); Source="WinRM(Get-LocalGroup)" }
    }

    if ($lg -and (@($lg.Groups).Count -gt 0 -or @($lg.Members).Count -gt 0)) {
      $localGroups       = @($lg.Groups)
      $localGroupMembers = @($lg.Members)
      $localGroupsSource = $lg.Source
    }
    else {
      # 2) Fallback: CIM/DCOM (ei vaadi WinRM:ää)
      $localGroupsSource = if ($cim) { "CIM(Win32_Group/Win32_GroupUser)" } else { "Ei WinRM eikä CIM" }

      if ($cim) {
        # Ryhmät
        $localGroups = Try-Run {
          Get-CimInstance -ClassName Win32_Group -Filter "LocalAccount=True" -CimSession $cim |
            Select-Object @{n="Name";e={$_.Name}}, @{n="Description";e={$_.Description}}
        } @()

        # Jäsenyydet (Win32_GroupUser: GroupComponent + PartComponent)
        $rawLinks = Try-Run {
          Get-CimInstance -ClassName Win32_GroupUser -CimSession $cim
        } @()

        $localGroupMembers = @()
        foreach ($lnk in @($rawLinks)) {
          $g = [string]$lnk.GroupComponent
          $p = [string]$lnk.PartComponent

          # Poimi nimet WMI-polusta: Name="...", Domain="..."
          $gName = ""
          $pName = ""
          $pDomain = ""

          if ($g -match 'Name="([^"]+)"') { $gName = $matches[1] }
          if ($p -match 'Name="([^"]+)"') { $pName = $matches[1] }
          if ($p -match 'Domain="([^"]+)"') { $pDomain = $matches[1] }

          if ([string]::IsNullOrWhiteSpace($gName) -or [string]::IsNullOrWhiteSpace($pName)) { continue }

          # Rajaa vain paikalliset ryhmät (Domain = kohdekone)
          if ($pDomain -and $pDomain -ne $ComputerName -and $pDomain -ne $env:COMPUTERNAME) {
            # Tämä on usein domain-käyttäjä/jäsen, jätetään silti mukaan (hyödyllinen tieto)
          }

          $localGroupMembers += [pscustomobject]@{
            Group           = $gName
            Name            = if ($pDomain) { "$pDomain\$pName" } else { $pName }
            ObjectClass     = ""
            PrincipalSource = ""
          }
        }

        # siisti sorttaus
        $localGroupMembers = @($localGroupMembers | Sort-Object Group, Name)
      }
    }

  } else {
    # Paikallinen kone: käytä Get-LocalGroup jos löytyy, muuten CIM
    if (Get-Command Get-LocalGroup -ErrorAction SilentlyContinue) {
      $localGroupsSource = "Local(Get-LocalGroup)"
      $localGroups = Get-LocalGroup | Select-Object Name, Description

      $localGroupMembers = @(
        Get-LocalGroup | ForEach-Object {
          $group = $_.Name
          try {
            Get-LocalGroupMember -Group $group -ErrorAction Stop |
              Select-Object @{n="Group";e={$group}}, Name, ObjectClass, PrincipalSource
          } catch { }
        }
      )
    } else {
      $localGroupsSource = "Local(CIM Win32_*)"
      $localGroups = Try-Run {
        Get-CimInstance -ClassName Win32_Group -Filter "LocalAccount=True" |
          Select-Object @{n="Name";e={$_.Name}}, @{n="Description";e={$_.Description}}
      } @()

      $rawLinks = Try-Run { Get-CimInstance -ClassName Win32_GroupUser } @()
      $localGroupMembers = @()
      foreach ($lnk in @($rawLinks)) {
        $g = [string]$lnk.GroupComponent
        $p = [string]$lnk.PartComponent
        $gName = ""; $pName = ""; $pDomain = ""
        if ($g -match 'Name="([^"]+)"') { $gName = $matches[1] }
        if ($p -match 'Name="([^"]+)"') { $pName = $matches[1] }
        if ($p -match 'Domain="([^"]+)"') { $pDomain = $matches[1] }
        if ([string]::IsNullOrWhiteSpace($gName) -or [string]::IsNullOrWhiteSpace($pName)) { continue }

        $localGroupMembers += [pscustomobject]@{
          Group           = $gName
          Name            = if ($pDomain) { "$pDomain\$pName" } else { $pName }
          ObjectClass     = ""
          PrincipalSource = ""
        }
      }
      $localGroupMembers = @($localGroupMembers | Sort-Object Group, Name)
    }
  }



  # ---------------- KERUU: FIREWALL ----------------
  $fwProfiles = @()
  $fwView     = @()
  $fwDump     = @()

  # UUSI: nimeä firewall-dumpit alkuprefixillä
  $fwCsv  = Join-Path $OutDir ("{0}-firewall-rules.csv" -f $NamePrefix)
  $fwJson = Join-Path $OutDir ("{0}-firewall-rules.json" -f $NamePrefix)

  if ($IsRemote) {
    $fwOut = Try-InvokeRemote -ComputerName $ComputerName -Default $null -ScriptBlock {
      if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) { return $null }

      $MaxFirewallRules = $using:MaxFirewallRules

      $profiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

      $rules = Get-NetFirewallRule |
        Where-Object { $_.Enabled -eq "True" } |
        Select-Object Name, DisplayName, Direction, Action, Profile, Group, Program, Service, PolicyStoreSource

      $rulesLimited = @($rules | Select-Object -First $MaxFirewallRules)

      $dump = @()
      foreach ($r in $rulesLimited) {
        $ports = @()
        $addrs = @()
        try { $ports = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r } catch {}
        try { $addrs = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r } catch {}

        $localPort  = (try { (($ports | Select-Object -ExpandProperty LocalPort)  | Where-Object { $_ }) -join "," } catch { "" })
        $remotePort = (try { (($ports | Select-Object -ExpandProperty RemotePort) | Where-Object { $_ }) -join "," } catch { "" })
        $protocol   = (try { (($ports | Select-Object -ExpandProperty Protocol)   | Where-Object { $_ }) -join "," } catch { "" })
        $lAddr      = (try { (($addrs | Select-Object -ExpandProperty LocalAddress)  | Where-Object { $_ }) -join "," } catch { "" })
        $rAddr      = (try { (($addrs | Select-Object -ExpandProperty RemoteAddress) | Where-Object { $_ }) -join "," } catch { "" })

        $dump += [pscustomobject]@{
          DisplayName   = $r.DisplayName
          Direction     = $r.Direction
          Action        = $r.Action
          Profile       = $r.Profile
          Group         = $r.Group
          Program       = $r.Program
          Service       = $r.Service
          Protocol      = $protocol
          LocalPort     = $localPort
          RemotePort    = $remotePort
          LocalAddress  = $lAddr
          RemoteAddress = $rAddr
          Source        = $r.PolicyStoreSource
        }
      }

      [pscustomobject]@{ Profiles=$profiles; Dump=$dump }
    }

    if ($fwOut) {
      $fwProfiles = @($fwOut.Profiles)
      $fwDump     = @($fwOut.Dump)

      $fwView = $fwDump | ForEach-Object {
        [pscustomobject]@{
          Nimi     = $_.DisplayName
          Suunta   = $_.Direction
          Toiminto = $_.Action
          Profiili = $_.Profile
          Proto    = $_.Protocol
          LPort    = $_.LocalPort
          Ohjelma  = if ($_.Program) { Split-Path $_.Program -Leaf } else { "" }
          Ryhmä    = $_.Group
          Lähde    = $_.Source
        }
      }

      $fwDump | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $fwCsv
      $fwDump | ConvertTo-Json -Depth 6 | Out-File -Encoding UTF8 $fwJson
    }
  } else {
    if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
      $fwProfiles = Try-Run {
        Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
      } @()

      $fwRules = Try-Run {
        Get-NetFirewallRule |
          Where-Object { $_.Enabled -eq "True" } |
          Select-Object Name, DisplayName, Direction, Action, Profile, Group, Program, Service, PolicyStoreSource
      } @()

      $fwRulesLimited = @($fwRules | Select-Object -First $MaxFirewallRules)

      foreach ($r in $fwRulesLimited) {
        $ports = Try-Run { Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r } @()
        $addrs = Try-Run { Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r } @()

        $localPort  = (Try-Run { (($ports | Select-Object -ExpandProperty LocalPort  -ErrorAction SilentlyContinue) | Where-Object { $_ }) -join "," } "")
        $remotePort = (Try-Run { (($ports | Select-Object -ExpandProperty RemotePort -ErrorAction SilentlyContinue) | Where-Object { $_ }) -join "," } "")
        $protocol   = (Try-Run { (($ports | Select-Object -ExpandProperty Protocol   -ErrorAction SilentlyContinue) | Where-Object { $_ }) -join "," } "")
        $lAddr      = (Try-Run { (($addrs | Select-Object -ExpandProperty LocalAddress  -ErrorAction SilentlyContinue) | Where-Object { $_ }) -join "," } "")
        $rAddr      = (Try-Run { (($addrs | Select-Object -ExpandProperty RemoteAddress -ErrorAction SilentlyContinue) | Where-Object { $_ }) -join "," } "")

        $fwDump += [pscustomobject]@{
          DisplayName   = $r.DisplayName
          Direction     = $r.Direction
          Action        = $r.Action
          Profile       = $r.Profile
          Group         = $r.Group
          Program       = $r.Program
          Service       = $r.Service
          Protocol      = $protocol
          LocalPort     = $localPort
          RemotePort    = $remotePort
          LocalAddress  = $lAddr
          RemoteAddress = $rAddr
          Source        = $r.PolicyStoreSource
        }
      }

      $fwView = $fwDump | ForEach-Object {
        [pscustomobject]@{
          Nimi     = $_.DisplayName
          Suunta   = $_.Direction
          Toiminto = $_.Action
          Profiili = $_.Profile
          Proto    = $_.Protocol
          LPort    = $_.LocalPort
          Ohjelma  = if ($_.Program) { Split-Path $_.Program -Leaf } else { "" }
          Ryhmä    = $_.Group
          Lähde    = $_.Source
        }
      }

      $fwDump | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $fwCsv
      $fwDump | ConvertTo-Json -Depth 6 | Out-File -Encoding UTF8 $fwJson
    }
  }

  # ---------------- KERUU: KUUNTELEVAT PORTIT ----------------
  $listeningPorts = Get-ListeningPorts -ComputerName $ComputerName -Remote:$IsRemote

  # UUSI: nimeä listening-ports-dumpit alkuprefixillä
  $listenCsv  = Join-Path $OutDir ("{0}-listening-ports.csv" -f $NamePrefix)
  $listenJson = Join-Path $OutDir ("{0}-listening-ports.json" -f $NamePrefix)

  if ($listeningPorts -and @($listeningPorts).Count -gt 0) {
    $listeningPorts | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $listenCsv
    $listeningPorts | ConvertTo-Json -Depth 6 | Out-File -Encoding UTF8 $listenJson
  }

  # ---------------- KERUU: DEFENDER ----------------
  # Etänä: yritetään WinRM:llä. Jos ei onnistu, jätetään tyhjäksi.
  $defStatus  = $null
  $defPrefs   = $null
  $defThreats = @()

  if ($IsRemote) {
    $defOut = Try-InvokeRemote -ComputerName $ComputerName -Default $null -ScriptBlock {
      if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) { return $null }

      $MaxDefenderThreats = $using:MaxDefenderThreats

      $status = try {
        Get-MpComputerStatus | Select-Object `
          AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, `
          IsTamperProtected, NISEnabled, OnAccessProtectionEnabled, RealTimeProtectionEnabled, `
          QuickScanAge, FullScanAge, SignatureAge, EngineVersion, AntivirusSignatureVersion
      } catch { $null }

      $prefs = try {
        Get-MpPreference | Select-Object `
          DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableIOAVProtection, DisableScriptScanning, `
          DisableArchiveScanning, DisableEmailScanning, MAPSReporting, SubmitSamplesConsent, CloudBlockLevel, `
          PUAProtection, AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions
      } catch { $null }

      $threats = @()
      if (Get-Command Get-MpThreat -ErrorAction SilentlyContinue) {
        try {
          $threats = Get-MpThreat | Select-Object ThreatName, SeverityID, CategoryID, DidThreatExecute, InitialDetectionTime, Resources |
            Select-Object -First $MaxDefenderThreats
        } catch {}
      }

      [pscustomobject]@{ Status=$status; Prefs=$prefs; Threats=$threats }
    }

    if ($defOut) {
      $defStatus  = $defOut.Status
      $defPrefs   = $defOut.Prefs
      $defThreats = @($defOut.Threats)
    }
  } else {
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
      $defStatus = Try-Run {
        Get-MpComputerStatus | Select-Object `
          AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, `
          IsTamperProtected, NISEnabled, OnAccessProtectionEnabled, RealTimeProtectionEnabled, `
          QuickScanAge, FullScanAge, SignatureAge, EngineVersion, AntivirusSignatureVersion
      } $null

      $defPrefs = Try-Run {
        Get-MpPreference | Select-Object `
          DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableIOAVProtection, DisableScriptScanning, `
          DisableArchiveScanning, DisableEmailScanning, MAPSReporting, SubmitSamplesConsent, CloudBlockLevel, `
          PUAProtection, AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions
      } $null

      if (Get-Command Get-MpThreat -ErrorAction SilentlyContinue) {
        $defThreats = Try-Run {
          Get-MpThreat | Select-Object ThreatName, SeverityID, CategoryID, DidThreatExecute, InitialDetectionTime, Resources |
            Select-Object -First $MaxDefenderThreats
        } @()
      }
    }
  }

  $defStatusView = @()
  if ($defStatus) {
    $defStatusView = @([pscustomobject]@{
      "AV käytössä"             = $defStatus.AntivirusEnabled
      "Vakoiluesto käytössä"    = $defStatus.AntispywareEnabled
      "Reaaliaikainen suojaus"  = $defStatus.RealTimeProtectionEnabled
      "Käyttäytymisen valvonta" = $defStatus.BehaviorMonitorEnabled
      "On-access suojaus"       = $defStatus.OnAccessProtectionEnabled
      "IOAV suojaus"            = $defStatus.IoavProtectionEnabled
      "NIS käytössä"            = $defStatus.NISEnabled
      "Tamper Protection"       = $defStatus.IsTamperProtected
      "Signatuurit (ikä/pv)"    = $defStatus.SignatureAge
      "Engine versio"           = $defStatus.EngineVersion
      "AV signatuuri"           = $defStatus.AntivirusSignatureVersion
      "Quick scan (ikä/pv)"     = $defStatus.QuickScanAge
      "Full scan (ikä/pv)"      = $defStatus.FullScanAge
    })
  }

  $defPrefsView = @()
  $asrRows = @()
  $asrSummary = @()
  if ($defPrefs) {
    $defPrefsView = @([pscustomobject]@{
      "Disable Realtime"     = $defPrefs.DisableRealtimeMonitoring
      "Disable Behavior"     = $defPrefs.DisableBehaviorMonitoring
      "Disable IOAV"         = $defPrefs.DisableIOAVProtection
      "Disable Script Scan"  = $defPrefs.DisableScriptScanning
      "Disable Archive Scan" = $defPrefs.DisableArchiveScanning
      "Disable Email Scan"   = $defPrefs.DisableEmailScanning
      "MAPS reporting"       = $defPrefs.MAPSReporting
      "Submit samples"       = $defPrefs.SubmitSamplesConsent
      "Cloud block level"    = $defPrefs.CloudBlockLevel
      "PUA protection"       = $defPrefs.PUAProtection
    })

    if ($defPrefs.AttackSurfaceReductionRules_Ids) {
      $ids = @($defPrefs.AttackSurfaceReductionRules_Ids)
      $actions = @($defPrefs.AttackSurfaceReductionRules_Actions)

      $asrRows = for ($i = 0; $i -lt $ids.Count; $i++) {
        $act = if ($i -lt $actions.Count) { $actions[$i] } else { $null }
        $actText = switch ($act) { 0 {"Disabled"} 1 {"Block"} 2 {"Audit"} 6 {"Warn"} default { "$act" } }
        [pscustomobject]@{ "ASR Rule ID" = $ids[$i]; "Toiminto" = $actText }
      }

      $asrSummary = @(
        [pscustomobject]@{ Tila="Block";    Maara=(@($asrRows | Where-Object { $_.Toiminto -eq "Block" }).Count) }
        [pscustomobject]@{ Tila="Audit";    Maara=(@($asrRows | Where-Object { $_.Toiminto -eq "Audit" }).Count) }
        [pscustomobject]@{ Tila="Warn";     Maara=(@($asrRows | Where-Object { $_.Toiminto -eq "Warn" }).Count) }
        [pscustomobject]@{ Tila="Disabled"; Maara=(@($asrRows | Where-Object { $_.Toiminto -eq "Disabled" }).Count) }
      )
    }
  }


  # ---------------- RENDER: HTML ----------------
  New-HTML -TitleText "Windows AuditReports - $ComputerName" -FilePath $HtmlPath -Online {

    New-HTMLHeader {
      New-HTMLText -Text "Windows-auditraportti" -FontSize 26 -FontWeight bold
      New-HTMLText -Text "Kohde:  $ComputerName" -FontSize 14
      New-HTMLText -Text ("Luotu: {0}" -f $Now.ToString("dd.MM.yyyy HH:mm")) -FontSize 12
    }

    New-HTMLSection -HeaderText "Ajokonteksti" {
      New-FlatTable -DataTable $execContext -HideFooter
      if ($reboot) {
        New-HTMLText -Text ("Reboot pending: <b>{0}</b> {1}" -f `
  $(if ($reboot.Pending) { "YES" } else { "NO" }),
  $(if ($reboot.Reasons) { "($($reboot.Reasons))" } else { "" })
) -FontSize 12
      }
      if ($lastHotfix) {
        New-HTMLText -Text ("Viimeisin hotfix: <b>{0}</b> ({1})" -f `
  $lastHotfix.HotFixID,
  ($lastHotfix.InstalledOn.ToString("dd.MM.yyyy"))
) -FontSize 12
      }
    }

    New-HTMLSection -HeaderText "Yhteenveto" {
      $uptimeDays = if ($os) { [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 2) } else { "" }
      $summary = @(
        [pscustomobject]@{ Kenttä="Kone"; Arvo=$ComputerName }
        [pscustomobject]@{ Kenttä="OS"; Arvo=($(if ($os) { $os.Caption } else { "" })) }
        [pscustomobject]@{ Kenttä="Build"; Arvo=($(if ($os) { $os.BuildNumber } else { "" })) }
        [pscustomobject]@{ Kenttä="Uptime (pv)"; Arvo=$uptimeDays }
        [pscustomobject]@{ Kenttä="RAM (GB)"; Arvo=($(if ($cs) { [math]::Round($cs.TotalPhysicalMemory/1GB,2) } else { "" })) }
        [pscustomobject]@{ Kenttä="Domain-joined"; Arvo=($(if ($adInfo) { $adInfo.CsPartOfDomain } else { "" })) }
        [pscustomobject]@{ Kenttä="Domain"; Arvo=($(if ($adInfo) { $adInfo.CsDomain } else { "" })) }
        [pscustomobject]@{ Kenttä="IIS asennettu"; Arvo=$iisInstalled }
        [pscustomobject]@{ Kenttä="SQL services"; Arvo=(@($sqlServices).Count) }
        [pscustomobject]@{ Kenttä="Palomuuri-sääntöjä (dump)"; Arvo=(@($fwDump).Count) }
        [pscustomobject]@{ Kenttä="Kuuntelevat portit"; Arvo=(@($listeningPorts).Count) }
        [pscustomobject]@{ Kenttä="Defender tiedot"; Arvo=([bool]$defStatus) }
        [pscustomobject]@{ Kenttä="Reboot pending"; Arvo=($(if ($reboot) { $reboot.Pending } else { "" })) }
      )
      New-FlatTable -DataTable $summary -HideFooter
    }

    New-HTMLSection -HeaderText "Perustiedot" {
      $basic = @()
      if ($os) {
        $basic += [pscustomobject]@{ Kenttä="Käyttöjärjestelmä"; Arvo=$os.Caption }
        $basic += [pscustomobject]@{ Kenttä="OS Versio"; Arvo=$os.Version }
        $basic += [pscustomobject]@{ Kenttä="Build"; Arvo=$os.BuildNumber }
        $basic += [pscustomobject]@{ Kenttä="Asennuspäivä"; Arvo=$os.InstallDate }
        $basic += [pscustomobject]@{ Kenttä="Uptime (päiviä)"; Arvo=[math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays,2) }
      }
      if ($cs) {
        $basic += [pscustomobject]@{ Kenttä="Valmistaja"; Arvo=$cs.Manufacturer }
        $basic += [pscustomobject]@{ Kenttä="Malli"; Arvo=$cs.Model }
        $basic += [pscustomobject]@{ Kenttä="RAM (GB)"; Arvo=[math]::Round($cs.TotalPhysicalMemory/1GB,2) }
      }
      if ($bios) { $basic += [pscustomobject]@{ Kenttä="BIOS"; Arvo=$bios.SMBIOSBIOSVersion } }
      if ($cpu)  { $basic += [pscustomobject]@{ Kenttä="CPU"; Arvo=$cpu.Name } }

      if ($basic.Count -gt 0) { New-FlatTable -DataTable $basic -HideFooter }
      else { New-HTMLText -Text "Perustietoja ei saatu." }
    }

    New-HTMLSection -HeaderText "Levyt" {
      if ($disks -and @($disks).Count -gt 0) {
        $diskRows = $disks | Select-Object DeviceID,
          @{n="Koko (GB)";e={[math]::Round($_.Size/1GB,2)}},
          @{n="Vapaa (GB)";e={[math]::Round($_.FreeSpace/1GB,2)}},
          @{n="Vapaa (%)";e={ if ($_.Size) { [math]::Round(($_.FreeSpace/[double]$_.Size)*100,2) } else { "" } }}

        New-NiceTable -Data $diskRows -PageLength 25 -HideFooter
      } else {
        New-HTMLText -Text "Levyjä ei saatu listattua."
      }
    }

    New-HTMLSection -HeaderText "Verkko" {
      if ($net -and @($net).Count -gt 0) {
        $netRows = $net | ForEach-Object {
          [pscustomobject]@{
            Adapter   = $_.Description
            MAC       = $_.MACAddress
            IPAddress = (Join-Arr $_.IPAddress)
            IPSubnet  = (Join-Arr $_.IPSubnet)
            Gateway   = (Join-Arr $_.DefaultIPGateway)
            DNS       = (Join-Arr $_.DNSServerSearchOrder)
          }
        }
        New-NiceTable -Data $netRows -PageLength 25 -HideFooter
      } else {
        New-HTMLText -Text "Verkkotietoja ei saatu listattua."
      }
    }

    New-HTMLSection -HeaderText "Kuuntelevat portit" {
      if ($listeningPorts -and @($listeningPorts).Count -gt 0) {
        New-NiceTable -Data $listeningPorts -PageLength 25 -HideFooter
        New-HTMLText -Text "Liitteet:" -FontWeight bold
        New-HTMLLink -Text (Split-Path $listenCsv -Leaf)  -Url (Split-Path $listenCsv -Leaf)
        New-HTMLLink -Text (Split-Path $listenJson -Leaf) -Url (Split-Path $listenJson -Leaf)
      } else {
        New-HTMLText -Text "Kuuntelevia portteja ei saatu listattua (WinRM ei käytössä / oikeudet / cmdlet puuttuu)."
      }
    }

    New-HTMLSection -HeaderText "Asennetut ohjelmistot" {
      if ($apps -and @($apps).Count -gt 0) {
        $appRows = $apps | Select-Object Scope, DisplayName, DisplayVersion, Publisher, InstallDate
        New-NiceTable -Data $appRows -PageLength 25 -HideFooter

        if (@($apps).Count -ge $MaxInstalledApps) {
          New-HTMLText -Text ("Huom: Ohjelmalista on rajattu ({0} ensimmäistä)." -f $MaxInstalledApps) -FontSize 12
        }
      } else {
        New-HTMLText -Text "Ohjelmistolistaa ei saatu (tai etäajo ei onnistunut)."
      }
    }

    New-HTMLSection -HeaderText "Paikalliset käyttäjät" {
      if ($localUsers -and @($localUsers).Count -gt 0) {
        New-NiceTable -Data $localUsers -PageLength 25 -HideFooter
      } else {
        New-HTMLText -Text "Paikallisia käyttäjiä ei saatu listattua tai niitä ei ole."
      }
    }

    New-HTMLSection -HeaderText "Paikalliset ryhmät ja jäsenyydet" {
      if ($localGroups -and @($localGroups).Count -gt 0) {
        New-HTMLText -Text "Ryhmät"
        New-NiceTable -Data $localGroups -PageLength 25 -HideFooter
      } else {
        New-HTMLText -Text "Paikallisia ryhmiä ei saatu listattua."
      }

      if ($localGroupMembers -and @($localGroupMembers).Count -gt 0) {
        New-HTMLText -Text "Ryhmien jäsenet"
        New-NiceTable -Data ($localGroupMembers | Sort-Object Group, Name) -PageLength 25 -HideFooter
      } else {
        New-HTMLText -Text "Ryhmien jäseniä ei saatu listattua."
      }
    }

    New-HTMLSection -HeaderText "Windows Firewall" {
      if ($fwProfiles -and @($fwProfiles).Count -gt 0) {
        New-HTMLText -Text "Palomuuriprofiilit"
        New-FlatTable -DataTable $fwProfiles -HideFooter
      } else {
        New-HTMLText -Text "Palomuuriprofiileja ei saatu listattua."
      }

      if ($fwView -and @($fwView).Count -gt 0) {
        $inAllow = $fwView | Where-Object { $_.Suunta -eq "Inbound" -and $_.Toiminto -eq "Allow" } | Select-Object -First 120
        $inBlock = $fwView | Where-Object { $_.Suunta -eq "Inbound" -and $_.Toiminto -eq "Block" } | Select-Object -First 120
        $custom  = $fwView | Where-Object { $_.Lähde -notmatch "FirewallAPI\.dll" } | Select-Object -First 120

        if (@($inAllow).Count -gt 0) {
          New-HTMLText -Text "Inbound Allow (rajattu)"
          New-NiceTable -Data ($inAllow | Select-Object Nimi, Profiili, Proto, LPort, Ohjelma, Ryhmä) -PageLength 25 -HideFooter
        }
        if (@($inBlock).Count -gt 0) {
          New-HTMLText -Text "Inbound Block (rajattu)"
          New-NiceTable -Data ($inBlock | Select-Object Nimi, Profiili, Proto, LPort, Ohjelma, Ryhmä) -PageLength 25 -HideFooter
        }
        if (@($custom).Count -gt 0) {
          New-HTMLText -Text "Custom/ei-builtin (rajattu)"
          New-NiceTable -Data ($custom | Select-Object Nimi, Suunta, Toiminto, Profiili, Proto, LPort, Ohjelma) -PageLength 25 -HideFooter
        }

        New-HTMLText -Text "Liitteet:" -FontWeight bold
        New-HTMLLink -Text (Split-Path $fwCsv -Leaf)  -Url (Split-Path $fwCsv -Leaf)
        New-HTMLLink -Text (Split-Path $fwJson -Leaf) -Url (Split-Path $fwJson -Leaf)
      } else {
        New-HTMLText -Text "Palomuurisääntöjä ei saatu listattua tai niitä ei ole."
      }
    }

    New-HTMLSection -HeaderText "Microsoft Defender" {
      if ($defStatusView -and @($defStatusView).Count -gt 0) {
        New-HTMLText -Text "Defenderin tila (tiivistelmä)"
        New-FlatTable -DataTable $defStatusView -HideFooter
      } else {
        New-HTMLText -Text "Defenderin tilaa ei saatu (ei käytössä / cmdletit puuttuvat / etäajo ei onnistunut)."
      }

      if ($defPrefsView -and @($defPrefsView).Count -gt 0) {
        New-HTMLText -Text "Defender-asetukset (tiivistelmä)"
        New-FlatTable -DataTable $defPrefsView -HideFooter
      }

      if ($asrSummary -and @($asrSummary).Count -gt 0) {
        New-HTMLText -Text "ASR-yhteenveto"
        New-FlatTable -DataTable $asrSummary -HideFooter
      }

      if ($asrRows -and @($asrRows).Count -gt 0) {
        New-HTMLText -Text "Attack Surface Reduction (ASR)"
        New-NiceTable -Data $asrRows -PageLength 25 -HideFooter
      }

      if ($defThreats -and @($defThreats).Count -gt 0) {
        $threatView = $defThreats | ForEach-Object {
          [pscustomobject]@{
            Uhka         = $_.ThreatName
            Vakavuus     = $_.SeverityID
            Kategoria    = $_.CategoryID
            Suoritettiin = $_.DidThreatExecute
            Havaittu     = $_.InitialDetectionTime
            Resurssit    = (($_.Resources | Out-String).Trim() -replace '\s+', ' ')
          }
        }
        New-HTMLText -Text "Havaitut uhat (rajattu)"
        New-NiceTable -Data $threatView -PageLength 25 -HideFooter
        New-HTMLText -Text ("Huom: Uhkalista on rajattu ({0})." -f $MaxDefenderThreats) -FontSize 12
      } else {
        New-HTMLText -Text "Ei listattavia uhkatietoja (tai etäajo ei onnistunut)."
      }
    }

    New-HTMLSection -HeaderText "AD / Domain-tiedot" {
      if ($adInfo -and $adInfo.CsPartOfDomain) {
        $domainRows = @(
          [pscustomobject]@{ Kenttä="Domain"; Arvo=$adInfo.CsDomain }
          [pscustomobject]@{ Kenttä="Domain Role"; Arvo=$adInfo.CsDomainRole }
          [pscustomobject]@{ Kenttä="Domain-joined"; Arvo=$adInfo.CsPartOfDomain }
        )
        New-FlatTable -DataTable $domainRows -HideFooter

        if ($adComputer) {
          $adRows = @(
            [pscustomobject]@{ Kenttä="DistinguishedName"; Arvo=$adComputer.DistinguishedName }
            [pscustomobject]@{ Kenttä="OS (AD)"; Arvo=$adComputer.OperatingSystem }
            [pscustomobject]@{ Kenttä="OS Version (AD)"; Arvo=$adComputer.OperatingSystemVersion }
            [pscustomobject]@{ Kenttä="Created"; Arvo=$adComputer.whenCreated }
            [pscustomobject]@{ Kenttä="LastLogonDate"; Arvo=$adComputer.LastLogonDate }
          )
          New-FlatTable -DataTable $adRows -HideFooter

          if ($adGroups -and @($adGroups).Count -gt 0) {
            New-HTMLText -Text "Kone-tilin ryhmäjäsenyydet"
            New-NiceTable -Data ($adGroups | Select-Object Name, DistinguishedName) -PageLength 25 -HideFooter
          } else {
            New-HTMLText -Text "Kone-tilin ryhmäjäsenyyksiä ei löytynyt tai niitä ei voitu lukea."
          }
        } else {
          New-HTMLText -Text $(if ($adModuleAvailable) { "AD-moduuli löytyi, mutta konetilin lisätietoja ei saatu luettua." } else { "ActiveDirectory-moduulia ei löytynyt (RSAT)." })
        }
      } else {
        New-HTMLText -Text "Kone ei ole domain-joined tai tietoa ei saatu."
      }
    }

    New-HTMLSection -HeaderText "Palveluroolit ja ominaisuudet" {
      if ($features -and @($features).Count -gt 0) {
        $roles        = @($features | Where-Object { $_.FeatureType -eq 'Role' })
        $roleServices = @($features | Where-Object { $_.FeatureType -eq 'Role Service' })
        $feat         = @($features | Where-Object { $_.FeatureType -eq 'Feature' -or $_.FeatureType -eq 'Capability' })

        if (@($roles).Count -gt 0) {
          New-HTMLText -Text "Roolit"
          New-NiceTable -Data ($roles | Select-Object DisplayName, Name, FeatureType, Path) -PageLength 25 -HideFooter
        } else { New-HTMLText -Text "Roolit: ei löytynyt." }

        if (@($roleServices).Count -gt 0) {
          New-HTMLText -Text "Roolipalvelut"
          New-NiceTable -Data ($roleServices | Select-Object DisplayName, Name, FeatureType, Path) -PageLength 25 -HideFooter
        } else { New-HTMLText -Text "Roolipalvelut: ei löytynyt." }

        if (@($feat).Count -gt 0) {
          New-HTMLText -Text "Ominaisuudet"
          New-NiceTable -Data ($feat | Select-Object DisplayName, Name, FeatureType, Path) -PageLength 25 -HideFooter
        } else { New-HTMLText -Text "Ominaisuudet: ei löytynyt." }

        New-HTMLText -Text "Liitteet:" -FontWeight bold
        New-HTMLLink -Text (Split-Path $featuresCsv -Leaf)  -Url (Split-Path $featuresCsv -Leaf)
        New-HTMLLink -Text (Split-Path $featuresJson -Leaf) -Url (Split-Path $featuresJson -Leaf)
      } else {
        New-HTMLText -Text "Roolit/ominaisuudet eivät ole listattavissa tässä ympäristössä (tai etäajo ei onnistunut)."
      }
    }

    New-HTMLSection -HeaderText "IIS" {
      if ($iisInstalled) {
        New-HTMLText -Text "IIS on asennettu."
        if ($iisSites -and @($iisSites).Count -gt 0) { New-NiceTable -Data $iisSites -PageLength 25 -HideFooter } else { New-HTMLText -Text "Sivustoja ei löytynyt." }
        if ($iisAppPools -and @($iisAppPools).Count -gt 0) { New-HTMLText -Text "Application Pools"; New-NiceTable -Data $iisAppPools -PageLength 25 -HideFooter }
        if ($iisBindings -and @($iisBindings).Count -gt 0) { New-HTMLText -Text "Bindings"; New-NiceTable -Data $iisBindings -PageLength 25 -HideFooter }
      } else {
        New-HTMLText -Text "IIS ei ole asennettu tai WebAdministration-moduuli ei ole käytettävissä (tai etäajo ei onnistunut)."
      }
    }

    New-HTMLSection -HeaderText "SQL Server" {
      if ($sqlServices -and @($sqlServices).Count -gt 0) {
        New-HTMLText -Text "SQL-palvelut"
        New-NiceTable -Data $sqlServices -PageLength 25 -HideFooter
      } else {
        New-HTMLText -Text "SQL-palveluita ei löytynyt tältä koneelta."
      }

      if ($sqlSummary -and @($sqlSummary).Count -gt 0) {
        New-HTMLText -Text "Instanssin perustiedot"
        New-FlatTable -DataTable $sqlSummary -HideFooter

        if ($sqlDatabases -and @($sqlDatabases).Count -gt 0) {
          New-HTMLText -Text "Tietokannat"
          New-NiceTable -Data $sqlDatabases -PageLength 25 -HideFooter
        }
      } else {
        New-HTMLText -Text "Instanssin lisätietoja ei saatu (SqlServer-moduuli puuttuu, instanssi ei vastaa tai etäajo/oikeudet eivät riitä)."
      }
    }

    New-HTMLSection -HeaderText "Liitehashit (SHA256)" {
      $hashPaths = @(
        $fwCsv, $fwJson,
        $featuresCsv, $featuresJson,
        $listenCsv, $listenJson,
        $RunLog
      ) | Where-Object { $_ -and (Test-Path $_) }

      $hashRows = Get-FileHashes -Paths $hashPaths
      if ($hashRows -and @($hashRows).Count -gt 0) {
        New-NiceTable -Data $hashRows -PageLength 25 -HideFooter
      } else {
        New-HTMLText -Text "Hash-tietoja ei saatu muodostettua."
      }
    }
  }

  # ---------------- POST: INJEKTOI CSS VARMASTI HTML:ÄÄN ----------------
  Try-Run {
    $html = Get-Content -Path $HtmlPath -Raw -ErrorAction Stop
    if ($html -notmatch 'DataTables: header \+ filters fix') {
      $styleTag = "<style>`n$FixCss`n</style>`n"
      $html = $html -replace '</head>', ($styleTag + '</head>')
      Set-Content -Path $HtmlPath -Value $html -Encoding UTF8
    }
  } $null | Out-Null

  # HTML-hash talteen (alkuprefixillä)
  $htmlHash = Try-Run { Get-FileHash -Path $HtmlPath -Algorithm SHA256 } $null
  if ($htmlHash) {
    $hashOut = Join-Path $OutDir ("{0}-filehashes.csv" -f $NamePrefix)
    @(
      [pscustomobject]@{ File=(Split-Path $HtmlPath -Leaf); Algorithm=$htmlHash.Algorithm; Hash=$htmlHash.Hash }
    ) | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $hashOut
  }

  "Valmista: $HtmlPath"

} catch {
  $_ | Out-String | Out-File -Encoding UTF8 -FilePath $ErrorLog
  throw
} finally {
  Try-Run { Stop-Transcript | Out-Null } $null | Out-Null
  if ($cim) { Try-Run { Remove-CimSession $cim } $null | Out-Null }
}