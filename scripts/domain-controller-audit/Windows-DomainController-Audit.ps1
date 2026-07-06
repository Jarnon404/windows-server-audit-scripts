#requires -Version 5.1
<#
.SYNOPSIS
Public-safe Windows Server and Domain Controller audit script.

.DESCRIPTION
Collects Windows Server and domain-controller focused inventory, AD DS role,
feature, local group, privileged group and operational audit information into
HTML and supporting output files.

This public version has been sanitized for GitHub:
- no customer names
- no tenant identifiers
- no internal hostnames
- no private IP addresses
- no credentials or secrets
- no generated audit reports

.NOTES
Run from an elevated PowerShell session on a server with the required Windows
and Active Directory administration modules available.
#>

$ErrorActionPreference = "Stop"

# ===============================
#  AUDIT (Controller PS1)
#  Aja ADDS/RSAT hallintakoneella
# ===============================

# ---------------- TARGET: kysy alussa ----------------
$TargetComputer = Read-Host "Enter target computer (FQDN/hostname). Empty = local computer"
if ([string]::IsNullOrWhiteSpace($TargetComputer)) { $TargetComputer = $env:COMPUTERNAME }

# ---------------- SETTINGS ----------------
$ComputerName = $TargetComputer
$Stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$NamePrefix = "{0}-{1}" -f $ComputerName, $Stamp

# Reports: AuditReports\<computer name>\
$OutDir   = Join-Path (Join-Path $PWD "AuditReports") $ComputerName
$HtmlPath = Join-Path $OutDir ("{0}-Domain-Controller-Audit.html" -f $NamePrefix)

$MaxFirewallRules   = 300
$MaxDefenderThreats = 50
$MaxInstalledApps   = 500

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# ---------------- HELPERS ----------------
function Try-Run {
  param([Parameter(Mandatory=$true)][scriptblock]$Script, $Default = $null)
  try { & $Script } catch { $Default }
}

function Try-InvokeRemote {
  param(
    [Parameter(Mandatory=$true)][string]$ComputerName,
    [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
    $Default = $null
  )
  try { Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock -ErrorAction Stop }
  catch { $Default }
}

$IsRemote = -not ($ComputerName -ieq $env:COMPUTERNAME -or $ComputerName -ieq "localhost" -or $ComputerName -ieq ".")

# CIM/DCOM sessio (ensisijainen etäkeruu)
$cim = $null
if ($IsRemote) {
  $cim = Try-Run {
    $so = New-CimSessionOption -Protocol Dcom
    New-CimSession -ComputerName $ComputerName -SessionOption $so -ErrorAction Stop
  } $null
}

$RunLog   = Join-Path $OutDir ("{0}-run.log" -f $NamePrefix)
$ErrorLog = Join-Path $OutDir ("{0}-error.txt" -f $NamePrefix)

function Test-IsAdmin {
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}

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
    $props = $row.PSObject.Properties | Where-Object { $_.MemberType -in 'NoteProperty','Property' }
    $ht = [ordered]@{}
    foreach ($p in $props) {
      $v = $p.Value
      if ($null -eq $v) { $ht[$p.Name] = ""; continue }
      if ($v -is [System.Array]) {
        $ht[$p.Name] = ( @($v) | ForEach-Object { if ($_ -eq $null) { "" } else { [string]$_ } } | Where-Object { $_ } ) -join ", "
        continue
      }
      if ($v -is [datetime]) { $ht[$p.Name] = $v.ToString("yyyy-MM-dd HH:mm:ss"); continue }
      $ht[$p.Name] = [string]$v
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
  if (-not $arr -or $arr.Count -eq 0) { New-HTMLText -Text "Ei dataa." -FontSize 12; return }

  $btn = @('copyHtml5','csvHtml5','excelHtml5','pdfHtml5','print','pageLength','searchBuilder','searchPanes','columnVisibility')

  $common = @{
    DataTable          = $arr
    ScrollX            = $true
    Filtering          = $true
    FilteringLocation  = 'Top'
    PagingLength       = $PageLength
    Buttons            = $btn
  }
  if ($HideFooter) { New-HTMLTable @common -HideFooter } else { New-HTMLTable @common }
}

function New-FlatTable {
  param([Parameter(Mandatory=$true)] $DataTable, [switch] $HideFooter)
  $flat = Convert-ToFlatTableData -Data $DataTable
  if ($HideFooter) { New-HTMLTable -DataTable $flat -HideFooter } else { New-HTMLTable -DataTable $flat }
}

function Get-CimSafe {
  param([string]$Class, [string]$Filter = $null)
  if ($cim) {
    if ($Filter) { return Try-Run { Get-CimInstance -ClassName $Class -Filter $Filter -CimSession $cim } $null }
    return Try-Run { Get-CimInstance -ClassName $Class -CimSession $cim } $null
  } else {
    if ($Filter) { return Try-Run { Get-CimInstance -ClassName $Class -Filter $Filter } $null }
    return Try-Run { Get-CimInstance -ClassName $Class } $null
  }
}

function Get-RebootPendingRemote {
  param([string]$ComputerName, [switch]$Remote)
  if ($Remote) {
    return Try-InvokeRemote -ComputerName $ComputerName -Default ([pscustomobject]@{Pending=$false;Reasons="(ei saatu etänä)"}) -ScriptBlock {
      $pending = $false; $reasons = @()
      $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
      )
      foreach ($p in $paths) { if (Test-Path $p) { $pending = $true; $reasons += (Split-Path $p -Leaf) } }
      try {
        $pf = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction Stop
        if ($pf -and $pf.PendingFileRenameOperations) { $pending = $true; $reasons += "PendingFileRenameOperations" }
      } catch {}
      [pscustomobject]@{ Pending=$pending; Reasons=($reasons | Sort-Object -Unique) -join ", " }
    }
  }

  $pending = $false; $reasons = @()
  $paths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
  )
  foreach ($p in $paths) { if (Test-Path $p) { $pending = $true; $reasons += (Split-Path $p -Leaf) } }
  $pf = Try-Run { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction Stop } $null
  if ($pf -and $pf.PendingFileRenameOperations) { $pending = $true; $reasons += "PendingFileRenameOperations" }
  [pscustomobject]@{ Pending=$pending; Reasons=($reasons | Sort-Object -Unique) -join ", " }
}

function Get-LastHotFixRemote {
  param([string]$ComputerName, [switch]$Remote)
  if ($Remote) { return Try-InvokeRemote -ComputerName $ComputerName -Default $null -ScriptBlock { Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 HotFixID, Description, InstalledOn } }
  return Try-Run { Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 HotFixID, Description, InstalledOn } $null
}

function Get-ListeningPortsRemote {
  param([string]$ComputerName, [switch]$Remote)
  if ($Remote) {
    return Try-InvokeRemote -ComputerName $ComputerName -Default @() -ScriptBlock {
      if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) { return @() }
      $list = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, OwningProcess -Unique | Sort-Object LocalPort, LocalAddress
      foreach ($c in $list) {
        $pname = ""
        try { $pname = (Get-Process -Id $c.OwningProcess -ErrorAction Stop).ProcessName } catch {}
        [pscustomobject]@{ LocalAddress=[string]$c.LocalAddress; LocalPort=$c.LocalPort; ProcessId=$c.OwningProcess; ProcessName=$pname }
      }
    }
  }

  if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) { return @() }
  return Try-Run {
    $list = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, OwningProcess -Unique | Sort-Object LocalPort, LocalAddress
    foreach ($c in $list) {
      $pname = Try-Run { (Get-Process -Id $c.OwningProcess -ErrorAction Stop).ProcessName } ""
      [pscustomobject]@{ LocalAddress=[string]$c.LocalAddress; LocalPort=$c.LocalPort; ProcessId=$c.OwningProcess; ProcessName=$pname }
    }
  } @()
}

function Get-LocalGroupsCim {
  param([CimSession]$CimSession)
  if (-not $CimSession) { return @() }
  Try-Run {
    Get-CimInstance -ClassName Win32_Group -Filter "LocalAccount=True" -CimSession $CimSession |
      Select-Object @{n="Name";e={$_.Name}}, @{n="Description";e={$_.Description}}
  } @()
}

function Get-LocalGroupMembersCim {
  param([CimSession]$CimSession)
  if (-not $CimSession) { return @() }

  Try-Run {
    $links = Get-CimInstance -ClassName Win32_GroupUser -CimSession $CimSession
    foreach ($l in $links) {
      $g = [string]$l.GroupComponent
      $p = [string]$l.PartComponent

      $gName   = if ($g -match 'Name="([^"]+)"')   { $matches[1] } else { "" }
      $pDomain = if ($p -match 'Domain="([^"]+)"') { $matches[1] } else { "" }
      $pName   = if ($p -match 'Name="([^"]+)"')   { $matches[1] } else { "" }

      if ($gName -and $pName) {
        [pscustomobject]@{
          Group           = $gName
          Name            = ("{0}\{1}" -f $pDomain, $pName).Trim("\")
          ObjectClass     = ""
          PrincipalSource = ""
        }
      }
    }
  } @() | Sort-Object Group, Name -Unique
}

function Get-FileHashes {
  param([Parameter(Mandatory=$true)][string[]]$Paths)
  $rows = @()
  foreach ($p in $Paths) {
    if ($p -and (Test-Path $p)) {
      $h = Try-Run { Get-FileHash -Path $p -Algorithm SHA256 } $null
      if ($h) { $rows += [pscustomobject]@{ File=(Split-Path $p -Leaf); Algorithm=$h.Algorithm; Hash=$h.Hash } }
    }
  }
  $rows
}

# ---------------- CSS fix DataTables ----------------
$FixCss = @'
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
table.dataTable thead th .dt-column-title,
table.dataTable thead th .dt-column-order,
.dataTables_wrapper .dataTables_scrollHead table.dataTable thead th .dt-column-title,
.dataTables_wrapper .dataTables_scrollHead table.dataTable thead th .dt-column-order { color: #111 !important; }
table.dataTable thead th,
.dataTables_wrapper .dataTables_scrollHead table.dataTable thead th { overflow: visible !important; }
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
table.dataTable thead th input::placeholder { color: #666 !important; opacity: 1 !important; }
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
.dataTables_wrapper .dataTables_scrollHeadInner,
.dataTables_wrapper .dataTables_scrollHeadInner table { width: 100% !important; }
table.dataTable thead th { min-width: 70px; }
'@

# ---------------- MAIN ----------------
try {
  Start-Transcript -Path $RunLog -Append | Out-Null

  # PSWriteHTML
  if (-not (Get-Module -ListAvailable -Name PSWriteHTML)) {
    Install-Module PSWriteHTML -Scope CurrentUser -Force -AllowClobber
  }
  Import-Module PSWriteHTML -Force

  $Now = Get-Date
  $isAdmin = Test-IsAdmin

  # Perus CIM
  $os    = Get-CimSafe -Class Win32_OperatingSystem
  $bios  = Get-CimSafe -Class Win32_BIOS
  $cpu   = Get-CimSafe -Class Win32_Processor
  $cs    = Get-CimSafe -Class Win32_ComputerSystem
  $disks = Get-CimSafe -Class Win32_LogicalDisk -Filter "DriveType=3"
  $net   = Get-CimSafe -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true"

  # DomainRole (CIM: Win32_ComputerSystem.DomainRole) 4/5 = DC
  $domainRole = if ($cs) { [int]$cs.DomainRole } else { -1 }
  $isDC = ($domainRole -in 4,5)

  # Reboot/hotfix/listening ports (WinRM best-effort)
  $reboot     = Get-RebootPendingRemote -ComputerName $ComputerName -Remote:$IsRemote
  $lastHotfix = Get-LastHotFixRemote -ComputerName $ComputerName -Remote:$IsRemote
  $listeningPorts = Get-ListeningPortsRemote -ComputerName $ComputerName -Remote:$IsRemote

  # Apps (WinRM best-effort)
  $apps = @()
  if ($IsRemote) {
    $apps = Try-InvokeRemote -ComputerName $ComputerName -Default @() -ScriptBlock {
      $MaxInstalledApps = $using:MaxInstalledApps
      $sources = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
      )
      $list = foreach ($p in $sources) {
        Get-ItemProperty $p -ErrorAction SilentlyContinue |
          Where-Object { $_.DisplayName } |
          Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
      }
      $list | Sort-Object DisplayName -Unique | Select-Object -First $MaxInstalledApps
    }
  } else {
    $apps = Try-Run {
      $sources = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
      )
      $list = foreach ($p in $sources) {
        Get-ItemProperty $p -ErrorAction SilentlyContinue |
          Where-Object { $_.DisplayName } |
          Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
      }
      $list | Sort-Object DisplayName -Unique | Select-Object -First $MaxInstalledApps
    } @()
  }

  # Local Users (CIM ok myös etänä)
  $localUsers = @()
  if (-not $isDC) {
    $localUsers = if ($cim) {
      Try-Run { Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" -CimSession $cim | Select-Object Name, Disabled, Lockout, PasswordChangeable, PasswordRequired } @()
    } else {
      Try-Run { Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True" | Select-Object Name, Disabled, Lockout, PasswordChangeable, PasswordRequired } @()
    }
  }

  # Local Groups + Members (DC: skip)
  $localGroups = @()
  $localGroupMembers = @()
  $localGroupsSource = ""
  if ($isDC) {
    $localGroupsSource = "DC: ei paikallista SAM-ryhmälistausta (by design)"
  } else {
    if ($cim) {
      $localGroupsSource = "CIM(Win32_Group/Win32_GroupUser)"
      $localGroups = Get-LocalGroupsCim -CimSession $cim
      $localGroupMembers = Get-LocalGroupMembersCim -CimSession $cim
    } else {
      $localGroupsSource = "Ei CIM-sessiota"
    }
  }

  # Windows Features / Roles (WinRM best-effort)
  $features = @()
  if ($IsRemote) {
    $features = Try-InvokeRemote -ComputerName $ComputerName -Default @() -ScriptBlock {
      if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        Import-Module ServerManager -ErrorAction SilentlyContinue | Out-Null
        Get-WindowsFeature | Where-Object { $_.Installed } | Select-Object DisplayName, Name, FeatureType, Path
      } else {
        Get-WindowsCapability -Online | Where-Object { $_.State -eq "Installed" } |
          Select-Object @{n="DisplayName";e={$_.Name}}, @{n="Name";e={$_.Name}}, @{n="FeatureType";e={"Capability"}}, @{n="Path";e={""}}
      }
    }
  } else {
    $features = Try-Run {
      if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        Import-Module ServerManager -ErrorAction Stop
        Get-WindowsFeature | Where-Object { $_.Installed } | Select-Object DisplayName, Name, FeatureType, Path
      } else {
        Get-WindowsCapability -Online | Where-Object { $_.State -eq "Installed" } |
          Select-Object @{n="DisplayName";e={$_.Name}}, @{n="Name";e={$_.Name}}, @{n="FeatureType";e={"Capability"}}, @{n="Path";e={""}}
      }
    } @()
  }

  # AD / Privileged groups (tämä osa ajetaan hallintakoneelta AD-moduulilla)
  $adModuleAvailable = $false
  $privGroups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators","DNSAdmins")
  $privMembers = @()
  $adminCountUsers = @()

  Try-Run {
    Import-Module ActiveDirectory -ErrorAction Stop
    $adModuleAvailable = $true

    foreach ($g in $privGroups) {
      Try-Run {
        Get-ADGroupMember -Identity $g -Recursive |
          Select-Object @{n="Group";e={$g}}, Name, SamAccountName, ObjectClass, DistinguishedName
      } @() | ForEach-Object { $privMembers += $_ }
    }

    $adminCountUsers = Try-Run {
      Get-ADUser -LDAPFilter "(adminCount=1)" -Properties SamAccountName, Enabled, LastLogonDate, PasswordLastSet, whenCreated, whenChanged |
        Select-Object Name, SamAccountName, Enabled, LastLogonDate, PasswordLastSet, whenCreated, whenChanged
    } @()
  } $null | Out-Null

  # Export liitteet (prefixillä)
  $featuresCsv  = Join-Path $OutDir ("{0}-windows-features.csv" -f $NamePrefix)
  $featuresJson = Join-Path $OutDir ("{0}-windows-features.json" -f $NamePrefix)
  if ($features -and @($features).Count -gt 0) {
    $features | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $featuresCsv
    $features | ConvertTo-Json -Depth 6 | Out-File -Encoding UTF8 $featuresJson
  }

  $listenCsv  = Join-Path $OutDir ("{0}-listening-ports.csv" -f $NamePrefix)
  $listenJson = Join-Path $OutDir ("{0}-listening-ports.json" -f $NamePrefix)
  if ($listeningPorts -and @($listeningPorts).Count -gt 0) {
    $listeningPorts | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $listenCsv
    $listeningPorts | ConvertTo-Json -Depth 6 | Out-File -Encoding UTF8 $listenJson
  }

  $privCsv = Join-Path $OutDir ("{0}-ad-privileged-members.csv" -f $NamePrefix)
  if ($privMembers -and @($privMembers).Count -gt 0) {
    $privMembers | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $privCsv
  }

  $adminCountCsv = Join-Path $OutDir ("{0}-ad-admincount1-users.csv" -f $NamePrefix)
  if ($adminCountUsers -and @($adminCountUsers).Count -gt 0) {
    $adminCountUsers | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $adminCountCsv
  }

  # ---------------- RENDER HTML ----------------
  New-HTML -TitleText "AuditReports - $ComputerName" -FilePath $HtmlPath -Online {

    New-HTMLHeader {
      New-HTMLText -Text "Windows audit (controller-ajolla)" -FontSize 26 -FontWeight bold
      New-HTMLText -Text "Kohde:  $ComputerName" -FontSize 14
      New-HTMLText -Text ("Luotu: {0}" -f $Now.ToString("dd.MM.yyyy HH:mm")) -FontSize 12
    }

    New-HTMLSection -HeaderText "Ajokonteksti" {
      $execContext = @(
        [pscustomobject]@{ Kenttä="Käyttäjä"; Arvo=("{0}\{1}" -f $env:USERDOMAIN, $env:USERNAME) }
        [pscustomobject]@{ Kenttä="Admin-oikeudet (ohjauskone)"; Arvo=$isAdmin }
        [pscustomobject]@{ Kenttä="PowerShell"; Arvo=("$($PSVersionTable.PSVersion)") }
        [pscustomobject]@{ Kenttä="Kohde"; Arvo=$ComputerName }
        [pscustomobject]@{ Kenttä="Etäajo"; Arvo=$IsRemote }
        [pscustomobject]@{ Kenttä="CIM (DCOM) sessio"; Arvo=([bool]$cim) }
        [pscustomobject]@{ Kenttä="Kohde DomainRole"; Arvo=$domainRole }
        [pscustomobject]@{ Kenttä="Kohde on DC"; Arvo=$isDC }
        [pscustomobject]@{ Kenttä="AD-moduuli (ohjauskone)"; Arvo=$adModuleAvailable }
      )
      New-FlatTable -DataTable $execContext -HideFooter

      if ($reboot) {
        New-HTMLText -Text ("Reboot pending: <b>{0}</b> {1}" -f $(if ($reboot.Pending){"YES"}else{"NO"}), $(if ($reboot.Reasons){"($($reboot.Reasons))"}else{""})) -FontSize 12
      }
      if ($lastHotfix) {
        New-HTMLText -Text ("Viimeisin hotfix: <b>{0}</b> ({1})" -f $lastHotfix.HotFixID, ($lastHotfix.InstalledOn.ToString("dd.MM.yyyy"))) -FontSize 12
      }
    }

    New-HTMLSection -HeaderText "Yhteenveto" {
      $uptimeDays = if ($os) { [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 2) } else { "" }
      $summary = @(
        [pscustomobject]@{ Kenttä="OS"; Arvo=($(if ($os) { $os.Caption } else { "" })) }
        [pscustomobject]@{ Kenttä="Build"; Arvo=($(if ($os) { $os.BuildNumber } else { "" })) }
        [pscustomobject]@{ Kenttä="Uptime (pv)"; Arvo=$uptimeDays }
        [pscustomobject]@{ Kenttä="RAM (GB)"; Arvo=($(if ($cs) { [math]::Round($cs.TotalPhysicalMemory/1GB,2) } else { "" })) }
        [pscustomobject]@{ Kenttä="Kuuntelevat portit"; Arvo=(@($listeningPorts).Count) }
        [pscustomobject]@{ Kenttä="Asennetut ohjelmat (rajattu)"; Arvo=(@($apps).Count) }
        [pscustomobject]@{ Kenttä="Paikalliset ryhmät"; Arvo=(@($localGroups).Count) }
        [pscustomobject]@{ Kenttä="Paikallisten ryhmien jäsenyydet"; Arvo=(@($localGroupMembers).Count) }
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
        $basic += [pscustomobject]@{ Kenttä="LastBootUpTime"; Arvo=$os.LastBootUpTime }
      }
      if ($cs) {
        $basic += [pscustomobject]@{ Kenttä="Valmistaja"; Arvo=$cs.Manufacturer }
        $basic += [pscustomobject]@{ Kenttä="Malli"; Arvo=$cs.Model }
        $basic += [pscustomobject]@{ Kenttä="Domain"; Arvo=$cs.Domain }
        $basic += [pscustomobject]@{ Kenttä="DomainRole"; Arvo=$cs.DomainRole }
      }
      if ($bios) { $basic += [pscustomobject]@{ Kenttä="BIOS"; Arvo=$bios.SMBIOSBIOSVersion } }
      if ($cpu)  { $basic += [pscustomobject]@{ Kenttä="CPU"; Arvo=$cpu.Name } }

      if ($basic.Count -gt 0) { New-FlatTable -DataTable $basic -HideFooter } else { New-HTMLText -Text "Perustietoja ei saatu." }
    }

    New-HTMLSection -HeaderText "Levyt" {
      if ($disks -and @($disks).Count -gt 0) {
        $diskRows = $disks | Select-Object DeviceID,
          @{n="Koko (GB)";e={[math]::Round($_.Size/1GB,2)}},
          @{n="Vapaa (GB)";e={[math]::Round($_.FreeSpace/1GB,2)}},
          @{n="Vapaa (%)";e={ if ($_.Size) { [math]::Round(($_.FreeSpace/[double]$_.Size)*100,2) } else { "" } }}
        New-NiceTable -Data $diskRows -PageLength 25 -HideFooter
      } else { New-HTMLText -Text "Levyjä ei saatu listattua." }
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
      } else { New-HTMLText -Text "Verkkotietoja ei saatu listattua." }
    }

    New-HTMLSection -HeaderText "Kuuntelevat portit" {
      if ($listeningPorts -and @($listeningPorts).Count -gt 0) {
        New-NiceTable -Data $listeningPorts -PageLength 25 -HideFooter
        New-HTMLText -Text "Liitteet:" -FontWeight bold
        New-HTMLLink -Text (Split-Path $listenCsv -Leaf)  -Url (Split-Path $listenCsv -Leaf)
        New-HTMLLink -Text (Split-Path $listenJson -Leaf) -Url (Split-Path $listenJson -Leaf)
      } else { New-HTMLText -Text "Kuuntelevia portteja ei saatu listattua (WinRM ei käytössä / oikeudet / cmdlet puuttuu)." }
    }

    New-HTMLSection -HeaderText "Asennetut ohjelmistot" {
      if ($apps -and @($apps).Count -gt 0) {
        New-NiceTable -Data $apps -PageLength 25 -HideFooter
        if (@($apps).Count -ge $MaxInstalledApps) { New-HTMLText -Text ("Huom: lista on rajattu ({0})." -f $MaxInstalledApps) -FontSize 12 }
      } else { New-HTMLText -Text "Ohjelmistolistaa ei saatu (etäajo ei onnistunut / WinRM pois)." }
    }

    New-HTMLSection -HeaderText "Paikalliset käyttäjät / ryhmät" {
      if ($isDC) {
        New-HTMLText -Text "Kohde on Domain Controller. Paikallista SAM-käyttäjä/ryhmälistaa ei ole samalla tavalla kuin jäsenpalvelimella."
      } else {
        if ($localUsers -and @($localUsers).Count -gt 0) { New-HTMLText -Text "Paikalliset käyttäjät"; New-NiceTable -Data $localUsers -PageLength 25 -HideFooter }
        else { New-HTMLText -Text "Paikallisia käyttäjiä ei saatu listattua (tai niitä ei ole)." }

        New-HTMLText -Text ("Lähde: {0}" -f $localGroupsSource) -FontSize 12
        if ($localGroups -and @($localGroups).Count -gt 0) { New-HTMLText -Text "Paikalliset ryhmät"; New-NiceTable -Data $localGroups -PageLength 25 -HideFooter }
        else { New-HTMLText -Text "Paikallisia ryhmiä ei saatu listattua." }

        if ($localGroupMembers -and @($localGroupMembers).Count -gt 0) { New-HTMLText -Text "Ryhmien jäsenet"; New-NiceTable -Data $localGroupMembers -PageLength 25 -HideFooter }
        else { New-HTMLText -Text "Ryhmien jäseniä ei saatu listattua." }
      }
    }

    New-HTMLSection -HeaderText "Palveluroolit ja ominaisuudet" {
      if ($features -and @($features).Count -gt 0) {
        $roles        = @($features | Where-Object { $_.FeatureType -eq 'Role' })
        $roleServices = @($features | Where-Object { $_.FeatureType -eq 'Role Service' })
        $feat         = @($features | Where-Object { $_.FeatureType -eq 'Feature' -or $_.FeatureType -eq 'Capability' })

        if (@($roles).Count -gt 0) { New-HTMLText -Text "Roolit"; New-NiceTable -Data $roles -PageLength 25 -HideFooter } else { New-HTMLText -Text "Roolit: ei löytynyt." }
        if (@($roleServices).Count -gt 0) { New-HTMLText -Text "Roolipalvelut"; New-NiceTable -Data $roleServices -PageLength 25 -HideFooter } else { New-HTMLText -Text "Roolipalvelut: ei löytynyt." }
        if (@($feat).Count -gt 0) { New-HTMLText -Text "Ominaisuudet"; New-NiceTable -Data $feat -PageLength 25 -HideFooter } else { New-HTMLText -Text "Ominaisuudet: ei löytynyt." }

        New-HTMLText -Text "Liitteet:" -FontWeight bold
        New-HTMLLink -Text (Split-Path $featuresCsv -Leaf)  -Url (Split-Path $featuresCsv -Leaf)
        New-HTMLLink -Text (Split-Path $featuresJson -Leaf) -Url (Split-Path $featuresJson -Leaf)
      } else {
        New-HTMLText -Text "Roolit/ominaisuudet eivät ole listattavissa (WinRM pois / oikeudet / ei ServerManager)."
      }
    }

    New-HTMLSection -HeaderText "AD: Privileged groups + adminCount=1" {
      if (-not $adModuleAvailable) {
        New-HTMLText -Text "ActiveDirectory-moduuli puuttuu ohjauskoneelta (RSAT)."
      } else {
        if ($privMembers -and @($privMembers).Count -gt 0) {
          New-HTMLText -Text "Privileged groups - jäsenet (recursive)"
          New-NiceTable -Data $privMembers -PageLength 25 -HideFooter
          New-HTMLText -Text "Liite:" -FontWeight bold
          New-HTMLLink -Text (Split-Path $privCsv -Leaf) -Url (Split-Path $privCsv -Leaf)
        } else {
          New-HTMLText -Text "Privileged group -jäsenyyksiä ei saatu (oikeudet / ryhmät / moduuli)."
        }

        if ($adminCountUsers -and @($adminCountUsers).Count -gt 0) {
          New-HTMLText -Text "adminCount=1 käyttäjät"
          New-NiceTable -Data $adminCountUsers -PageLength 25 -HideFooter
          New-HTMLText -Text "Liite:" -FontWeight bold
          New-HTMLLink -Text (Split-Path $adminCountCsv -Leaf) -Url (Split-Path $adminCountCsv -Leaf)
        } else {
          New-HTMLText -Text "adminCount=1 käyttäjiä ei saatu listattua."
        }
      }
    }

    New-HTMLSection -HeaderText "Liitehashit (SHA256)" {
      $hashPaths = @($featuresCsv,$featuresJson,$listenCsv,$listenJson,$privCsv,$adminCountCsv,$RunLog) | Where-Object { $_ -and (Test-Path $_) }
      $hashRows = Get-FileHashes -Paths $hashPaths
      if ($hashRows -and @($hashRows).Count -gt 0) { New-NiceTable -Data $hashRows -PageLength 25 -HideFooter }
      else { New-HTMLText -Text "Hash-tietoja ei saatu muodostettua." }
    }
  }

  # CSS inject
  Try-Run {
    $html = Get-Content -Path $HtmlPath -Raw -ErrorAction Stop
    if ($html -notmatch 'table\.dataTable thead th') {
      $styleTag = "<style>`n$FixCss`n</style>`n"
      $html = $html -replace '</head>', ($styleTag + '</head>')
      Set-Content -Path $HtmlPath -Value $html -Encoding UTF8
    }
  } $null | Out-Null

  "Valmista: $HtmlPath"

} catch {
  $_ | Out-String | Out-File -Encoding UTF8 -FilePath $ErrorLog
  throw
} finally {
  Try-Run { Stop-Transcript | Out-Null } $null | Out-Null
  if ($cim) { Try-Run { Remove-CimSession $cim } $null | Out-Null }
}