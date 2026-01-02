<#
MasterTune: Debloat + Cleanup + Tune (4GB/64GB eMMC – z. B. Lenovo IdeaPad Duet 3)

WICHTIG:
- Apply-Läufe benötigen i. d. R. Admin.
- DryRun kann optional ohne Admin laufen: -DryRun -AllowDryRunWithoutAdmin
  (Appx/Provisioned-Abfragen sind dann eingeschränkt; es wird gewarnt statt „Zugriff verweigert“ zu spammen).

Run (empfohlen):
  Set-ExecutionPolicy Bypass -Scope Process
  .\Win11-Duet3-MasterTune.ps1 -Apply -Profile Duet3LowEnd

DryRun (keine Änderungen):
  .\Win11-Duet3-MasterTune.ps1 -Apply -Profile Duet3LowEnd -DryRun

DryRun ohne Admin (nur Preview, eingeschränkt):
  .\Win11-Duet3-MasterTune.ps1 -Apply -Profile Duet3LowEnd -DryRun -AllowDryRunWithoutAdmin

Aggressiv (MaxPerformance):
  # Aggressiveres Profil für max. Performance auf Low-End:
  #  - entfernt zusätzliche Consumer-Features (Widgets/Teams consumer/Clipchamp)
  #  - reduziert Hintergrundlast (Background Apps/Telemetry Policies/Update-Bandwidth)
  #  - optional inkl. nicht zwingender Lenovo-Tools (keine Treiber)
  #  - OneDrive bleibt standardmäßig im Autostart
  .\Win11-Duet3-MasterTune.ps1 -Apply -Profile MaxPerformance

Custom Beispiele:
  .\Win11-Duet3-MasterTune.ps1 -Apply -Profile Duet3LowEnd -RemoveWidgets -RemoveTeamsConsumer -RemoveClipchamp -ReduceSearchIndex
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [ValidateSet("Duet3LowEnd","Conservative","MaxPerformance","Custom")]
  [Alias('Profile')]
  [string]$TuneProfile = "Duet3LowEnd",

  [switch]$Apply,
  [switch]$DryRun,

  [switch]$DoDebloat,
  [switch]$DoCleanup,
  [switch]$DoTune,

  [switch]$RemoveWidgets,
  [switch]$RemoveTeamsConsumer,
  [switch]$RemoveClipchamp,
  [switch]$RemoveLenovoOptional,

  [switch]$DisableSysMain,
  [switch]$ReduceSearchIndex,

  [switch]$ReduceUpdateBandwidth,
  [switch]$DisableHibernation,
  [switch]$DisableFastStartup,
  [switch]$DisableBackgroundApps,
  [switch]$DisableXboxFeatures,
  [switch]$OptimizeEdge,
  [switch]$TrimComponentStore,
  [switch]$DisableTelemetry,
  [switch]$OptimizePageFile,
  [switch]$SkipRestorePoint,
  [switch]$AllowDryRunWithoutAdmin,
  [switch]$OptimizeAutostart,
  [switch]$KeepOneDriveAutostart,
  [string]$EdgeCacheRoot = "$env:LOCALAPPDATA\Microsoft\Edge\User Data",

  [string]$LogPath = "$env:ProgramData\Win11-Duet3\MasterTune.log"
)

$SelectedProfile = $TuneProfile

function Assert-Admin {
  # Allow analysis-only runs without elevation.
  if ($DryRun -and $AllowDryRunWithoutAdmin) { return }
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Please start PowerShell as Administrator. (Use -DryRun -AllowDryRunWithoutAdmin for preview.)"
  }
}

function Initialize-LogDir {
  $dir = Split-Path -Parent $LogPath
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

function Log([string]$msg) {
  $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
  $line = "[$ts] $msg"
  Write-Host $line
  try {
    Add-Content -Path $LogPath -Value $line -ErrorAction Stop
  } catch {
    # Logging must never break the script.
    Write-Host "[$ts] WARN: Could not write log file '$LogPath': $($_.Exception.Message)"
  }
}

function Reset-LogFile {
  try {
    if (Test-Path $LogPath) {
      Remove-Item -Path $LogPath -Force -ErrorAction SilentlyContinue
    }
  } catch {
    # best effort
  }
}

function New-RestorePointSafe([string]$name) {
  try {
    if ($DryRun) { Log "DRYRUN: Restore point '$name'"; return }
    Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue | Out-Null
    Checkpoint-Computer -Description $name -RestorePointType "MODIFY_SETTINGS" -ErrorAction SilentlyContinue
    Log "Restore point requested (works only if System Protection is enabled)."
  } catch {
    Log "WARN: Could not create restore point: $($_.Exception.Message)"
  }
}

function Set-RegValue([string]$Path,[string]$Name,$Value,[ValidateSet("String","DWord","Binary")] [string]$Type="DWord") {
  if ($DryRun) { Log "DRYRUN: Set $Path\$Name=$Value ($Type)"; return }
  if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
  New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
  Log "Set $Path\$Name=$Value ($Type)"
}

function Disable-ServiceSafe([string]$ServiceName) {
  $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  if (-not $svc) { Log "Service '$ServiceName' not found."; return }
  if ($DryRun) { Log "DRYRUN: Disable service $ServiceName"; return }
  try {
    if ($svc.Status -ne 'Stopped') { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue }
    Set-Service -Name $ServiceName -StartupType Disabled
    Log "Service '$ServiceName' disabled."
  } catch {
    Log "WARN: Could not disable service '$ServiceName': $($_.Exception.Message)"
  }
}

function Set-ServiceManualSafe([string]$ServiceName) {
  $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  if (-not $svc) { Log "Service '$ServiceName' not found."; return }
  if ($DryRun) { Log "DRYRUN: Set service $ServiceName to Manual"; return }
  try {
    Set-Service -Name $ServiceName -StartupType Manual
    Log "Service '$ServiceName' set to Manual."
  } catch {
    Log "WARN: Could not set service '$ServiceName' to Manual: $($_.Exception.Message)"
  }
}

function Get-AppxPackagesSafe {
  param(
    [switch]$AllUsers,
    [string]$Pattern
  )

  $isAdmin = $false
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    $isAdmin = $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { $isAdmin = $false }

  try {
    if ($AllUsers -and $isAdmin) {
      $q = Get-AppxPackage -AllUsers -ErrorAction Stop
    } else {
      if ($AllUsers -and -not $isAdmin) {
        Log "WARN: Not elevated; Appx query will be CurrentUser only (skipping -AllUsers)."
      }
      $q = Get-AppxPackage -ErrorAction Stop
    }

    if ($Pattern) {
      return ($q | Where-Object { $_.Name -like $Pattern -or $_.PackageFullName -like $Pattern })
    }
    return $q
  } catch {
    Log "WARN: Appx query failed: $($_.Exception.Message)"
    return @()
  }
}

function Get-AppxProvisionedPackagesSafe {
  param([string]$Pattern)

  $isAdmin = $false
  try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    $isAdmin = $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { $isAdmin = $false }

  if (-not $isAdmin) {
    Log "WARN: Not elevated; skipping provisioned Appx query (Get-AppxProvisionedPackage -Online)."
    return @()
  }

  try {
    $q = Get-AppxProvisionedPackage -Online -ErrorAction Stop
    if ($Pattern) {
      return ($q | Where-Object { $_.DisplayName -like $Pattern -or $_.PackageName -like $Pattern })
    }
    return $q
  } catch {
    Log "WARN: Provisioned Appx query failed: $($_.Exception.Message)"
    return @()
  }
}

function Remove-AppxByPattern {
  [CmdletBinding(SupportsShouldProcess=$true)]
  param([string]$Pattern)

  $pkgs = Get-AppxPackagesSafe -AllUsers -Pattern $Pattern |
    Select-Object Name,PackageFullName -Unique

  foreach ($p in $pkgs) {
    if ($PSCmdlet.ShouldProcess($p.PackageFullName,"Remove-AppxPackage")) {
      if ($DryRun) { Log "DRYRUN: Remove-AppxPackage $($p.PackageFullName)"; continue }
      try { Remove-AppxPackage -Package $p.PackageFullName -AllUsers -ErrorAction SilentlyContinue | Out-Null } catch {}
      Log "Removed Appx: $($p.Name)"
    }
  }

  $prov = Get-AppxProvisionedPackagesSafe -Pattern $Pattern |
    Select-Object DisplayName,PackageName -Unique

  foreach ($pp in $prov) {
    if ($PSCmdlet.ShouldProcess($pp.PackageName,"Remove-AppxProvisionedPackage")) {
      if ($DryRun) { Log "DRYRUN: Remove-AppxProvisionedPackage $($pp.PackageName)"; continue }
      try { Remove-AppxProvisionedPackage -Online -PackageName $pp.PackageName -ErrorAction SilentlyContinue | Out-Null } catch {}
      Log "Removed provisioned package: $($pp.DisplayName)"
    }
  }
}

function Get-AppsByNameLike([string[]]$NameLike) {
  $paths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
  )

  foreach ($p in $paths) {
    Get-ItemProperty $p -ErrorAction SilentlyContinue |
      Where-Object { $_.DisplayName -and ($NameLike | Where-Object { $_.DisplayName -like $_ }) } |
      Select-Object DisplayName,UninstallString,QuietUninstallString
  }
}

function Uninstall-Win32ByNameLike {
  [CmdletBinding(SupportsShouldProcess=$true)]
  param([string[]]$NameLike)

  $apps = Get-AppsByNameLike -NameLike $NameLike

  foreach ($a in ($apps | Sort-Object DisplayName -Unique)) {
    $cmd = $a.QuietUninstallString
    if (-not $cmd) { $cmd = $a.UninstallString }
    if (-not $cmd) { Log "WARN: No uninstall string for '$($a.DisplayName)'."; continue }

    if ($PSCmdlet.ShouldProcess($a.DisplayName,"Uninstall Win32")) {
      if ($DryRun) { Log "DRYRUN: Uninstall '$($a.DisplayName)' via: $cmd"; continue }

      Log "Uninstalling '$($a.DisplayName)' ..."
      try {
        $exe=""; $argList=""
        if ($cmd -match '^\s*"(.*?)"\s*(.*)$') { $exe=$matches[1]; $argList=$matches[2] }
        elseif ($cmd -match '^\s*(\S+)\s+(.*)$') { $exe=$matches[1]; $argList=$matches[2] }
        else { $exe=$cmd; $argList="" }

        if ($exe -match 'msiexec(\.exe)?$' -and $argList -match '/I\s*\{') {
          $argList = ($argList -replace '/I','/X') + " /qn /norestart"
        }

        Start-Process -FilePath $exe -ArgumentList $argList -Wait -WindowStyle Hidden
        Log "Uninstall started: $($a.DisplayName)"
      } catch {
        Log "WARN: Uninstall failed '$($a.DisplayName)': $($_.Exception.Message)"
      }
    }
  }
}

function Remove-RunEntrySafe([string]$RegPath,[string]$Name) {
  if (-not (Test-Path $RegPath)) { return }
  if ($DryRun) { Log "DRYRUN: Remove autostart entry $RegPath\\$Name (if present)"; return }
  try {
    $props = Get-ItemProperty -Path $RegPath -ErrorAction SilentlyContinue
    if ($null -ne $props -and ($props.PSObject.Properties.Name -contains $Name)) {
      Remove-ItemProperty -Path $RegPath -Name $Name -ErrorAction SilentlyContinue
      Log "Autostart entry removed: $RegPath\\$Name"
    }
  } catch {
    Log ("WARN: Could not remove autostart entry {0}\\{1}: {2}" -f $RegPath,$Name,$_.Exception.Message)
  }
}

function Optimize-AutostartSafe {
  Log "--- Autostart optimization ---"

  # Keep this conservative: only remove known consumer/updater tray items if present.
  # Do NOT touch security, touch, audio, graphics, or cloud sync unless explicitly added later.

  $runPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
  )

  # Common optional entries (best-effort; will only remove if exact name exists)
  $names = @(
    "MicrosoftEdgeAutoLaunch",
    "MicrosoftEdgeUpdate",
    "Teams",
    "com.squirrel.Teams.Teams",
    "Spotify",
    "Discord"
    # NOTE: OneDrive is used on this device; do not disable its autostart unless explicitly requested.
  )

  if (-not $KeepOneDriveAutostart) {
    # Only if the user explicitly wants to disable the OneDrive Run entry.
    $names += "OneDrive"
  } else {
    Log "OneDrive autostart preserved (-KeepOneDriveAutostart)."
  }

  foreach ($rp in $runPaths) {
    foreach ($n in $names) {
      Remove-RunEntrySafe -RegPath $rp -Name $n
    }
  }

  Log "Autostart optimization done (conservative)."
}

function Show-DryRunPreview {
  Log "--- DryRun Preview (no changes will be applied) ---"

  Log "Planned profile: $SelectedProfile"
  Log "Planned actions: Debloat=$DoDebloat Cleanup=$DoCleanup Tune=$DoTune"

  if ($DoDebloat) {
    $patterns = @(
      "*Microsoft.BingNews*",
      "*Microsoft.BingWeather*",
      "*Microsoft.GetHelp*",
      "*Microsoft.Getstarted*",
      "*Microsoft.MicrosoftSolitaireCollection*",
      "*Microsoft.People*",
      "*Microsoft.SkypeApp*",
      "*Microsoft.Xbox*",
      "*Microsoft.GamingApp*",
      "*Microsoft.ZuneMusic*",
      "*Microsoft.ZuneVideo*",
      "*Microsoft.MixedReality.Portal*",
      "*Microsoft.YourPhone*",
      "*Microsoft.WindowsMaps*",
      "*Microsoft.MicrosoftOfficeHub*",
      "*Microsoft.Todos*"
    )

    if ($RemoveClipchamp)     { $patterns += "*Clipchamp.Clipchamp*" }
    if ($RemoveTeamsConsumer) { $patterns += "*MicrosoftTeams*"; $patterns += "*MSTeams*" }
    if ($RemoveWidgets)       { $patterns += "*MicrosoftWindows.Client.WebExperience*" }

    if ($RemoveLenovoOptional) {
      $patterns += @("*E046963F.LenovoCompanion*","*Lenovo*Vantage*","*LenovoUtility*","*LenovoHotkeys*")
    }

    $appx = foreach ($pat in ($patterns | Select-Object -Unique)) {
      Get-AppxPackagesSafe -AllUsers -Pattern $pat |
        Select-Object Name,PackageFullName
    }
    $appx = $appx | Sort-Object Name -Unique
    Log ("DryRun: Appx candidates matched: {0}" -f ($appx.Count))
    foreach ($i in ($appx | Select-Object -First 50)) { Log ("DryRun:  Appx -> {0}" -f $i.Name) }
    if ($appx.Count -gt 50) { Log ("DryRun:  ...and {0} more" -f ($appx.Count - 50)) }

    $win32Likes = @(
      "McAfee*","Norton*","Avast*","AVG*","WildTangent*",
      "Booking.com*","ExpressVPN*","CyberLink*Power2Go*",
      "Amazon*","Disney+*","Spotify*"
    )
    if ($RemoveLenovoOptional) {
      $win32Likes += @("Lenovo Vantage*","Lenovo Utility*","Lenovo Hotkeys*","Lenovo Service Bridge*")
    }
    $apps = Get-AppsByNameLike -NameLike $win32Likes | Sort-Object DisplayName -Unique
    Log ("DryRun: Win32 uninstall candidates matched: {0}" -f ($apps.Count))
    foreach ($a in ($apps | Select-Object -First 50)) { Log ("DryRun:  Win32 -> {0}" -f $a.DisplayName) }
    if ($apps.Count -gt 50) { Log ("DryRun:  ...and {0} more" -f ($apps.Count - 50)) }
  }

  if ($DoCleanup) {
    foreach ($path in @(
      "$env:WINDIR\SoftwareDistribution\Download",
      "$env:ProgramData\Microsoft\Windows\DeliveryOptimization\Cache",
      "$env:ProgramData\Microsoft\Windows\WER",
      "$env:LOCALAPPDATA\Microsoft\Windows\WER",
      "$env:TEMP",
      "$env:WINDIR\Temp"
    )) {
      if (Test-Path $path) {
        $count = (Get-ChildItem $path -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object).Count
        Log ("DryRun: Would clear '{0}' (items: {1})" -f $path,$count)
      } else {
        Log ("DryRun: Path not present: '{0}'" -f $path)
      }
    }
    Log "DryRun: Would run DISM StartComponentCleanup"
  }

  if ($DoTune) {
    Log "DryRun: Would set several registry values (UI animations, background apps, GameDVR, telemetry policy)."
    Log "DryRun: Would change power plan to Ultimate Performance (if available) and set CPU AC min/max to 100%."
    Log "DryRun: Would disable hibernation."
    if ($DisableSysMain) { Log "DryRun: Would disable service SysMain" } else { Log "DryRun: SysMain left enabled." }
    if ($ReduceSearchIndex) { Log "DryRun: Would set WSearch to Manual and apply Windows Search policy" } else { Log "DryRun: Windows Search left as-is." }
  }

  Log ("DryRun: Extra flags => DisableBackgroundApps=$DisableBackgroundApps DisableHibernation=$DisableHibernation DisableFastStartup=$DisableFastStartup ReduceUpdateBandwidth=$ReduceUpdateBandwidth DisableXboxFeatures=$DisableXboxFeatures DisableTelemetry=$DisableTelemetry")
}

function Invoke-Debloat {
  Log "--- Debloat ---"

  $common = @(
    "*Microsoft.BingNews*",
    "*Microsoft.BingWeather*",
    "*Microsoft.GetHelp*",
    "*Microsoft.Getstarted*",
    "*Microsoft.MicrosoftSolitaireCollection*",
    "*Microsoft.People*",
    "*Microsoft.SkypeApp*",
    "*Microsoft.Xbox*",
    "*Microsoft.GamingApp*",
    "*Microsoft.ZuneMusic*",
    "*Microsoft.ZuneVideo*",
    "*Microsoft.MixedReality.Portal*",
    "*Microsoft.YourPhone*",
    "*Microsoft.WindowsMaps*",
    "*Microsoft.MicrosoftOfficeHub*",
    "*Microsoft.Todos*"
  )

  foreach ($p in $common) { Remove-AppxByPattern $p }

  if ($RemoveClipchamp)     { Remove-AppxByPattern "*Clipchamp.Clipchamp*" }
  if ($RemoveTeamsConsumer) { Remove-AppxByPattern "*MicrosoftTeams*"; Remove-AppxByPattern "*MSTeams*" }
  if ($RemoveWidgets)       { Remove-AppxByPattern "*MicrosoftWindows.Client.WebExperience*" }

  if ($RemoveLenovoOptional) {
    Log "Lenovo/OEM removal enabled (may impact hotkeys/utilities)."
    foreach ($p in @("*E046963F.LenovoCompanion*","*Lenovo*Vantage*","*LenovoUtility*","*LenovoHotkeys*")) {
      Remove-AppxByPattern $p
    }
    Uninstall-Win32ByNameLike @("Lenovo Vantage*","Lenovo Utility*","Lenovo Hotkeys*","Lenovo Service Bridge*")
  } else {
    Log "Lenovo/OEM apps untouched."
  }

  # Explicit OEM/AV bloat removal coverage
  # (McAfee is often preinstalled as Win32 and sometimes shows up in store-provisioned packages.)
  Remove-AppxByPattern "*McAfee*"

  Uninstall-Win32ByNameLike @(
    "McAfee*","McAfee Security*","WebAdvisor*","McAfee WebAdvisor*",
    "Norton*","Avast*","AVG*","WildTangent*",
    "Booking.com*","ExpressVPN*","CyberLink*Power2Go*",
    "Amazon*","Disney+*","Spotify*"
  )
}

function Invoke-Cleanup {
  Log "--- Cleanup ---"

  if (-not $DryRun) {
    Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
    Stop-Service bits -Force -ErrorAction SilentlyContinue
  }

  $wu = "$env:WINDIR\SoftwareDistribution\Download"
  if (Test-Path $wu) {
    if ($DryRun) { Log "DRYRUN: Clear $wu" }
    else {
      Get-ChildItem $wu -Recurse -Force -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
      Log "Windows Update download cache cleared."
    }
  }

  if (-not $DryRun) {
    Start-Service bits -ErrorAction SilentlyContinue
    Start-Service wuauserv -ErrorAction SilentlyContinue
  }

  $do = "$env:ProgramData\Microsoft\Windows\DeliveryOptimization\Cache"
  if (Test-Path $do) {
    if ($DryRun) { Log "DRYRUN: Clear $do" }
    else {
      Get-ChildItem $do -Recurse -Force -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
      Log "Delivery Optimization cache cleared."
    }
  }

  foreach ($p in @("$env:ProgramData\Microsoft\Windows\WER","$env:LOCALAPPDATA\Microsoft\Windows\WER")) {
    if (Test-Path $p) {
      if ($DryRun) { Log "DRYRUN: Clear $p" }
      else {
        Get-ChildItem $p -Recurse -Force -ErrorAction SilentlyContinue |
          Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Log "WER cleared: $p"
      }
    }
  }

  foreach ($p in @($env:TEMP,"$env:WINDIR\Temp")) {
    if (Test-Path $p) {
      if ($DryRun) { Log "DRYRUN: Clear $p" }
      else {
        Get-ChildItem $p -Recurse -Force -ErrorAction SilentlyContinue |
          Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        Log "TEMP cleared: $p"
      }
    }
  }

  if ($DryRun) { Log "DRYRUN: dism /Online /Cleanup-Image /StartComponentCleanup /NoRestart" }
  else {
    try {
      dism /Online /Cleanup-Image /StartComponentCleanup /NoRestart | Out-Null
      Log "Component store cleaned."
    } catch {
      Log "WARN: DISM failed: $($_.Exception.Message)"
    }
  }

  if ($TrimComponentStore) {
    if ($DryRun) { Log "DRYRUN: dism /Online /Cleanup-Image /StartComponentCleanup /ResetBase" }
    else {
      try { dism /Online /Cleanup-Image /StartComponentCleanup /ResetBase | Out-Null; Log "Component store trimmed (ResetBase)." }
      catch { Log "WARN: DISM ResetBase failed: $($_.Exception.Message)" }
    }
  }
}

function Invoke-Tune {
  Log "--- Tune ---"

  Set-RegValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" "EnableTransparency" 0 "DWord"
  Set-RegValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarAnimations" 0 "DWord"
  Set-RegValue "HKCU:\Control Panel\Desktop" "DragFullWindows" "0" "String"
  Set-RegValue "HKCU:\Control Panel\Desktop" "MenuShowDelay" "0" "String"
  Set-RegValue "HKCU:\Control Panel\Desktop\WindowMetrics" "MinAnimate" "0" "String"

  Set-RegValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" "GlobalUserDisabled" 1 "DWord"
  Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsRunInBackground" 2 "DWord"

  Set-RegValue "HKCU:\System\GameConfigStore" "GameDVR_Enabled" 0 "DWord"
  Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" 0 "DWord"

  $rk = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
  if (Test-Path $rk) {
    if ($DryRun) { Log "DRYRUN: Remove OneDrive Run entry if exists" }
    else {
      $p = Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue
      if ($p -and $p.OneDrive) {
        Remove-ItemProperty -Path $rk -Name "OneDrive" -ErrorAction SilentlyContinue
        Log "OneDrive autorun removed."
      }
    }
  }

  Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 1 "DWord"

  if ($DryRun) {
    Log "DRYRUN: powercfg ultimate performance + CPU 100/100 AC"
  } else {
    try {
      $schemes = powercfg /L
      if ($schemes -notmatch "Ultimate Performance") {
        powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 | Out-Null
      }
      $schemes2 = powercfg /L
      $guidLine = $schemes2 | Select-String "Ultimate Performance" | Select-Object -First 1
      if ($guidLine) {
        $guid = $guidLine.ToString().Split()[3]
        if ($guid) {
          powercfg /S $guid | Out-Null
          Log "Power plan set to Ultimate Performance."
        }
      }
      powercfg -SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN 100 | Out-Null
      powercfg -SETACVALUEINDEX SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX 100 | Out-Null
      powercfg -SETACTIVE SCHEME_CURRENT | Out-Null
    } catch {
      Log "WARN: powercfg failed: $($_.Exception.Message)"
    }
  }

  if ($DryRun) { Log "DRYRUN: powercfg -h off" }
  else {
    try {
      powercfg -h off | Out-Null
      Log "Hibernation disabled."
    } catch {
      Log "WARN: Could not disable hibernation: $($_.Exception.Message)"
    }
  }

  if ($DisableSysMain) { Disable-ServiceSafe "SysMain" } else { Log "SysMain left enabled." }

  if ($ReduceSearchIndex) {
    Set-ServiceManualSafe "WSearch"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowIndexingEncryptedStoresOrItems" 0 "DWord"
  } else {
    Log "Windows Search left as-is."
  }

  # Extra low-end optimizations
  Optimize-VisualsLowEnd

  if ($DisableBackgroundApps) {
    Set-RegValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" "GlobalUserDisabled" 1 "DWord"
    Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsRunInBackground" 2 "DWord"
  }

  if ($DisableTelemetry) {
    Disable-TelemetryPolicies
  }

  if ($ReduceUpdateBandwidth) {
    Optimize-UpdateBandwidth
  }

  if ($DisableFastStartup) {
    Disable-FastStartupSafe
  }

  if ($DisableHibernation) {
    if ($DryRun) { Log "DRYRUN: powercfg -h off" } else { try { powercfg -h off | Out-Null; Log "Hibernation disabled." } catch { Log "WARN: Could not disable hibernation: $($_.Exception.Message)" } }
  }

  if ($DisableXboxFeatures) {
    Disable-XboxFeatures
  }

  if ($OptimizeEdge) {
    Optimize-EdgeLowEnd
  }

  if ($OptimizePageFile) {
    Optimize-PageFileSafe
  }

  # Prefer Ultimate Performance on low-end devices
  Set-PowerPlanUltimatePerformanceSafe
}

function Invoke-ExternalCommandSafe([string]$Display,[string]$FilePath,[string]$ArgumentList) {
  if ($DryRun) { Log ("DRYRUN: {0}: {1} {2}" -f $Display,$FilePath,$ArgumentList); return }
  try {
    Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -Wait -WindowStyle Hidden
    Log ("OK: {0}" -f $Display)
  } catch {
    Log ("WARN: Failed {0}: {1}" -f $Display,$($_.Exception.Message))
  }
}

function Set-PowerPlanUltimatePerformanceSafe {
  if ($DryRun) { Log "DRYRUN: Ensure and activate 'Ultimate Performance' power plan"; return }
  try {
    $schemes = powercfg /L
    if ($schemes -notmatch "Ultimate Performance") {
      powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 | Out-Null
    }
    $schemes2 = powercfg /L
    $guidLine = $schemes2 | Select-String "Ultimate Performance" | Select-Object -First 1
    if ($guidLine) {
      $guid = $guidLine.ToString().Split()[3]
      if ($guid) {
        powercfg /S $guid | Out-Null
        Log "Power plan set to Ultimate Performance."
      }
    }
  } catch {
    Log "WARN: powercfg failed: $($_.Exception.Message)"
  }
}

function Optimize-VisualsLowEnd {
  # Visual effects: best performance, keep fonts smoothing.
  Set-RegValue "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "VisualFXSetting" 2 "DWord"
  Set-RegValue "HKCU:\Control Panel\Desktop" "UserPreferencesMask" ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)) "Binary"
}

function Optimize-UpdateBandwidth {
  # Delivery Optimization: reduce background downloads on low-end eMMC.
  Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" 0 "DWord"
  Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DOMinBackgroundQoS" 10 "DWord"
  Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DOMaxBackgroundBandwidth" 10 "DWord"
}

function Optimize-EdgeLowEnd {
  # Reduce Edge disk churn: keep caching reasonable.
  if (-not (Test-Path $EdgeCacheRoot)) { Log "Edge profile path not found: $EdgeCacheRoot"; return }
  Log "Edge optimization note: consider clearing cache periodically on 64GB eMMC."
}

function Disable-FastStartupSafe {
  # Fast Startup can cause longer disk usage spikes on constrained devices.
  Set-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" "HiberbootEnabled" 0 "DWord"
}

function Optimize-PageFileSafe {
  # Conservative: leave system managed by default; optionally set fixed size to reduce fragmentation.
  if ($DryRun) { Log "DRYRUN: Would keep pagefile system-managed (recommended) unless fixed sizing is configured."; return }
  Log "Pagefile: leaving system-managed (recommended for stability on 4GB RAM)."
}

function Disable-TelemetryPolicies {
  Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0 "DWord"
  Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1 "DWord"
}

function Disable-XboxFeatures {
  Remove-AppxByPattern "*Microsoft.Xbox*"
  Remove-AppxByPattern "*Microsoft.GamingApp*"
  Set-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" 0 "DWord"
}

function Show-PhaseProgress([int]$Index,[int]$Total,[string]$Activity,[string]$Status="") {
  $pct = [Math]::Min(100,[Math]::Max(0,[int](($Index / [double]$Total) * 100)))
  if ([string]::IsNullOrWhiteSpace($Status)) {
    $Status = "Step $Index of $Total"
  }
  try {
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $pct
  } catch {
    # ignore (Write-Progress may fail in some hosts)
  }
}

function Complete-Progress([string]$Activity) {
  try {
    Write-Progress -Activity $Activity -Completed
  } catch {
    # ignore
  }
}

# ---------------- MAIN ----------------

Assert-Admin
Initialize-LogDir
Reset-LogFile

Log "=== MasterTune v2 start (Profile=$SelectedProfile, DryRun=$DryRun) ==="

if (-not $Apply) {
  Log "Abort: please run with -Apply."
  exit 1
}

$explicit = $DoDebloat -or $DoCleanup -or $DoTune
if (-not $explicit) {
  if ($SelectedProfile -eq "Duet3LowEnd") {
    $DoDebloat=$true; $DoCleanup=$true; $DoTune=$true
    $DisableBackgroundApps=$true
    $DisableHibernation=$true
    $DisableFastStartup=$true
    $ReduceUpdateBandwidth=$true
    $DisableXboxFeatures=$true
    $TrimComponentStore=$true
    $DisableTelemetry=$true
    $KeepOneDriveAutostart=$true
  }
  elseif ($SelectedProfile -eq "Conservative") { $DoDebloat=$false; $DoCleanup=$true; $DoTune=$true }
  elseif ($SelectedProfile -eq "MaxPerformance") {
    # Aggressive but keep Windows usable for VS Code + streaming.
    $DoDebloat=$true; $DoCleanup=$true; $DoTune=$true

    # Remove optional consumer features
    $RemoveWidgets=$true
    $RemoveTeamsConsumer=$true
    $RemoveClipchamp=$true

    # OEM optional cleanup (not drivers)
    $RemoveLenovoOptional=$true

    # Performance-oriented tuning
    $DisableBackgroundApps=$true
    $DisableHibernation=$true
    $DisableFastStartup=$true
    $ReduceUpdateBandwidth=$true
    $DisableXboxFeatures=$true
    $DisableTelemetry=$true

    # Optional: on 64GB eMMC this can reclaim space at the cost of rollback.
    $TrimComponentStore=$true

    # Sensible toggles
    $ReduceSearchIndex=$true
    $DisableSysMain=$false

    # Minor: Edge disk churn note
    $OptimizeEdge=$true

    # OneDrive is used: keep it in autostart.
    $KeepOneDriveAutostart=$true

    $OptimizeAutostart=$true
  }
  else { $DoDebloat=$false; $DoCleanup=$true; $DoTune=$true }
}

if ($DryRun) {
  Show-DryRunPreview
}

if (-not $SkipRestorePoint) {
  New-RestorePointSafe "MasterTune-v2-$SelectedProfile"
} else {
  Log "Restore point skipped."
}

$phases = @()
if ($DoDebloat) { $phases += 'Debloat' }
if ($DoCleanup) { $phases += 'Cleanup' }
if ($DoTune)    { $phases += 'Tune' }
if ($OptimizeAutostart) { $phases += 'Autostart' }
if ($phases.Count -eq 0) { $phases = @('No work') }

$progressActivity = "MasterTune v2 ($SelectedProfile)"
$step = 0
$total = $phases.Count

foreach ($phase in $phases) {
  $step++
  Show-PhaseProgress -Index $step -Total $total -Activity $progressActivity -Status $phase

  switch ($phase) {
    'Debloat'   { Invoke-Debloat }
    'Cleanup'   { Invoke-Cleanup }
    'Tune'      { Invoke-Tune }
    'Autostart' { Optimize-AutostartSafe }
    default     { }
  }
}

Complete-Progress -Activity $progressActivity

Log "=== MasterTune v2 done ==="
Log "Recommendation: reboot. Then wait 10-20 minutes idle and check performance."
