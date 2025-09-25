<#PSScriptInfo

.VERSION 0.1.2
.GUID 37311878-913e-4dd0-bc2f-a9400438f589
.AUTHOR Jörg Brors
.COMPANYNAME
.COPYRIGHT (c) 2025 Jörg Brors. All rights reserved.
.TAGS FSLogix Update GoldenImage ZipCompare OnlineCompare
.LICENSEURI https://opensource.org/licenses/MIT
.PROJECTURI https://github.com/joergbrors/Update-FSLogix
.DESCRIPTION Update-FSLogix checks, downloads, and updates Microsoft FSLogix to the latest available release (PowerShell 5.1 compatible).
.RELEASENOTES
    0.1.2 – Default to BITS for downloads with automatic fallback to Invoke-WebRequest; clarify docs; minor robustness fixes.
    0.1.1 – PS 5.1 hardening: remove null-coalescing, avoid ProxyUseDefaultCredentials, implement NoProxy via DefaultWebProxy, keep only 5.1-safe params.
    0.1.0 – Add -Update path, support -InstallerPath (ZIP/EXE), robust version compare, TLS 1.2, admin check, summary.
    0.0.1 – Initial release.
#>
<#
.SYNOPSIS
    Checks, downloads, and updates Microsoft FSLogix to the latest available release.

.PARAMETER AcceptEula
    Required for -Update.

.PARAMETER Update
    Perform silent in-place upgrade if newer.

.PARAMETER ResolveOnly
    Resolve final aka.ms target URL and print it.

.PARAMETER OnlineCompare
    Show best-effort version hint from URL.

.PARAMETER ZipCompare
    Compare package FileVersion vs installed (no install).

.PARAMETER InstallerPath
    Local ZIP or EXE to use instead of downloading.

.PARAMETER DownloadUrl
    Defaults to https://aka.ms/fslogix_download.

.PARAMETER UseBits
    Use BITS for download (default). To force Invoke-WebRequest instead, pass -UseBits:$false.

.PARAMETER NoProxy
    Bypass system proxy for this process (via .NET DefaultWebProxy).

.PARAMETER KeepTemp
    Keep temp files.

.PARAMETER LogPath
    Log directory (default C:\ProgramData\FSLogix\Update).
#>

#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [switch]$AcceptEula,
    [switch]$Update,
    [switch]$ResolveOnly,
    [switch]$OnlineCompare,
    [switch]$ZipCompare,
    [string]$InstallerPath = "",
    [string]$DownloadUrl = "https://aka.ms/fslogix_download",
    [switch]$UseBits = $true,
    [switch]$NoProxy,
    [switch]$KeepTemp,
    [string]$LogPath = "C:\ProgramData\FSLogix\Update"
)

# --- Pre-flight: TLS & Admin ---
try {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
} catch { }

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-Admin)) {
    Write-Warning "Please run elevated (Administrator). Some actions will fail otherwise."
}

# Handle NoProxy for the whole process (PS 5.1-safe)
$originalProxy = [System.Net.WebRequest]::DefaultWebProxy
if ($NoProxy) {
    try {
        [System.Net.WebRequest]::DefaultWebProxy = New-Object System.Net.WebProxy  # direct
    } catch { }
    # also clear env proxies for child operations
    $env:http_proxy  = $null
    $env:https_proxy = $null
    $env:HTTP_PROXY  = $null
    $env:HTTPS_PROXY = $null
}

# --- Logging ---
function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO","WARN","ERROR","DEBUG")]
        [string]$Level = "INFO"
    )
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    # Write to console without polluting the pipeline
    Write-Host $line
    if ($script:LogFile) { Add-Content -Path $script:LogFile -Value $line }
}
if (-not (Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force | Out-Null }
$script:LogFile = Join-Path $LogPath ("fslogix_update_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
Write-Log "Log file: $script:LogFile"

# --- Helpers ---
function Get-FSLogixInstalledVersion {
    $reg = "HKLM:\SOFTWARE\FSLogix\Apps"
    $result = [ordered]@{
        Installed       = $false
        Running         = $false
        FileVersion     = $null
        RegistryVersion = $null
        ExePath         = "C:\Program Files\FSLogix\Apps\frx.exe"
    }

    if (Test-Path $reg) {
        try {
            $val = Get-ItemProperty -Path $reg -ErrorAction Stop
            $result.RegistryVersion = $val.Version
        } catch {
            Write-Log "Registry read failed: $_" "WARN"
        }
    }

    if (Test-Path $result.ExePath) {
        try {
            $fv = (Get-Item $result.ExePath).VersionInfo.FileVersion
            $result.FileVersion = $fv
            $result.Installed = $true
        } catch {
            Write-Log "Failed to read frx.exe FileVersion: $_" "WARN"
        }
    }

    try {
        $svc = Get-Service -Name "frxsvc" -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") { $result.Running = $true }
    } catch { }

    [pscustomobject]$result
}

function Resolve-FslogixUrl {
    param([Parameter(Mandatory)][string]$Url)
    # Use HttpWebRequest to catch Location header without auto-redirect (PS 5.1-safe)
    try {
        $req = [System.Net.HttpWebRequest]::Create($Url)
        $req.AllowAutoRedirect = $false
        $req.Method = "HEAD"
        $resp = $req.GetResponse()
        try {
            $loc = $resp.Headers["Location"]
            if ([string]::IsNullOrWhiteSpace($loc)) { return $Url } else { return $loc }
        } finally { $resp.Close() }
    } catch {
        # If it threw due to 3xx, try to read Location from the response
        try {
            $resp = $_.Exception.Response
            if ($resp -and $resp.Headers) {
                $loc = $resp.Headers["Location"]
                if ($loc) { return $loc }
            }
        } catch { }
        Write-Log "Failed to resolve URL ($Url): $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Download-File {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Destination
    )
    if (Test-Path $Destination) { Remove-Item -Path $Destination -Force -ErrorAction SilentlyContinue }

    if ($UseBits) {
        Write-Log "Using BITS transfer..."
        try {
            Start-BitsTransfer -Source $Url -Destination $Destination -DisplayName "FSLogix Download" -ErrorAction Stop
            return
        } catch {
            Write-Log "BITS transfer failed: $($_.Exception.Message). Falling back to Invoke-WebRequest..." "WARN"
        }
    }

    try {
        Write-Log "Using Invoke-WebRequest for download..."
        Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing -ErrorAction Stop
    } catch {
        Write-Log "Download failed: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Expand-Zip {
    param(
        [Parameter(Mandatory)][string]$ZipPath,
        [Parameter(Mandatory)][string]$Destination
    )
    if (-not (Test-Path $Destination)) { New-Item -Path $Destination -ItemType Directory -Force | Out-Null }
    Expand-Archive -Path $ZipPath -DestinationPath $Destination -Force
}

function Try-ParseVersion {
    param([string]$s)
    try {
        $parts = ($s -split '[^\d]+' | Where-Object { $_ -ne '' })
        if ($parts.Count -ge 3) {
            $padded = @($parts[0], $parts[1], $parts[2], ($(if ($parts.Count -ge 4) { $parts[3] } else { '0' })))
            $norm = ($padded[0..3]) -join '.'
            return [version]$norm
        }
    } catch { }
    return $null
}

function Get-FileVersionVersionObj {
    param([string]$FilePath)
    $fv = (Get-Item $FilePath).VersionInfo.FileVersion
    $vObj = Try-ParseVersion -s $fv
    [pscustomobject]@{ Raw = $fv; Version = $vObj }
}

function Find-SetupInFolder { param([string]$Root)
    $setup = Get-ChildItem -Path $Root -Recurse -Filter "FSLogixAppsSetup.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($setup) { return $setup.FullName } else { return $null }
}

function Stop-Start-FrxSvc { param([switch]$StopOnly)
    $svc = Get-Service -Name "frxsvc" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-Log "Stopping service frxsvc..."
        Stop-Service -Name frxsvc -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    if (-not $StopOnly) {
        Write-Log "Starting service frxsvc..."
        Start-Service -Name frxsvc -ErrorAction SilentlyContinue
    }
}

function Install-FSLogix {
    param(
        [Parameter(Mandatory)][string]$SetupExe,
        [Parameter(Mandatory)][string]$LogDir
    )
    if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
    $setupLog = Join-Path $LogDir ("FSLogixSetup_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
    # Assumption: silent flags supported by FSLogix EXE
    $args = '/install /quiet /norestart /log "{0}"' -f $setupLog

    Write-Log "Running: `"$SetupExe`" $args"
    if ($PSCmdlet.ShouldProcess($SetupExe, "Install FSLogix")) {
        Stop-Start-FrxSvc -StopOnly
        $p = Start-Process -FilePath $SetupExe -ArgumentList $args -Wait -PassThru
        Write-Log "Installer exit code: $($p.ExitCode)"
        Start-Sleep -Seconds 2
        Stop-Start-FrxSvc
        return $p.ExitCode
    }
    return 0
}

# --- State ---
$installed = Get-FSLogixInstalledVersion
Write-Log "Installed: Installed=$($installed.Installed), Running=$($installed.Running), FileVersion=$($installed.FileVersion), RegistryVersion=$($installed.RegistryVersion)"

# --- Work folders ---
$workRoot = Join-Path ([IO.Path]::GetTempPath()) ("fslogix_{0}" -f ([guid]::NewGuid().ToString('N')))
$newPaths = [ordered]@{
    Root         = $workRoot
    Zip          = Join-Path $workRoot "fslogix.zip"
    Extract      = Join-Path $workRoot "extract"
    SetupExe     = $null
    Source       = $null   # 'URL' | 'InstallerPathZIP' | 'InstallerPathEXE'
    ResolvedUrl  = $null
}
New-Item -Path $workRoot -ItemType Directory -Force | Out-Null

# Ensure cleanup of proxy on exit
$cleanupProxyScriptBlock = {
    param($originalProxyRef, $noProxyFlag)
    if ($noProxyFlag) {
        try { [System.Net.WebRequest]::DefaultWebProxy = $originalProxyRef } catch { }
    }
}

try {
    if ($InstallerPath) {
        if (-not (Test-Path $InstallerPath)) { throw "InstallerPath not found: $InstallerPath" }
        $ext = [IO.Path]::GetExtension($InstallerPath).ToLowerInvariant()
        if ($ext -eq ".zip") {
            Write-Log "Using local ZIP: $InstallerPath"
            $newPaths.Source = 'InstallerPathZIP'
            Expand-Zip -ZipPath $InstallerPath -Destination $newPaths.Extract
            $setupExe = Find-SetupInFolder -Root $newPaths.Extract
            if (-not $setupExe) { throw "FSLogixAppsSetup.exe not found in ZIP." }
            $newPaths.SetupExe = $setupExe
        }
        elseif ($ext -eq ".exe") {
            Write-Log "Using local EXE: $InstallerPath"
            $newPaths.Source = 'InstallerPathEXE'
            $newPaths.SetupExe = $InstallerPath
        }
        else { throw "Unsupported file extension for InstallerPath: $ext" }
    }
    else {
        $resolved = Resolve-FslogixUrl -Url $DownloadUrl
        if (-not $resolved) { throw "Could not resolve download URL." }
        $newPaths.ResolvedUrl = $resolved
        Write-Log "Resolved final download URL: $resolved"

        Write-Log "Downloading package to $($newPaths.Zip)"
        Download-File -Url $resolved -Destination $newPaths.Zip
        Unblock-File -Path $newPaths.Zip -ErrorAction SilentlyContinue

        Expand-Zip -ZipPath $newPaths.Zip -Destination $newPaths.Extract
        $setupExe = Find-SetupInFolder -Root $newPaths.Extract
        if (-not $setupExe) { throw "FSLogixAppsSetup.exe not found after extraction." }
        $newPaths.SetupExe = $setupExe
        $newPaths.Source = 'URL'
    }

    # --- Version from package ---
    $pkgVersionInfo = Get-FileVersionVersionObj -FilePath $newPaths.SetupExe
    Write-Log "Package FSLogixAppsSetup.exe FileVersion (raw): $($pkgVersionInfo.Raw)"
    if (-not $pkgVersionInfo.Version) { Write-Log "Could not parse package version for robust comparison." "WARN" }

    # --- Installed version ---
    $installedVersionObj = $null
    if ($installed.FileVersion) {
        $installedVersionObj = Try-ParseVersion -s $installed.FileVersion
        Write-Log "Installed frx.exe FileVersion (raw): $($installed.FileVersion); parsed=$installedVersionObj"
    } else {
        Write-Log "FSLogix appears not installed or frx.exe missing." "WARN"
    }

    # --- Decide upgrade ---
    $isUpgradeAvailable = $false
    if ($pkgVersionInfo.Version -and $installedVersionObj) {
        $isUpgradeAvailable = ($installedVersionObj -lt $pkgVersionInfo.Version)
        Write-Log ("Comparison: Installed={0}  Package={1}  UpgradeAvailable={2}" -f $installedVersionObj, $pkgVersionInfo.Version, $isUpgradeAvailable)
    } elseif ($pkgVersionInfo.Version -and -not $installedVersionObj) {
        $isUpgradeAvailable = $true
        Write-Log "Treating as upgrade: installed version unknown, package has version." "WARN"
    }

    # --- Modes ---
    if ($ResolveOnly) {
        if ($newPaths.ResolvedUrl) {
            Write-Log "ResolveOnly: final URL = $($newPaths.ResolvedUrl)"
        } else {
            Write-Log "ResolveOnly: using local installer (no URL)."
        }
        return
    }

    if ($OnlineCompare) {
        if ($newPaths.ResolvedUrl) {
            $m = [regex]::Match($newPaths.ResolvedUrl, '(?<v>\d{4}\.\d{1,2}|\d{1,2}\.\d{1,2}|\d+\.\d+\.\d+\.\d+)')
            if ($m.Success) { Write-Log "Info: version hint in URL: $($m.Groups['v'].Value)" }
            else { Write-Log "No clear version hint in URL." "WARN" }
        } else {
            Write-Log "OnlineCompare requested, but using local InstallerPath. Skipping." "WARN"
        }
        return
    }

    if ($ZipCompare -and -not $Update) {
        Write-Log "ZipCompare: comparison complete. No install performed."
        return
    }

    if ($Update) {
        if (-not $AcceptEula) {
            Write-Log "You must specify -AcceptEula to proceed with installation." "ERROR"
            throw "EULA not accepted."
        }
        if (-not $isUpgradeAvailable -and $installed.Installed) {
            Write-Log "Installed version is up-to-date or newer. No installation performed."
        } else {
            $exit = [int](Install-FSLogix -SetupExe $newPaths.SetupExe -LogDir $LogPath)
            if ($exit -ne 0) {
                Write-Log "Installer returned non-zero exit code: $exit" "ERROR"
                throw "FSLogix installation failed with exit code $exit"
            } else {
                Write-Log "FSLogix installation completed successfully."
            }
        }
    }
}
finally {
    # restore default proxy if changed
    & $cleanupProxyScriptBlock $originalProxy $NoProxy | Out-Null
    if (-not $KeepTemp -and (Test-Path $workRoot)) {
        try { Remove-Item -Path $workRoot -Recurse -Force -ErrorAction SilentlyContinue } catch { }
    } else {
        Write-Log "Keeping temp folder: $workRoot"
    }
}

# --- Summary ---
$after = Get-FSLogixInstalledVersion
$result = [pscustomobject]@{
    LogFile                  = $script:LogFile
    Source                   = $newPaths.Source
    ResolvedUrl              = $newPaths.ResolvedUrl
    PackageSetupExe          = $newPaths.SetupExe
    Installed_Before         = $installed
    Installed_After          = $after
    Package_FileVersion_Raw  = $pkgVersionInfo.Raw
    Package_FileVersion      = $pkgVersionInfo.Version
}
$result | Format-List
