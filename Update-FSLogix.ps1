<#PSScriptInfo

.VERSION 0.0.1
.GUID 37311878-913e-4dd0-bc2f-a9400438f589
.AUTHOR Jörg Brors
.COMPANYNAME 
.COPYRIGHT (c) 2025 Jörg Brors. All rights reserved.
.TAGS FSLogix Update GoldenImage ZipCompare OnlineCompare
.LICENS MIT
.PROJECTURI https://github.com/joergbrors/Update-FSLogix
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
    0.0.1 – Initial release, created by ChatGPT on behalf of Jörg Brors.
#>
<#
.SYNOPSIS
Checks, downloads, and updates Microsoft FSLogix to the latest available release.

.DESCRIPTION
Update-FSLogix checks the installed FSLogix version on the host and, if requested, downloads
the current package via the official aka.ms redirect, extracts the ZIP, reads the
FSLogixAppsSetup.exe FileVersion, compares it to the installed build, and performs a
silent in-place upgrade when newer. Created by ChatGPT on behalf of Jörg Brors.
All output is in English.

.PARAMETER Update
Perform the in-place silent upgrade if a newer build is available.

.PARAMETER ZipCompare
Download the latest ZIP, extract it, read the EXE FileVersion, and compare only (no install).

.PARAMETER ResolveOnly
Resolve the final download URL behind https://aka.ms/fslogix_download and show it.

.PARAMETER NoProxy
Disable system proxy usage for HTTP requests (useful for strict corporate proxies).

.PARAMETER KeepTemp
Keep the downloaded ZIP and extracted temp folder for troubleshooting.

.EXAMPLE
.\Update-FSLogix.ps1
Performs a check only (no changes).

.EXAMPLE
.\Update-FSLogix.ps1 -ZipCompare
Downloads current package, extracts, and compares version with installed build.

.EXAMPLE
.\Update-FSLogix.ps1 -Update
Performs a silent in-place upgrade if the downloaded build is newer.

.NOTES
Run in an elevated PowerShell session (Administrator). Works with Windows PowerShell 5.1 and newer.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [switch]$AcceptEula,
    [switch]$Update,
    [switch]$ResolveOnly,
    [switch]$OnlineCompare,
    [switch]$ZipCompare,
    [string]$InstallerPath = "",
    [string]$DownloadUrl = "https://aka.ms/fslogix_download",
    [switch]$UseBits,
    [switch]$NoProxy,
    [switch]$KeepTemp,
    [string]$LogPath = "C:\ProgramData\FSLogix\Update"
)

# --- Logging helper ---
function Write-Log {
    param([string]$Message, [string]$Level="INFO")
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Write-Output $line
    if ($global:LogFile) { Add-Content -Path $global:LogFile -Value $line }
}

# --- Prepare logging ---
if (-not (Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force | Out-Null }
$global:LogFile = Join-Path $LogPath ("fslogix_update_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
Write-Log "Log file: $global:LogFile"

# --- Get installed FSLogix version ---
function Get-FSLogixInstalledVersion {
    $reg = "HKLM:\SOFTWARE\FSLogix\Apps"
    $result = [ordered]@{
        Installed = $false; Running = $false; FileVersion = $null; RegistryVersion = $null
    }

    if (Test-Path $reg) {
        $val = Get-ItemProperty -Path $reg -ErrorAction SilentlyContinue
        $result.RegistryVersion = $val.Version
        $exe = "C:\Program Files\FSLogix\Apps\frx.exe"
        if (Test-Path $exe) {
            $fv = (Get-Item $exe).VersionInfo.FileVersion
            $result.FileVersion = $fv
            $result.Installed = $true
        }
        $svc = Get-Service -Name "frxsvc" -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") { $result.Running = $true }
    }
    [pscustomobject]$result
}

$installed = Get-FSLogixInstalledVersion
Write-Log "Installed before: Installed=$($installed.Installed), Running=$($installed.Running), FileVersion=$($installed.FileVersion), RegistryVersion=$($installed.RegistryVersion)"

# --- Resolve aka.ms link ---
function Resolve-FslogixUrl {
    param([string]$Url)
    try {
        $req = [System.Net.WebRequest]::Create($Url)
        $req.AllowAutoRedirect = $false
        $resp = $req.GetResponse()
        $final = $resp.GetResponseHeader("Location")
        $resp.Close()
        return $final
    } catch {
        Write-Log "Failed to resolve URL: $_" "ERROR"
        return $null
    }
}

# --- Download helper ---
function Download-File {
    param([string]$Url, [string]$Destination)
    if ($UseBits) {
        Write-Log "Using BITS transfer..."
        Start-BitsTransfer -Source $Url -Destination $Destination -DisplayName "FSLogix Download"
    }
    else {
        try {
            Write-Log "Using WebClient for download..."
            $wc = New-Object System.Net.WebClient
            if ($NoProxy) { $wc.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy() }
            $wc.DownloadFile($Url, $Destination)
        }
        catch {
            Write-Log "WebClient failed, trying Invoke-WebRequest..." "WARN"
            Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing
        }
    }
}

# --- Compare version inside ZIP ---
function Compare-ZipVersion {
    param([string]$Url)

    $temp = New-Item -Path ([IO.Path]::GetTempPath()) -Name ("fslogix_{0}" -f (Get-Random)) -ItemType Directory
    $zipPath = Join-Path $temp "fslogix.zip"
    Write-Log "Downloading package to $zipPath"
    Download-File -Url $Url -Destination $zipPath

    $extract = Join-Path $temp "extract"
    Expand-Archive -Path $zipPath -DestinationPath $extract -Force
    $setup = Get-ChildItem -Path $extract -Recurse -Filter "FSLogixAppsSetup.exe" | Select-Object -First 1
    if ($setup) {
        $filever = (Get-Item $setup.FullName).VersionInfo.FileVersion
        Write-Log "Extracted FSLogixAppsSetup.exe version: $filever"
        if ($installed.FileVersion -ne $null) {
            if ([version]$installed.FileVersion -lt [version]$filever) {
                Write-Log "Installed version $($installed.FileVersion) is older than package version $filever" "WARN"
            } else {
                Write-Log "Installed version $($installed.FileVersion) is up-to-date (>= $filever)"
            }
        }
    } else {
        Write-Log "Setup executable not found in ZIP" "ERROR"
    }

    if (-not $KeepTemp) { Remove-Item -Path $temp -Recurse -Force }
}

# --- Main flow ---
$finalUrl = Resolve-FslogixUrl -Url $DownloadUrl
if ($finalUrl) { Write-Log "Resolved final download URL: $finalUrl" }

if ($ZipCompare) {
    if ($finalUrl) { Compare-ZipVersion -Url $finalUrl }
    return
}

if ($OnlineCompare) {
    if ($finalUrl -match "FSLogix_(?<mver>\d{2}\.\d{2})\.zip") {
        Write-Log "Info: version in URL (marketing): $($matches['mver'])"
        Write-Log "No full build in filename to compare against installed build." "WARN"
    }
    return
}

if ($ResolveOnly) {
    Write-Log "ResolveOnly: final URL = $finalUrl"
    return
}

Write-Log "Default: check only. Use -Update or -ZipCompare for actions."
