# Update-FSLogix

## Overview
`Update-FSLogix` is a PowerShell 5.1–compatible script to check, download, and update Microsoft FSLogix to the latest available release.

### Features

- Detects the currently installed FSLogix version (registry + file version of `frx.exe`).
- Resolves the official aka.ms download URL (no redirect loops, PS 5.1-safe).
- Downloads the package using BITS by default with automatic fallback to `Invoke-WebRequest`.
- Extracts the ZIP, finds `FSLogixAppsSetup.exe`, parses its FileVersion, and compares.
- Optionally performs a silent, in-place upgrade when a newer version is available.

Ideal for golden images and AVD/RDS session hosts.

---

## Requirements

- Windows with PowerShell 5.1.
- Run elevated for install/upgrade (recommended).
- Internet access to `https://aka.ms/fslogix_download` unless using `-InstallerPath`.
- BITS service available (default download method), otherwise the script falls back to `Invoke-WebRequest`.

---

## Usage
You can execute the script from this repository or install it into your environment. Examples below assume the script file is available as `Update-FSLogix.ps1`.

### Quick check (no install)

```powershell
PowerShell -ExecutionPolicy Bypass -File .\Update-FSLogix.ps1 -ZipCompare
```

### Update to latest (silent)

```powershell
PowerShell -ExecutionPolicy Bypass -File .\Update-FSLogix.ps1 -Update -AcceptEula
```

### Use a local installer (ZIP or EXE)

```powershell
PowerShell -ExecutionPolicy Bypass -File .\Update-FSLogix.ps1 -InstallerPath C:\path\to\FSLogix.zip -Update -AcceptEula
```

### Resolve only (print final URL)

```powershell
PowerShell -ExecutionPolicy Bypass -File .\Update-FSLogix.ps1 -ResolveOnly
```

### Show version hint from URL

```powershell
PowerShell -ExecutionPolicy Bypass -File .\Update-FSLogix.ps1 -OnlineCompare
```

---

## Parameters

- `-AcceptEula` Required when using `-Update`.
- `-Update` Perform a silent in-place upgrade if the package is newer than installed.
- `-ResolveOnly` Resolve the aka.ms link and print the final target URL.
- `-OnlineCompare` Print a best-effort version hint parsed from the URL.
- `-ZipCompare` Compare package FileVersion vs. installed version (no install).
- `-InstallerPath <ZIP|EXE>` Use a local ZIP/EXE instead of downloading.
- `-DownloadUrl <string>` Defaults to `https://aka.ms/fslogix_download`.
- `-UseBits` Use BITS for download (default). To force `Invoke-WebRequest` instead, pass `-UseBits:$false`.
- `-NoProxy` Bypass system proxy for this process (via .NET `DefaultWebProxy`).
- `-KeepTemp` Keep temp working folder for troubleshooting.
- `-LogPath <dir>` Log directory. Default: `C:\ProgramData\FSLogix\Update`.

---

## Behavior and Notes

- Download uses BITS by default. If BITS fails, the script automatically falls back to `Invoke-WebRequest` with `-UseBasicParsing` for PS 5.1.
- Version comparison is robust: the script parses numeric components from `FileVersion` and normalizes to a 4-part version for comparison.
- The script enables TLS 1.2 for compatibility with Microsoft endpoints.
- Logging goes to console (without polluting pipeline) and to a rolling log file in `-LogPath`.

---

## Changelog

- 0.1.2
	- Default to BITS for downloads with automatic fallback to `Invoke-WebRequest`.
	- Clarified README and parameter docs.
	- Minor robustness fixes for version parsing and logging.
- 0.1.1
	- PowerShell 5.1 hardening and proxy handling.
- 0.1.0
	- Added `-Update`, `-InstallerPath`, version compare improvements.
- 0.0.1
	- Initial release.
