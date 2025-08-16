# Update-FSLogix

## Overview
`Update-FSLogix` is a PowerShell script designed to **check, download, and update** Microsoft FSLogix on Windows hosts.  
It automates the process of:
- Detecting the currently installed FSLogix version  
- Downloading the latest release via the official Microsoft aka.ms link  
- Extracting the ZIP archive  
- Comparing versions (installed vs. available)  
- Performing a silent upgrade if required  

The script is especially useful for **Azure Virtual Desktop (AVD)** or **Remote Desktop Services (RDS)** environments where keeping FSLogix up-to-date is critical.

---

## Installation

### From PowerShell Gallery
```powershell
Install-Script -Name Update-FSLogix -Scope CurrentUser -Force
