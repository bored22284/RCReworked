
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole] "Administrator")) {
    Write-Warning "Run this script as Administrator!"
    exit
}

$processesToKill = @('explorer', 'Widgets', 'widgetservice', 'msedgewebview2', 'MicrosoftEdge*', 'chredge', 'msedge', 'edge', 'msteams', 'msfamily', 'WebViewHost', 'Clipchamp')
foreach ($p in $processesToKill) {
    Get-Process -Name $p -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

$ALLHIVES = @(
    'HKCU:\SOFTWARE',
    'HKLM:\SOFTWARE',
    'HKCU:\SOFTWARE\Policies',
    'HKLM:\SOFTWARE\Policies'
)

foreach ($sw in $ALLHIVES) {
    Remove-Item -Path "$sw\Microsoft\EdgeUpdate" -Recurse -Force -ErrorAction SilentlyContinue
}

$remove_win32 = @("Microsoft Edge", "Microsoft Edge Update")
foreach ($name in $remove_win32) {
    foreach ($sw in $ALLHIVES) {
        $key = "$sw\Microsoft\Windows\CurrentVersion\Uninstall\$name"
        if (Test-Path $key) {
            Remove-ItemProperty -Path $key -Name 'NoRemove' -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $key -Name 'NoModify' -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $key -Name 'NoRepair' -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $key -Name 'ForceRemove' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $key -Name 'Delete' -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        }
    }
}

$remove_appx = @("MicrosoftEdge", "Win32WebViewHost", "WebExperience", "GamingServices")
$provisioned = Get-AppxProvisionedPackage -Online
$appxpackage = Get-AppxPackage -AllUsers

foreach ($choice in $remove_appx) {
    if ([string]::IsNullOrWhiteSpace($choice)) { continue }

    $provisioned | Where-Object { $_.PackageName -like "*$choice*" } | ForEach-Object {
        Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -AllUsers -ErrorAction SilentlyContinue
    }
    $appxpackage | Where-Object { $_.PackageFullName -like "*$choice*" } | ForEach-Object {
        Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue
    }
}

$foldersToScan = @('LocalApplicationData','ProgramFilesX86','ProgramFiles')
$edgesSetup = @()

foreach ($folder in $foldersToScan) {
    $path = [Environment]::GetFolderPath($folder)
    $edgesSetup += Get-ChildItem -Path "$path\Microsoft\Edge*" -Recurse -Filter 'setup.exe' -ErrorAction SilentlyContinue
}

foreach ($setup in $edgesSetup) {
    $args = "--uninstall --msedge --system-level --verbose-logging --force-uninstall"
    Start-Process -FilePath $setup.FullName -ArgumentList $args -Wait -ErrorAction SilentlyContinue
}

Get-ChildItem 'HKLM:\SOFTWARE\Classes\Installer\Products' | ForEach-Object {
    $product = Get-ItemProperty $_.PSPath
    if ($product.ProductName -like '*Microsoft Edge*') {
        $prodGuid = ($_.PSChildName -split '(.{8})(.{4})(.{4})(.{4})' -join '-').Trim('-')
        msiexec.exe /x $prodGuid /qn
        Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
        foreach ($sw in $ALLHIVES) {
            Remove-Item -Path "$sw\Microsoft\Windows\CurrentVersion\Uninstall\$prodGuid" -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

$edgeUpdates = Get-ChildItem "$env:ProgramFiles\Microsoft\EdgeUpdate\*" -Filter "MicrosoftEdgeUpdate.exe" -Recurse -ErrorAction SilentlyContinue
foreach ($update in $edgeUpdates) {
    & $update.FullName /unregsvc
    Start-Sleep -Seconds 3
    & $update.FullName /uninstall
    Start-Sleep -Seconds 3
}

Unregister-ScheduledTask -TaskName "MicrosoftEdgeUpdate*" -Confirm:$false -ErrorAction SilentlyContinue

Remove-Item "$env:ProgramFiles\Microsoft\Temp" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Tombstones\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue
Start-Process "takeown.exe" -ArgumentList '/f "C:\Program Files (x86)\Microsoft" /r /d y' -Wait -NoNewWindow
Start-Process "icacls.exe" -ArgumentList '"C:\Program Files (x86)\Microsoft" /grant administrators:F /t' -Wait -NoNewWindow
Remove-Item "C:\Program Files (x86)\Microsoft" -Recurse -Force
Remove-Item "$env:USERPROFILE\Desktop\Microsoft Edge.lnk" -Force -ErrorAction SilentlyContinue














