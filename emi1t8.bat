@echo off
Echo.
Echo Basic Tweaks
Title Applying Basic Tweaks & Color 05
timeout /t 2 >Nul
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "FilterAdministratorToken" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v LazyModeTimeout /t REG_DWORD /d 0x249F0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MultiMedia\systemprofile" /v "NoLazyMode" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "36" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "LsaCfgFlags" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "ConfigureSystemGuardLaunch" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "Locked" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "Locked" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Locked" /t REG_DWORD /d 0 /f
DISM /Online /Enable-Feature:Microsoft-Hyper-V-All /Quiet /NoRestart
reg add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "DiagnosticErrorText" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticErrorText" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticLinkText" /t REG_SZ /d "" /f
Reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d "2" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "Migrated" /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d 1 /f
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessGazeInput" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessNotifications" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTasks" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTrustedDevices" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessBackgroundSpatialPerception" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoice" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoiceAboveLock" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d 2 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v Value /t REG_SZ /d Allow /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v Value /t REG_SZ /d Allow /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v Value /t REG_SZ /d Deny /f
reg add "HKCU\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Unrestricted" /f
reg add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Unrestricted" /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSyncUserOverride" /t REG_DWORD /d 2 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v ConfigureWindowsSpotlight /t REG_DWORD /d 2 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v IncludeEnterpriseSpotlight /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightWindowsWelcomeExperience /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightOnActionCenter /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightOnSettings /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableThirdPartySuggestions /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v ScoobeSystemSettingEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableThirdPartySuggestions /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338393Enabled /t REG_DWORD /d 0 /f
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /V "1806" /T "REG_DWORD" /D "00000000" /F
REG ADD "HKU.DEFAULT\Control Panel\Accessibility\HighContrast" /V "Flags" /T "REG_SZ" /D "0" /F
REG ADD "HKU.DEFAULT\Control Panel\Accessibility\Keyboard Response" /V "Flags" /T "REG_SZ" /D "0" /F
REG ADD "HKU.DEFAULT\Control Panel\Accessibility\MouseKeys" /V "Flags" /T "REG_SZ" /D "0" /F
REG ADD "HKU.DEFAULT\Control Panel\Accessibility\SoundSentry" /V "Flags" /T "REG_SZ" /D "0" /F
REG ADD "HKU.DEFAULT\Control Panel\Accessibility\StickyKeys" /V "Flags" /T "REG_SZ" /D "0" /F
REG ADD "HKU.DEFAULT\Control Panel\Accessibility\TimeOut" /V "Flags" /T "REG_SZ" /D "0" /F
REG ADD "HKU.DEFAULT\Control Panel\Accessibility\ToggleKeys" /V "Flags" /T "REG_SZ" /D "0" /F
REG ADD "HKCU\Control Panel\Accessibility\MouseKeys" /V "Flags" /T "REG_SZ" /D "186" /F
REG ADD "HKCU\Control Panel\Accessibility\MouseKeys" /V "MaximumSpeed" /T "REG_SZ" /D "40" /F
REG ADD "HKCU\Control Panel\Accessibility\MouseKeys" /V "TimeToMaximumSpeed" /T "REG_SZ" /D "3000" /F
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowCommercialDataPipeline" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDesktopAnalyticsProcessing" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowUpdateComplianceProcessing" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowWUfBCloudProcessing" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DisableEnterpriseAuthProxy" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DisableTelemetryOptInChangeNotification" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DisableTelemetryOptInSettingsUx" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DisableDiagnosticDataViewer" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "EnableConfigFlighting" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /V "Start" /T "REG_DWORD" /D "0" /F
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /V "Start" /T "REG_DWORD" /D "0" /F
REG ADD "HKCU\Control Panel\Keyboard" /V "KeyboardDelay" /T "REG_SZ" /D "0" /F"
REG ADD "HKCU\Control Panel\Keyboard" /V "KeyboardSpeed" /T "REG_SZ" /D "31" /F"
REG ADD "HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response" /V AutoRepeatDelay /T REG_DWORD /D 200 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response" /V AutoRepeatRate /T REG_DWORD /D 6 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response" /V DelayBeforeAcceptance /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response" /V Flags /T REG_DWORD /D 59 /F
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /V "StartupDelayInMSec" /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /V "WaitForIdleState" /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /V "StartupDelayInMSec" /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /V "WaitForIdleState" /T REG_DWORD /D 0 /F
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /f
schtasks /Change /TN Microsoft\Windows\Defrag\ScheduledDefrag /Disable
schtasks /Change /TN Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents /Disable
schtasks /Change /TN Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic /Disable
schtasks /Change /tn "\Microsoft\Windows\DiskCleanup\SilentCleanup" /disable
schtasks /Change /tn "\Microsoft\Windows\Chkdsk\ProactiveScan" /disable
reg delete "HKLM\SOFTWARE\Classes\Folder\shell\pintohome" /f
reg add "HKCR\.txt\ShellNew" /v "ItemName" /t REG_EXPAND_SZ /d "@%%SystemRoot%%\system32\notepad.exe-470" /f
reg add "HKCR\txtfilelegacy" /ve /t REG_SZ /d "Text Document" /f
reg add "HKLM\SOFTWARE\Classes\.reg\ShellNew" /v "ItemName" /t REG_EXPAND_SZ /d "@%%SystemRoot%%\system32\notepad.exe-470" /f
reg add "HKLM\SOFTWARE\Classes\.ps1" /ve /t REG_SZ /d "ps1legacy" /f
reg add "HKLM\SOFTWARE\Classes\ps1legacy" /ve /t REG_SZ /d "Windows PowerShell Script" /f
reg add "HKLM\SOFTWARE\Classes\ps1legacy" /v "FriendlyTypeName" /t REG_SZ /d "Windows PowerShell Script" /f
reg delete "HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKLM\SOFTWARE\Classes\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}" /f
reg delete "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKLM\SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKLM\SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f
reg delete "HKLM\SOFTWARE\Classes\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f
reg delete "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f
reg delete "HKLM\SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" /f
reg delete "HKLM\SOFTWARE\Classes\*\shellex\ContextMenuHandlers\Sharing" /f
reg delete "HKLM\SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers\Sharing" /f
reg delete "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers\Sharing" /f
reg delete "HKLM\SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers\Sharing" /f
reg delete "HKLM\SOFTWARE\Classes\LibraryFolder\background\shellex\ContextMenuHandlers\Sharing" /f
reg delete "HKLM\SOFTWARE\Classes\UserLibraryFolder\shellex\ContextMenuHandlers\Sharing" /f
reg delete "HKLM\SOFTWARE\Classes\Folder\ShellEx\ContextMenuHandlers\Library Location" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\Shell\Open\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll" ImageView_Fullscreen %%1" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\Shell\Open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f
reg add "HKLM\SOFTWARE\Classes\Applications\photoviewer.dll\shell\open" /v "MuiVerb" /t REG_SZ /d "@photoviewer.dll-3043" /f
reg add "HKLM\SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll" ImageView_Fullscreen %%1" /f
reg add "HKLM\SOFTWARE\Classes\Applications\photoviewer.dll\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap" /v "FriendlyTypeName" /t REG_EXPAND_SZ /d "@%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll-3056" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\DefaultIcon" /ve /t REG_SZ /d "%%SystemRoot%%\System32\imageres.dll-70" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\shell\open\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll" ImageView_Fullscreen %%1" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f
reg add "HKLM\SOFTWARE\Classes\Applications\photoviewer.dll\shell\print" /v "NeverDefault" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Classes\Applications\photoviewer.dll\shell\print\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll" ImageView_Fullscreen %%1" /f
reg add "HKLM\SOFTWARE\Classes\Applications\photoviewer.dll\shell\print\DropTarget" /v "Clsid" /t REG_SZ /d "{60fd46de-f830-4894-a628-6fa81bc0190d}" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF" /v "EditFlags" /t REG_DWORD /d "65536" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF" /v "FriendlyTypeName" /t REG_EXPAND_SZ /d "@%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll-3055" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\DefaultIcon" /ve /t REG_SZ /d "%%SystemRoot%%\System32\imageres.dll-72" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\shell\open" /v "MuiVerb" /t REG_EXPAND_SZ /d "@%%ProgramFiles%%\Windows Photo Viewer\photoviewer.dll-3043" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\shell\open\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll" ImageView_Fullscreen %%1" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg" /v "EditFlags" /t REG_DWORD /d "65536" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg" /v "FriendlyTypeName" /t REG_EXPAND_SZ /d "@%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll-3055" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\DefaultIcon" /ve /t REG_SZ /d "%%SystemRoot%%\System32\imageres.dll-72" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\shell\open" /v "MuiVerb" /t REG_EXPAND_SZ /d "@%%ProgramFiles%%\Windows Photo Viewer\photoviewer.dll-3043" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\shell\open\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll" ImageView_Fullscreen %%1" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif" /v "FriendlyTypeName" /t REG_EXPAND_SZ /d "@%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll-3057" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif\DefaultIcon" /ve /t REG_SZ /d "%%SystemRoot%%\System32\imageres.dll-83" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif\shell\open\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll" ImageView_Fullscreen %%1" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png" /v "FriendlyTypeName" /t REG_EXPAND_SZ /d "@%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll-3057" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png\DefaultIcon" /ve /t REG_SZ /d "%%SystemRoot%%\System32\imageres.dll-71" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png\shell\open\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll" ImageView_Fullscreen %%1" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp" /v "EditFlags" /t REG_DWORD /d "65536" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\DefaultIcon" /ve /t REG_SZ /d "%%SystemRoot%%\System32\wmphoto.dll-400" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\shell\open" /v "MuiVerb" /t REG_EXPAND_SZ /d "@%%ProgramFiles%%\Windows Photo Viewer\photoviewer.dll-3043" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\shell\open\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll" ImageView_Fullscreen %%1" /f
reg add "HKLM\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f
reg add "HKLM\SOFTWARE\Classes\SystemFileAssociations\image\shell\Image Preview\command" /ve /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\rundll32.exe \"%%ProgramFiles%%\Windows Photo Viewer\PhotoViewer.dll" ImageView_Fullscreen %%1" /f
reg add "HKLM\SOFTWARE\Classes\SystemFileAssociations\image\shell\Image Preview\DropTarget" /v "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" /v "Attributes" /t REG_DWORD /d "2962489444" /f
REG ADD "HKU\.DEFAULT\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "0" /f >NUL 2>&1"
reg add "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_DWORD /d "0" /f"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v Serialize /t REG_DWORD /d "0" /f"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v SerializeLegacyRegistryKeys /t REG_DWORD /d "0" /f"
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MultiMedia\systemprofile" /v "NoLazyMode" /t REG_DWORD /d "1" /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "CursorCaptureEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AppBroadcast\GlobalSettings" /v "AudioCaptureEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AppBroadcast\GlobalSettings" /v "MicrophoneCaptureEnabledByDefault" /t REG_DWORD /d "0" /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AppBroadcast\GlobalSettings" /v "CameraCaptureEnabledByDefault" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\HardCap0" /v "CapPercentage" /t REG_DWORD /d "0" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\HardCap0" /v "SchedulingType" /t REG_DWORD /d "0" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\Paused" /v "CapPercentage" /t REG_DWORD /d "0" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\Paused" /v "SchedulingType" /t REG_DWORD /d "0" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFull" /v "CapPercentage" /t REG_DWORD /d "0" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFull" /v "SchedulingType" /t REG_DWORD /d "0" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLow" /v "CapPercentage" /t REG_DWORD /d "0" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLow" /v "SchedulingType" /t REG_DWORD /d "0" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\BackgroundDefault" /v "IsLowPriority" /t REG_DWORD /d "0" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Frozen" /v "IsLowPriority" /t REG_DWORD /d "0" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenDNCS" /v "IsLowPriority" /t REG_DWORD /d "0" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenDNK" /v "IsLowPriority" /t REG_DWORD /d "0" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenPPLE" /v "IsLowPriority" /t REG_DWORD /d "0" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Paused" /v "IsLowPriority" /t REG_DWORD /d "0" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\PausedDNK" /v "IsLowPriority" /t REG_DWORD /d "0" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Pausing" /v "IsLowPriority" /t REG_DWORD /d "0" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\PrelaunchForeground" /v "IsLowPriority" /t REG_DWORD /d "0" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\ThrottleGPUInterference" /v "IsLowPriority" /t REG_DWORD /d "0" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Critical" /v "BasePriority" /t REG_DWORD /d "82" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Critical" /v "OverTargetPriority" /t REG_DWORD /d "50" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\CriticalNoUi" /v "BasePriority" /t REG_DWORD /d "82" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\CriticalNoUi" /v "OverTargetPriority" /t REG_DWORD /d "50" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\EmptyHostPPLE" /v "BasePriority" /t REG_DWORD /d "82" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\EmptyHostPPLE" /v "OverTargetPriority" /t REG_DWORD /d "50" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\High" /v "BasePriority" /t REG_DWORD /d "82" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\High" /v "OverTargetPriority" /t REG_DWORD /d "50" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Low" /v "BasePriority" /t REG_DWORD /d "82" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Low" /v "OverTargetPriority" /t REG_DWORD /d "50" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Lowest" /v "BasePriority" /t REG_DWORD /d "82" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Lowest" /v "OverTargetPriority" /t REG_DWORD /d "50" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Medium" /v "BasePriority" /t REG_DWORD /d "82" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Medium" /v "OverTargetPriority" /t REG_DWORD /d "50" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\MediumHigh" /v "BasePriority" /t REG_DWORD /d "82" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\MediumHigh" /v "OverTargetPriority" /t REG_DWORD /d "50" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\StartHost" /v "BasePriority" /t REG_DWORD /d "82" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\StartHost" /v "OverTargetPriority" /t REG_DWORD /d "50" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryHigh" /v "BasePriority" /t REG_DWORD /d "82" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryHigh" /v "OverTargetPriority" /t REG_DWORD /d "50" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryLow" /v "BasePriority" /t REG_DWORD /d "82" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryLow" /v "OverTargetPriority" /t REG_DWORD /d "50" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\IO\NoCap" /v "IOBandwidth" /t REG_DWORD /d "0" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap" /v "CommitLimit" /t REG_DWORD /d "4294967295" /f"
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap" /v "CommitTarget" /t REG_DWORD /d "4294967295" /f"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v MiscPolicyInfo /t REG_DWORD /d 2 /f"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v PassedPolicy /t REG_DWORD /d 0 /f"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v ShippedWithReserves /t REG_DWORD /d 0 /f"
dism /Online /Set-ReservedStorageState /State:Disabled
Reg delete "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f >nul 2>&1
Reg add "HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /f >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "DisableDeleteNotification" /t REG_DWORD /d "0x0" /f"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "DontVerifyRandomDrivers" /t REG_DWORD /d "0x1" /f"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "DisableLastAccessUpdate" /t REG_DWORD /d "0x1" /f"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "Disable8dot3NameCreation" /t REG_DWORD /d "0x1" /f"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "FilterSupportedFeaturesMode" /t REG_DWORD /d "0x0" /f"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "FileNameCache" /t REG_DWORD /d "0x1000" /f"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "ConfigFileAllocSize" /t REG_DWORD /d "0x200" /f"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d "0x0" /f"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsAllowExtendedCharacter8dot3Rename" /t REG_DWORD /d "0x0" /f"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsBugcheckOnCorrupt" /t REG_DWORD /d "0x0" /f"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisable8dot3NameCreation" /t REG_DWORD /d "0x1" /f"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisableCompression" /t REG_DWORD /d "0x0" /f"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisableEncryption" /t REG_DWORD /d "0x1" /f"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisableLfsDowngrade" /t REG_DWORD /d "0x0" /f"
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /f"
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /f"
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v "LsaCfgFlags" /t REG_DWORD /d "0" /f"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "LsaCfgFlags" /t REG_DWORD /d "0" /f"
reg add "HKLM\Software\Microsoft\FTH" /v "Enabled" /t REG_DWORD /d "1" /f >nul 2>&1"
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DelayedDesktopSwitchTimeout" /t REG_DWORD /d "0" /f"
reg add "HKCU\Control Panel\Mouse" /v "DoubleClickSpeed" /t REG_SZ /d "200" /f
Reg add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "0" /f
Reg add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "0XA" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "10" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /f"
reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnableAutocorrection" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnableDoubleTapSpace" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnableInkingWithTouch" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnablePredictionSpaceInsertion" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnableSpellchecking" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnableTextPrediction" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\AccessPage\Camera" /v "CameraEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Input\Settings" /v "EnableHwkbAutocorrection" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Input\Settings" /v "EnableHwkbTextPrediction" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Input\Settings" /v "InsightsEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Input\Settings" /v "MultilingualEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Input\Settings" /v "InsightsEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Input\Settings" /v "PredictionDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Input\Settings" /v "UserStatsEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnablePredictionSpaceInsertion" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Tracing" /v "EnableAutoFileTracing" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Tracing" /v "EnableFileTracing" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsInkWorkspace" /v "AllowSuggestedAppsInWindowsInkWorkspace" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v "AllowWindowsInkWorkspace" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v HideSCAMeetNow /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer /v DisableNotificationCenter /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Dsh /v AllowNewsAndInterests /t REG_DWORD /d 0 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Multimedia\Audio /v UserDuckingPreference /t REG_DWORD /d 3 /f
reg add HKCU\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings /v ShowLockOption /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings /v ShowSleepOption /t REG_DWORD /d 0 /f
reg add HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps /v AgentActivationEnabled /t REG_DWORD /d 0 /f
reg add HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps /v AgentActivationLastUsed /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Narrator" /v "IntonationPause" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Narrator" /v "ReadHints" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Narrator" /v "ErrorNotificationType" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Narrator" /v "EchoChars" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Narrator" /v "EchoWords" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Narrator" /v "NarratorCursorHighlight" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Narrator" /v "CoupleNarratorCursorKeyboard" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Narrator\NoRoam" /v "EchoToggleKeys" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Narrator\NoRoam" /v "DuckAudio" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Narrator\NoRoam" /v "WinEnterLaunchEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Narrator\NoRoam" /v "ScriptingEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Narrator\NoRoam" /v "OnlineServicesEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Narrator\NarratorHome" /v "MinimizeType" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Narrator\NarratorHome" /v "AutoStart" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\ScreenMagnifier" /v "FollowCaret" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\ScreenMagnifier" /v "FollowNarrator" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\ScreenMagnifier" /v "FollowMouse" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\ScreenMagnifier" /v "FollowFocus" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "AltTabSettings" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 31 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "GPU Priority" /t REG_DWORD /d 31 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Rate" /t REG_DWORD /d 4 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Discord" /d ""C:\Users\%UserProfile%\AppData\Local\Discord\Update.exe" --processStart Discord.exe" /f"
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d 2 /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "TaskbarAnimations" /t REG_DWORD /d 0 /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "WindowAnimations" /t REG_DWORD /d 0 /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d 0 /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ThumbnailCacheSize" /t REG_DWORD /d 0 /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "FontSmoothing" /t REG_DWORD /d 1 /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Desktop" /v "VisualFXSetting" /t REG_DWORD /d 2 /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "MenuAnimations" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Quota System" /v EnableCpuQuota /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
cls
exit