<#
Win 10 / Server 2016 / Server 2019 Initial Setup Script - Tweak library
Additional tweaks to the original Win10.psm1
#>

##########
#beginregion Privacy Tweaks
##########

# Disable TIPC - Used for improved inking and typing recognition
Function DisableTIPC {
        Write-Output "Disabling TIPC..."
        If (!(Test-Path "HKCU:\Software\Microsoft\Input\TIPC")) {
            New-Item -Path "HKCU:\Software\Microsoft\Input\TIPC" -Force | Out-Null
        }
        If (!(Test-Path "HKU:")) {
            New-PSDrive -Name "HKU" -PSProvider "Registry" -Root "HKEY_USERS" | Out-Null
        }
        If (!(Test-Path "HKU:\.DEFAULT\Software\Microsoft\Input\TIPC")) {
            New-Item -Path "HKU:\.DEFAULT\Software\Microsoft\Input\TIPC" -Force | Out-Null
        }
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Input\TIPC" -Name "Enabled" -Type DWord -Value 0
        Set-ItemProperty -Path "HKU:\.DEFAULT\Software\Microsoft\Input\TIPC" -Name "Enabled" -Type DWord -Value 0
}

# Enable TIPC - Used for improved inking and typing recognition
Function EnableTIPC {
	Write-Output "Enabling TIPCs..."
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Input\TIPC" -Name "Enabled" -Type DWord -Value 1
        Set-ItemProperty -Path "HKU:\.DEFAULT\Software\Microsoft\Input\TIPC" -Name "Enabled" -Type DWord -Value 1
}

# Disable collection of diagnostic data
Function DisableDataCollection {
	Write-Output "Disable data collection"
        If (!(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection")) {
            New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Force | Out-Null
        }
        If (!(Test-Path "HKU:")) {
            New-PSDrive -Name "HKU" -PSProvider "Registry" -Root "HKEY_USERS" | Out-Null
        }
        If (!(Test-Path "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack")) {
            New-Item -Path "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" -Force | Out-Null
        }
        If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack")) {
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" -Force | Out-Null
        }
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 1
	Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "MaxTelemetryAllowed" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" -Name "ShowedToastAtLevel" -Type DWord -Value 1
	Set-ItemProperty -Path "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" -Name "ShowedToastAtLevel" -Type DWord -Value 1
}

# Enable collection of diagnostic data
Function EnableDataCollection {
	Write-Output "Enable data collection"
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "MaxTelemetryAllowed" -Type DWord -Value 0
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" -Name "ShowedToastAtLevel" -Type DWord -Value 0
        Set-ItemProperty -Path "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" -Name "ShowedToastAtLevel" -Type DWord -Value 0
}

# Disable location permissions
# Note: Different than DisableLocation which disables location feature and scripting 
Function DisableLocation {
       Write-Output "Disable location permissions"
       If (!(Test-Path "HKLM:\Software\Microsoft\Settings\FindMyDevice")) {
            New-Item -Path "HKLM:\Software\Microsoft\Settings\FindMyDevice" -Force | Out-Null
       }
       If (!(Test-Path "HKU:")) {
            New-PSDrive -Name "HKU" -PSProvider "Registry" -Root "HKEY_USERS" | Out-Null
       }
       If (!(Test-Path "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
            New-Item -Path "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
       }
       If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
            New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
       }

       Set-ItemProperty -Path "HKLM:\Software\Microsoft\Settings\FindMyDevice" -Name "LocationSyncEnabled" -Type DWord -Value 0
       Set-ItemProperty -Path "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
       Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
}

# Enable location permissions
# Note: Different than EnableLocation which enables location feature and scripting
Function EnableLocation {
       Write-Output "Enable location permissions"
       Set-ItemProperty -Path "HKLM:\Software\Microsoft\Settings\FindMyDevice" -Name "LocationSyncEnabled" -Type DWord -Value 1
       Set-ItemProperty -Path "HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Allow"
       Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Allow"
}

# Disable online speech recognition
Function DisableSpeech {
       Write-Output "Disable speech recognition"
       If (!(Test-Path "HKLM:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy")) {
            New-Item -Path "HKLM:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Force | Out-Null
       }
       If (!(Test-Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy")) {
            New-Item -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Force | Out-Null
       }
       If (!(Test-Path "HKU:")) {
            New-PSDrive -Name "HKU" -PSProvider "Registry" -Root "HKEY_USERS" | Out-Null
       }
       If (!(Test-Path "HKU:\.DEFAULT\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy")) {
            New-Item -Path "HKU:\.DEFAULT\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Force | Out-Null
       }
       Set-ItemProperty -Path "HKLM:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Type DWord -Value 0
       Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Type DWord -Value 0
       Set-ItemProperty -Path "HKU:\.DEFAULT\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Type DWord -Value 0
}

# Enable online speech recognition
Function EnableSpeech {
       Write-Output "Enable speech recognition"
       Set-ItemProperty -Path "HKLM:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Type DWord -Value 1
       Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Type DWord -Value 1
       Set-ItemProperty -Path "HKU:\.DEFAULT\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" -Name "HasAccepted" -Type DWord -Value 1
}

# Disable privacy settings experience at sign-in after new account
Function DisablePrivacyExperience {
       Write-Output "Disable privacy experience"
       If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\OOBE")) {
            New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\OOBE" -Force | Out-Null
       }
       Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\OOBE" -Name "DisablePrivacyExperience" -Type DWord -Value 1
}

# Enable privacy settings experience at sign-in after new account
Function EnablePrivacyExperience {
       Write-Output "Enable privacy experience"
       Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\OOBE" -Name "DisablePrivacyExperience" -Type DWord -Value 0
}

##########
#endregion Privacy Tweaks
##########


##########
#beginregion Services Tweaks
##########

# Disable Xbox services
Function DisableXboxServices {
        Write-Output "Disable Xbox services"
        $services = @(
            "XblAuthManager"                           # Xbox Live Auth Manager
            "XblGameSave"                              # Xbox Live Game Save Service
            "XboxNetApiSvc"                            # Xbox Live Networking Service
        )

        foreach ($service in $services) {
            Write-Output "Trying to disable $service"
            Get-Service -Name $service | Set-Service -StartupType Disabled
        }
}

# Enable Xbox services
Function EnableXboxServices {
        Write-Output "Enable Xbox services"
        $services = @(
            "XblAuthManager"                           # Xbox Live Auth Manager
            "XblGameSave"                              # Xbox Live Game Save Service
            "XboxNetApiSvc"                            # Xbox Live Networking Service
        )

        foreach ($service in $services) {
            Write-Output "Trying to enable $service"
            Get-Service -Name $service | Set-Service -StartupType Automatic | Start-Service -WarningAction SilentlyContinue
        }
}

# Disable unwanted Windows services not handled by other functions
Function DisableMiscWindowsServices {
        Write-Output "Disable misc Windows services"
        $services = @(
            "diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
            "lfsvc"                                    # Geolocation Service
            "MapsBroker"                               # Downloaded Maps Manager
            "NetTcpPortSharing"                        # Net.Tcp Port Sharing Service
            "RemoteAccess"                             # Routing and Remote Access
            # "RemoteRegistry"                          # Remote Registry
            "SharedAccess"                             # Internet Connection Sharing (ICS)
            "TrkWks"                                   # Distributed Link Tracking Client
            # "WbioSrvc"                                # Windows Biometric Service (required for Fingerprint reader / facial detection)
            #"WlanSvc"                                 # WLAN AutoConfig
            "WMPNetworkSvc"                            # Windows Media Player Network Sharing Service
            # "wscsvc"                                  # Windows Security Center Service
            "ndu"                                      # Windows Network Data Usage Monitor
            # Services which cannot be disabled
            # "WdNisSvc"
        )

        foreach ($service in $services) {
            Write-Output "Trying to disable $service"
            Get-Service -Name $service | Set-Service -StartupType Disabled
        }
}

# Enable unwanted Windows services not handled by other functions
Function EnableMiscWindowsServices {
        Write-Output "Enable misc Windows services"
        $services = @(
            "diagnosticshub.standardcollector.service" # Microsoft (R) Diagnostics Hub Standard Collector Service
            "lfsvc"                                    # Geolocation Service
            "MapsBroker"                               # Downloaded Maps Manager
            "NetTcpPortSharing"                        # Net.Tcp Port Sharing Service
            "RemoteAccess"                             # Routing and Remote Access
            # "RemoteRegistry"                          # Remote Registry
            "SharedAccess"                             # Internet Connection Sharing (ICS)
            "TrkWks"                                   # Distributed Link Tracking Client
            # "WbioSrvc"                                # Windows Biometric Service (required for Fingerprint reader / facial detection)
            #"WlanSvc"                                 # WLAN AutoConfig
            "WMPNetworkSvc"                            # Windows Media Player Network Sharing Service
            # "wscsvc"                                  # Windows Security Center Service
            "ndu"                                      # Windows Network Data Usage Monitor
            # Services which cannot be disabled
            # "WdNisSvc"
        )

        foreach ($service in $services) {
            Write-Output "Trying to enable $service"
            Get-Service -Name $service | Set-Service -StartupType Automatic | Start-Service -WarningAction SilentlyContinue
        }
}

##########
#endregion Services Tweaks
##########


##########
#beginregion UI Tweaks
##########

# Disable auto tray icons
Function DisableAutoTrayIcons {
    Write-Output "Disabling auto tray icons..."
    if (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer") {
        $properties = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"
        if ( $properties ) {
            if (Get-Member -InputObject $properties -Name "EnableAutoTray") {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0
            }
        }
    }
}

# Enable auto tray icons. Hide tray icons as needed.
Function EnableAutoTrayIcons {
    Write-Output "Enabling auto tray icons..."
    if (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer") {
        $properties = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"
        if ( $properties ) {
            if (Get-Member -InputObject $properties -Name "EnableAutoTray") {
                Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray"
            }
        }
    }
}

##########
#endregion UI Tweaks
##########


##########
#beginregion Explorer UI Tweaks
##########

# Hide Camera Roll icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function HideCameraRollFromExplorer {
	Write-Output "Hiding Camera Roll icon from Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{2B20DF75-1EDA-4039-8097-38798227D5B7}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{2B20DF75-1EDA-4039-8097-38798227D5B7}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

# Show Camera Roll icon in Explorer namespace
Function ShowCameraRollInExplorer {
	Write-Output "Showing Camera Roll icon in Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{2B20DF75-1EDA-4039-8097-38798227D5B7}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{2B20DF75-1EDA-4039-8097-38798227D5B7}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
}

# Hide Saved Pictures icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
Function HideSavedPicturesFromExplorer {
	Write-Output "Hiding Saved Pictures icon from Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{E25B5812-BE88-4bd9-94B0-29233477B6C3}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{E25B5812-BE88-4bd9-94B0-29233477B6C3}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Hide"
}

# Show Saved Pictures icon in Explorer namespace
Function ShowSavedPicturesInExplorer {
	Write-Output "Showing Saved Pictures icon in Explorer namespace..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{E25B5812-BE88-4bd9-94B0-29233477B6C3}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{E25B5812-BE88-4bd9-94B0-29233477B6C3}\PropertyBag" -Name "ThisPCPolicy" -Type String -Value "Show"
}

# NOTE: Setting desktop icon size this way no longer persists as of 2021, not sure which build. Using ctrl + scroll is an easy enough workaround.
# Small Desktop Icons
Function SmallDesktopIcons {
	Write-Output "Setting small desktop icons..."
	Set-ItemProperty -path HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop -name IconSize -value 24
}

# Medium Desktop Icons
Function MediumDesktopIcons {
	Write-Output "Setting medium desktop icons..."
	Set-ItemProperty -path HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop -name IconSize -value 32
}

# Large Desktop Icons
Function LargeDesktopIcons {
	Write-Output "Setting large desktop icons..."
	Set-ItemProperty -path HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop -name IconSize -value 36
}

##########
#endregion Explorer UI Tweaks
##########

# Export functions
Export-ModuleMember -Function *