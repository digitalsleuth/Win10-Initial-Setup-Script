<#
Win 10 / Server 2016 / Server 2019 Initial Setup Script - Tweak library
Additional tweaks to the original Win10.psm1
#>

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

# Export functions
Export-ModuleMember -Function *