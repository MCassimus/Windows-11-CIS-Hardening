#Requires -RunAsAdministrator


###########################
# Account/Logon Hardening #
###########################
Write-Host "###########################"
Write-Host "# Account/Login hardening #"
Write-Host "###########################"

Write-Host "    Rename and disable built in admin and guest accounts"
#Rename and disable well known accounts
Get-LocalUser Administrator -ErrorAction SilentlyContinue | Rename-LocalUser -NewName LocalAdministrator
Disable-LocalUser LocalAdministrator
Get-LocalUser Guest -ErrorAction SilentlyContinue | Rename-LocalUser -NewName LocalGuest
Disable-LocalUser LocalGuest

Write-Host "    Set password requirements"
# Set local account password requirements
net accounts /maxpwage:365 | Out-Null
net accounts /minpwage:1 | Out-Null
net accounts /minpwlen:14 | Out-Null
net accounts /forcelogoff:15 | Out-Null
net accounts /uniquepw:24 | Out-Null
net accounts /lockoutthreshold:5 | Out-Null # 5 login attempts before lockout
net accounts /lockoutduration:15 | Out-Null # unlock after 15 minutes
net accounts /lockoutwindow:15 | Out-Null # unlock after 15 minutes
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\SAM" -Name RelaxMinimumPasswordLengthLimits  -Value 1 # This setting will enable the enforcement of longer and generally stronger passwords or passphrases where MFA is not in use.

Write-Host "    Configuring login/logout features"
#Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name NoConnectedUser -Value 3 # Disables microsoft accounts from being logged in for user accounts
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name DisableCAD -Value 0 # Require Ctrl + Alt + Del on login
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name DontDisplayLastUserName -Value 1 # Dont display the last logged in user
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LegalNoticeText -Value "Authorized users only." # Display a login banner
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LegalNoticeCaption -Value "Warning" # Display a login banner
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name CachedLogonsCount -Value 4 # number of account logins cached if AD controller is not reachable
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name ScRemoveOption -Value 1 # Lock the current session if smart card is removed from the machine
Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name InactivityTimeoutSecs -Value 900 # lock computer after 15 minutes

Write-Host "    Configurating the Lanman service"
# LAN Manager (SMB) config
Set-ItemProperty "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name RequireSecuritySignature -Value 1 # always digitally sign communiations
Set-ItemProperty "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -Name EnableSecuritySignature -Value 1 # always digitally sign communications if client agrees
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMBServerNameHardeningLevel -Value 1 # Server spn target name validation is set to accept if provided by client
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymous -Value 1 # do not allow enumeration of accounts without authentication
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name DisableDomainCreds -Value 1 # do not allow storage of creds for network authentication
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name NullSessionPipes -Value "" # named pipes that can be accessed anonymously set to none
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name UseMachineID -Value 1 #allow local system to use computer identity for NTLM
Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name SupportedEncryptionTypes -Value 2147483640 -Force #configure kerberos to use AES_256_HMAC_SHA1 encrption


####################
# Device Hardening #
####################
Write-Host "###########################"
Write-Host "#    Device hardening     #"
Write-Host "###########################"

Write-Host "    Configuring external device settings"
# configure external devices
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name AllocateDASD -Value 2 # Ensure Devices: Allowed to format and eject removable media is set to 'Administrators and Interactive Users'
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -Name AddPrinterDrivers -Value 1 # prevent users from installing printer drivers
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name MaxDevicePasswordFailedAttempts -Value 10 # bitlocker will lock the drive after 10 failed login attempts