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
Set-ItemProperty "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -Name RequireSecuritySignature -Value 1 # always digitally sign communications if client agrees
Set-ItemProperty "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -Name EnableSecuritySignature -Value 1 # always digitally sign communications if client agrees
Set-ItemProperty "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" -Name EnableSecuritySignature -Value 1 # always digitally sign communications if client agrees
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name NullSessionPipes -Value "" # named pipes that can be accessed anonymously set to none
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMBServerNameHardeningLevel -Value 1 # Server spn target name validation is set to accept if provided by client
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymous -Value 1 # do not allow enumeration of accounts without authentication
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name DisableDomainCreds -Value 1 # do not allow storage of creds for network authentication
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel -Value 5 # respond only with ntlmv2
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name UseMachineID -Value 1 #allow local system to use computer identity for NTLM

#create more ntlm registry hives if they do not already exist
if ((Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0") -ne $true) {
    New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Force | Out-Null
}
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -name NTLMMinClientSec -Value 537395200 #require 128 bit encryption for ntlmv2 client
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -name NTLMMinServerSec -Value 537395200 #require 128 bit encryption for ntlmv2 server

#Create the kerberos\parameters hives if they do not exist already
if ((Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters") -ne $true) {
    New-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Force | Out-Null
}
Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" -Name SupportedEncryptionTypes -Value 2147483640 #configure kerberos to use AES_256_HMAC_SHA1 encrption

Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography" -Name ForceKeyProtection -Value 1 # force strong key protection on user keys stored on the computer

Write-Host "    Configuring UAC prompt behavior"
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name FilterAdministratorToken -Value 1 # controls admin approval mode for the built in admin account
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentAdminBehavior -Value 1 # controls admin approval mode for admin accounts
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorUser -Value 1 # controls admin approval mode for admin accounts
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name PromptOnSecureDesktop -Value 1 # uac elevation prompt is displayed on desktop


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

Write-Host "    Configuring windows services"
#configure (disable) windows services
Set-Service -Name BTAGService -StartupType Disabled -Status Stopped # Disabled bluetooth audio gateway service as bluetooth is not encrypted well
Set-Service -Name bthserv -StartupType Disabled -Status Stopped # Disable bluetooth service for discovery and association
Set-Service -Name MapsBroker -StartupType Disabled -Status Stopped # can reveal location to hackers and downloads data from 3rd parties
Set-Service -Name SharedAccess -StartupType Disabled # prevent unauthorized bridging of networks
Set-Service -Name lltdsvc -StartupType Disabled -Status Stopped # prevent unauthorized discovery and connections
Set-Service -Name LxssManager -StartupType Disabled -Status Stopped # linux subsystem allows linux applications full access on windows and opens possibility of bad code to run on machines
Set-Service -Name MSiSCSI -StartupType Disabled -Status Stopped # iSCSI uses weak auth protocols
Set-Service -Name PNRPsvc -StartupType Disabled -Status Stopped # disable serverless peer name resolution, rely on DHCP for this
Set-Service -Name p2psvc -StartupType Disabled -Status Stopped # disable multi-party communication using p2p grouping
Set-Service -Name p2pimsvc -StartupType Disabled -Status Stopped # provides identity services to peer name resolution protocols
Set-Service -Name PNRPAutoReg -StartupType Disabled -Status Stopped # publishes machine name to peer name resolution protocols
Set-Service -Name Spooler -StartupType Disabled -Status Stopped # CVE-2021-34527 PrintNightmare vulernabilities
Set-Service -Name wercplsupport -StartupType Disabled -Status Stopped # sends data to microsoft for troubleshooting, disable to increase privacy and decrease shared data
Set-Service -Name RasAuto -StartupType Disabled -Status Stopped # creates a remote connection when a program references dns or netbios
Set-Service -Name SessionEnv -StartupType Disabled -Status Stopped # rdp session maintainence and certs
Set-Service -Name UmRdpService -StartupType Disabled -Status Stopped # allows redirection of devices for rdp sessions
Set-Service -Name TermService -StartupType Disabled # rdp server
Set-Service -Name RpcLocator -StartupType Disabled -Status Stopped # does not provide functionality since windows vista - powers rpc name service database
Set-Service -Name LanmanServer -StartupType Disabled -Status Stopped # network file sharing service disabled, device should only be a client and not a server
Set-Service -Name upnphost -StartupType Disabled -Status Stopped # disable upnp devices to be hosted from this device
Set-Service -Name SSDPSRV -StartupType Disabled # discovers and annmounces network devices that use the ssdp protocol
Set-Service -Name WerSvc -StartupType Disabled -Status Stopped # windows errors should report to IT and not to microsoft, can unknowningly report sensitive data to microsoft
Set-Service -Name Wecsvc -StartupType Disabled -Status Stopped # remote connections to devices should be minimized. windows event collector disabled so events will be viewed locally
Set-Service -Name WMPNetworkSvc -StartupType Disabled -Status Stopped # disable network sharing from windows media player
Set-Service -Name icssvc -StartupType Disabled -Status Stopped #  windows hotspot could expose services to non-authorized devices or individuals
Set-Service -Name WpnService -StartupType Disabled -Status Stopped # windows push notification service gets 3rd party updates from the cloud
Set-Service -Name PushToInstall -StartupType Disabled -Status Stopped # manages apps that are pushed to the device from the microsoft store
Set-Service -Name WinRM -StartupType Disabled -Status Stopped # win-rm enables remote management via web service. listens on all network interfaces
Set-Service -Name XboxGipSvc -StartupType Disabled -Status Stopped # xbox service
Set-Service -Name XblAuthManager -StartupType Disabled -Status Stopped # xbox service
Set-Service -Name XblGameSave -StartupType Disabled -Status Stopped # xbox service
Set-Service -Name XboxNetApiSvc -StartupType Disabled -Status Stopped # xbox service

Write-Host "    Configuring windows event logging"
# windows events logging
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable | Out-Null # log success and failed login attempts
auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable | Out-Null  # generate events by changes in application groups
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null # generate events for changes in users
auditpol /set /subcategory:"Plug and Play Events" /success:enable | Out-Null  # log when a device is plugged in
auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null  # log when a process is created
auditpol /set /subcategory:"Account Lockout" /failure:enable | Out-Null # log success and failed login attempts
auditpol /set /subcategory:"Group Membership" /success:enable | Out-Null  # log groups from logon token
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable | Out-Null # generate events for logon sessions such as rdp, runas, lock/unlock
auditpol /set /subcategory:"Detailed File Share" /failure:enable | Out-Null # log failed attempts at file share access
auditpol /set /subcategory:"File Share" /success:enable /failure:enable | Out-Null # log access to a shared folder
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable | Out-Null # audit events to COM+ objects or task scheduler
auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable | Out-Null # audit when files are accessed on removable storage
auditpol /set /subcategory:"Authorization Policy Change" /success:enable | Out-Null  # report changes in authorization policy
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable | Out-Null # changes to firewall rules
auditpol /set /subcategory:"Other Policy Change Events" /failure:enable | Out-Null # 
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable | Out-Null # reports when a user account or service uses a sensitive privilege.
auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable | Out-Null #  reports on the activities of the Internet Protocol security (IPsec) driver
auditpol /set /subcategory:"Security System Extension" /success:enable | Out-Null # reports the loading of extension code such as authentication packages by the security subsystem

# windows settings
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name NoLockScreenSlideshow -Value 1 # disable lockscreen slideshow