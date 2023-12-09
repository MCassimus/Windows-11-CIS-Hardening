# Run This Script with Powershell (As Admin) 
Invoke-WebRequest https://github.com/MCassimus/Windows-11-CIS-Hardening/archive/main.zip -OutFile CIS.zip<br>
Expand-Archive CIS.zip<br>
Remove-Item CIS.zip<br>
powershell -ExecutionPolicy Bypass -c .\CIS\Windows-11-CIS-Hardening-main\SecureWindows.ps1<br>
Remove-Item -Recurse -Force
