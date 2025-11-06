# Incident Response - CheckList
## ◉  User Account Enumeration.
- Goal is to  enumerate  all user's account with the privilege assigned.
- In additional , Last LogOn date and time must be mapped with date and time incident took place. 
- Check which users are assigned with LocalGroup  and Group Policies 
```bash
Command in Powershell : Get-LocalUser | Select Name, Lastlogon
```
## ◉ Log  Entries - Enumeration 
- Log Entries are records of events that happen in your computer, either by a person or by a running process
-  The Windows event log contains logs from the operating system and applications. It stores the event with event occured - Date , Time , User account info with it's event ID . 
-  As a security Analyst, we need to hunt for malicious event, For this , we need to look for specific event ID with its messages such as information , warning and errors 

- Event Logs are stored in :   
1. Security Logs.
```bash
C:\Windows\System32\config\SECURITY
```
2. Software Log.
```bash
C:\Windows\System32\config\SOFTWARE
```
3. System Log.
```bash
C:\Windows\System32\config\SYSTEM
```
4. Windows Event Logs.
```bash
C:\Windows\System32\winevt
```
- System Log: Windows system event log contains events related to the system and its components. Failure to load the boot-start driver is an example of a system-level event.
- Application Log: Events related to a software or an application hosted on a Windows computer get logged under the application event log. For example, the problem in starting Microsoft PowerPoint comes under the Application log.
- Security: Security logs contain events related to the safety of the system. The event gets recorded via the Windows auditing process. Examples include failed and valid logins, file deletions, etc.
- Setup: The setup log contains events that occur during the installation of the Windows operating system. On domain controllers, this log will also record events related to Active Directory.
- Forwarded Events: Contains event logs forwarded from other computers in the same network.
### Important Event ID's to investigate
```bash
- 4720: New user Created

- 4688: A new process has been created

- 4722: A user account was enabled

- 4724: User Password reset 

- 4728: User assigned to admin group

- 4624: Log on sucessful

- 4634: Account log off activity on a system

- 4625 : Account failed to log in (bruteforce)

- 4672: Special priviledge assigned to new logon

- 4733: Memeber removed from a security enable local group

- 5156: The Windows Filtering Platform has allowed connection

- 7045: A service was installed in the system

- 4657: A registry value was modified

- 4660: An object was deleted

- 4663: An attempt was made to access, modify, delete an object

- 7036: a service has entered the stopped state

- 7040: a service has disabled
```
## Did you investigate LogOn Type?
```bash
Logon type 2
Logon type 3
Logon type 8
Logon type 10
```
## Automating Event Logs : 
#### Quick Incident Response tool (MUST) : https://github.com/AlmCo/Panorama.git
Users - Password, Admin, Last logon, Last password update
Startup commands - Command, Active
Task scheduler - Name, Next run, Status
Installed Softwares - List
Recently used files - List
Active processes - Name, ID, Communication 
 ```bash
Double-click OR from CMD without arguments - Opens the GUI
```
#### APT Hunter 
- Source : https://github.com/ahmedkhlief/APT-Hunter/releases/download/V3.0/APT-Hunter-Windows.zip
- Uses
 ```bash
python3 APT-Hunter.py -p /opt/wineventlogs/ -o /path/to/save
```
#### ChainSaw
- Source : https://github.com/WithSecureLabs/chainsaw/releases/download/v2.6.0/chainsaw_x86_64-pc-windows-msvc.zip
- Uses
 ```bash
./chainsaw hunt -r rules/ evtx_attack_samples -s sigma/rules --mapping mappings/sigma-event-logs-all.yml --level critical
``` 
#### Loki (Malware scanner via YARA rules)
- Source :https://github.com/Neo23x0/Loki
- YARA Templates : https://github.com/VirusTotal/yara-python/releases
- Nuclei Malware Templates : https://github.com/daffainfo/nuclei-malware.git
- Uses
 ```bash
Need to add commands
``` 
#### Psrecon (overall recon for infected host) : https://github.com/gfoss/PSRecon.git
 ```bash
.\psrecon.ps1
```
## ◉  AmCache Investigation
- AmCache.hve is a Windows system file that is created to store information related to program executions. The artifacts in this file can serve as a huge aid in an investigation, it records the processes recently run on the system and lists the paths of the files executed
- AmCache.hve is stored in : 
 ```bash
C:\Windows\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Amcache.hve
```

## ◉  Binary (.exe) Analysing via Sandbox enviroment
- VirusTotal      : https://www.virustotal.com/gui/home
- AnyRun          : https://any.run/
- Intezer Analyze : https://analyze.intezer.com/
- Hybrid-Analysis : https://hybrid-analysis.com/

## ◉ Investigating Powershell payloads and more.
- Hacker use powershell to compromise windows environment.
- Powershell sometimes could be difficult to spot on and investigate as attacker powershell obfuscation is pretty common to hide within the host or evade AV in most of the case
- Understanding Powershell Obfuscation : 
### Base64 Patterns - Learning Aid

| Base64 Code | Mnemonic Aid | Decoded* | Description |
|-------------|--------------|----------|------------------------------------------|
| `JAB` | 🗣 Jabber | `$.` | Variable declaration (UTF-16) |
| `TVq` | 📺 Television | `MZ` | MZ header |
| `SUVY` | 🚙 SUV | `IEX` | PowerShell Invoke Expression |
| `SQBFAF` | 🐣 Squab favorite | `I.E.` | PowerShell Invoke Expression (UTF-16) |
| `SQBuAH` | 🐣 Squab uahhh | `I.n.` | PowerShell Invoke string (UTF-16) e.g. `Invoke-Mimikatz` |
| `PAA` | 💪 "Pah!" | `<.` | Often used by Emotet (UTF-16) |
| `cwBhA` | 🦁 Chewbaka | `s.a.` | Often used in malicious droppers (UTF-16) 'sal' instead of 'var' |
| `aWV4` | 😲 Awe version 4 | `iex` | PowerShell Invoke Expression |
| `aQBlA` | 💦 Aqua Blah (aquaplaning) | `i.e.` | PowerShell Invoke Expression (UTF-16) |
| `R2V0` | 🤖 R2D2 but version 0 | `Get` | Often used to obfuscate imports like GetCurrentThreadId |
| `dmFy` | 👹 defy / demonify | `var` | Variable declaration |
| `dgBhA` | debugger + high availability | `v.a.` | Variable declaration (UTF-16) |
| `dXNpbm` | Dixon problem | `usin` | Often found in compile after delivery attacks |
| `H4sIA` | 🚁 HForce (Helicopter Force) I agree | | gzip magic bytes (0x1f8b), e.g. `echo 'test' \| gzip -cf \| base64` |
| `Y21k` | 🎆 Year 21k bug | `cmd` | As used in `cmd.exe /c wscript.exe` or the like |
| `IAB` | 🥱 I am bored | ` s` | wide lower case `s`, often something like `sEt-iTem` |
| `cABhAH` | 🕋 Kaaba | `p.a.` | wide formatted `param` |
| `Qzpc` | 🖥 Quiz PC | `C:\` | Root of Windows partition (upper case) |
| `Yzpc` | 🖥 Yes PC | `c:\` | Root of Windows partition (lower case) |
| `UEs` | 🏬 Upper East Side | `PK` | ZIP, Office documents |
| `ey` | 🗣 Hey | `{ ` | Indicates JSON data |

\* the `.` stands for `0x00` found in UTF-16 encoded text.
- Source : https://gist.github.com/Neo23x0/6af876ee72b51676c82a2db8d2cd3639

## Often found patterns

| Base64 Code | Decoded | Description |
|------------------------|--------------|------------------------------------------|
| `AAAAAAAAAAAA` | `\x00\x00\x00\x00\x00\x00\x00\x00\x00` | Sequence of binary zeros |
| `////////////` | `\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF` | Sequence of 0xFF bytes |
| `ICAgICAgICAg` | `         ` | Sequence of space characters |

### ◉ Dynamic Malware Analysis : 
#### There are few key point that you need to keep in mind while analyzing malware dynamically. Reember : Gathering only IOC's is not malware analysis.
- Behavior Analysis: Observe the malware's behavior, such as file system modifications, network communication, process creation, registry changes, and potential evasion techniques. Identify any malicious or suspicious activities.
- Payload Identification: Determine the malware's payload, such as the type of malware (e.g., ransomware, trojan, worm) and its intended impact on the system or network. Identify any malicious functions or modules within the binary.
- Infection Vector: Identify how the malware entered the system or network. Determine the initial infection vector, such as email attachments, malicious websites, or compromised software.
- Persistence Mechanisms: Determine how the malware achieves persistence on the infected system, such as creating registry entries, modifying startup configurations, or installing rootkits. Identify the techniques used to maintain a presence and resist removal.
- Anti-analysis Techniques: Identify any techniques employed by the malware to evade detection or hinder analysis, such as code obfuscation, anti-debugging, or anti-VM techniques. Determine the methods used to protect the malware's presence and make analysis more challenging.
- Indicators of Compromise (IOCs): Extract any relevant IOCs, such as IP addresses, domains, file names, or hashes associated with the malware. These IOCs can be used to enhance detection and response capabilities across the network. Limiting to IOC's is what analyst be do.
- Command and Control (C2) Communication: Identify any network communication between the malware and its command and control server(s). Determine the protocols, ports, and encryption methods used for communication.
- Data Exfiltration: Identify if the malware exfiltrates sensitive information from the compromised system or network. Determine the data types targeted and the mechanisms used for data theft.
- Mitigation and Remediation: Based on the analysis, develop effective mitigation and remediation strategies to contain the infection, remove the malware, and prevent future incidents. This may include updating antivirus signatures, patching vulnerabilities, or implementing network security measures.


### ◉ Processes -  Enumeration
- A method of executing arbitrary code in the address space of a separate live process.
- If sysmon is enable make sure you check Sysymon logs.
- Is any powershell.exe running? 
- Did you find any malicious processes running with abnormal extenstion?
- Did you find any processes running in high processes usages? 
- Dump the suspecious process for memory Forensics.
- Check few things to investigate running processes
 ```bash
EventID:8
Port Number : TCP/447 and TCP/449 network connections
lsass.exe and svchost.exe is running ? 
```
#### Tools 
• Process Explorer
• Process Hacker
• Volatility
• x64dbg

## ◉ Memory Forensics (memory dump)
- Memory forensics is forensic analysis of a computer's memory dump. Its primary application is investigation of advanced computer attacks which are stealthy enough to avoid leaving data on the computer's hard drive. Consequently, the memory (RAM) must be analyzed for forensic information.
- It can help investigators to uncover evidence of malicious activities, such as malware infections, rootkits, network connections, encryption keys, passwords, and hidden processes.
- Tool Source - Volatility : https://github.com/volatilityfoundation/volatility/wiki/Installation
- Uses : 
1. Investigating Memory Profile via KDBG for windows kernal. It helps Operating system to identify memory was originated (Suggested Profile)
 ```bash
volatility -f /path/saved/for/file/example.mem imageinfo 
```
2. Profile Investigating. This is give such valuable information such as processes running while the memory was running in kernal level
 ```bash
volatility -f /path/saved/for/file/example.mem --profile=win10x64_1762 pslist
```
3. Running PSscanwill list the processes running is displayed accoording to process ID assigned to them. Also thread, session are handle as mentioned on the bassis of timestap. It also helps to identify unknown processes running
 ```bash
volatility -f /path/saved/for/file/example.mem --profile=win10x64_1762 psscan
```
4. HashDump helps to extract and decrypt cached domain crediantial stored in the registry. Once dumped you can use hashcat to JohnTheRipper to crach hashes

 ```bash
volatility -f /path/saved/for/file/example.mem --profile=win10x64_1762 hashdump
```
5. Lsdump helps to find out secret LSA. 
 ```bash
volatility -f /path/saved/for/file/example.mem --profile=win10x64_1762 lsdump
```
6. NotePad files are used highly by APT group for injection or most of the time for ransome note. 
 ```bash
volatility -f /path/saved/for/file/example.mem --profile=win10x64_1762 notepad
```
## ◉ Task Scheduler 
- An attacker may exploit the Windows Task Scheduler to schedule malicious programmers for initial or recurrent execution example everyday at 6:00 AM , once a week , 21st of every month or even once  a year.
- For persistence purposes, an attacker may utilize Windows Task Scheduler to launch applications at system startup or on a scheduled basis.
- Windows Task Scheduler may be utilized to execute remote code to run a process under the context of a specified account for Privilege Escalation.
 ```bash
Simple Type Task Scheduler or Type 𝐭𝐚𝐬𝐤𝐬𝐜𝐡𝐝.𝐦𝐬𝐜 in Run
```
## ◉ Startup 
- Check startup via Task Manager and check if any script or any cloud based service.
- Hackers takes advantage of start-up.
- Hackers do this by injecting arbitrary code on active running processes that will run once PC gets started 

 ```bash
wmic startup list full
wmic startup list brief
Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | FL
```

## ◉  Hunting  malicious   Payload
- Detecting suspicious powershell script (payload) running in background is one of the tricky process to figure out. 
- As a responder , we need to hunt the malicious payload (know and unknown threat). Once identified you can use open source threat intelligence platform 
- Example : Virus Total , maxmind.com and other sandbox mentioned above.
```bash
CMD : forfiles /D -10 /S /M *.ps1 /C "cmd /c echo @path"  
Powershell : forfiles /D -10 /S /M *.ps1 /C "powershell/c echo @path" 
```
## ◉ Retriving Deleted Files or Folder and even footprint.
- In most of the cases attacker or even victim tend to formate or delete evidence via PC , pendrive or even HDD/SSD.
- Retrive such important evidence is crucial for future investivation
- I highly recommend using Recuva for retriving datas from Hard-disk, SSD and pendrive
- Source : https://www.ccleaner.com/recuva 
- Uses:
 ```bash
Double click executable and good to go.
```

## ◉  Firewall
-  As a responder, we need to pay attention to firewall configuration and settings.
-  We need to investigate inbound and outbounding traffic. 
-  As a responder, open session must be investigator we need to investigate open session
```bash
Firewall settings (Powershell) : netsh firewall show config
Open session (Powershell) : net session
```
## ◉ Registry Entries
- The registry is a system-defined database in which applications and system components store and retrieve configuration data.
-  By hijacking the Registry entries utilized by services, attackers can run their malicious payloads. 
-  Attackers may use weaknesses in registry permissions to divert from the initially stated executable to one they control upon Service start, allowing them to execute their unauthorized malware.
```bash
Run this command in Run : regedit
```
## ◉ DNS - Enumeration
- Since, DNS is a crucial part of any communication. Adversary's take an advantages of DNS to and communicates  to their CNC server.  
-  As a analyst , we need to verify if the infected host is communicating with attackers server. 
-  To verify, Paste the IP to virus total.
-  Check any Malicious IP's or DNS connect seen in HOSTS file
 ```bash
C:\Windows\System32\drivers\etc\hosts
```
