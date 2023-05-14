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
- Event Logs are stored in :   𝐂:\𝐖𝐈𝐍𝐃𝐎𝐖𝐒\𝐬𝐲𝐬𝐭𝐞𝐦𝟑𝟐\𝐜𝐨𝐧𝐟𝐢𝐠\ 
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
- Uses
 ```bash
Need to add commands
``` 
#### Psrecon (overall recon for infected host) : https://github.com/gfoss/PSRecon.git
 ```bash
.\psrecon.ps1
```
## ◉  Binary (.exe) Analysing via Sandbox enviroment
- VirusTotal      : https://www.virustotal.com/gui/home
- AnyRun          : https://any.run/
- Intezer Analyze : https://analyze.intezer.com/
- Hybrid-Analysis : https://hybrid-analysis.com/
## ◉ Processes -  Enumeration
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
3. 

## ◉ Task Scheduler 
- An attacker may exploit the Windows Task Scheduler to schedule malicious programmers for initial or recurrent execution example everyday at 6:00 AM , once a week , 21st of every month or even once  a year.
- For persistence purposes, an attacker may utilize Windows Task Scheduler to launch applications at system startup or on a scheduled basis.
- Windows Task Scheduler may be utilized to execute remote code to run a process under the context of a specified account for Privilege Escalation.
 ```bash
Simple Type Task Scheduler or Type 𝐭𝐚𝐬𝐤𝐬𝐜𝐡𝐝.𝐦𝐬𝐜 in Run
```
## ◉ Startup 
- Check startup via Task Manager and check if any script or any cloud based services running such as MEGA.
- Hackers takes advantage of start-up.
- Hackers do this by injecting arbitrary code on active running processes that will run once PC gets started 

## ◉  Hunting  malicious   Payload
- Detecting suspicious powershell script (payload) running in background is one of the tricky process to figure out. 
- As a responder , we need to hunt the malicious payload (know and unknown threat). Once identified you can use open source threat intelligence platform 
- Example : Virus Total , maxmind.com and other sandbox mentioned above.
```bash
CMD : forfiles /D -10 /S /M *.ps1 /C "cmd /c echo @path"  
Powershell : forfiles /D -10 /S /M *.ps1 /C "powershell/c echo @path" 
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
