# Incident Response - CheckList
## ◉  User Account Enumeration.
- Goal is to  enumerate  all user's account with the privilege assigned.
- In additional , Last LogOn date and time must be mapped with date and time incident took place. 
- Check which users are assigned with LocalGroup  and Group Policies 
```bash
Get-LocalUser | Select Name, Lastlogon
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
#### Psrecon : https://github.com/gfoss/PSRecon.git
 ```bash
.\psrecon.ps1
```
## ◉  Binary (.exe) Analysing via Sandbox enviroment
- VirusTotal      : https://www.virustotal.com/gui/home
- AnyRun          : https://any.run/
- Intezer Analyze : https://analyze.intezer.com/
## ◉ Processes -  Enumeration
- A method of executing arbitrary code in the address space of a separate live process.
- If sysmon is enable make sure you check Sysymon logs.
- Is any powershell.exe running? 
- Did you find any malicious processes running with abnormal extenstion?
- Did you find any processes running in high processes usages? 
- Dump the suspecious process for memory Forensics.
- Check few things to investigate running processes
- 
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



