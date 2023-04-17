# Windows-Incident-Response-Playbook

#### ◉  User Account Enumeration.
- Goal is to  enumerate  all user's account with the privilege assigned.
- In additional , Last LogOn date and time must be mapped with date and time incident took place. 
- Check which users are assigned with LocalGroup  and Group Policies 
```bash
Get-LocalUser | Select Name, Lastlogon
```
#### ◉ Processes -  Enumeration
- Identifying malicious process that has high consumption  that will lead artifacts. Example : shell.ps1 , powershell.Xmrl
-  Artificates such as memory dump 
-  Dump the malicious processes and keep for forensic analysis (DFIR)

#### ◉  Task Scheduler 
- An attacker may exploit the Windows Task Scheduler to schedule malicious programmers for initial or recurrent execution example everyday at 6:00 AM , once a week , 21st of every month or even once  a year.
- For persistence purposes, an attacker may utilize Windows Task Scheduler to launch applications at system startup or on a scheduled basis.
- Windows Task Scheduler may be utilized to execute remote code to run a process under the context of a specified account for Privilege Escalation.

#### ◉ Startup 
- Hackers takes advantage of start-up.
-  Hackers do this by injecting arbitrary code on active running processes that will run once PC gets started 

#### ◉ Registry Entries
- The registry is a system-defined database in which applications and system components store and retrieve configuration data.
-  By hijacking the Registry entries utilized by services, attackers can run their malicious payloads. 
-  Attackers may use weaknesses in registry permissions to divert from the initially stated executable to one they control upon Service start, allowing them to execute their unauthorized malware.

#### ◉  Active - TCP & UDP ports

-  As an Incident Responder, you should carefully pay attention to the active TCP and UDP ports of your system.
-  Motive must be investigating incoming and outgoing connections, routing tables, port listening, and usage statistics.
-   For example , port 53 communicating to C2 server.

#### ◉  Hunting  malicious   Payload
- Detecting suspicious powershell script (payload) running in background is one of the tricky process to figure out. 
-  As a responder , we need to hunt the malicious payload (know and unknown threat). Once identified you can use open source threat intelligence platform 
-  Example : Virus Total , maxmind.com and more
```bash
CMD : forfiles /D -10 /S /M *.ps1 /C "cmd /c echo @path"  
Powershell : forfiles /D -10 /S /M *.ps1 /C "powershell/c echo @path" 
```
#### ◉  Firewall
-  As a responder, we need to pay attention to firewall configuration and settings.
-  We need to investigate inbound and outbounding traffic. 
-  As a responder, open session must be investigator we need to investigate open session
```bash
Firewall settings : netsh firewall show config
Open session : net session
```
#### ◉ Log  Entries - Enumeration 
- Log Entries are records of events that happen in your computer, either by a person or by a running process
-  The Windows event log contains logs from the operating system and applications. It stores the event with event occured - Date , Time , User account info with it's event ID . 
-  As a security Analyst, we need to hunt for malicious event, For this , we need to look for specific event ID with its messages such as information , warning and errors 

#### ◉ DNS - Enumeration
- Since, DNS is a crucial part of any communication. Adversary's take an advantages of DNS to and communicates  to their CNC server.  
-  As a analyst , we need to verify if the infected host is communicating with attackers server. 
-  For this, C:\Windows\System32\drivers\etc\hosts, once you open IP's are seen.
-  To verify, Paste the IP to virus total.
