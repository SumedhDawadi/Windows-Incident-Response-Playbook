#### ◉ Log  Entries - Enumeration 
- Log Entries are records of events that happen in your computer, either by a person or by a running process
-  The Windows event log contains logs from the operating system and applications. It stores the event with event occured - Date , Time , User account info with it's event ID . 
-  As a security Analyst, we need to hunt for malicious event, For this , we need to look for specific event ID with its messages such as information , warning and errors 
- Event Logs are stored in :  C:\WINDOWS\system32\config\ 
- System Log: Windows system event log contains events related to the system and its components. Failure to load the boot-start driver is an example of a system-level event.
- Application Log: Events related to a software or an application hosted on a Windows computer get logged under the application event log. For example, the problem in starting Microsoft PowerPoint comes under the Application log.
- Security: Security logs contain events related to the safety of the system. The event gets recorded via the Windows auditing process. Examples include failed and valid logins, file deletions, etc.
- Setup: The setup log contains events that occur during the installation of the Windows operating system. On domain controllers, this log will also record events related to Active Directory.
- Forwarded Events: Contains event logs forwarded from other computers in the same network.
## Important Event ID's to investigate

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
- https://github.com/ahmedkhlief/APT-Hunter/releases/download/V3.0/APT-Hunter-Windows.zip
- Uses
 ```bash
python3 APT-Hunter.py    -p /opt/wineventlogs/
```


