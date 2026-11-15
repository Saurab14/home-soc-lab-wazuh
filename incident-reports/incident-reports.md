# Home SOC Lab: Incident Reports

Incident reports for the custom Wazuh detection rules in the home SOC lab. Each incident was generated deliberately as an authorised test on 15 November 2026 and documented as it would be in a real SOC workflow.

**Lab environment:** SOC01 (Wazuh 4.14.10 manager, `192.168.56.10`), WIN11-01 (Windows 11 Pro with Sysmon and Wazuh agent, `192.168.56.20`), KALI-01 (Kali Linux with Wazuh agent, `192.168.56.30`). Times are in AEDT (UTC+11). The Windows hostname is redacted as `[hostname]`.

| Incident ID | Name | Rule ID | Endpoint | Severity | Time (AEDT) |
|---|---|---|---|---|---|
| INC-001 | Windows Failed Logon | 100100 | WIN11-01 | Medium | 10:05 pm |
| INC-002 | PowerShell Process Creation | 100101 | WIN11-01 | Medium | 10:36 pm |
| INC-003 | New Local User Account Created | 100102 | WIN11-01 | Medium | 10:48 pm |
| INC-004 | SSH Brute Force Attempt | 100200, 100201 | KALI-01 | High | 10:55 pm |
| INC-005 | Privileged Sudo Activity | 100202 | KALI-01 | Low | 11:10 pm |

---

## Incident Report: Windows Failed Logon

### 1. Incident Summary

- **Incident ID:** INC-001
- **Date and Time:** 15 November 2026, 10:05 pm (AEDT)
- **Affected Endpoint:** WIN11-01 (`192.168.56.20`)
- **Severity:** Medium
- **Status:** Resolved

### 2. Detection Details

- **Detection Rule ID:** 100100 (custom rule, child of built-in rule 60122, level 7)
- **Event ID:** 4625 (An account failed to log on)
- **Log Source:** Windows Security
- **MITRE ATT&CK Technique:** T1110 - Brute Force

### 3. Observed Activity

Three incorrect passwords were entered for the lab user `socuser` at the Windows lock screen on WIN11-01 during detection testing. Windows recorded Security event 4625 for each attempt, the Wazuh agent forwarded the events to the manager on SOC01, and custom rule 100100 generated a level 7 alert for each one with the description "Windows failed logon detected on [hostname] for user socuser". Wazuh recorded the target account, logon type, workstation name, failure status and the time of each attempt.

### 4. Investigation

- **Source endpoint:** WIN11-01 (agent ID 001, `192.168.56.20`)
- **Timestamp:** 2026-11-15 11:05 UTC (10:05 pm AEDT), three events within about one minute
- **Username:** `socuser`
- **Process or service involved:** Windows logon process (interactive logon at the lock screen, logon type 2)
- **Source IP address, if relevant:** Not applicable (local logon, no remote address recorded)
- **Relevant command line or file path:** Not applicable
- **Failure reason:** Wrong password for an existing account (status `0xC000006D`, sub-status `0xC000006A`)
- **Related events:** Three 4625 events for the same account, followed by event 4624 (successful logon) for `socuser` about one minute later. No 4625 events were recorded for any other account.

### 5. Findings

**Authorised.** The failed logons were generated deliberately as part of lab testing. The failures were few, they targeted a single existing account, and a successful logon by the same account followed. There was no sign of password guessing across multiple accounts.

### 6. Recommended Response

- Validate the activity with the system owner.
- Investigate related events, in particular repeated 4625 events from the same source or against several accounts.
- Review the affected account for a successful logon (event 4624) that follows a run of failures.
- Contain the endpoint if repeated failures are followed by an unexpected successful logon.
- Reset credentials if compromise is suspected.
- Document remediation.

### 7. Conclusion

Rule 100100 detected failed Windows logons on WIN11-01. The analyst reviewed the account, logon type, failure status and surrounding events in the Wazuh dashboard, and confirmed the activity was an authorised test. The case showed that a few failed logons are low risk on their own, and that the useful signal is the pattern: how often it happens, which accounts are targeted, and whether a successful logon follows.

### 8. Evidence

- Wazuh dashboard alert for rule 100100 (screenshot, sanitised): `evidence/inc-001-failed-logon-alert.png`
- Search used: `rule.id:100100`
- No passwords, private keys or personal information are included.

---

## Incident Report: PowerShell Process Creation

### 1. Incident Summary

- **Incident ID:** INC-002
- **Date and Time:** 15 November 2026, 10:36 pm (AEDT)
- **Affected Endpoint:** WIN11-01 (`192.168.56.20`, Wazuh agent ID 001)
- **Severity:** Medium
- **Status:** Resolved

### 2. Detection Details

- **Detection Rule ID:** 100101 (custom rule, child of built-in rule 61603, level 8)
- **Event ID:** 1 (Sysmon: Process creation)
- **Log Source:** Sysmon (`Microsoft-Windows-Sysmon/Operational`), collected by Wazuh as an Event Channel log
- **MITRE ATT&CK Technique:** T1059.001 - Command and Scripting Interpreter: PowerShell (tactic: Execution)

### 3. Observed Activity

PowerShell was launched interactively on WIN11-01 during detection testing. Sysmon recorded a process creation event for `powershell.exe`, the Wazuh agent forwarded it to the manager on SOC01, and the `windows_eventchannel` decoder parsed it. Custom rule 100101 then generated a level 8 alert with the description "PowerShell process creation detected on [hostname]".

Wazuh recorded the executable path, command line, parent process, user, integrity level, working directory, logon session and SHA256 hash of the executable. The alert was the 19th firing of rule 100101 since the manager started.

### 4. Investigation

- **Source endpoint:** WIN11-01 (agent ID 001, `192.168.56.20`), reporting to manager `soc01`
- **Timestamp:** Sysmon `UtcTime` 2026-11-15 11:36:20 UTC (10:36 pm AEDT). The alert was indexed at 11:36:26 UTC.
- **Username:** `[hostname]\socuser` (a standard lab user)
- **Process or service involved:** `powershell.exe` (Windows PowerShell, original file name `PowerShell.EXE`, version 10.0.26100.9549, vendor Microsoft Corporation), process ID 3004
- **Parent process:** `C:\Windows\explorer.exe` (process ID 5456), run by the same user
- **Source IP address, if relevant:** Not applicable (local process execution)
- **Relevant command line or file path:**
  - Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
  - Command line: `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"` (no arguments)
  - Working directory: `C:\WINDOWS\system32\`
- **Session details:** Integrity level Medium (not elevated), terminal session 1 (interactive desktop session), logon ID `0x8f752`
- **File hash (SHA256):** `60C9B29843624DD8AF6B6A7B26147753BE6AEEF65098B9A503CC50850AFE410F`
- **Related events:** Other Sysmon event 1 entries whose parent process ID is 3004 (child processes of this session), and earlier firings of rule 100101 from repeated lab testing. Search used to check: `data.win.eventdata.parentProcessId:3004`.

### 5. Findings

**Authorised.** PowerShell was opened manually by the lab user to trigger the detection. The indicators support this:

- The parent process was `explorer.exe`, which is what launching PowerShell from the Start menu or desktop produces.
- The command line had no arguments, so there were no encoded commands, hidden-window flags, execution policy bypasses or download cradles.
- The process ran at Medium integrity in the interactive user session, with no elevation.
- The executable path was the standard Windows location, and the file metadata matched Microsoft's Windows PowerShell.

The rule alerts on every PowerShell launch, so in a real investigation the command line and parent process decide whether it is routine or suspicious.

### 6. Recommended Response

- Validate the activity with the system owner.
- Investigate related events, such as child processes, network connections and file creation from the same session.
- Review the account and parent process that launched PowerShell.
- Contain the endpoint if the command line shows encoded commands, hidden windows or remote downloads.
- Reset credentials if the session is suspected to be attacker-controlled.
- Document remediation.

### 7. Conclusion

Rule 100101 detected PowerShell execution on WIN11-01 through Sysmon telemetry. The analyst reviewed the command line, parent process, user and integrity level in the Wazuh dashboard, and confirmed the activity was an authorised test launched from the desktop. The case showed that PowerShell alerts need context to be useful: the command line and parent process, not just the process name, separate routine use from suspicious use.

### 8. Evidence

- Wazuh dashboard alert for rule 100101 (screenshot, sanitised): `evidence/inc-002-powershell-alert.png`
- Search used: `rule.id:100101`
- Alert details referenced: rule ID 100101, level 8, decoder `windows_eventchannel`, Sysmon event ID 1, record ID 4979.
- The hostname has been replaced with `[hostname]`, and no passwords, private keys or personal information are included.

---

## Incident Report: New Local User Account Created

### 1. Incident Summary

- **Incident ID:** INC-003
- **Date and Time:** 15 November 2026, 10:48 pm (AEDT)
- **Affected Endpoint:** WIN11-01 (`192.168.56.20`)
- **Severity:** Medium
- **Status:** Resolved

### 2. Detection Details

- **Detection Rule ID:** 100102 (custom rule, child of built-in rule 60109, level 8)
- **Event ID:** 4720 (A user account was created)
- **Log Source:** Windows Security
- **MITRE ATT&CK Technique:** T1136.001 - Create Account: Local Account

### 3. Observed Activity

A new local user account, `testuser`, was created on WIN11-01 from an elevated Command Prompt during detection testing. Windows recorded Security event 4720, the Wazuh agent forwarded it to the manager on SOC01, and custom rule 100102 generated a level 8 alert with the description "New Windows user account created on [hostname]: testuser". Wazuh recorded the new account name and the account that created it. The test account was deleted after the alert was confirmed.

### 4. Investigation

- **Source endpoint:** WIN11-01 (agent ID 001, `192.168.56.20`)
- **Timestamp:** 2026-11-15 11:48 UTC (10:48 pm AEDT)
- **Username:** New account `testuser`, created by `socuser`
- **Process or service involved:** Command Prompt (`cmd.exe`) running `net.exe`, in an elevated session
- **Source IP address, if relevant:** Not applicable (local activity)
- **Relevant command line or file path:** `net user testuser <redacted> /add` (password removed)
- **Related events:** Event 4722 (account enabled) for `testuser`, Sysmon event 1 for `net.exe` and `net1.exe`, and event 4726 (account deleted) when the test account was removed with `net user testuser /delete`. No group membership change (event 4732) was recorded for the account.

### 5. Findings

**Authorised.** The account was created intentionally to test rule 100102 and was deleted after the test. The creator was the known lab administrator, the account was not added to the Administrators group, and no logon by the new account was observed.

### 6. Recommended Response

- Validate the activity with the system owner.
- Investigate related events, including group membership changes (4732) and any logon by the new account.
- Review the affected accounts and the account that created the new user.
- Contain the endpoint if the account was created without authorisation or was added to a privileged group.
- Reset credentials for the creating account if compromise is suspected.
- Document remediation, including deletion of the unauthorised account.

### 7. Conclusion

Rule 100102 detected the creation of a local account on WIN11-01. The analyst identified the creator, the command used and the follow-on events, and confirmed the account was an authorised test that was cleaned up. The case showed why account creation is a high-value signal, because attackers often create accounts to keep access, and why checking group membership and later logons is part of the investigation.

### 8. Evidence

- Wazuh dashboard alert for rule 100102 (screenshot, sanitised): `evidence/inc-003-account-created-alert.png`
- Search used: `rule.id:100102`
- No passwords, private keys or personal information are included. The password used in the test command has been removed.

---

## Incident Report: SSH Brute Force Attempt

### 1. Incident Summary

- **Incident ID:** INC-004
- **Date and Time:** 15 November 2026, 10:55 pm (AEDT)
- **Affected Endpoint:** KALI-01 (`192.168.56.30`)
- **Severity:** High
- **Status:** Resolved

### 2. Detection Details

- **Detection Rule ID:** 100200 (single SSH failure, level 7) and 100201 (five failures from one source within 120 seconds, level 10). Both are custom rules.
- **Event ID:** Not applicable (Linux sshd authentication log entries have no event ID). The parent rule is built-in rule 5716.
- **Log Source:** Linux authentication (`/var/log/auth.log`, sshd)
- **MITRE ATT&CK Technique:** T1110 - Brute Force

### 3. Observed Activity

Six SSH logins with an incorrect password were made against the `kali` account on KALI-01 within about one minute during detection testing. The sshd service logged each attempt as "Failed password", the Wazuh agent forwarded the lines to the manager, and rule 100200 alerted on each failure. Once five failures from the same source IP were seen within two minutes, rule 100201 generated a level 10 correlation alert. Wazuh recorded the target account, source IP, source port and timestamp. The built-in brute force rule 5712 may also have fired.

### 4. Investigation

- **Source endpoint:** KALI-01 (`192.168.56.30`)
- **Timestamp:** 2026-11-15 11:55 UTC (10:55 pm AEDT) for the first failure, with the rule 100201 alert raised on the fifth failure about 40 seconds later
- **Username:** `kali` (targeted account)
- **Process or service involved:** `sshd` (OpenSSH server)
- **Source IP address, if relevant:** `192.168.56.10` (SOC01, a lab machine on the host-only network)
- **Relevant command line or file path:** `/var/log/auth.log`, with log lines in the form "Failed password for kali from 192.168.56.10 port [port] ssh2"
- **Related events:** Rule 100200 alerts leading up to rule 100201, and built-in rule 5712 if triggered. No "Accepted password" line was logged for the source IP after the failures.

### 5. Findings

**Authorised.** The failed logins were generated deliberately from a lab machine to test the brute force rules. The source IP belongs to the lab network, the activity stopped after the test, and there was no successful login from that address after the failures. The same pattern from an unknown or external address would be treated as suspicious.

### 6. Recommended Response

- Validate the activity with the system owner.
- Investigate related events, in particular whether a successful login followed the failures.
- Review the targeted accounts and the source IP.
- Contain the endpoint if a successful login from the source IP is found, and block the source IP at the firewall.
- Reset credentials for targeted accounts if compromise is suspected.
- Harden SSH: use key-based authentication, disable password login and root login, and consider rate limiting with fail2ban.
- Document remediation.

### 7. Conclusion

Rules 100200 and 100201 detected an SSH password-guessing pattern against KALI-01. The analyst traced the source IP and targeted account in the Wazuh dashboard, checked for a successful login afterwards, and confirmed the activity was an authorised test. The case showed how a single-event rule and a frequency-based correlation rule work together: the first gives visibility of each attempt, and the second raises the priority when the pattern looks like an attack.

### 8. Evidence

- Wazuh dashboard alerts for rules 100200 and 100201 (screenshot, sanitised): `evidence/inc-004-ssh-bruteforce-alerts.png`
- Search used: `rule.id:(100200 OR 100201)`
- `wazuh-logtest` output showing both rules firing (sanitised): `evidence/inc-004-logtest-output.png`
- No passwords, private keys or personal information are included.

---

## Incident Report: Privileged Sudo Activity

### 1. Incident Summary

- **Incident ID:** INC-005
- **Date and Time:** 15 November 2026, 11:10 pm (AEDT)
- **Affected Endpoint:** KALI-01 (`192.168.56.30`)
- **Severity:** Low
- **Status:** Resolved

### 2. Detection Details

- **Detection Rule ID:** 100202 (custom rule, child of built-in rule 5402, level 5)
- **Event ID:** Not applicable (Linux sudo authentication log entries have no event ID)
- **Log Source:** Linux authentication (`/var/log/auth.log`, sudo)
- **MITRE ATT&CK Technique:** T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching

### 3. Observed Activity

The user `kali` ran two commands as root with `sudo` on KALI-01 during detection testing. The sudo service logged each command, the Wazuh agent forwarded the lines to the manager, and custom rule 100202 generated a level 5 alert for each one with the description "Linux: Privileged sudo activity by kali on sudo". Wazuh recorded the invoking user, the target user (`root`), the working directory and the full command.

### 4. Investigation

- **Source endpoint:** KALI-01 (`192.168.56.30`)
- **Timestamp:** 2026-11-15 12:10 UTC (11:10 pm AEDT)
- **Username:** `kali` (running commands as `root`)
- **Process or service involved:** `sudo`
- **Source IP address, if relevant:** Not applicable (local terminal session)
- **Relevant command line or file path:** `sudo ls` (`/usr/bin/ls`) and `sudo whoami` (`/usr/bin/whoami`), both run from `/home/kali`
- **Related events:** The two sudo alerts came from the same terminal session (`pts/0`). No user or group changes (rules 5902 and 5904) and no other sudo commands were recorded in that session.

### 5. Findings

**Authorised.** The commands were run by the lab user to test rule 100202. The user was the expected administrator, the commands were harmless (`ls` and `whoami`), and no persistence or account changes followed. Because the rule fires on every sudo command, a real investigation would look at which command was run, not the sudo use itself.

### 6. Recommended Response

- Validate the activity with the system owner.
- Investigate related events, in particular sudo commands that change users, groups, services or system files.
- Review the affected account and its sudo privileges.
- Contain the endpoint if the commands were not made by the account owner.
- Reset credentials if the account may be compromised.
- Document remediation.

### 7. Conclusion

Rule 100202 detected privileged command execution through sudo on KALI-01. The analyst reviewed the user, command and session in the Wazuh dashboard and confirmed the activity was an authorised test. The case showed that sudo use is common and low risk on its own, so the value of this rule comes from reviewing the commands run and watching for sudo use by unexpected accounts.

### 8. Evidence

- Wazuh dashboard alert for rule 100202 (screenshot, sanitised): `evidence/inc-005-sudo-alert.png`
- Search used: `rule.id:100202`
- `wazuh-logtest` output showing rule 100202 firing (sanitised): `evidence/inc-005-logtest-output.png`
- No passwords, private keys or personal information are included.
