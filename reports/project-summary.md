# Home SOC Lab: Project Summary

**Project:** Virtualised Security Operations Centre (SOC) built on Wazuh
**Platform:** Oracle VirtualBox
**Date:** 15 November 2026
**Version:** 1.0

---

## 1. Executive Summary

This project designed, deployed and tested a small virtualised SOC environment. A central Wazuh server (SOC01) collects security telemetry from a Windows 11 endpoint (WIN11-01) and a Linux endpoint (KALI-01). Custom detection rules were written for six common attack behaviours, tested with controlled activity, and documented as incident reports.

The lab covers the main SOC workflow: collecting endpoint telemetry, writing and tuning detection rules, generating test events, investigating alerts and documenting the findings. It ran entirely on virtual machines, so no production systems were involved.

**Key results**

- Three virtual machines deployed on a private host-only network (`192.168.56.0/24`), with NAT adapters for outbound internet access.
- Wazuh 4.14.10 manager, indexer and dashboard running on Ubuntu Server 24.04 LTS.
- Wazuh agents enrolled on Windows 11 Pro and Kali Linux, with Sysmon providing detailed Windows process telemetry.
- Six custom detection rules (three Windows, three Linux) mapped to MITRE ATT&CK techniques.
- Each detection tested with controlled activity and documented in a structured incident report.

![Home SOC lab network diagram](../evidence/home-soc-lab-network-diagram.png)

---

## 2. Objectives

1. Build a central monitoring platform and connect separate Windows and Linux endpoints to it.
2. Collect endpoint telemetry that is useful for detection, including Windows Security events, Sysmon events and Linux authentication logs.
3. Write custom Wazuh rules for authentication abuse, suspicious process execution, account creation and privilege use.
4. Validate each rule with controlled test activity.
5. Practise the investigation and reporting steps an analyst follows after an alert.

---

## 3. Lab Architecture

### 3.1 Platform choice

Wazuh was chosen as the central monitoring platform because it is an open-source, integrated solution for event collection, analysis and endpoint monitoring. Its manager-and-agent design supports both Windows and Linux endpoints. It also provides custom rule development and file integrity monitoring, both relevant to this project. Running the platform on a dedicated server kept it separate from the everyday host computer.

### 3.2 Network design

Each virtual machine has two VirtualBox network adapters, which separate internet access from lab communication:

| Adapter | Type | Purpose |
|---|---|---|
| Adapter 1 | NAT | Outbound internet access for updates and package downloads |
| Adapter 2 | Host-only (`192.168.56.0/24`) | Private network for communication between the Wazuh server and the endpoints |

Static addresses on the host-only network give the agents a consistent address for the manager. The host-only network is a private virtual network, but it should not be described as a guarantee of complete isolation from the host operating system.

### 3.3 Virtual machines

| VM | Operating system | Host-only IP | Role |
|---|---|---|---|
| SOC01 | Ubuntu Server 24.04 LTS | `192.168.56.10` | Wazuh manager, indexer and dashboard (version 4.14.10) |
| WIN11-01 | Windows 11 Pro | `192.168.56.20` | Monitored Windows endpoint with Wazuh agent (ID 001) and Sysmon |
| KALI-01 | Kali Linux | `192.168.56.30` | Monitored Linux endpoint with Wazuh agent |

### 3.4 Data flow

1. Activity occurs on an endpoint, such as a Windows event or a Linux log entry.
2. The Wazuh agent collects the configured event or log line.
3. The agent sends it to the manager at `192.168.56.10` over the host-only network.
4. The manager decodes the event and evaluates it against built-in and custom rules.
5. Matching events become alerts, which are stored by the indexer.
6. The analyst reviews alerts and agent status in the Wazuh dashboard.

Wazuh's default ports are TCP 1514 for agent events and TCP 1515 for agent enrolment.

---

## 4. Telemetry Sources

| Endpoint | Source | What it provides |
|---|---|---|
| WIN11-01 | Windows Security event log | Logon failures (event 4625) and account management (event 4720) |
| WIN11-01 | Sysmon (`Microsoft-Windows-Sysmon/Operational`) | Process creation (event 1) with command line, parent process, user and file hash |
| KALI-01 | Linux authentication log (`/var/log/auth.log`) | SSH logins and sudo commands |

The Windows agent was configured to collect the Sysmon channel, and Windows auditing was enabled for logon and user account management events. On Kali, `rsyslog` was installed so that `/var/log/auth.log` is written for the agent to read.

---

## 5. Detection Engineering

### 5.1 Custom rules

Six custom rules were written in `/var/ossec/etc/rules/local_rules.xml` on the Wazuh manager. Rules run on the manager, not on the endpoints, so one rule file covers every enrolled agent.

| Rule ID | Level | Detects | Parent rule | Log source | MITRE ATT&CK |
|---|---|---|---|---|---|
| 100100 | 7 | Failed Windows logon | 60122 | Security event 4625 | T1110 Brute Force |
| 100101 | 8 | PowerShell process creation | 61603 | Sysmon event 1 | T1059.001 Command and Scripting Interpreter: PowerShell |
| 100102 | 8 | New local user account | 60109 | Security event 4720 | T1136.001 Create Account: Local Account |
| 100200 | 7 | SSH password failure | 5716 | Linux `auth.log` (sshd) | T1110 Brute Force |
| 100201 | 10 | Five SSH failures from one source IP within 120 seconds | Correlates rule 100200 | Linux `auth.log` (sshd) | T1110 Brute Force |
| 100202 | 5 | Command run as root with sudo | 5402 | Linux `auth.log` (sudo) | T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching |

The rules are in `detection-rules/windows-rules.xml` and `detection-rules/linux-rules.xml`, and the full mapping is in `detection-rules/detection-mapping.md`.

### 5.2 Design decisions

- **Parent rules:** Each rule builds on a built-in Wazuh rule with `if_sid`, so it only evaluates relevant events and does not compete with the built-in rule that matches first.
- **Separate groups:** Rules sit in sibling `<group>` blocks. Wazuh does not allow groups to be nested.
- **Case-insensitive matching:** The PowerShell rule uses `type="pcre2"` so the `(?i)` flag works.
- **Correlation:** Rule 100201 uses `frequency`, `timeframe` and `same_source_ip` so that failures from different sources are not counted together.
- **Syntax check before restart:** Every change was validated with `wazuh-analysisd -t` before the manager was restarted, and a backup of the rules file was taken first.

---

## 6. Testing and Results

Each rule was tested by generating the matching activity on the relevant endpoint and confirming the alert in the Wazuh dashboard.

| Rule | Test activity | Where | Result |
|---|---|---|---|
| 100100 | Wrong password entered at the Windows lock screen | WIN11-01 | Alert generated |
| 100101 | PowerShell launched from the desktop | WIN11-01 | Alert generated |
| 100102 | Local account created with `net user` from an elevated prompt, then deleted | WIN11-01 | Alert generated |
| 100200 | SSH login with an incorrect password | KALI-01 | Alert generated |
| 100201 | Repeated incorrect SSH logins within two minutes | KALI-01 | Correlation alert generated |
| 100202 | `sudo ls` and `sudo whoami` | KALI-01 | Alert generated |

For the PowerShell test, the alert recorded the executable path, the command line, the parent process (`explorer.exe`), the user, the integrity level and the file hash. That is enough context to decide whether a PowerShell launch is routine.

Detailed procedures and results are in `detection-testing/`, and each incident is written up in `incident-reports/`.

---

## 7. Incident Investigation

Each detection was documented in a standard incident report with eight sections: summary, detection details, observed activity, investigation, findings, recommended response, conclusion and evidence. The investigations followed the same questions each time:

- Which endpoint, user, process and source IP were involved?
- What do the related events show before and after the alert?
- Was the activity authorised, suspicious or inconclusive?
- What response would be appropriate if it were not a test?

All activity in this project was generated deliberately in the lab, so the findings were recorded as authorised. The reports were written to show how the same alerts would be handled in a real environment.

---

## 8. Challenges and Resolutions

| Challenge | Cause | Resolution |
|---|---|---|
| Windows 11 setup forced a Microsoft account | Recent Windows builds hide the local-account option | Used a local-account workaround during setup so no personal account was used in the lab |
| Wazuh agent package not found on Kali (`Unable to locate package`) | The repository key was saved in a format apt could not read, and `apt update` was not run after adding the repository | Re-imported the key with `gpg --dearmor`, ran `apt update`, then installed the agent |
| Agent version compatibility | A Wazuh agent must not be newer than the manager | Checked the manager version and installed a matching agent version |
| Kali showed "Destination Host Unreachable" to the Wazuh server | Host-only adapter was not configured or not on the same network | Checked the adapter, the network name and the address, and confirmed both VMs were on `192.168.56.0/24` |
| Agent showed as active but was disconnected in the dashboard | `active` only means the service is running, not that it is connected | Checked `ossec.log`, connectivity and the manager address to confirm the connection |
| PowerShell rule did not fire in `wazuh-logtest` | The pasted JSON was decoded as `json`, and built-in Windows parent rules only apply to `windows_eventchannel` events; `(?i)` also needs `type="pcre2"` | Corrected the regex type and validated the rule with real Sysmon events from the agent |
| Vulnerability scanner errors in `ossec.log` | Vulnerability feed download had failed | Confirmed the errors predated the rule changes and did not affect rules or agents |

---

## 9. Security Considerations

- The lab is for learning and contains no production data. Test accounts and passwords were created only for the lab.
- A local Windows account was used instead of a personal Microsoft account, so no real credentials or synced data exist in the lab.
- The host-only network keeps lab traffic private, but it does not guarantee isolation from the host, so malware samples should not be run in this environment without further isolation.
- Kali is normally an attacker platform. Using it as a monitored endpoint means attacker and victim activity can mix in the alerts. A dedicated attacker VM or a separate clean Linux target would give cleaner data.
- Evidence is sanitised before it is published: no passwords, private keys or personal information, and hostnames are redacted where they contain personal names.
- VM snapshots were used as restore points before testing.

---

## 10. Limitations

- **Small scale:** The lab has two endpoints and one analyst, so it does not show detection at enterprise volume.
- **Controlled tests:** Test activity was simple and deliberate. It shows that rules fire, but not how they perform against a real attacker who tries to avoid detection.
- **Noisy rules:** Rules 100101 and 100202 alert on every PowerShell launch and every sudo command. They give visibility but would produce many false positives on a busy system without tuning.
- **Untuned thresholds:** The SSH correlation threshold (five failures in 120 seconds) was chosen for the lab and has not been tuned against real traffic. Wazuh's built-in rule 5712 can also fire on the same activity.
- **Single data source per behaviour:** Detections rely on logs only. There is no network traffic monitoring and no automated response.
- **File integrity monitoring:** Configuration files for file integrity monitoring are included in the repository, but its detection results are not part of the findings in this summary.

---

## 11. Future Work

1. Tune the noisy rules, for example by alerting on PowerShell only with suspicious command-line options such as encoded commands, or on sudo only for sensitive commands.
2. Enable real-time file integrity monitoring on critical Linux and Windows paths, and add test results and an incident report for it.
3. Replace manual tests with scripted adversary emulation, such as Atomic Red Team, mapped to MITRE ATT&CK techniques.
4. Add a dedicated attacker VM and a clean Linux target so attacker and victim activity are separate.
5. Add network monitoring, for example Suricata, and correlate network alerts with endpoint alerts.
6. Test Wazuh active response, for example automatically blocking a source IP after repeated SSH failures.
7. Build dashboards and saved searches for the rules in this project.

---

## 12. Skills Demonstrated

- Virtualisation and network design with VirtualBox (NAT and host-only adapters, static addressing)
- Deploying and administering Wazuh server components and agents on Windows and Linux
- Windows telemetry with Sysmon and Windows audit policy
- Writing, testing and troubleshooting custom detection rules, including frequency-based correlation
- Mapping detections to MITRE ATT&CK
- Alert triage, investigation and structured incident reporting
- Troubleshooting connectivity, package and version issues
- Technical documentation and evidence handling

---

## 13. Conclusion

The project produced a working SOC lab with central monitoring of Windows and Linux endpoints, six custom detection rules mapped to MITRE ATT&CK, and a documented testing and investigation process. It showed how telemetry is collected, how rules turn raw events into alerts, and how an analyst uses the surrounding context to judge whether an alert is a real concern. It also showed the limits of simple rules and where the next improvements lie: tuning, wider telemetry and more realistic attack simulation.

---

## 14. Repository Guide

| Folder | Contents |
|---|---|
| [`architecture/`](../architecture/) | Network topology and lab components |
| [`installation/`](../installation/) | Setup guides for the Wazuh server, Windows agent, Kali agent and Sysmon |
| [`configurations/`](../configurations/) | Agent and file integrity monitoring configuration files |
| [`detection-rules/`](../detection-rules/) | Custom Wazuh rules and the detection-to-MITRE mapping |
| [`incident-reports/`](../incident-reports/) | Incident reports for the tested detections |
| [`evidence/`](../evidence/) | Sanitised screenshots and rule output |
