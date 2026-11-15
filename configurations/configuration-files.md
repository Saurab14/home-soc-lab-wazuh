# Configuration Files

## 1. Overview

This section documents selected configuration extracts from the Wazuh home SOC lab. The extracts cover the Wazuh manager (SOC01), custom detection rules, the Kali Linux agent (KALI-01), and the Windows 11 agent (WIN11-01).

These are selected extracts from the live VM configuration files, not complete replacements for the original files.

## 2. Configuration locations

| Component | VM | Live configuration path |
|---|---|---|
| Wazuh manager | SOC01 | `/var/ossec/etc/ossec.conf` |
| Custom detection rules | SOC01 | `/var/ossec/etc/rules/local_rules.xml` |
| Wazuh agent | KALI-01 | `/var/ossec/etc/ossec.conf` |
| Wazuh agent | WIN11-01 | `C:\Program Files (x86)\ossec-agent\ossec.conf` |

## 3. Wazuh manager configuration — SOC01

### 3.1 Agent authentication service

**Source:** `/var/ossec/etc/ossec.conf`

```xml
<!-- Configuration for wazuh-authd -->
<auth>
  <disabled>no</disabled>
  <port>1515</port>
  <use_source_ip>no</use_source_ip>
  <purge>yes</purge>
  <use_password>no</use_password>
  <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
  <ssl_verify_host>no</ssl_verify_host>
  <ssl_manager_cert>etc/sslmanager.cert</ssl_manager_cert>
  <ssl_manager_key>etc/sslmanager.key</ssl_manager_key>
  <ssl_auto_negotiate>no</ssl_auto_negotiate>
</auth>
```

This block enables the agent enrolment/authentication service on TCP port `1515`. Password-based enrolment is disabled in this configuration. The manager certificate and private-key paths are referenced by the service.

**Security note:** Never publish the private key referenced by `ssl_manager_key`. The `use_password` and certificate-verification settings should be reviewed before adapting this lab configuration for a production environment.

### 3.2 Cluster configuration

```xml
<cluster>
  <name>wazuh</name>
  <node_name>node01</node_name>
  <node_type>master</node_type>
  <key></key>
  <port>1516</port>
  <bind_addr>0.0.0.0</bind_addr>
  <nodes>
    <node>NODE_IP</node>
  </nodes>
  <hidden>no</hidden>
  <disabled>yes</disabled>
</cluster>
```

The block defines cluster parameters, but `<disabled>yes</disabled>` means cluster functionality is disabled. The project therefore documents a single-manager lab and does not claim to implement a functioning Wazuh cluster.

### 3.3 Manager-side log collection

```xml
<ossec_config>
  <localfile>
    <log_format>journald</log_format>
    <location>journald</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>
</ossec_config>
```

The manager is configured to collect system journal entries, Wazuh active-response log entries, and Debian package-management activity from `/var/log/dpkg.log`.

---

## 4. Custom Wazuh detection rules — SOC01

**Source:** `/var/ossec/etc/rules/local_rules.xml`

The local rules file contains rules for selected SSH, Windows authentication, process creation, account management, and sudo events.

### 4.1 SSH example rule

```xml
<group name="local,syslog,sshd,">
  <rule id="100001" level="5">
    <if_sid>5716</if_sid>
    <srcip>1.1.1.1</srcip>
    <description>sshd: authentication failed from IP 1.1.1.1.</description>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>
</group>
```

This rule matches an SSH authentication failure from the specifically configured source IP `1.1.1.1`. Because the IP is hard-coded, this is a fixed demonstration condition, not a general detector for failed SSH logins from any address.

### 4.2 Windows failed logon

```xml
<group name="local,windows,authentication,">
  <rule id="100100" level="7">
    <if_sid>60122</if_sid>
    <description>Windows failed logon detected on $(win.system.computer) for user $(win.eventdata.targetUserName)</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```

Identifies a Windows failed-logon event matched by parent rule `60122`. The alert description includes the computer and target username. MITRE ATT&CK mapping: **T1110 — Brute Force**.

### 4.3 PowerShell process creation

```xml
<group name="local,windows,sysmon,process,">
  <rule id="100101" level="8">
    <if_sid>61603</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe$</field>
    <description>PowerShell process creation detected on $(win.system.computer)</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>
</group>
```

Matches a process-creation event whose image field ends in `powershell.exe`, case-insensitively. MITRE ATT&CK mapping: **T1059.001 — PowerShell**. PowerShell is a legitimate administration tool; this alert requires investigation and is not proof of malicious activity.

### 4.4 Windows account creation

```xml
<group name="local,windows,account_management,">
  <rule id="100102" level="8">
    <if_sid>60109</if_sid>
    <description>New Windows user account created on $(win.system.computer): $(win.eventdata.targetUserName)</description>
    <mitre>
      <id>T1136.001</id>
    </mitre>
  </rule>
</group>
```

Identifies the account-creation event matched by parent rule `60109` and includes the target username. MITRE ATT&CK mapping: **T1136.001 — Local Account**.

### 4.5 Linux SSH authentication failures and frequency detection

```xml
<group name="local,linux,sshd,authentication_failed,">
  <rule id="100200" level="7">
    <if_sid>5716</if_sid>
    <match>Failed password</match>
    <description>Linux: SSH authentication failure detected from $(srcip)</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>

  <rule id="100201" level="10" frequency="5" timeframe="120">
    <if_matched_sid>100200</if_matched_sid>
    <same_source_ip />
    <description>Linux: Multiple SSH authentication failures from $(srcip) within two minutes</description>
    <mitre>
      <id>T1110</id>
    </mitre>
  </rule>
</group>
```

Rule `100200` matches SSH authentication failure events containing `Failed password`. Rule `100201` is intended to raise a higher-level alert when matching failures recur from the same source IP within a 120-second timeframe. MITRE ATT&CK mapping: **T1110 — Brute Force**.

### 4.6 Linux sudo activity

```xml
<group name="local,linux,sudo,privilege_escalation,">
  <rule id="100202" level="5">
    <if_sid>5402</if_sid>
    <description>Linux: Privileged sudo activity by $(srcuser) on $(program_name)</description>
    <mitre>
      <id>T1548.003</id>
    </mitre>
  </rule>
</group>
```

Identifies sudo-related activity matched by parent rule `5402`. MITRE ATT&CK mapping: **T1548.003 — Sudo and Sudo Caching**. Sudo use can be legitimate; analysts should review the account, command, host, time, and surrounding activity.

**Rule validation note:** Parent rule IDs and event field names must match the events decoded by the installed Wazuh version. XML validity alone does not prove that a rule matches as intended.

---

## 5. Kali Linux agent configuration — KALI-01

**Source:** `/var/ossec/etc/ossec.conf`

### 5.1 Manager connection and enrolment

```xml
<ossec_config>
  <client>
    <server>
      <address>192.168.56.10</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>kali, kali2026, kali2026.2</config-profile>
    <notify_time>20</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
    <enrollment>
      <enabled>yes</enabled>
      <agent_name>KALI-01</agent_name>
      <authorization_pass_path>etc/authd.pass</authorization_pass_path>
    </enrollment>
  </client>
</ossec_config>
```

The agent is configured to connect to manager `192.168.56.10` over TCP port `1514`, uses the agent name `KALI-01`, and has enrolment enabled. The `authorization_pass_path` setting references a local file; do not publish that file or any enrolment secret.

### 5.2 Linux log sources

```xml
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>

  <localfile>
    <location>/var/log/auth.log</location>
    <log_format>syslog</log_format>
  </localfile>

  <localfile>
    <location>/var/log/syslog</location>
    <log_format>syslog</log_format>
  </localfile>
</ossec_config>
```

The configured sources include Wazuh active-response activity, package-management records, authentication events, and general system messages. Confirm that each path exists and is populated on the installed Kali system.

---

## 6. Windows 11 agent configuration — WIN11-01

**Source:** `C:\Program Files (x86)\ossec-agent\ossec.conf`

### 6.1 Windows Event Channel and active-response log collection

```xml
<ossec_config>
  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>active-response\active-responses.log</location>
    <log_format>syslog</log_format>
  </localfile>
</ossec_config>
```

The Windows agent is configured to collect events from the Windows `System` Event Channel and monitor its active-response log.

### 6.2 File Integrity Monitoring

```xml
<ossec_config>
  <syscheck>
    <disabled>no</disabled>
    <directories check_all="yes" realtime="yes">C:\SOC\Sensitive</directories>
  </syscheck>
</ossec_config>
```

This enables Syscheck/File Integrity Monitoring and configures real-time monitoring of `C:\SOC\Sensitive`. The `check_all="yes"` option enables the configured checks for the monitored directory. File changes should be assessed in context; a change is not automatically malicious.

---

## 7. Validation and operational verification

Use the following checks after configuration changes.

### 7.1 Validate the local rules XML

On SOC01:

```bash
sudo xmllint --noout /var/ossec/etc/rules/local_rules.xml
```

### 7.2 Test rule matching

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Provide representative event data and check whether the expected rule is matched. Confirm the actual decoded fields and parent rule before relying on a custom rule.

### 7.3 Check manager and Linux agent services

On SOC01:

```bash
sudo systemctl status wazuh-manager
```

On KALI-01:

```bash
sudo systemctl status wazuh-agent
```

### 7.4 Check the Windows agent service

Run PowerShell as Administrator:

```powershell
Get-Service WazuhSvc
```

After changing an agent configuration, restart the relevant agent service and verify that the endpoint reconnects. Then check the Wazuh Dashboard for agent status and the expected telemetry.

A service showing as running does not, by itself, prove that the expected events are arriving. Similarly, a rule being present in `local_rules.xml` does not prove that it has generated an alert.

---

## 8. Security considerations

- Never commit private keys, passwords, enrolment secrets, `client.keys`, or the contents of `etc/authd.pass`.
- Keep the manager private key referenced by `ssl_manager_key` on SOC01.
- Review authentication-service settings before reusing this configuration outside an isolated lab.
- The SSH example rule with source IP `1.1.1.1` is a fixed-IP match and should not be represented as a general failed-login rule.
- PowerShell, sudo, account creation, and file modification can be legitimate administrative activity. Alerts require contextual investigation.
- Review hostnames, usernames, IP addresses, and directory names before publishing a public repository.

## 9. Implementation status and evidence

The extracts in this document were supplied from the configuration files on the lab VMs. The following levels of verification should be reported separately:

| Verification level | Meaning |
|---|---|
| Configured | The setting is present in the VM configuration file. |
| Service checked | The relevant service was checked and its state recorded. |
| Telemetry verified | The expected event was observed arriving in Wazuh. |
| Detection tested | A controlled test event generated an alert with the expected custom rule ID. |

Do not describe a custom rule as successfully tested unless the corresponding rule ID has been observed for a controlled test event. Where available, add a sanitised screenshot or test record showing the agent, event, timestamp, and alert/rule ID.

## 10. Summary

The lab uses a central Wazuh manager on SOC01, a Kali Linux endpoint, and a Windows 11 endpoint. The documented settings cover agent enrolment and communication, Linux and Windows log collection, custom detection logic, and Windows File Integrity Monitoring.

These configuration extracts provide a technical reference for the lab and a basis for repeatable validation and future detection engineering.
