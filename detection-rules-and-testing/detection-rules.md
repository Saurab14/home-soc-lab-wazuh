# Detection Rules

## 1. Overview

This section documents the custom detection rules implemented and tested in the Wazuh home SOC lab. The rules extend the default Wazuh detection capability by identifying selected authentication, process-execution, account-management, and privilege-related activities across the monitored Windows and Linux endpoints.

The rules are maintained centrally on the Wazuh manager (SOC01) in:

```text
/var/ossec/etc/rules/local_rules.xml
```

The custom rules use locally assigned rule IDs and are organised by operating system and activity type. Each rule defines a detection condition, alert severity, description, and (where applicable) a MITRE ATT&CK technique mapping.

The rules were validated in the lab using controlled test activity and checked through Wazuh rule testing and alert monitoring.

## 2. Detection engineering objectives

The detection rules were developed to support the following monitoring objectives:

- Identify unsuccessful authentication attempts against Windows and Linux systems.
- Highlight repeated SSH authentication failures that may indicate password guessing or brute-force activity.
- Detect PowerShell process creation for further investigation.
- Identify the creation of new local Windows accounts.
- Monitor privileged activity performed through `sudo` on Linux endpoints.
- Provide useful alert descriptions and MITRE ATT&CK mappings to support investigation and triage.

Detection alerts are indicators for investigation. An alert does not, by itself, establish malicious intent or confirm that a system has been compromised.

## 3. Rule inventory

| Rule ID | Detection name | Platform | Severity level | MITRE ATT&CK |
|---|---|---|---:|---|
| `100001` | SSH authentication failure from a specified source IP | Linux / SSH | 5 | Not explicitly mapped |
| `100100` | Windows failed logon | Windows | 7 | T1110 – Brute Force |
| `100101` | PowerShell process creation | Windows / Sysmon | 8 | T1059.001 – PowerShell |
| `100102` | Windows account creation | Windows | 8 | T1136.001 – Local Account |
| `100200` | Linux SSH authentication failure | Linux / SSH | 7 | T1110 – Brute Force |
| `100201` | Repeated Linux SSH authentication failures from the same source IP | Linux / SSH | 10 | T1110 – Brute Force |
| `100202` | Linux sudo activity | Linux | 5 | T1548.003 – Sudo and Sudo Caching |

**Severity interpretation:** Wazuh rule levels indicate the configured alert priority. Higher levels should generally receive greater analyst attention, but severity must be considered alongside the event context, affected asset, user, source, and business impact.

---

## 4. Windows detection rules

### 4.1 Rule 100100 — Windows failed logon

**Rule configuration**

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

**Detection logic**

The rule uses Wazuh parent rule `60122` to identify a Windows failed-logon event. When the parent rule matches, the custom rule generates a level 7 alert and includes the computer name and target username in the alert description.

**Security relevance**

Repeated failed logons may indicate password guessing, brute-force attempts, or attempts to access an account using invalid credentials. However, mistyped passwords, expired credentials, and misconfigured services can also generate failed-logon events.

**MITRE ATT&CK mapping**

- **Tactic:** Credential Access
- **Technique:** T1110 – Brute Force

**Analyst investigation**

1. Identify the affected Windows endpoint and target username.
2. Review the event timestamp and available source information.
3. Determine whether failures are isolated or repeated.
4. Correlate the activity with successful logons and other authentication events.
5. Establish whether the activity is expected, user-generated, or suspicious.

**Recommended response**

If the activity is unauthorised or part of a broader attack pattern, follow the organisation's incident-response process. This may include validating the account owner, reviewing related logons, and escalating suspected credential attacks.

### 4.2 Rule 100101 — PowerShell process creation

**Rule configuration**

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

**Detection logic**

The rule uses parent rule `61603` and checks the `win.eventdata.image` field using a case-insensitive PCRE2 expression. The expression matches process image paths ending in `powershell.exe`.

**Security relevance**

PowerShell is a legitimate Windows administration and automation tool. It is also frequently used in attacks to execute commands, automate actions, download content, and carry out post-compromise activity. The rule therefore highlights PowerShell process creation for review; it does not classify every PowerShell execution as malicious.

**MITRE ATT&CK mapping**

- **Tactic:** Execution
- **Technique:** T1059.001 – PowerShell

**Analyst investigation**

1. Identify the Windows endpoint and event timestamp.
2. Review the process image and available process details.
3. Examine the parent process and user account where the telemetry provides them.
4. Review the command line and related process events, if available.
5. Determine whether the execution is associated with approved administration, software activity, or unexpected behaviour.

**Recommended response**

Escalate executions that are unexpected or inconsistent with normal endpoint activity. Preserve relevant event details and investigate associated parent processes, command-line arguments, network activity, and subsequent actions.

### 4.3 Rule 100102 — Windows account creation

**Rule configuration**

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

**Detection logic**

The rule uses parent rule `60109` to identify a Windows account-creation event. The generated alert includes the affected computer and target username.

**Security relevance**

Unauthorised account creation can provide an attacker with an additional account for persistence or future access. Legitimate administrators and software deployment processes may also create accounts, so the event must be assessed in context.

**MITRE ATT&CK mapping**

- **Tactic:** Persistence
- **Technique:** T1136.001 – Local Account

**Analyst investigation**

1. Identify the newly created username and affected endpoint.
2. Determine which account performed the creation, using the original event details.
3. Check whether the creation was approved and associated with a legitimate change.
4. Review the account's group memberships and subsequent logon activity.
5. Correlate the event with other account-management or privilege-related alerts.

**Recommended response**

If the account was created without authorisation, escalate the incident and follow the approved account-containment process. Preserve the relevant security events for investigation.

---

## 5. Linux detection rules

### 5.1 Rule 100001 — SSH authentication failure from a specified source IP

**Rule configuration**

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

**Detection logic**

The rule uses parent rule `5716` and matches SSH authentication failures where the source IP is exactly `1.1.1.1`. It generates a level 5 alert and adds authentication-failure and PCI DSS-related group labels.

**Important scope limitation**

The source IP is hard-coded. Consequently, this rule only matches the specified address; it is not a general-purpose rule for all SSH authentication failures. The broader Linux SSH detection is handled by rule `100200`.

**Analyst investigation**

Review the source address, target endpoint, account name, timestamp, and surrounding SSH activity. Confirm whether the source is expected and whether repeated attempts or successful logons followed the failure.

### 5.2 Rule 100200 — Linux SSH authentication failure

**Rule configuration**

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
</group>
```

**Detection logic**

The rule uses parent rule `5716` and checks for the text `Failed password` in the decoded event. A matching event generates a level 7 alert and includes the source IP address in the description.

**Security relevance**

SSH authentication failures can result from legitimate user mistakes, automated service attempts, password guessing, or brute-force activity. The source and frequency of the attempts help determine their significance.

**MITRE ATT&CK mapping**

- **Tactic:** Credential Access
- **Technique:** T1110 – Brute Force

**Analyst investigation**

1. Identify the source IP and affected Linux endpoint.
2. Review the attempted username and event timestamp.
3. Determine whether the source generated multiple failures.
4. Check for successful SSH authentication around the same period.
5. Correlate the activity with other alerts from the endpoint or source.

### 5.3 Rule 100201 — Repeated SSH authentication failures

**Rule configuration**

```xml
<rule id="100201" level="10" frequency="5" timeframe="120">
  <if_matched_sid>100200</if_matched_sid>
  <same_source_ip />
  <description>Linux: Multiple SSH authentication failures from $(srcip) within two minutes</description>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
```

**Detection logic**

This frequency-based rule monitors events matched by rule `100200`. It is configured with a frequency of 5 and a timeframe of 120 seconds, with `<same_source_ip />` used to correlate matching events from the same source IP.

The purpose is to identify repeated SSH authentication failures from one source within a two-minute period and generate a higher-level, level 10 alert.

**Security relevance**

A concentration of failed SSH authentication attempts from one source may indicate password guessing or brute-force activity. The frequency condition helps distinguish repeated attempts from isolated authentication mistakes.

**MITRE ATT&CK mapping**

- **Tactic:** Credential Access
- **Technique:** T1110 – Brute Force

**Analyst investigation**

1. Identify the source IP and destination Linux endpoint.
2. Review the events contributing to the frequency alert.
3. Check the attempted usernames and timing of the failures.
4. Look for successful authentication before or after the repeated failures.
5. Determine whether the source is an approved scanner, administrator workstation, automated service, or unknown system.

**Recommended response**

For confirmed unauthorised activity, follow the organisation's response process. Potential actions include escalating the event, reviewing SSH exposure and authentication policy, and applying approved source-blocking or account-protection controls.

### 5.4 Rule 100202 — Linux sudo activity

**Rule configuration**

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

**Detection logic**

The rule uses parent rule `5402` to identify sudo-related activity and generates a level 5 alert. The description includes the source username and program name when those fields are available in the decoded event.

**Security relevance**

Sudo provides legitimate privilege elevation for Linux administration. Unexpected or unauthorised use may indicate privilege misuse or an attempt to perform actions requiring elevated permissions.

**MITRE ATT&CK mapping**

- **Tactic:** Privilege Escalation
- **Technique:** T1548.003 – Sudo and Sudo Caching

**Analyst investigation**

1. Identify the user and endpoint associated with the event.
2. Review the command or program executed, where available.
3. Confirm whether the user was expected to perform privileged activity.
4. Correlate the event with authentication, SSH, and system activity.
5. Determine whether the action was authorised and consistent with the user's role.

---

## 6. Detection testing and validation

The custom rules were tested in the lab against controlled activity on the relevant endpoints. Validation focused on confirming that the expected event telemetry was available to Wazuh and that the corresponding custom rule could match the event.

### 6.1 Validation workflow

The following workflow was used to validate detection logic:

1. Confirm that the relevant endpoint agent is connected to the Wazuh manager.
2. Confirm that the required event source is configured and producing telemetry.
3. Generate controlled test activity appropriate to the detection use case.
4. Locate the resulting event in the Wazuh Dashboard.
5. Confirm that the intended custom rule ID is matched.
6. Review the alert description, severity level, and available event fields.
7. Record the result and retain sanitised evidence.

### 6.2 Rule validation checklist

| Rule ID | Test objective | Expected detection |
|---|---|---|
| `100001` | Generate an SSH authentication failure matching the configured source-IP condition | Level 5 alert for the specified source IP |
| `100100` | Generate a Windows failed-logon event | Level 7 Windows failed-logon alert |
| `100101` | Launch PowerShell so that Sysmon records process creation | Level 8 PowerShell process-creation alert |
| `100102` | Create a controlled Windows local account | Level 8 Windows account-creation alert |
| `100200` | Generate a Linux SSH failed-password event | Level 7 SSH authentication-failure alert |
| `100201` | Generate repeated SSH failed-password events from the same source within the configured timeframe | Level 10 repeated-failure alert |
| `100202` | Perform a controlled sudo operation | Level 5 sudo-activity alert |

### 6.3 Rule syntax and matching checks

The local rules file can be checked for XML syntax on SOC01:

```bash
sudo xmllint --noout /var/ossec/etc/rules/local_rules.xml
```

Wazuh's log testing utility can be used to inspect rule matching:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

After making changes to the live rules file, restart the manager and check its status:

```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager
```

The Wazuh Dashboard can then be used to review the resulting alerts and confirm the matched rule IDs.

### 6.4 Evidence to retain

For each test, retain a sanitised record containing:

- Test case and objective.
- Endpoint name and operating system.
- Date and time of the controlled activity.
- Relevant event source and event details.
- Expected and observed Wazuh rule ID.
- Alert level and description.
- Test outcome and any investigation notes.

Do not publish credentials, authentication keys, private keys, or other sensitive information in screenshots or test records.

---

## 7. Detection coverage and limitations

The custom rules provide visibility into selected security events, but they do not constitute complete coverage of the MITRE ATT&CK framework or all possible attack techniques.

| Detection area | Current rule coverage | Considerations |
|---|---|---|
| Authentication failures | Windows failed logon and Linux SSH failures | Correlate repeated failures with successful logons and account context. |
| Brute-force indicators | Repeated Linux SSH failures from the same source IP | The frequency rule is limited to the configured event and correlation conditions. |
| Process execution | PowerShell process creation | Process creation alone does not establish malicious behaviour. |
| Account management | Windows account creation | Confirm whether the creation was authorised. |
| Privileged activity | Linux sudo activity | Review the command, user, and operational context. |
| File integrity | Windows FIM configuration is documented separately in Section 8.3 | Investigate the file, change, user, and process context. |

The fixed-IP SSH rule (`100001`) is deliberately narrow because it contains a specific source address. Rule `100200` provides the broader failed-password detection, while rule `100201` adds frequency-based correlation.

The detection rules should be periodically reviewed as the lab evolves. Changes to Wazuh versions, event formats, parent rule IDs, or endpoint logging settings may require rule tuning and revalidation.

## 8. Security and operational considerations

- Treat alerts as investigation leads, not automatic proof of compromise.
- Confirm the endpoint, user, source, timestamp, and surrounding activity before making a severity or incident decision.
- Use controlled and authorised test activity only.
- Review custom rules after Wazuh upgrades or changes to event collection.
- Avoid exposing sensitive endpoint details or credentials in public evidence.
- Keep custom rule IDs unique within the local rules configuration.
- Document rule changes and retain test evidence so that detection behaviour can be reproduced.

## 9. Summary

The lab's custom Wazuh rules provide detection coverage for Windows authentication failures, PowerShell process creation, Windows account creation, Linux SSH authentication failures, repeated SSH failures, and Linux sudo activity.

By combining event-source configuration, custom rule logic, MITRE ATT&CK references, controlled validation, and analyst investigation guidance, this section demonstrates a practical detection-engineering workflow. The rules provide a foundation for further tuning and expansion as additional log sources and use cases are introduced.
