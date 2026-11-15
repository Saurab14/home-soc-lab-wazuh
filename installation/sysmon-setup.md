# Microsoft Sysmon Installation and Wazuh Integration

## 1. Purpose

Microsoft Sysmon (System Monitor), part of Microsoft Sysinternals, was
deployed on the dedicated Windows lab endpoint to provide detailed
system activity telemetry. In this lab, Sysmon process-creation events
were used to support endpoint monitoring and security investigations.

Sysmon records selected system activity in the Windows Event Log. Wazuh
can collect the Sysmon Operational event channel through the Windows
agent's event-channel collection configuration.

## 2. Environment

  Item                          Configuration
  ----------------------------- ----------------------------------------
  Endpoint                      `WIN11-01`
  Operating system              Windows 11 Pro
  Sysmon executable directory   `C:\Tools\Sysmon`
  Event channel                 `Microsoft-Windows-Sysmon/Operational`
  Event ID verified             `1` -- Process creation
  SIEM                          Wazuh `4.14.10`

## 3. Download and Prepare Sysmon

Sysmon was obtained from the official Microsoft Sysinternals
distribution:

https://learn.microsoft.com/sysinternals/downloads/sysmon

The downloaded archive was extracted to:

``` text
C:\Tools\Sysmon
```

The executable used for the 64-bit Windows endpoint was `Sysmon64.exe`.

## 4. Install Sysmon

Open PowerShell as Administrator and run:

``` powershell
cd C:\Tools\Sysmon
.\Sysmon64.exe -accepteula -i
```

This installs the Sysmon service using its default configuration. A
custom Sysmon configuration file should only be documented if one was
separately created and deployed.

## 5. Verify the Sysmon Service

Run:

``` powershell
Get-Service Sysmon64
```

Confirm that the service is running.

## 6. Verify Event Generation

Sysmon records should be available in the following Windows Event Log
channel:

``` text
Microsoft-Windows-Sysmon/Operational
```

To retrieve recent process-creation events (Event ID 1), run:

``` powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 1
} -MaxEvents 10 | Format-List TimeCreated, Id, Message
```

A controlled application launch, such as opening Notepad inside the
Windows lab VM, can be used to generate a process-creation event.

## 7. Configure Wazuh Event Collection

The Wazuh Windows agent configuration file is:

``` text
C:\Program Files (x86)\ossec-agent\ossec.conf
```

The following configuration entry was added inside the existing
`<ossec_config>` element:

``` xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Ensure the entry is not duplicated and that the XML remains well-formed.

Restart the Wazuh agent from elevated PowerShell:

``` powershell
Restart-Service WazuhSvc
```

## 8. Validate End-to-End Collection

Validation was performed at two levels:

1.  **Endpoint validation:** confirm that Sysmon is running and Event ID
    1 records are present in the local Sysmon Operational channel.
2.  **SIEM validation:** confirm that Sysmon event data from `WIN11-01`
    is received by the Wazuh manager and can be inspected in the Wazuh
    platform.

When analysing the results, distinguish between event collection and
alert generation. A collected Sysmon event may not appear in an
alert-only view if it does not match an alerting rule.

## 9. Troubleshooting

If Sysmon events are not visible:

-   Check that the `Sysmon64` service is running.
-   Confirm that the Sysmon Operational channel contains events.
-   Confirm that the Wazuh agent service is running.
-   Check that the `localfile` entry is inside the correct XML root
    element.
-   Check for duplicate or malformed XML entries.
-   Restart the Wazuh agent after correcting the configuration.
-   Review the Wazuh agent log for collection or configuration errors.

## 10. Security and Documentation Notes

Sysmon telemetry can include process names, command-line arguments, file
paths, usernames and other operational details. Review and redact event
data before publishing examples.

The installation described here uses the default Sysmon installation
command. Do not claim that advanced Sysmon filtering or a custom
configuration was deployed unless that configuration was actually
created and tested.

## 11. Outcome

Sysmon was installed on `WIN11-01`, its service was verified as running,
and process-creation events were confirmed in the Sysmon Operational
event channel. Wazuh collection of that event channel was configured
through the Windows agent and Sysmon Event ID 1 telemetry was verified
as reaching the Wazuh manager.
