# SOC Lab Architecture and Network Design

## 1. Purpose and Motivation

The purpose of this project was to design, deploy and evaluate a small,
virtualised Security Operations Centre (SOC) environment that provides
practical experience with centralised security monitoring and defensive
security operations.

A SOC relies on collecting security telemetry from systems, analysing
events, identifying potentially suspicious activity and supporting
investigation and response. Building this lab provided a controlled
environment in which to practise these activities across different
operating systems without using production infrastructure.

The lab was developed to bring together a central security monitoring
platform and separate endpoint systems. This design makes it possible to
observe endpoint activity centrally, investigate security events,
validate monitoring configurations and document the results of
controlled tests. It also provides a repeatable environment for further
learning in SIEM operations, endpoint monitoring, detection engineering
and incident investigation.

## 2. Selection of Wazuh

Wazuh was selected as the central security monitoring platform because
it provides an integrated, open-source solution for security event
collection, analysis and endpoint monitoring.

The Wazuh architecture supports a central manager and enrolled endpoint
agents. Agents collect relevant endpoint data and forward it to the
manager, where events can be analysed using decoders and detection
rules. The Wazuh dashboard provides a central interface for reviewing
alerts, monitoring agent status and investigating collected security
information.

Wazuh was suitable for this lab because it supports both Windows and
Linux endpoints and provides capabilities relevant to the project,
including security event analysis, file integrity monitoring and custom
rule development. Its agent-based architecture also allowed the lab to
use a dedicated monitoring server rather than installing the monitoring
platform directly on the everyday host computer.

## 3. VirtualBox Network Architecture

Oracle VirtualBox was used to host the lab's virtual machines. Each
virtual machine was configured with two network adapters to separate
internet connectivity from communication within the lab.

### 3.1 NAT network adapter

The first adapter on each virtual machine was configured in VirtualBox
using Network Address Translation (NAT). This adapter provided outbound
internet connectivity for tasks such as installing operating-system
updates and downloading required packages.

### 3.2 Host-only network adapter

The second adapter was configured as a VirtualBox Host-only network
interface. This created a private network for communication between the
SOC server and the monitored endpoints.

The host-only network used the `192.168.56.0/24` subnet. Static
addresses were assigned to the lab systems so that each endpoint could
consistently communicate with the Wazuh server.

This two-adapter arrangement separated the lab's management and
monitoring traffic from its internet access. NAT was used for outbound
connectivity, while the host-only network was used for communication
between the lab machines. The host-only network is a private virtual
network; it should not be described as a guarantee of complete isolation
from the host operating system.

## 4. Virtual Machine Components and Responsibilities

The environment consisted of three virtual machines, each with a
distinct role.

  ------------------------------------------------------------------------
  Virtual machine  Operating system  Host-only IP address Role
  ---------------- ---------------- --------------------- ----------------
  SOC01            Ubuntu Server          `192.168.56.10` Central Wazuh
                   24.04 LTS                              server

  WIN11-01         Windows 11 Pro         `192.168.56.20` Monitored
                                                          Windows endpoint

  KALI-01          Kali Linux             `192.168.56.30` Monitored Linux
                                                          endpoint
  ------------------------------------------------------------------------

### 4.1 SOC01 -- Wazuh server

SOC01 hosted the central Wazuh platform on Ubuntu Server 24.04 LTS. It
provided the central management and analysis point for the lab.

The Wazuh manager received data from enrolled agents and evaluated
events using the configured decoders and rules. The Wazuh indexer stored
indexed security data, while the Wazuh dashboard provided the web-based
interface used to review agent status, alerts and investigation
information.

SOC01 was assigned the static host-only address `192.168.56.10`.

### 4.2 WIN11-01 -- Windows endpoint

WIN11-01 was the Windows 11 Pro endpoint used to generate and monitor
Windows security activity.

The Wazuh agent was installed on this machine and enrolled with the
central Wazuh manager. Sysmon was also configured to provide additional
Windows telemetry, including process-creation events. The relevant event
channels were configured for collection so that Windows activity could
be forwarded for central analysis.

WIN11-01 was assigned the static host-only address `192.168.56.20`.

### 4.3 KALI-01 -- Linux endpoint

KALI-01 was the Kali Linux endpoint used to represent a Linux system
within the monitoring environment.

The intended monitoring role of this machine was to provide Linux
endpoint telemetry to the central Wazuh platform through the Wazuh
agent. Relevant Linux log sources and endpoint monitoring configurations
could then be used for security-event analysis and controlled
investigation exercises.

KALI-01 was assigned the static host-only address `192.168.56.30`.


## 5. IP Address Allocation

The host-only network used the `192.168.56.0/24` address range. Static
addresses were assigned to the three virtual machines to provide
predictable communication between the Wazuh manager and its endpoints.

  System     Interface purpose     Host-only IP address
  ---------- ------------------- ----------------------
  SOC01      Wazuh server            `192.168.56.10/24`
  WIN11-01   Windows endpoint        `192.168.56.20/24`
  KALI-01    Linux endpoint          `192.168.56.30/24`

The `/24` prefix represents the subnet mask `255.255.255.0`. The
addresses shown in this table refer to the host-only interfaces, not the
NAT interfaces. NAT-assigned addresses may differ between virtual
machines and are not used as the fixed endpoint addresses in this lab
design.

## 6. Endpoint Communication with the Wazuh Server

The Wazuh server acted as the central monitoring destination for the
enrolled endpoints.

The Wazuh agent on each endpoint was configured with the manager's
host-only address, `192.168.56.10`. Because the endpoints and server
shared the same host-only subnet, they could communicate directly over
the virtual network without relying on their NAT addresses.

The communication workflow was as follows:

1.  Security-relevant activity occurred on a monitored endpoint, such as
    a Windows event or Linux system log event.
2.  The endpoint's Wazuh agent collected the configured event or
    monitoring data.
3.  The agent communicated with the Wazuh manager at `192.168.56.10`
    over the host-only network.
4.  The manager processed incoming data using its analysis components,
    including decoders and rules.
5.  Events that matched alerting rules were made available for review in
    the Wazuh platform.
6.  The analyst used the Wazuh dashboard to review agent status, examine
    alerts and investigate the activity.

For a standard Wazuh agent deployment, TCP port `1514` is commonly used
for agent communication and TCP port `1515` for agent enrolment. The
actual ports and protocols should be confirmed against the lab's Wazuh
configuration before treating these as verified settings.

## 7. Architecture Summary

The lab used a centralised monitoring design in which SOC01 provided the
Wazuh management and analysis services, while WIN11-01 and KALI-01
represented monitored endpoint systems.

VirtualBox NAT adapters provided outbound internet connectivity for
system maintenance and package installation. Host-only adapters provided
the private network path used for communication between the endpoints
and the Wazuh server.

This architecture provided a practical environment for learning how
endpoint telemetry is collected and analysed centrally. It also
established a foundation for controlled security testing, alert
investigation, detection-rule validation and documentation of defensive
security operations.
