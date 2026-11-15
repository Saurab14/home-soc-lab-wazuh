# Kali Linux Endpoint Preparation and Wazuh Agent Deployment

## 1. Purpose

This document describes the Kali Linux endpoint's intended role in the
Home SOC Lab and provides the deployment procedure for integrating it
with the central Wazuh manager.

**Deployment status must be confirmed before this document is presented
as a completed integration.** The lab records establish the Kali VM's
network interface details and the intended hostname and host-only
address. They do not, by themselves, establish that the Wazuh agent
installation and registration were completed successfully.

## 2. Endpoint Environment

  Item                      Intended configuration
  ------------------------- ------------------------
  Virtual machine           Kali Linux
  Hostname                  `KALI-01`
  Host-only address         `192.168.56.30/24`
  Wazuh manager             `192.168.56.10`
  Agent name                `KALI-01`
  Agent group               `default`
  Virtualisation platform   Oracle VirtualBox

The Kali VM uses two network adapters:

-   `eth0` -- NAT interface for outbound connectivity. The observed
    address was `10.0.2.15/24`.
-   `eth1` -- Host-only interface for communication with the SOC lab.
    The initially observed address was `192.168.56.104/24`; the intended
    static address is `192.168.56.30/24`.

## 3. Set the Hostname

To set the Linux hostname:

``` bash
sudo hostnamectl set-hostname KALI-01
```

Review `/etc/hosts` and ensure the local hostname mapping is
appropriate. For example:

``` text
127.0.1.1    KALI-01
```

Verify:

``` bash
hostnamectl
hostname
```

The hostname should report `KALI-01`.

## 4. Configure the Host-only Address

The observed NetworkManager connection for `eth1` was
`Wired connection 2`. Confirm the connection name on the VM before
applying changes:

``` bash
nmcli connection show
nmcli device status
ip -br addr
```

If the connection name is still `Wired connection 2`, configure its IPv4
address:

``` bash
sudo nmcli connection modify "Wired connection 2" \
  ipv4.method manual \
  ipv4.addresses 192.168.56.30/24 \
  ipv4.gateway "" \
  ipv4.dns "" \
  ipv6.method disabled
```

Activate the connection:

``` bash
sudo nmcli connection up "Wired connection 2"
```

Verify:

``` bash
ip -br addr
```

Expected interface addressing:

-   `eth0`: NAT address, typically DHCP-assigned.
-   `eth1`: `192.168.56.30/24`.

Test connectivity to SOC01:

``` bash
ping -c 4 192.168.56.10
```

Successful replies confirm basic IP connectivity between Kali and the
Wazuh server. They do not alone prove that the Wazuh agent is installed
or enrolled.

## 5. Prepare the Wazuh Package Repository

The following commands prepare the official Wazuh APT repository on
Kali:

``` bash
sudo apt update
sudo apt install curl gnupg apt-transport-https -y
```

Import the Wazuh signing key:

``` bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
  sudo gpg --no-default-keyring \
  --keyring /usr/share/keyrings/wazuh.gpg --import
```

Set key permissions:

``` bash
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
```

Add the Wazuh 4.x repository:

``` bash
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | \
  sudo tee /etc/apt/sources.list.d/wazuh.list
```

Refresh package metadata:

``` bash
sudo apt update
```

Check the available agent package version:

``` bash
apt-cache policy wazuh-agent
```

The Wazuh manager in this lab was version `4.14.10`. Select a compatible
agent version and avoid installing an agent version newer than the
manager. Confirm package availability in the repository before
specifying a version.

## 6. Install and Enrol the Agent

Use the Wazuh dashboard's **Deploy new agent** instructions or the
official Wazuh agent installation documentation for the selected Linux
package and version.

The intended deployment values are:

  Parameter         Value
  ----------------- -----------------
  Manager address   `192.168.56.10`
  Agent name        `KALI-01`
  Agent group       `default`

The agent must be installed, configured with the manager address,
enrolled with the manager and started. Do not mark this procedure
complete until the service is running and the agent is shown as active
in the Wazuh dashboard.

## 7. Start and Verify the Agent

After installation and configuration, enable and start the service:

``` bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

Check service status:

``` bash
sudo systemctl status wazuh-agent
```

Inspect the agent configuration for the manager address:

``` bash
grep -n -E '<address>|<port>' /var/ossec/etc/ossec.conf
```

Review recent agent log entries:

``` bash
sudo tail -n 50 /var/ossec/logs/ossec.log
```

On SOC01, verify that the agent appears in the Wazuh agent inventory
with the expected name and an `Active` status. Record the actual agent
ID and version in this document after verification.

## 8. Optional Linux Log Collection

Before configuring additional log sources, check which files exist on
the Kali VM:

``` bash
ls -l /var/log/auth.log /var/log/syslog
```

If the required log files are not present, identify and configure the
appropriate logging service and source before adding Wazuh collection
entries.

For systems where these files are present, the following entries are
examples to add inside the existing `<ossec_config>` element in
`/var/ossec/etc/ossec.conf`:

``` xml
<localfile>
  <location>/var/log/auth.log</location>
  <log_format>syslog</log_format>
</localfile>

<localfile>
  <location>/var/log/syslog</location>
  <log_format>syslog</log_format>
</localfile>
```

Do not add duplicate entries. Back up the configuration before editing,
validate the XML and restart the agent after making changes:

``` bash
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.backup
sudo systemctl restart wazuh-agent
```

## 9. Troubleshooting

If the agent does not become active:

1.  Confirm the host-only interface has `192.168.56.30/24`.
2.  Confirm Kali can reach `192.168.56.10`.
3.  Confirm the Wazuh manager is running.
4.  Confirm the manager address in `/var/ossec/etc/ossec.conf`.
5.  Check the agent service with `systemctl status wazuh-agent`.
6.  Review `/var/ossec/logs/ossec.log` for connection or enrolment
    errors.
7.  Confirm the installed agent version is compatible with the manager.
8.  Check that the required communication ports are allowed by the lab
    configuration.

## 10. Completion Criteria

Kali integration should be described as complete only after all
applicable checks pass:

-   Hostname is `KALI-01`.
-   Host-only address is `192.168.56.30/24`.
-   Kali can reach SOC01 at `192.168.56.10`.
-   Wazuh agent package is installed.
-   Agent is configured to communicate with the correct manager.
-   Agent service is running.
-   Agent is enrolled and appears as `Active` in the Wazuh dashboard.
-   Expected Linux log sources are configured and verified, if log
    collection is claimed.

Record the actual completion date, agent ID, agent version and test
evidence after performing these checks.

## 11. Security Considerations

Use Kali only within the authorised lab environment for the documented
exercises. Do not publish credentials, enrolment keys, private keys or
unredacted logs. Review all configuration examples before making the
repository public.
