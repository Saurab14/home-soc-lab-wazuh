# Wazuh Server Deployment and Configuration

## 1. Purpose

This document records the deployment and initial validation of the
central Wazuh server used in the Home SOC Lab. The server provides the
central management and security-event analysis capability for the
monitored endpoints.

## 2. Server Environment

  Item                      Configuration
  ------------------------- -------------------------------------------
  Virtual machine           `SOC01-Ubuntu-Wazuh-Server`
  Operating system          Ubuntu Server 24.04.5 LTS
  Wazuh version             `4.14.10`
  Host-only address         `192.168.56.10/24`
  NAT address               DHCP-assigned; observed as `10.0.2.15/24`
  Virtualisation platform   Oracle VirtualBox
  RAM                       6 GB
  Virtual CPUs              4
  Virtual disk              100 GB, dynamically allocated

The host-only address is the stable address used by lab endpoints to
reach the Wazuh manager. The NAT interface provides outbound
connectivity for package installation and system updates.

## 3. Network Configuration

The virtual machine was configured with two network adapters:

-   **Adapter 1 -- NAT:** provides outbound internet connectivity. The
    Ubuntu interface was observed as `enp0s3`, with DHCP address
    `10.0.2.15/24`.
-   **Adapter 2 -- Host-only:** provides private communication with the
    other lab virtual machines. The Ubuntu interface was observed as
    `enp0s8`, configured with `192.168.56.10/24`.

The host-only interface is the endpoint-facing management and monitoring
path. The NAT address is not used as the fixed Wazuh manager address in
endpoint configurations.

## 4. Wazuh Deployment

Wazuh was deployed as an all-in-one installation on the Ubuntu Server
virtual machine. The installation provides the following principal
components:

  -----------------------------------------------------------------------
  Component                           Responsibility
  ----------------------------------- -----------------------------------
  Wazuh manager                       Receives and analyses endpoint data
                                      and evaluates detection rules

  Wazuh indexer                       Stores and indexes security data
                                      for searching and analysis

  Wazuh dashboard                     Provides the web interface for
                                      agent administration, alert review
                                      and investigation
  -----------------------------------------------------------------------

The installed Wazuh version was verified as `4.14.10`.

> **Reproducibility note:** The original installation command sequence
> and installer output should be added from the lab operator's own
> records if exact command-by-command reproduction is required. This
> document records the verified deployment configuration and service
> checks rather than inventing an installation transcript.

## 5. Administrative Access

The Wazuh dashboard was accessed from the host computer using:

`https://192.168.56.10`

The dashboard uses HTTPS. A browser warning may be displayed because the
local lab deployment uses a self-signed certificate. This is expected in
this lab context; it should not be interpreted as a publicly trusted
certificate.

SSH administration from the Windows host was verified using:

``` bash
ssh socadmin@192.168.56.10
```

The Ubuntu administrative account used for this lab was `socadmin`.
Passwords and other credentials are intentionally excluded from this
repository.

## 6. Service Validation

The following commands can be used on SOC01 to check the service state:

``` bash
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-dashboard
```

The three services were confirmed as active after deployment.

The Wazuh manager log can be inspected with:

``` bash
sudo tail -n 50 /var/ossec/logs/ossec.log
```

The alert JSON log is located at:

``` text
/var/ossec/logs/alerts/alerts.json
```

For example, to review recent alert records:

``` bash
sudo tail -n 20 /var/ossec/logs/alerts/alerts.json
```

These files may contain hostnames, usernames, IP addresses or other
operational details. Do not publish raw production-like logs or
unredacted lab logs.

## 7. Dashboard and Agent Administration

The Wazuh dashboard was used to:

-   Review the status of enrolled agents.
-   Confirm endpoint connectivity.
-   Review security alerts and event details.
-   Access threat-hunting and endpoint-security views.
-   Support investigation and validation activities.

The dashboard is available on the host-only address at
`https://192.168.56.10`.

## 8. Configuration and Data Protection

The following items must not be committed to a public repository:

-   Wazuh administrator passwords or password files.
-   Private keys, certificates containing private key material, or
    authentication tokens.
-   Unredacted logs and archives.
-   Installer bundles containing secrets.
-   Virtual machine disk images.

If configuration examples are published, they must be reviewed and
sanitised first.

## 9. Deployment Outcome

The Ubuntu Server virtual machine successfully hosted the Wazuh
all-in-one platform. The Wazuh manager, indexer and dashboard services
were verified as active, the dashboard was accessible over the host-only
network, and SSH administration from the Windows host was confirmed.

## 10. Operational Notes

Useful paths and commands:

  -------------------------------------------------------------------------------------------------
  Purpose                             Location or command
  ----------------------------------- -------------------------------------------------------------
  Wazuh manager configuration         `/var/ossec/etc/ossec.conf`

  Wazuh manager log                   `/var/ossec/logs/ossec.log`

  Alert JSON log                      `/var/ossec/logs/alerts/alerts.json`

  Custom local rules                  `/var/ossec/etc/rules/local_rules.xml`

  Test rules                          `sudo /var/ossec/bin/wazuh-logtest`

  Validate XML                        `sudo xmllint --noout /var/ossec/etc/rules/local_rules.xml`

  Restart manager                     `sudo systemctl restart wazuh-manager`
  -------------------------------------------------------------------------------------------------
