# wazuh-virustotal-activeresponse

# Wazuh Malware Detection and Auto-Removal Guide

This guide provides step-by-step instructions for configuring Wazuh to detect and automatically remove malicious files. The setup includes File Integrity Monitoring (FIM), VirusTotal integration for threat detection, and an Active Response script to automatically remove threats.

## Architecture Overview

This solution consists of:
- Wazuh agent configured for real-time directory monitoring
- VirusTotal integration to scan suspicious files
- Custom active response script to remove malicious files
- Custom rules to trigger alerts and responses

## Prerequisites

- Wazuh server and agent properly installed and communicating
- VirusTotal API key (free or premium)
- Root/administrative access to both Wazuh server and agent systems

## 1. Wazuh Agent Configuration

### 1.1 Enable File Integrity Monitoring (FIM)

First, locate and modify the `<syscheck>` block in the Wazuh agent configuration:

```bash
sudo vi /var/ossec/etc/ossec.conf
```

Ensure that FIM is enabled by setting:

```xml
<syscheck>
  <disabled>no</disabled>
  <!-- other syscheck configurations -->
</syscheck>
```

### 1.2 Configure Real-time Monitoring

Add the following line within the `<syscheck>` block to monitor the `/root` directory in real-time:

```xml
<directories realtime="yes">/root</directories>
```

### 1.3 Install Required Utilities

The active response script requires `jq` to process JSON:

```bash
# For Debian/Ubuntu
sudo apt update
sudo apt -y install jq

# For CentOS/RHEL
sudo yum install -y jq
```

### 1.4 Create the Active Response Script

Create a file at `/var/ossec/active-response/bin/remove-threat.sh`:

```bash
sudo vi /var/ossec/active-response/bin/remove-threat.sh
```

Add the following content:

```bash
#!/bin/bash
LOCAL=`dirname $0`;
cd $LOCAL
cd ../
PWD=`pwd`
read INPUT_JSON
FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.data.virustotal.source.file)
COMMAND=$(echo $INPUT_JSON | jq -r .command)
LOG_FILE="${PWD}/../logs/active-responses.log"
#------------------------ Analyze command -------------------------#
if [ ${COMMAND} = "add" ]
then
 # Send control message to execd
 printf '{"version":1,"origin":{"name":"remove-threat","module":"active-response"},"command":"check_keys", "parameters":{"keys":[]}}\n'
 read RESPONSE
 COMMAND2=$(echo $RESPONSE | jq -r .command)
 if [ ${COMMAND2} != "continue" ]
 then
  echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Remove threat active response aborted" >> ${LOG_FILE}
  exit 0;
 fi
fi
# Removing file
rm -f $FILENAME
if [ $? -eq 0 ]; then
 echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Successfully removed threat" >> ${LOG_FILE}
else
 echo "`date '+%Y/%m/%d %H:%M:%S'` $0: $INPUT_JSON Error removing threat" >> ${LOG_FILE}
fi
exit 0;
```

### 1.5 Set Proper Permissions

Configure proper ownership and permissions for the active response script:

```bash
sudo chmod 750 /var/ossec/active-response/bin/remove-threat.sh
sudo chown root:wazuh /var/ossec/active-response/bin/remove-threat.sh
```

### 1.6 Restart Wazuh Agent

Apply the changes by restarting the Wazuh agent:

```bash
sudo systemctl restart wazuh-agent
```

## 2. Wazuh Server Configuration

### 2.1 Create Custom FIM Alert Rules

Create or edit the local rules file:

```bash
sudo vi /var/ossec/etc/rules/local_rules.xml
```

Add the following FIM rules that will trigger on `/root` directory modifications:

```xml
<group name="syscheck,pci_dss_11.5,nist_800_53_SI.7,">
    <!-- Rules for Linux systems -->
    <rule id="100200" level="7">
        <if_sid>550</if_sid>
        <field name="file">/root</field>
        <description>File modified in /root directory.</description>
    </rule>
    <rule id="100201" level="7">
        <if_sid>554</if_sid>
        <field name="file">/root</field>
        <description>File added to /root directory.</description>
    </rule>
</group>
```

### 2.2 Configure VirusTotal Integration

Edit the Wazuh server configuration file:

```bash
sudo vi /var/ossec/etc/ossec.conf
```

Add the following VirusTotal integration block:

```xml
<ossec_config>
  <integration>
    <name>virustotal</name>
    <api_key>YOUR_VIRUS_TOTAL_API_KEY</api_key> <!-- Replace with your actual VirusTotal API key -->
    <rule_id>100200,100201</rule_id>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
```

> **Important**: Replace `YOUR_VIRUS_TOTAL_API_KEY` with your actual VirusTotal API key.

### 2.3 Configure Active Response Command

Add the following Active Response configuration to the Wazuh server configuration file:

```xml
<ossec_config>
  <command>
    <name>remove-threat</name>
    <executable>remove-threat.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>
  <active-response>
    <disabled>no</disabled>
    <command>remove-threat</command>
    <location>local</location>
    <rules_id>87105</rules_id>
  </active-response>
</ossec_config>
```

> **Note**: Rule 87105 is a predefined Wazuh rule that triggers when VirusTotal detects a malicious file.

### 2.4 Add Active Response Alert Rules

Add the following rules to the local rules file to alert on Active Response actions:

```xml
<group name="virustotal,">
  <rule id="100092" level="12">
    <if_sid>657</if_sid>
    <match>Successfully removed threat</match>
    <description>$(parameters.program) removed threat located at $(parameters.alert.data.virustotal.source.file)</description>
  </rule>
  <rule id="100093" level="12">
    <if_sid>657</if_sid>
    <match>Error removing threat</match>
    <description>Error removing threat located at $(parameters.alert.data.virustotal.source.file)</description>
  </rule>
</group>
```

### 2.5 Restart Wazuh Manager

Apply the changes by restarting the Wazuh manager:

```bash
sudo systemctl restart wazuh-manager
```

## 3. Testing the Setup

### 3.1 Download an EICAR Test File

To test the configuration, download an EICAR test file to the monitored directory on the endpoint:

```bash
sudo curl -Lo /root/eicar.com https://secure.eicar.org/eicar.com 
sudo ls -lah /root/eicar.com
```

### 3.2 Verify Process Flow

When successful, the following sequence should occur:

1. File is created in `/root`
2. Wazuh FIM detects the new file (rule 100201)
3. VirusTotal integration scans the file hash
4. VirusTotal detects the EICAR file as malicious (rule 87105)
5. Active Response is triggered
6. The `remove-threat.sh` script removes the file
7. A success alert is generated (rule 100092)

### 3.3 Monitoring Alert Flow

Check the Wazuh logs for the alert flow:

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.log | grep -E "100201|87105|100092"
```

## 4. Viewing Alerts in Wazuh Dashboard

To visualize the alerts in the Wazuh dashboard:

1. Navigate to the Wazuh dashboard
2. Go to the **Threat Hunting** module
3. Add the following filter in the search bar:
   ```
   rule.id: is one of 553,100092,87105,100201
   ```

## 5. Expanding the Configuration

### 5.1 Monitor Additional Directories

To monitor additional directories, add more `<directories>` entries in the `<syscheck>` block:

```xml
<directories realtime="yes" check_all="yes">/etc</directories>
<directories realtime="yes" check_all="yes">/var/www/html</directories>
<directories realtime="yes" check_all="yes">/opt/important_data</directories>
```

### 5.2 Adjust Alert Thresholds

You can modify rule levels based on the severity you want to assign:

- Level 1-4: Low severity
- Level 5-8: Medium severity 
- Level 9-12: High severity
- Level 13-16: Critical severity

## 6. Troubleshooting

### 6.1 Check File Permissions

Ensure the active response script has correct permissions:

```bash
ls -la /var/ossec/active-response/bin/remove-threat.sh
```

### 6.2 Verify VirusTotal API Key

Test your VirusTotal API key:

```bash
curl --request GET \
  --url 'https://www.virustotal.com/api/v3/ip_addresses/1.1.1.1' \
  --header 'x-apikey: YOUR_API_KEY'
```

### 6.3 Check Logs for Errors

Monitor Wazuh logs for potential issues:

```bash
sudo tail -f /var/ossec/logs/ossec.log
sudo tail -f /var/ossec/logs/active-responses.log
```

### 6.4 Verify Rule Triggering

Check if custom rules are being triggered:

```bash
sudo grep -i "100200\|100201" /var/ossec/logs/alerts/alerts.log
```

---

This setup provides a comprehensive approach to automatically detect and remove malicious files using Wazuh's File Integrity Monitoring, VirusTotal integration, and Active Response capabilities.
