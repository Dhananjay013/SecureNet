# Snort Installation and Configuration Guide

This repository provides a setup guide to install and configure Snort for live monitoring. The repository contains four Snort rule files that need to be added to the Snort rules directory and enabled for proper malware detection.

## Repository Structure

```
- rules/
  - malware-backdoor.rules
  - malware-cnc.rules
  - malware-other.rules
  - malware-tool.rules
```

## Installing Snort on Ubuntu/Linux

### 1. Update System and Install Dependencies

```sh
sudo apt update && sudo apt upgrade -y
sudo apt install -y snort
```

### 2. Verify Snort Installation

```sh
snort -V
```

### 3. Download and Install Community Rules

```sh
sudo wget https://www.snort.org/downloads/community/snort3-community-rules.tar.gz
sudo tar -xvzf snort3-community-rules.tar.gz -C /etc/snort/rules
```

Include these rules in `snort.conf`:

```sh
include $RULE_PATH/community.rules
```

### 4. Configure Snort Rules

Move the provided Snort rule files into the Snort rules directory:

```sh
sudo mv rules/<*>.rules /etc/snort/rules/
```

### 5. Modify Snort Configuration File

Edit the Snort configuration file to change the `HOME_NET` variable:

```sh
sudo nano /etc/snort/snort.conf
```

Find the following line:

```sh
var HOME_NET any
```

Change it to:

```sh
var HOME_NET <LOCAL_USER_ADDRESS>
```

Replace `<LOCAL_USER_ADDRESS>` with your actual local network address.

### 6. Enable Custom Rules

Edit the Snort configuration file to include the custom rule files:

```sh
sudo nano /etc/snort/snort.conf
```

Uncomment or add the following lines under the rules section:

```sh
include $RULE_PATH/malware-backdoor.rules
include $RULE_PATH/malware-cnc.rules
include $RULE_PATH/malware-other.rules
include $RULE_PATH/malware-tool.rules
```

Save and exit the file.

### 7. Test Snort Configuration

```sh
sudo snort -T -c /etc/snort/snort.conf
```

### 8. Run Snort for Live Network Monitoring

```sh
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
```

Replace `eth0` with the appropriate network interface name (use `ip a` to check your interfaces).

## Notes

- Ensure Snort is running with proper permissions.
- Modify rule files if needed for better customization.
- Regularly update Snort and the rules to stay protected against new threats.

This guide helps in setting up Snort with custom rules for detecting malware-related activities in live network traffic.

