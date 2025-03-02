# CAPEv2 Installation and Configuration Guide

This guide provides step-by-step instructions for setting up CAPEv2 on an Ubuntu system, along with configuring Windows 10 as a victim sandbox for malware analysis.

---

## 1. Prepare Requirements

### **Nested Virtualization**
CAPEv2 requires a nested virtualization architecture where a hypervisor runs a virtual machine that also acts as a hypervisor. Below are the specifications used:

### **Host Machine Specifications**
Ensure your system meets these minimum requirements:
- **OS:** Ubuntu 22.04.5
- **CPU:** Intel or AMD with virtualization support (VT-x/AMD-V)
- **RAM:** 16GB+ recommended
- **Disk Space:** 100GB+
- **Network:** Internet connection

### **Virtual Machine (VM) Specifications (CAPEv2 Host)**
- **OS:** Ubuntu 22.04.5 (Same as host OS)
- **RAM:** 8GB+
- **Disk:** 80GB+
- **Network:** Bridged or NAT

---

## 2. Clone CAPEv2 Repository

After setting up the virtualized environment, clone the CAPEv2 repository:
```bash
sudo apt-get install git -y
git clone https://github.com/kevoreilly/CAPEv2.git
```

---

## 3. Modify the KVM Installer

Navigate to the CAPEv2 installer directory:
```bash
cd CAPEv2/installer
ls -lh
```
Modify the `kvm-qemu.sh` script by replacing the `<WOOT>` string with the correct DSDT code. You can obtain the DSDT code in three ways:

### **Option 1: Using `acpidump` Tool**
```bash
sudo apt install acpica-tools -y
sudo acpidump > acpidump.out
sudo acpixtract -a acpidump.out
sudo iasl -d dsdt.dat
```

### **Option 2: Using `Hardware ID` String**
```bash
cat dsdt.dsl | grep "Hardware ID"
```

### **Option 3: Referencing an Open-Source Database**
Visit: [linuxhw/ACPI](https://github.com/linuxhw/ACPI)

Replace `<WOOT>` with the obtained DSDT string.

---

## 4. Execute the KVM Installer

Run the following commands to install KVM and its dependencies:
```bash
sudo chmod a+x kvm-qemu.sh
sudo ./kvm-qemu.sh all cape 2>&1 | tee kvm-qemu.log
sudo ./kvm-qemu.sh virtmanager cape 2>&1 | tee kvm-qemu-virtmanager.log
```
Reboot the system after installation:
```bash
sudo reboot
```
Verify that the `virbr0` network interface is present:
```bash
ifconfig
```

---

## 5. Execute the CAPEv2 Installer (Sandbox System)

Modify `cape2.sh` with the following values:
- `NETWORK_IFACE`: `virbr0`
- `IFACE_IP`: `192.168.122.1`
- `PASSWD`: Set a password for the CAPEv2 database

Run the installation:
```bash
sudo chmod a+x cape2.sh
sudo ./cape2.sh base 2>&1 | tee cape2-base.log
```
Reboot after installation:
```bash
sudo reboot
```
Ensure the following services are running:
```bash
sudo systemctl status cape.service
sudo systemctl status cape-processor.service
sudo systemctl status cape-rooter.service
sudo systemctl status cape-web.service
```

---

## 6. Configure PostgreSQL Database

Ensure PostgreSQL is correctly configured:
```bash
sudo -u postgres psql
\list
```
If necessary, alter the database owner:
```bash
ALTER DATABASE cape OWNER TO cape;
\q
```

---

## 7. Install Optional Features

Install additional dependencies:
```bash
cd /opt/CAPEv2
poetry run pip3 install -r extra/optional_dependencies.txt
```
If missing dependencies occur:
```bash
sudo apt-get install graphviz graphviz-dev
poetry run pip3 install chepy
sudo systemctl restart cape*
```

---

## 8. Setting Up Windows 10 as a Victim Machine

### **8.1. Create a Windows 10 VM**
- Install **Windows 10 (x64)** as a virtual machine in KVM/QEMU.
- Allocate **at least 2 CPUs, 4GB RAM, and 40GB disk**.
- Use **virbr0** as the network interface.
- Disable **Windows Defender, Firewall, and Windows Updates**.

### **8.2. Install Required Dependencies**
1. **Enable Remote Desktop Protocol (RDP)**
   ```powershell
   Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0
   Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
   ```
2. **Install Python and CAPEv2 Agent**
   - Download and install [Python 3.7+](https://www.python.org/downloads/)
   - Clone the CAPEv2 agent repository:
     ```powershell
     git clone https://github.com/kevoreilly/CAPEv2-agent.git
     ```
   - Run the agent script:
     ```powershell
     python agent.py
     ```
3. **Disable User Account Control (UAC)**
   ```powershell
   reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
   ```

### **8.3. Configure the Windows VM for CAPEv2**
- Set a static IP (`192.168.122.10`)
- Set the CAPEv2 host (`192.168.122.1`) as the DNS server
- Configure the CAPEv2 web interface to recognize the Windows 10 VM
- Restart the Windows VM and ensure the CAPEv2 agent is running

---

## 9. Testing the Setup

To verify the setup:
```bash
curl http://192.168.122.1:8000/tasks/create/file/
```
If successful, you should see a response from CAPEv2.

To submit a malware sample for analysis:
```bash
curl -F "file=@malware.exe" http://192.168.122.1:8000/tasks/create/file/
```

---

## 10. Accessing the CAPEv2 Web Interface

After setup, you can access CAPEv2's web interface by navigating to:
```
http://192.168.122.1:8000
```

---

