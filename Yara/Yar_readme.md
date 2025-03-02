# YARA Signatures for Malware Detection

This repository contains YARA signatures for detecting various malware strains, including Akira and LockBit, which were specified in the PNB Cybersecurity Hackathon problem statement. The signatures are organized in the `malware_yara/` directory, with an index file `malware_index3.yar` that includes all individual signature files.

## Repository Structure

```
- malware_index3.yar  # Master index file including all YARA rules
- malware_yara/        # Directory containing 84 malware YARA signature files
```

### Example Entry in `malware_index3.yar`

```yara
include "/media/sf_ubuntu_vm_shared/malware_yara/ATM.Malware.Ploutus-I.yar"
```

## Running YARA Signatures on Ubuntu/Linux

### 1. Install YARA

Ensure that YARA is installed on your system. You can install it using the following command:

```sh
sudo apt update && sudo apt install yara -y
```

### 2. Clone This Repository

```sh
git clone <your-github-repo-url>
cd <your-repo-folder>
```

### 3. Run YARA on a File or Directory

To scan a file:

```sh
yara -r malware_index3.yar /path/to/suspicious/file
```

To scan an entire directory:

```sh
yara -r malware_index3.yar /path/to/suspicious/directory
```

### 4. Running YARA in Live Process Scanning

To scan running processes:

```sh
yara -p malware_index3.yar
```

## Running YARA on Windows

The same YARA rules can be used on Windows, but the setup process differs slightly.

### 1. Install YARA on Windows

Download the latest Windows YARA binaries from: [https://github.com/VirusTotal/yara/releases](https://github.com/VirusTotal/yara/releases)

Extract the YARA binaries and add them to the system's environment path.

### 2. Running YARA on Windows

Navigate to the directory where YARA is installed and run the following command:

```powershell
yara64.exe -r malware_index3.yar C:\path\to\scan
```

To scan running processes on Windows:

```powershell
yara64.exe -p malware_index3.yar
```

## Notes

- Modify paths in `malware_index3.yar` if necessary to reflect your actual file locations.
- Ensure that you have the required permissions to scan certain directories or processes.
- Regularly update the YARA signatures to stay ahead of emerging malware threats.

