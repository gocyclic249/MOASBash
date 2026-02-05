#THIS IS IN ALPHA!!! DO NOT USE IN PROD UNTILL VERY WELL TESTED FOR YOUR SYSTEM!!!!!!!!!!!!

# MOAS - System Inventory and Audit Tool (Bash/Linux Version)

A comprehensive Linux system inventory and audit tool. This is a bash port of the original [MOAS PowerShell script](https://github.com/gocyclic249/MOAS), converted for Linux environments.

## Features

- **Basic System Information**: OS details, kernel version, hostname, manufacturer, BIOS info (via dmidecode)
- **Hardware Information**: CPU model/cores/threads, RAM total/available, swap
- **Disk Information**: All mounted filesystems with size, used, and available space
- **Network Adapter Information**: All interfaces with IP addresses, MAC, state, speed, MTU, gateway, DNS
- **Local User Accounts**: Users with UID, GID, groups, home directory, and shell
- **Installed Packages**: Support for apt/dpkg (Debian/Ubuntu), rpm/dnf/yum (RHEL/CentOS/Fedora), pacman (Arch), apk (Alpine)
- **Network Ports/Processes**: Active TCP connections and UDP listeners with process information
- **ICS/SCADA Protocol Detection**: Identifies 60+ industrial control system protocols by port number
- **Event Log Collection**: Configurable days of logs from journalctl or syslog
- **DISA SCC Support**: SCAP Compliance Checker for DISA STIG compliance (air-gapped friendly)
- **OpenSCAP Support**: Alternative compliance scanning with SCAP content

## Requirements

- Bash 4.0 or later
- Root privileges recommended for full functionality

### Optional Dependencies

The script will check for missing tools at startup and show package names and offline download links for your distro.

| Tool | Purpose | Debian/Ubuntu | CentOS/RHEL |
|------|---------|---------------|-------------|
| `ss` | Network port collection (preferred) | `iproute2` | `iproute` |
| `netstat` | Network port collection (alternative) | `net-tools` | `net-tools` |
| `jq` | Enhanced log parsing | `jq` | `jq` |
| `unzip` | SCC bundle extraction | `unzip` | `unzip` |
| `dmidecode` | BIOS/system manufacturer info | `dmidecode` | `dmidecode` |
| `oscap` | OpenSCAP compliance scanning | `libopenscap8` | `openscap-scanner` |

## Installation

```bash
git clone https://github.com/gocyclic249/MOASBash.git
cd MOASBash
chmod +x MOAS.sh
```

## Usage

### Interactive Mode (with prompts)

```bash
sudo ./MOAS.sh
```

### Silent Mode (no prompts)

```bash
sudo ./MOAS.sh --silent
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Display help message and exit |
| `-s, --silent` | Run in silent mode (no prompts) |
| `--scc` | Enable DISA SCC compliance scan |
| `--scc-info` | Show which SCC bundle to download for this system |
| `--scap` | Enable OpenSCAP compliance scan (alternative) |
| `--scap-profile PATH` | Path to SCAP content file (e.g., ssg-*-ds.xml) |
| `--log-days DAYS` | Number of days of logs to collect (1-365, default: 90) |

### Examples

```bash
# Interactive mode
sudo ./MOAS.sh

# Check which SCC bundle to download
./MOAS.sh --scc-info

# Silent mode with DISA SCC scan
sudo ./MOAS.sh --silent --scc

# Silent mode with default settings
sudo ./MOAS.sh --silent

# Silent mode with OpenSCAP scan
sudo ./MOAS.sh --silent --scap --scap-profile /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml

# Silent mode with 30 days of logs
sudo ./MOAS.sh --silent --log-days 30

# Display help
./MOAS.sh --help
```

## DISA SCC Setup (for Air-Gapped Systems)

The DISA SCAP Compliance Checker (SCC) is the official DoD tool for STIG compliance scanning. This script supports SCC for air-gapped environments where systems cannot access the internet.

### Step 1: Determine Required Bundle

Run the following command on your target system to see which SCC bundle you need:

```bash
./MOAS.sh --scc-info
```

This will display the recommended bundle based on your OS and architecture.

### Step 2: Download SCC Bundle

On an internet-connected system, download the appropriate bundle from:

**https://public.cyber.mil/stigs/scap/** (no login required)

Available bundles for Linux:

| OS | Bundle Filename |
|----|-----------------|
| Ubuntu 18-20 (amd64) | `scc-X.X_ubuntu18-20_amd64_bundle.zip` |
| Ubuntu 22+ (amd64) | `scc-X.X_ubuntu22_amd64_bundle.zip` |
| Ubuntu 20/Raspberry Pi (arm64) | `scc-X.X_ubuntu20_raspios*_arm64_bundle.zip` |
| RHEL 7 / SLES 12-15 / Oracle 7 | `scc-X.X_rhel7_sles12-15_oracle-linux7_x86_64_bundle.zip` |
| RHEL 8 / Oracle 8 (x86_64) | `scc-X.X_rhel8_oracle-linux8_x86_64_bundle.zip` |
| RHEL 8 / Oracle 8 (aarch64) | `scc-X.X_rhel8_oracle-linux8_aarch64_bundle.zip` |
| RHEL 9 / Oracle 9 | `scc-X.X_rhel9_oracle-linux9_x86_64_bundle.zip` |

### Step 3: Transfer to Target System

Transfer the ZIP file to your air-gapped target system using approved media (USB drive, CD, etc.).

### Step 4: Place Bundle in Script Directory

Place the SCC bundle ZIP file in the **same directory** as `MOAS.sh`:

```
/path/to/MOASBash/
├── MOAS.sh
├── scc-5.10.2_ubuntu22_amd64_bundle.zip   <-- Place ZIP here
├── README.md
└── LICENSE
```

If the target system doesn't have `unzip`, you can also extract the `.deb` or `.rpm` package from the bundle on another system and place it in the script directory instead.

### Step 5: Run Scan

```bash
sudo ./MOAS.sh --scc
```

The script will automatically:
1. Check if SCC is already installed (PATH and `/opt/scc/`)
2. If not installed, extract the ZIP bundle (if `unzip` is available)
3. Find the `.deb` or `.rpm` package and install it via `dpkg` or `rpm`
4. Enable all SCAP content (`cscc -ea`)
5. Run the SCAP compliance scan
6. Save results to the output directory

**Note:** Once SCC is installed (to `/opt/scc/`), subsequent runs will find it automatically without needing the bundle.

## Output

Creates a timestamped folder in the script directory containing:

| File | Description |
|------|-------------|
| `BasicInfo-*.csv` | System/hardware information (key-value pairs) |
| `LocalUsers-*.csv` | Local user accounts with group memberships |
| `InstalledPackages-*.csv` | Installed software packages |
| `PPS-*.csv` | Network ports, processes, and ICS/SCADA protocol detection |
| `Logs-*.csv` | System log entries |
| `SCC/` | DISA SCC results (if scan was run) |
| `SCAP/` | OpenSCAP results (if scan was run) |

### Output Format

All output files use CSV format with quoted fields, matching the original PowerShell version's output format for compatibility.

## Privilege Requirements

### With Root Privileges (recommended)

- Full BIOS/system information via dmidecode
- All network connections with process information
- Full log access including security-relevant entries
- DISA SCC compliance scanning
- OpenSCAP compliance scanning

### Without Root Privileges

- Basic OS and kernel information
- CPU and memory information
- Disk usage (user-accessible mounts)
- Network interface configuration
- Local user accounts (from /etc/passwd)
- Installed packages
- User-accessible network connections
- Limited log access

## Supported Systems

| Distribution | Versions |
|--------------|----------|
| Ubuntu | 18.04, 20.04, 22.04, 24.04 |
| Debian | 10+ |
| RHEL/CentOS/Rocky/Alma | 7, 8, 9 |
| Oracle Linux | 7, 8, 9 |
| SUSE/SLES | 12, 15 |
| Fedora | 30+ |
| Arch Linux | Current |
| Alpine Linux | Current |

## ICS/SCADA Protocol Detection

The tool detects over 60 industrial control system protocols including:

- Modbus TCP (port 502)
- DNP3 (ports 19999, 20000)
- EtherNet/IP (ports 2222, 44818)
- OPC UA (ports 3480, 4840)
- PROFINET (ports 34962-34964)
- Siemens S7 (port 102)
- BACnet/IP (port 47808)
- HART-IP (ports 5094, 5095)
- And many more...

## Differences from PowerShell Version

| Feature | PowerShell | Bash |
|---------|------------|------|
| GUI Configuration | Yes | No (terminal only) |
| SFC Scan | Yes (Windows) | No (Linux equivalent not applicable) |
| SCAP Tool | SCAP Compliance Checker (cscc.exe) | DISA SCC (cscc) or OpenSCAP (oscap) |
| Package Manager | Win32_Product | dpkg/rpm/pacman/apk |
| Event Logs | Windows Event Log | journalctl/syslog |
| System Info | WMI | /proc, /sys, dmidecode |

## Troubleshooting

### "#!/bin/bash^M: bad interpreter" Error

If you see this error when running the script:

```
bash: ./MOAS.sh: /bin/bash^M: bad interpreter: No such file or directory
```

This means the file has Windows-style line endings (CRLF). Fix it by running:

```bash
sed -i 's/\r$//' MOAS.sh
```

### "Permission denied" Error

Make sure the script is executable:

```bash
chmod +x MOAS.sh
```

Then run with:

```bash
sudo ./MOAS.sh
```

## License

GPL 2.0 - See [LICENSE](LICENSE) file.

## Original Author

Dan B - Original PowerShell MOAS script

## Bash Port

Converted from PowerShell for Linux systems.
