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
- **OpenSCAP Support**: Optional compliance scanning with SCAP content

## Requirements

- Bash 4.0 or later
- Root privileges recommended for full functionality
- Common Linux utilities: `ip`, `ss` or `netstat`, `df`, `bc`, `jq` (for log parsing)

### Optional Dependencies

- `dmidecode` - For detailed BIOS/system manufacturer information
- `oscap` - For OpenSCAP compliance scanning

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
| `--scap` | Enable OpenSCAP compliance scan |
| `--scap-profile PATH` | Path to SCAP content file (e.g., ssg-*-ds.xml) |
| `--log-days DAYS` | Number of days of logs to collect (1-365, default: 90) |

### Examples

```bash
# Interactive mode
sudo ./MOAS.sh

# Silent mode with default settings
sudo ./MOAS.sh --silent

# Silent mode with OpenSCAP scan
sudo ./MOAS.sh --silent --scap --scap-profile /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml

# Silent mode with 30 days of logs
sudo ./MOAS.sh --silent --log-days 30

# Display help
./MOAS.sh --help
```

## Output

Creates a timestamped folder in the script directory containing:

| File | Description |
|------|-------------|
| `BasicInfo-*.csv` | System/hardware information (key-value pairs) |
| `LocalUsers-*.csv` | Local user accounts with group memberships |
| `InstalledPackages-*.csv` | Installed software packages |
| `PPS-*.csv` | Network ports, processes, and ICS/SCADA protocol detection |
| `Logs-*.csv` | System log entries |
| `SCAP/` | OpenSCAP results (if scan was run) |

### Output Format

All output files use CSV format with quoted fields, matching the original PowerShell version's output format for compatibility.

## Privilege Requirements

### With Root Privileges (recommended)

- Full BIOS/system information via dmidecode
- All network connections with process information
- Full log access including security-relevant entries
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

- Ubuntu 20.04+
- Debian 10+
- RHEL/CentOS/Rocky Linux 7+
- Fedora 30+
- Arch Linux
- Alpine Linux

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
| SCAP Tool | SCAP Compliance Checker (cscc.exe) | OpenSCAP (oscap) |
| Package Manager | Win32_Product | dpkg/rpm/pacman/apk |
| Event Logs | Windows Event Log | journalctl/syslog |
| System Info | WMI | /proc, /sys, dmidecode |

## License

GPL 2.0 - See [LICENSE](LICENSE) file.

## Original Author

Dan B - Original PowerShell MOAS script

## Bash Port

Converted from PowerShell for Linux systems.
