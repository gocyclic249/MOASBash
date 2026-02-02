#!/bin/bash
#
# MOAS - System Inventory and Audit Tool (Bash/Linux Version)
# This is a Linux port of MOAS.ps1 (PowerShell version)
# Original Author: Dan B
# Bash Port: Converted from PowerShell for Linux systems
# Released under GPL 2.0 License
#
# Change Log (Bash Version):
# V1.0 Initial Linux port - terminal only, no GUI
#      - Basic system information (OS, BIOS, CPU, RAM)
#      - Disk and network adapter information
#      - Local user accounts with group memberships
#      - Installed packages (supports apt, dnf, yum, pacman)
#      - Active network connections with ICS/SCADA protocol detection
#      - System logs via journalctl
#      - OpenSCAP support
#      - Summary report
# V1.1 Added DISA SCC (SCAP Compliance Checker) support
#      - Auto-detects OS and recommends correct SCC bundle
#      - Extracts and runs SCC from bundle in script directory
#      - Designed for air-gapped systems (manual file transfer)
#
# Known Working Systems:
# Ubuntu 20.04+, Debian 10+
# RHEL/CentOS/Rocky 7+
# Fedora 30+
# Arch Linux
#

#region Color Definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color
#endregion

#region Default Parameters
SHOW_HELP=false
SILENT=false
RUN_SCAP=false
RUN_SCC=false
SCAP_PROFILE=""
LOG_DAYS=90
#endregion

#region Version
VERSION="1.1"
#endregion

#region Helper Functions
print_green() {
    echo -e "${GREEN}$1${NC}"
}

print_yellow() {
    echo -e "${YELLOW}$1${NC}"
}

print_red() {
    echo -e "${RED}$1${NC}"
}

print_cyan() {
    echo -e "${CYAN}$1${NC}"
}

print_white() {
    echo -e "${WHITE}$1${NC}"
}

print_gray() {
    echo -e "${GRAY}$1${NC}"
}

# Function to write CSV header
write_csv_header() {
    local file="$1"
    shift
    local IFS=','
    echo "\"$*\"" | sed 's/,/","/g' > "$file"
}

# Function to append CSV row
append_csv_row() {
    local file="$1"
    shift
    local row=""
    for field in "$@"; do
        # Escape double quotes and wrap in quotes
        field="${field//\"/\"\"}"
        row="${row}\"${field}\","
    done
    # Remove trailing comma
    echo "${row%,}" >> "$file"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to get value or "N/A"
get_value_or_na() {
    local value="$1"
    if [ -z "$value" ]; then
        echo "N/A"
    else
        echo "$value"
    fi
}

# Function to detect OS and recommend SCC bundle
# Returns: recommended SCC bundle filename pattern
get_scc_bundle_info() {
    local os_id=""
    local os_version_id=""
    local arch=$(uname -m)

    # Read OS information
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        os_id="$ID"
        os_version_id="$VERSION_ID"
    fi

    # Map architecture
    local scc_arch=""
    case "$arch" in
        x86_64)  scc_arch="x86_64" ;;
        aarch64) scc_arch="aarch64" ;;
        armv7l)  scc_arch="armv7l" ;;
        amd64)   scc_arch="amd64" ;;
        *)       scc_arch="$arch" ;;
    esac

    # Determine bundle based on OS
    local bundle_pattern=""
    local bundle_name=""
    local download_url="https://public.cyber.mil/stigs/scap/"

    case "$os_id" in
        ubuntu)
            case "${os_version_id%%.*}" in
                18|19|20)
                    if [ "$scc_arch" = "aarch64" ] || [ "$scc_arch" = "arm64" ]; then
                        bundle_name="scc-*_ubuntu20_raspios*_arm64_bundle.zip"
                        bundle_pattern="Ubuntu 20/Raspberry Pi OS ARM64"
                    else
                        bundle_name="scc-*_ubuntu18-20_amd64_bundle.zip"
                        bundle_pattern="Ubuntu 18-20 AMD64"
                    fi
                    ;;
                21|22|23|24)
                    bundle_name="scc-*_ubuntu22_amd64_bundle.zip"
                    bundle_pattern="Ubuntu 22+ AMD64"
                    ;;
                *)
                    bundle_name="scc-*_ubuntu22_amd64_bundle.zip"
                    bundle_pattern="Ubuntu (latest available)"
                    ;;
            esac
            ;;
        debian)
            # Debian uses Ubuntu packages
            bundle_name="scc-*_ubuntu22_amd64_bundle.zip"
            bundle_pattern="Ubuntu 22 AMD64 (Debian compatible)"
            ;;
        rhel|centos|rocky|almalinux)
            case "${os_version_id%%.*}" in
                7)
                    bundle_name="scc-*_rhel7_sles12-15_oracle-linux7_x86_64_bundle.zip"
                    bundle_pattern="RHEL 7 / SLES 12-15 / Oracle Linux 7 x86_64"
                    ;;
                8)
                    if [ "$scc_arch" = "aarch64" ]; then
                        bundle_name="scc-*_rhel8_oracle-linux8_aarch64_bundle.zip"
                        bundle_pattern="RHEL 8 / Oracle Linux 8 AARCH64"
                    else
                        bundle_name="scc-*_rhel8_oracle-linux8_x86_64_bundle.zip"
                        bundle_pattern="RHEL 8 / Oracle Linux 8 x86_64"
                    fi
                    ;;
                9|10)
                    bundle_name="scc-*_rhel9_oracle-linux9_x86_64_bundle.zip"
                    bundle_pattern="RHEL 9 / Oracle Linux 9 x86_64"
                    ;;
                *)
                    bundle_name="scc-*_rhel9_oracle-linux9_x86_64_bundle.zip"
                    bundle_pattern="RHEL (latest available)"
                    ;;
            esac
            ;;
        fedora)
            # Fedora uses RHEL packages - match to closest RHEL version
            bundle_name="scc-*_rhel9_oracle-linux9_x86_64_bundle.zip"
            bundle_pattern="RHEL 9 x86_64 (Fedora compatible)"
            ;;
        ol|oracle)
            case "${os_version_id%%.*}" in
                7)
                    bundle_name="scc-*_rhel7_sles12-15_oracle-linux7_x86_64_bundle.zip"
                    bundle_pattern="Oracle Linux 7 x86_64"
                    ;;
                8)
                    bundle_name="scc-*_rhel8_oracle-linux8_x86_64_bundle.zip"
                    bundle_pattern="Oracle Linux 8 x86_64"
                    ;;
                *)
                    bundle_name="scc-*_rhel9_oracle-linux9_x86_64_bundle.zip"
                    bundle_pattern="Oracle Linux 9 x86_64"
                    ;;
            esac
            ;;
        sles|opensuse*)
            bundle_name="scc-*_rhel7_sles12-15_oracle-linux7_x86_64_bundle.zip"
            bundle_pattern="SLES 12-15 x86_64"
            ;;
        *)
            bundle_name="UNKNOWN"
            bundle_pattern="Unknown OS - please check cyber.mil for compatible bundle"
            ;;
    esac

    # Return as a formatted string (bundle_name|bundle_pattern|download_url)
    echo "${bundle_name}|${bundle_pattern}|${download_url}"
}

# Function to display SCC requirements
show_scc_requirements() {
    local info=$(get_scc_bundle_info)
    local bundle_name=$(echo "$info" | cut -d'|' -f1)
    local bundle_pattern=$(echo "$info" | cut -d'|' -f2)
    local download_url=$(echo "$info" | cut -d'|' -f3)

    echo ""
    print_cyan "========================================================"
    print_cyan "  DISA SCC (SCAP Compliance Checker) Requirements"
    print_cyan "========================================================"
    echo ""
    print_white "  Detected System:"
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        echo "    OS: $NAME $VERSION"
    fi
    echo "    Architecture: $(uname -m)"
    echo ""
    print_yellow "  Required SCC Bundle:"
    echo "    Pattern: $bundle_pattern"
    echo "    Filename: $bundle_name"
    echo ""
    print_yellow "  Download Location:"
    echo "    $download_url"
    echo ""
    print_yellow "  Instructions:"
    echo "    1. Download the SCC bundle from cyber.mil (no login required)"
    echo "    2. Transfer the ZIP file to this system"
    echo "    3. Place the ZIP file in the same directory as this script:"
    print_white "       $(dirname "${BASH_SOURCE[0]}")/"
    echo "    4. Run this script with --scc flag"
    echo ""
    print_cyan "  The script will automatically:"
    echo "    - Find the SCC bundle ZIP file"
    echo "    - Extract the bundle"
    echo "    - Extract the tar.gz installer"
    echo "    - Run the SCAP compliance scan"
    echo "    - Save results to the output directory"
    echo ""
    print_cyan "========================================================"
    echo ""
}

# Function to find and setup SCC
setup_scc() {
    local script_dir="$1"
    local output_dir="$2"

    local info=$(get_scc_bundle_info)
    local bundle_pattern=$(echo "$info" | cut -d'|' -f1)

    if [ "$bundle_pattern" = "UNKNOWN" ]; then
        print_red "  Cannot determine SCC bundle for this OS"
        return 1
    fi

    # Look for SCC bundle in script directory
    print_green "Looking for SCC bundle in: $script_dir"

    local scc_zip=$(find "$script_dir" -maxdepth 1 -name "scc-*_bundle.zip" -type f 2>/dev/null | head -1)

    if [ -z "$scc_zip" ]; then
        print_red "  SCC bundle not found!"
        echo ""
        show_scc_requirements
        return 1
    fi

    print_green "  Found SCC bundle: $(basename "$scc_zip")"

    # Create SCC working directory
    local scc_work_dir="${output_dir}/SCC"
    mkdir -p "$scc_work_dir"

    # Extract the ZIP bundle
    print_green "  Extracting SCC bundle..."
    if command_exists unzip; then
        unzip -q -o "$scc_zip" -d "$scc_work_dir" 2>/dev/null
        if [ $? -ne 0 ]; then
            print_red "  Failed to extract ZIP bundle"
            return 1
        fi
    else
        print_red "  'unzip' command not found - please install unzip"
        WARNINGS+=("SCC scan skipped - unzip not installed")
        return 1
    fi

    # Find and extract the tar.gz file
    local scc_tarball=$(find "$scc_work_dir" -name "scc-*.tar.gz" -type f 2>/dev/null | head -1)

    if [ -z "$scc_tarball" ]; then
        # Try to find tar.gz in subdirectories
        scc_tarball=$(find "$scc_work_dir" -name "*.tar.gz" -type f 2>/dev/null | head -1)
    fi

    if [ -n "$scc_tarball" ]; then
        print_green "  Found tarball: $(basename "$scc_tarball")"
        print_green "  Extracting SCC application..."

        local scc_extract_dir="${scc_work_dir}/scc"
        mkdir -p "$scc_extract_dir"

        tar -xzf "$scc_tarball" -C "$scc_extract_dir" 2>/dev/null
        if [ $? -ne 0 ]; then
            print_red "  Failed to extract tarball"
            return 1
        fi

        # Find the cscc executable
        SCC_EXECUTABLE=$(find "$scc_extract_dir" -name "cscc" -type f -executable 2>/dev/null | head -1)

        if [ -z "$SCC_EXECUTABLE" ]; then
            # Try without executable flag (might need chmod)
            SCC_EXECUTABLE=$(find "$scc_extract_dir" -name "cscc" -type f 2>/dev/null | head -1)
            if [ -n "$SCC_EXECUTABLE" ]; then
                chmod +x "$SCC_EXECUTABLE" 2>/dev/null
            fi
        fi

        if [ -n "$SCC_EXECUTABLE" ]; then
            print_green "  Found SCC executable: $SCC_EXECUTABLE"
            echo "$SCC_EXECUTABLE"
            return 0
        fi
    fi

    # If no tarball, check for RPM or DEB packages
    local scc_rpm=$(find "$scc_work_dir" -name "scc-*.rpm" -type f 2>/dev/null | head -1)
    local scc_deb=$(find "$scc_work_dir" -name "scc-*.deb" -type f 2>/dev/null | head -1)

    if [ -n "$scc_rpm" ] || [ -n "$scc_deb" ]; then
        print_yellow "  Found package installer but no standalone tarball"
        print_yellow "  For air-gapped systems, the tarball is recommended"
        print_yellow "  You can install the package manually:"
        [ -n "$scc_rpm" ] && echo "    sudo rpm -i $scc_rpm"
        [ -n "$scc_deb" ] && echo "    sudo dpkg -i $scc_deb"
        echo ""

        # Check if SCC is already installed
        if command_exists cscc; then
            SCC_EXECUTABLE=$(which cscc)
            print_green "  Using installed SCC: $SCC_EXECUTABLE"
            echo "$SCC_EXECUTABLE"
            return 0
        fi
    fi

    print_red "  Could not find or setup SCC executable"
    return 1
}

# Function to run SCC scan
run_scc_scan() {
    local scc_exe="$1"
    local output_dir="$2"

    if [ -z "$scc_exe" ] || [ ! -x "$scc_exe" ]; then
        print_red "SCC executable not found or not executable"
        return 1
    fi

    local scc_results_dir="${output_dir}/SCC/Results"
    mkdir -p "$scc_results_dir"

    print_green "Running SCC Compliance Scan..."
    print_gray "  This may take several minutes..."
    echo ""

    # Run SCC with output directory
    # SCC typically uses -u for unattended mode with output directory
    "$scc_exe" -u "$scc_results_dir" 2>&1

    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        print_green "SCC scan completed successfully!"
        # Count result files
        local result_count=$(find "$scc_results_dir" -type f 2>/dev/null | wc -l)
        print_green "  Results saved to: $scc_results_dir ($result_count files)"
        return 0
    else
        print_yellow "SCC scan completed with exit code: $exit_code"
        print_yellow "  Check results in: $scc_results_dir"
        return $exit_code
    fi
}
#endregion

#region Help Display
show_help() {
    echo ""
    print_cyan "========================================================"
    print_cyan "  MOAS - System Inventory and Audit Tool v${VERSION}"
    print_cyan "========================================================"
    echo ""
    print_yellow "DESCRIPTION:"
    echo "  Collects system inventory data including hardware, software,"
    echo "  network configuration, local users, event logs, and optionally"
    echo "  runs DISA SCC or OpenSCAP compliance scans."
    echo ""
    print_yellow "USAGE:"
    echo "  ./MOAS.sh                     # Interactive mode"
    echo "  ./MOAS.sh --help              # Display this help message"
    echo "  ./MOAS.sh --silent [options]  # Silent/batch mode"
    echo "  ./MOAS.sh --scc-info          # Show SCC bundle requirements"
    echo ""
    print_yellow "PARAMETERS:"
    echo "  -h, --help           Display this help message and exit"
    echo ""
    echo "  -s, --silent         Run in silent mode (no prompts)"
    echo ""
    print_yellow "  DISA SCC (SCAP Compliance Checker):"
    echo "  --scc                Enable DISA SCC scan"
    echo "                       Requires SCC bundle ZIP in script directory"
    echo "                       Download from: https://public.cyber.mil/stigs/scap/"
    echo ""
    echo "  --scc-info           Display SCC bundle requirements for this system"
    echo "                       Shows which file to download from cyber.mil"
    echo ""
    print_yellow "  OpenSCAP (alternative):"
    echo "  --scap               Enable OpenSCAP scan (requires oscap installed)"
    echo ""
    echo "  --scap-profile PATH  Path to SCAP profile/content file"
    echo "                       Default: searches for ssg-* content"
    echo ""
    print_yellow "  Other Options:"
    echo "  --log-days DAYS      Number of days of logs to collect"
    echo "                       Range: 1-365, Default: 90"
    echo ""
    print_yellow "EXAMPLES:"
    print_gray "  # Interactive mode"
    print_gray "  ./MOAS.sh"
    echo ""
    print_gray "  # Show which SCC bundle to download"
    print_gray "  ./MOAS.sh --scc-info"
    echo ""
    print_gray "  # Silent mode with DISA SCC scan (bundle must be in script dir)"
    print_gray "  ./MOAS.sh --silent --scc"
    echo ""
    print_gray "  # Silent mode with defaults (90 days logs, no SCAP)"
    print_gray "  ./MOAS.sh --silent"
    echo ""
    print_gray "  # Silent mode with OpenSCAP scan"
    print_gray "  ./MOAS.sh --silent --scap --scap-profile /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml"
    echo ""
    print_gray "  # Silent mode with 30 days of logs"
    print_gray "  ./MOAS.sh --silent --log-days 30"
    echo ""
    print_yellow "SCC BUNDLE SETUP (for air-gapped systems):"
    echo "  1. On an internet-connected system, visit:"
    echo "     https://public.cyber.mil/stigs/scap/"
    echo ""
    echo "  2. Download the appropriate SCC bundle for your target OS:"
    echo "     - Ubuntu 18-20:  scc-X.X_ubuntu18-20_amd64_bundle.zip"
    echo "     - Ubuntu 22+:    scc-X.X_ubuntu22_amd64_bundle.zip"
    echo "     - RHEL 7:        scc-X.X_rhel7_sles12-15_oracle-linux7_x86_64_bundle.zip"
    echo "     - RHEL 8:        scc-X.X_rhel8_oracle-linux8_x86_64_bundle.zip"
    echo "     - RHEL 9:        scc-X.X_rhel9_oracle-linux9_x86_64_bundle.zip"
    echo ""
    echo "  3. Transfer the ZIP file to the target system"
    echo ""
    echo "  4. Place ZIP in the same directory as MOAS.sh"
    echo ""
    echo "  5. Run: sudo ./MOAS.sh --scc"
    echo ""
    print_yellow "OUTPUT:"
    echo "  Creates a dated folder in the script directory containing:"
    echo "    - BasicInfo-*.csv        System/hardware information"
    echo "    - LocalUsers-*.csv       Local user accounts"
    echo "    - InstalledPackages-*.csv Installed packages"
    echo "    - PPS-*.csv              Network ports and processes"
    echo "    - Logs-*.csv             System log entries"
    echo "    - SCC/                   SCC results folder (if run)"
    echo "    - SCAP/                  OpenSCAP results folder (if run)"
    echo ""
    print_yellow "REQUIREMENTS:"
    echo "  - Bash 4.0 or later"
    echo "  - Root privileges recommended for full functionality"
    echo "  - unzip command (for SCC bundle extraction)"
    echo "  - Without root: Some hardware info and security logs are limited"
    echo ""
    print_yellow "SUPPORTED SYSTEMS:"
    echo "  Ubuntu 18+, Debian 10+, RHEL/CentOS/Rocky 7+, Fedora, SLES 12+"
    echo ""
    exit 0
}
#endregion

#region Parse Arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            SHOW_HELP=true
            shift
            ;;
        -s|--silent)
            SILENT=true
            shift
            ;;
        --scc)
            RUN_SCC=true
            shift
            ;;
        --scc-info)
            show_scc_requirements
            exit 0
            ;;
        --scap)
            RUN_SCAP=true
            shift
            ;;
        --scap-profile)
            SCAP_PROFILE="$2"
            shift 2
            ;;
        --log-days)
            LOG_DAYS="$2"
            if ! [[ "$LOG_DAYS" =~ ^[0-9]+$ ]] || [ "$LOG_DAYS" -lt 1 ]; then
                LOG_DAYS=1
            elif [ "$LOG_DAYS" -gt 365 ]; then
                LOG_DAYS=365
            fi
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

if [ "$SHOW_HELP" = true ]; then
    show_help
fi
#endregion

#region Administrator Check
IS_ROOT=false
if [ "$(id -u)" -eq 0 ]; then
    IS_ROOT=true
fi

if [ "$IS_ROOT" = false ]; then
    echo ""
    print_yellow "========================================================"
    print_yellow "  WARNING: Script is NOT running as root"
    print_yellow "========================================================"
    echo ""
    print_red "  WILL BE LIMITED (Requires root):"
    print_red "    [X] Some hardware details (dmidecode)"
    print_red "    [X] Security-sensitive log entries"
    print_red "    [X] OpenSCAP scans"
    echo ""
    print_green "  WILL STILL COLLECT (No root required):"
    print_green "    [+] Basic System Information (hostname, OS, kernel)"
    print_green "    [+] CPU and Memory Information"
    print_green "    [+] Disk Information (df, mount points)"
    print_green "    [+] Network Adapter Information (IP, interfaces)"
    print_green "    [+] Local User Accounts"
    print_green "    [+] Installed Packages"
    print_green "    [+] Active Network Connections"
    print_green "    [+] User-accessible logs"
    echo ""
    print_cyan "  To run with full capabilities:"
    print_cyan "    sudo ./MOAS.sh"
    echo ""

    if [ "$SILENT" = false ]; then
        read -p "Continue with limited scan? (Y/N): " CONTINUE
        if [[ ! "$CONTINUE" =~ ^[Yy]$ ]]; then
            print_red "Exiting..."
            exit 1
        fi
        echo ""
        print_yellow "  Continuing with limited scan..."
    else
        print_yellow "  Silent mode: Continuing with limited scan..."
    fi
    echo ""
fi
#endregion

#region Interactive Mode Configuration
if [ "$SILENT" = false ]; then
    echo ""
    print_cyan "========================================================"
    print_cyan "  MOAS Configuration"
    print_cyan "========================================================"
    echo ""

    # DISA SCC Configuration
    print_white "DISA SCC (SCAP Compliance Checker) Configuration:"
    # Check if SCC bundle exists in script directory
    SCRIPT_DIR_CHECK="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    SCC_BUNDLE_CHECK=$(find "$SCRIPT_DIR_CHECK" -maxdepth 1 -name "scc-*_bundle.zip" -type f 2>/dev/null | head -1)

    if [ -n "$SCC_BUNDLE_CHECK" ]; then
        print_green "  Found SCC bundle: $(basename "$SCC_BUNDLE_CHECK")"
        read -p "  Run DISA SCC compliance scan? (Y/N) [N]: " RUN_SCC_INPUT
        if [[ "$RUN_SCC_INPUT" =~ ^[Yy]$ ]]; then
            RUN_SCC=true
        fi
    else
        print_yellow "  No SCC bundle found in script directory"
        echo "  To use SCC, download the appropriate bundle from:"
        echo "    https://public.cyber.mil/stigs/scap/"
        echo "  Run './MOAS.sh --scc-info' to see which bundle you need"
    fi
    echo ""

    # OpenSCAP Configuration (alternative to SCC)
    if [ "$RUN_SCC" = false ]; then
        print_white "OpenSCAP Configuration (alternative to SCC):"
        if command_exists oscap; then
            read -p "  Run OpenSCAP scan? (Y/N) [N]: " RUN_SCAP_INPUT
            if [[ "$RUN_SCAP_INPUT" =~ ^[Yy]$ ]]; then
                RUN_SCAP=true
                # Try to find SCAP content
                DEFAULT_SCAP=$(find /usr/share/xml/scap -name "ssg-*-ds.xml" 2>/dev/null | head -1)
                if [ -n "$DEFAULT_SCAP" ]; then
                    echo "  Found SCAP content: $DEFAULT_SCAP"
                    read -p "  Use this profile? (Y/N) [Y]: " USE_DEFAULT
                    if [[ ! "$USE_DEFAULT" =~ ^[Nn]$ ]]; then
                        SCAP_PROFILE="$DEFAULT_SCAP"
                    else
                        read -p "  Enter path to SCAP profile: " SCAP_PROFILE
                    fi
                else
                    read -p "  Enter path to SCAP profile: " SCAP_PROFILE
                fi
            fi
        else
            print_yellow "  OpenSCAP (oscap) not installed - skipping OpenSCAP options"
        fi
        echo ""
    fi

    # Log Collection Configuration
    print_white "Event Log Collection:"
    read -p "  Collect logs from the past (days) [90]: " LOG_DAYS_INPUT
    if [[ "$LOG_DAYS_INPUT" =~ ^[0-9]+$ ]]; then
        LOG_DAYS="$LOG_DAYS_INPUT"
        if [ "$LOG_DAYS" -lt 1 ]; then
            LOG_DAYS=1
        elif [ "$LOG_DAYS" -gt 365 ]; then
            LOG_DAYS=365
        fi
    fi
    echo ""
fi
#endregion

#region Initialize Variables
print_green "Initializing Variables"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NOW=$(date '+%Y%m%d-%H%M')
SHORT_DATE=$(date '+%Y%m%d')
HOSTNAME=$(hostname)
SCAN_SAVE_DIR="${SCRIPT_DIR}/${SHORT_DATE}-${HOSTNAME}"

# Create output directory
mkdir -p "$SCAN_SAVE_DIR"

# Output files
CSV_BASIC_INFO="${SCAN_SAVE_DIR}/${HOSTNAME}-BasicInfo-${NOW}.csv"
CSV_LOCAL_USERS="${SCAN_SAVE_DIR}/${HOSTNAME}-LocalUsers-${NOW}.csv"
CSV_INSTALLED_PACKAGES="${SCAN_SAVE_DIR}/${HOSTNAME}-InstalledPackages-${NOW}.csv"
CSV_PPS="${SCAN_SAVE_DIR}/${HOSTNAME}-PPS-${NOW}.csv"
CSV_LOGS="${SCAN_SAVE_DIR}/${HOSTNAME}-Logs-${NOW}.csv"

# Tracking arrays
declare -a COLLECTED_ITEMS
declare -a WARNINGS
START_TIME=$(date +%s)
#endregion

#region Display Configuration
print_green "Configuration:"
if [ "$RUN_SCC" = true ]; then
    echo "  Run DISA SCC: Yes"
elif [ "$RUN_SCAP" = true ]; then
    echo "  Run OpenSCAP: Yes"
    echo "  SCAP Profile: $SCAP_PROFILE"
else
    echo "  Run SCAP: No"
fi
echo "  Log Days: $LOG_DAYS"
echo ""
#endregion

#region Basic System Information
print_green "Writing Basic Information"

# Initialize CSV
write_csv_header "$CSV_BASIC_INFO" "Title" "Data"

# Hostname
append_csv_row "$CSV_BASIC_INFO" "Computer Name" "$HOSTNAME"

# OS Information
if [ -f /etc/os-release ]; then
    source /etc/os-release
    append_csv_row "$CSV_BASIC_INFO" "OS Name" "$(get_value_or_na "$NAME")"
    append_csv_row "$CSV_BASIC_INFO" "OS Version" "$(get_value_or_na "$VERSION")"
    append_csv_row "$CSV_BASIC_INFO" "OS ID" "$(get_value_or_na "$ID")"
    append_csv_row "$CSV_BASIC_INFO" "OS ID Like" "$(get_value_or_na "$ID_LIKE")"
fi

# Kernel Information
KERNEL_VERSION=$(uname -r)
KERNEL_ARCH=$(uname -m)
append_csv_row "$CSV_BASIC_INFO" "Kernel Version" "$KERNEL_VERSION"
append_csv_row "$CSV_BASIC_INFO" "Architecture" "$KERNEL_ARCH"

# Current User
CURRENT_USER=$(whoami)
append_csv_row "$CSV_BASIC_INFO" "Current User" "$CURRENT_USER"

# System Manufacturer/Model (requires root for dmidecode)
if [ "$IS_ROOT" = true ] && command_exists dmidecode; then
    SYS_MANUFACTURER=$(dmidecode -s system-manufacturer 2>/dev/null | head -1)
    SYS_PRODUCT=$(dmidecode -s system-product-name 2>/dev/null | head -1)
    SYS_SERIAL=$(dmidecode -s system-serial-number 2>/dev/null | head -1)
    SYS_UUID=$(dmidecode -s system-uuid 2>/dev/null | head -1)
    BIOS_VENDOR=$(dmidecode -s bios-vendor 2>/dev/null | head -1)
    BIOS_VERSION=$(dmidecode -s bios-version 2>/dev/null | head -1)
    BIOS_DATE=$(dmidecode -s bios-release-date 2>/dev/null | head -1)

    append_csv_row "$CSV_BASIC_INFO" "System Manufacturer" "$(get_value_or_na "$SYS_MANUFACTURER")"
    append_csv_row "$CSV_BASIC_INFO" "System Product Name" "$(get_value_or_na "$SYS_PRODUCT")"
    append_csv_row "$CSV_BASIC_INFO" "System Serial Number" "$(get_value_or_na "$SYS_SERIAL")"
    append_csv_row "$CSV_BASIC_INFO" "System UUID" "$(get_value_or_na "$SYS_UUID")"
    append_csv_row "$CSV_BASIC_INFO" "BIOS Vendor" "$(get_value_or_na "$BIOS_VENDOR")"
    append_csv_row "$CSV_BASIC_INFO" "BIOS Version" "$(get_value_or_na "$BIOS_VERSION")"
    append_csv_row "$CSV_BASIC_INFO" "BIOS Date" "$(get_value_or_na "$BIOS_DATE")"
elif [ -f /sys/class/dmi/id/sys_vendor ]; then
    # Fallback for non-root access
    SYS_VENDOR=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)
    SYS_NAME=$(cat /sys/class/dmi/id/product_name 2>/dev/null)
    append_csv_row "$CSV_BASIC_INFO" "System Manufacturer" "$(get_value_or_na "$SYS_VENDOR")"
    append_csv_row "$CSV_BASIC_INFO" "System Product Name" "$(get_value_or_na "$SYS_NAME")"
fi

# CPU Information
print_green "Getting CPU Information"
if [ -f /proc/cpuinfo ]; then
    CPU_MODEL=$(grep -m1 "model name" /proc/cpuinfo | cut -d: -f2 | xargs)
    CPU_CORES=$(grep -c "^processor" /proc/cpuinfo)
    CPU_THREADS=$(nproc 2>/dev/null || echo "$CPU_CORES")

    append_csv_row "$CSV_BASIC_INFO" "CPU Model" "$(get_value_or_na "$CPU_MODEL")"
    append_csv_row "$CSV_BASIC_INFO" "CPU Cores" "$CPU_CORES"
    append_csv_row "$CSV_BASIC_INFO" "CPU Threads" "$CPU_THREADS"
fi

if command_exists lscpu; then
    CPU_SOCKETS=$(lscpu | grep "^Socket(s):" | awk '{print $2}')
    CPU_MHZ=$(lscpu | grep "CPU MHz:" | awk '{print $3}')
    CPU_MAX_MHZ=$(lscpu | grep "CPU max MHz:" | awk '{print $4}')

    [ -n "$CPU_SOCKETS" ] && append_csv_row "$CSV_BASIC_INFO" "CPU Sockets" "$CPU_SOCKETS"
    [ -n "$CPU_MHZ" ] && append_csv_row "$CSV_BASIC_INFO" "CPU MHz" "$CPU_MHZ"
    [ -n "$CPU_MAX_MHZ" ] && append_csv_row "$CSV_BASIC_INFO" "CPU Max MHz" "$CPU_MAX_MHZ"
fi

# Memory Information
print_green "Getting Memory Information"
if [ -f /proc/meminfo ]; then
    MEM_TOTAL_KB=$(grep "MemTotal:" /proc/meminfo | awk '{print $2}')
    MEM_TOTAL_GB=$(echo "scale=2; $MEM_TOTAL_KB / 1024 / 1024" | bc 2>/dev/null || echo "$((MEM_TOTAL_KB / 1024 / 1024))")
    MEM_FREE_KB=$(grep "MemFree:" /proc/meminfo | awk '{print $2}')
    MEM_AVAILABLE_KB=$(grep "MemAvailable:" /proc/meminfo | awk '{print $2}')
    SWAP_TOTAL_KB=$(grep "SwapTotal:" /proc/meminfo | awk '{print $2}')
    SWAP_FREE_KB=$(grep "SwapFree:" /proc/meminfo | awk '{print $2}')

    append_csv_row "$CSV_BASIC_INFO" "RAM Total (GB)" "$MEM_TOTAL_GB"

    if [ -n "$MEM_AVAILABLE_KB" ]; then
        MEM_AVAILABLE_GB=$(echo "scale=2; $MEM_AVAILABLE_KB / 1024 / 1024" | bc 2>/dev/null || echo "$((MEM_AVAILABLE_KB / 1024 / 1024))")
        append_csv_row "$CSV_BASIC_INFO" "RAM Available (GB)" "$MEM_AVAILABLE_GB"
    fi

    if [ "$SWAP_TOTAL_KB" -gt 0 ] 2>/dev/null; then
        SWAP_TOTAL_GB=$(echo "scale=2; $SWAP_TOTAL_KB / 1024 / 1024" | bc 2>/dev/null || echo "$((SWAP_TOTAL_KB / 1024 / 1024))")
        append_csv_row "$CSV_BASIC_INFO" "Swap Total (GB)" "$SWAP_TOTAL_GB"
    fi
fi

COLLECTED_ITEMS+=("Basic System Information")
#endregion

#region Disk Information
print_green "Getting Disk Information"

# Get disk information using df
while IFS= read -r line; do
    FILESYSTEM=$(echo "$line" | awk '{print $1}')
    SIZE=$(echo "$line" | awk '{print $2}')
    USED=$(echo "$line" | awk '{print $3}')
    AVAIL=$(echo "$line" | awk '{print $4}')
    USE_PERCENT=$(echo "$line" | awk '{print $5}' | tr -d '%')
    MOUNT=$(echo "$line" | awk '{print $6}')

    # Convert to GB (df -BG gives sizes in G)
    SIZE_NUM=$(echo "$SIZE" | tr -d 'G')
    AVAIL_NUM=$(echo "$AVAIL" | tr -d 'G')

    append_csv_row "$CSV_BASIC_INFO" "Disk ${MOUNT} Filesystem" "$FILESYSTEM"
    append_csv_row "$CSV_BASIC_INFO" "Disk ${MOUNT} Size (GB)" "$SIZE_NUM"
    append_csv_row "$CSV_BASIC_INFO" "Disk ${MOUNT} Available (GB)" "$AVAIL_NUM"
    append_csv_row "$CSV_BASIC_INFO" "Disk ${MOUNT} Used (%)" "$USE_PERCENT"
done < <(df -BG --output=source,size,used,avail,pcent,target -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | tail -n +2)

COLLECTED_ITEMS+=("Disk Information")
#endregion

#region Network Adapter Information
print_green "Getting Network Adapter Information"

ADAPTER_INDEX=1

# Get network interfaces
for IFACE in $(ls /sys/class/net/ 2>/dev/null | grep -v lo); do
    # Interface name
    append_csv_row "$CSV_BASIC_INFO" "Network Adapter ${ADAPTER_INDEX} Name" "$IFACE"

    # MAC Address
    MAC=$(cat "/sys/class/net/${IFACE}/address" 2>/dev/null)
    [ -n "$MAC" ] && append_csv_row "$CSV_BASIC_INFO" "Network Adapter ${ADAPTER_INDEX} MAC Address" "$MAC"

    # State
    STATE=$(cat "/sys/class/net/${IFACE}/operstate" 2>/dev/null)
    [ -n "$STATE" ] && append_csv_row "$CSV_BASIC_INFO" "Network Adapter ${ADAPTER_INDEX} State" "$STATE"

    # IP Addresses (using ip command)
    if command_exists ip; then
        IP_ADDRS=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | tr '\n' '; ' | sed 's/; $//')
        [ -n "$IP_ADDRS" ] && append_csv_row "$CSV_BASIC_INFO" "Network Adapter ${ADAPTER_INDEX} IPv4 Address" "$IP_ADDRS"

        IP6_ADDRS=$(ip -6 addr show "$IFACE" 2>/dev/null | grep -oP '(?<=inet6\s)[a-f0-9:]+' | grep -v "^fe80" | tr '\n' '; ' | sed 's/; $//')
        [ -n "$IP6_ADDRS" ] && append_csv_row "$CSV_BASIC_INFO" "Network Adapter ${ADAPTER_INDEX} IPv6 Address" "$IP6_ADDRS"
    fi

    # Speed (if available)
    SPEED=$(cat "/sys/class/net/${IFACE}/speed" 2>/dev/null)
    [ -n "$SPEED" ] && [ "$SPEED" != "-1" ] && append_csv_row "$CSV_BASIC_INFO" "Network Adapter ${ADAPTER_INDEX} Speed (Mbps)" "$SPEED"

    # MTU
    MTU=$(cat "/sys/class/net/${IFACE}/mtu" 2>/dev/null)
    [ -n "$MTU" ] && append_csv_row "$CSV_BASIC_INFO" "Network Adapter ${ADAPTER_INDEX} MTU" "$MTU"

    ((ADAPTER_INDEX++))
done

# Default Gateway
if command_exists ip; then
    DEFAULT_GW=$(ip route | grep default | awk '{print $3}' | head -1)
    [ -n "$DEFAULT_GW" ] && append_csv_row "$CSV_BASIC_INFO" "Default Gateway" "$DEFAULT_GW"
fi

# DNS Servers
if [ -f /etc/resolv.conf ]; then
    DNS_SERVERS=$(grep "^nameserver" /etc/resolv.conf | awk '{print $2}' | tr '\n' '; ' | sed 's/; $//')
    [ -n "$DNS_SERVERS" ] && append_csv_row "$CSV_BASIC_INFO" "DNS Servers" "$DNS_SERVERS"
fi

COLLECTED_ITEMS+=("Network Adapter Information")
#endregion

#region Local Users
print_green "Getting Local Users"

write_csv_header "$CSV_LOCAL_USERS" "UserName" "UID" "GID" "Description" "HomeDirectory" "Shell" "Groups"

USER_COUNT=0
while IFS=: read -r USERNAME PASSWORD UID GID GECOS HOME SHELL; do
    # Skip system accounts (UID < 1000) unless they have login shells
    if [ "$UID" -ge 1000 ] || [[ "$SHELL" == *"bash"* ]] || [[ "$SHELL" == *"zsh"* ]] || [[ "$SHELL" == *"sh"* && "$SHELL" != *"nologin"* && "$SHELL" != *"false"* ]]; then
        # Get user's groups
        GROUPS=$(groups "$USERNAME" 2>/dev/null | cut -d: -f2 | xargs | tr ' ' ';')

        append_csv_row "$CSV_LOCAL_USERS" "$USERNAME" "$UID" "$GID" "$GECOS" "$HOME" "$SHELL" "$GROUPS"
        ((USER_COUNT++))
    fi
done < /etc/passwd

COLLECTED_ITEMS+=("Local Users (${USER_COUNT} users)")
#endregion

#region Installed Packages
print_green "Getting Installed Packages (this may take a moment)..."

write_csv_header "$CSV_INSTALLED_PACKAGES" "Name" "Version" "Architecture" "Description"

PKG_COUNT=0

# Detect package manager and get installed packages
if command_exists dpkg; then
    # Debian/Ubuntu
    print_gray "  Using dpkg for package list..."
    while IFS=$'\t' read -r NAME VERSION ARCH DESC; do
        append_csv_row "$CSV_INSTALLED_PACKAGES" "$NAME" "$VERSION" "$ARCH" "$DESC"
        ((PKG_COUNT++))
    done < <(dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Description}\n' 2>/dev/null | cut -c1-500)

elif command_exists rpm; then
    # RHEL/CentOS/Fedora
    print_gray "  Using rpm for package list..."
    while IFS=$'\t' read -r NAME VERSION ARCH DESC; do
        append_csv_row "$CSV_INSTALLED_PACKAGES" "$NAME" "$VERSION" "$ARCH" "$DESC"
        ((PKG_COUNT++))
    done < <(rpm -qa --queryformat '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SUMMARY}\n' 2>/dev/null)

elif command_exists pacman; then
    # Arch Linux
    print_gray "  Using pacman for package list..."
    while IFS= read -r line; do
        NAME=$(echo "$line" | awk '{print $1}')
        VERSION=$(echo "$line" | awk '{print $2}')
        append_csv_row "$CSV_INSTALLED_PACKAGES" "$NAME" "$VERSION" "N/A" "N/A"
        ((PKG_COUNT++))
    done < <(pacman -Q 2>/dev/null)

elif command_exists apk; then
    # Alpine Linux
    print_gray "  Using apk for package list..."
    while IFS= read -r line; do
        NAME=$(echo "$line" | sed 's/-[0-9].*//')
        VERSION=$(echo "$line" | grep -oP '\d+\.\d+.*' | head -1)
        append_csv_row "$CSV_INSTALLED_PACKAGES" "$NAME" "$VERSION" "N/A" "N/A"
        ((PKG_COUNT++))
    done < <(apk list -I 2>/dev/null)
else
    print_yellow "  No supported package manager found"
    WARNINGS+=("Package list unavailable - no supported package manager")
fi

COLLECTED_ITEMS+=("Installed Packages (${PKG_COUNT} packages)")
#endregion

#region Network Ports and Processes (PPS)
print_green "Getting TCP and UDP Ports"

write_csv_header "$CSV_PPS" "LocalAddress" "RemoteAddress" "Proto" "LocalPort" "RemotePort" "State" "PID" "ProcessName" "ICS_Protocol"

# ICS/SCADA Protocol mapping function
get_ics_protocol() {
    local PORT="$1"
    local PROTO="$2"

    case "$PORT" in
        80) echo "HTTP" ;;
        443) echo "HTTPS" ;;
        102) echo "ICCP/Siemens S7 COTP/IEC 61850 MMS" ;;
        135) echo "OPC Classic (DCOM RPC)" ;;
        502) echo "Modbus TCP" ;;
        789) echo "Red Lion Crimson v3" ;;
        1089|1090|1091) echo "Foundation Fieldbus HSE" ;;
        1541) echo "Foxboro/Schneider DCS" ;;
        1911) echo "Niagara Fox (Tridium)" ;;
        1962) echo "PCWorx" ;;
        2222|2223) echo "EtherNet/IP" ;;
        2221) echo "Rockwell Allen-Bradley DF1" ;;
        2404) echo "IEC 60870-5-104" ;;
        2455) echo "WAGO I/O (PCWorx)" ;;
        3480|4840) echo "OPC UA Discovery Server" ;;
        4000) echo "Emerson/Fisher ROC Plus" ;;
        4712|4713) echo "Siemens WinCC OA" ;;
        4911) echo "Niagara Fox SSL (Tridium)" ;;
        5006|5007) echo "Mitsubishi MELSEC-Q" ;;
        5050|5051) [ "$PROTO" = "UDP" ] && echo "Telvent OASyS DNA" ;;
        5052|5065) echo "Telvent OASyS DNA" ;;
        5094|5095) echo "HART-IP" ;;
        5450) echo "OSIsoft PI Server" ;;
        6000) echo "Schneider ClearSCADA" ;;
        6543) echo "Schneider Modicon" ;;
        9600) echo "OMRON FINS" ;;
        10307|10311|10364|10365|10407|10409|10410|10412|10414|10415|10428|10431|10432|10447|10449|10450) echo "ABB Ranger 2003" ;;
        11001) echo "Johnson Controls Metasys N1" ;;
        12135|12137) echo "Telvent OASyS DNA" ;;
        12316|12645|12647|12648|13722|13724|13782|13783) echo "ABB Ranger 2003" ;;
        17185) echo "Rockwell RSLinx" ;;
        18000) echo "Iconic Genesis32 GenBroker" ;;
        18245|18246) echo "GE SRTP" ;;
        19999|20000) echo "DNP3" ;;
        20256) echo "Unitronics PCOM" ;;
        20547) echo "ProConOS (PCWorx)" ;;
        34962|34963|34964) echo "PROFINET" ;;
        34980) [ "$PROTO" = "UDP" ] && echo "EtherCAT" ;;
        38000|38001|38011|38012|38014|38015|38200|38210|38301|38400|38700) echo "SNC GENe" ;;
        38589|38593|38600|38971|39129|39278) echo "ABB Ranger 2003" ;;
        41100) echo "Yokogawa CENTUM" ;;
        41794) [ "$PROTO" = "UDP" ] && echo "Crestron (Building Automation)" ;;
        44818) echo "EtherNet/IP CIP" ;;
        45678) echo "Foxboro DCS AIMAPI" ;;
        47808) [ "$PROTO" = "UDP" ] && echo "BACnet/IP" ;;
        47809) [ "$PROTO" = "UDP" ] && echo "BACnet/IP Secure" ;;
        48898) echo "Niagara Fox Secure" ;;
        50001|50002|50003|50004|50005|50006|50007|50008|50009|50010|50011|50012|50013|50014|50015|50016|50018|50019|50025|50026|50027|50028|50110|50111) echo "Siemens Spectrum Power TG" ;;
        50020|50021) [ "$PROTO" = "UDP" ] && echo "Siemens Spectrum Power TG" ;;
        51000|51001|51002) echo "Honeywell Experion PKS" ;;
        55000|55001|55002) [ "$PROTO" = "UDP" ] && echo "FL-net Reception" ;;
        55003) [ "$PROTO" = "UDP" ] && echo "FL-net Transmission" ;;
        55555) echo "Foxboro DCS FoxAPI" ;;
        57176) echo "CODESYS Runtime" ;;
        62900|62911|62924|62930|62938|62956|62957|62963|62981|62982|62985|62992|63012|63041|63075|63079|63082|63088|63094|65443) echo "SNC GENe" ;;
        69) [ "$PROTO" = "UDP" ] && echo "TFTP (ICS Firmware)" ;;
        161) [ "$PROTO" = "UDP" ] && echo "SNMP" ;;
        162) [ "$PROTO" = "UDP" ] && echo "SNMP Trap" ;;
        *) echo "n/a" ;;
    esac
}

PPS_COUNT=0

# Use ss (preferred) or netstat
if command_exists ss; then
    # TCP connections
    while IFS= read -r line; do
        STATE=$(echo "$line" | awk '{print $1}')
        LOCAL=$(echo "$line" | awk '{print $4}')
        REMOTE=$(echo "$line" | awk '{print $5}')
        PROC_INFO=$(echo "$line" | awk '{print $6}')

        # Parse local address and port
        LOCAL_ADDR=$(echo "$LOCAL" | rev | cut -d: -f2- | rev)
        LOCAL_PORT=$(echo "$LOCAL" | rev | cut -d: -f1 | rev)

        # Parse remote address and port
        REMOTE_ADDR=$(echo "$REMOTE" | rev | cut -d: -f2- | rev)
        REMOTE_PORT=$(echo "$REMOTE" | rev | cut -d: -f1 | rev)

        # Extract PID and process name
        PID=$(echo "$PROC_INFO" | grep -oP 'pid=\K\d+' | head -1)
        PROC_NAME=$(echo "$PROC_INFO" | grep -oP '\("?\K[^",)]+' | head -1)

        # Get ICS protocol
        ICS_PROTO=$(get_ics_protocol "$REMOTE_PORT" "TCP")

        # Skip loopback
        if [[ "$LOCAL_ADDR" != "127.0.0.1" && "$LOCAL_ADDR" != "::1" && "$REMOTE_ADDR" != "127.0.0.1" && "$REMOTE_ADDR" != "::1" ]]; then
            append_csv_row "$CSV_PPS" "$LOCAL_ADDR" "$REMOTE_ADDR" "TCP" "$LOCAL_PORT" "$REMOTE_PORT" "$STATE" "$PID" "$PROC_NAME" "$ICS_PROTO"
            ((PPS_COUNT++))
        fi
    done < <(ss -tnp 2>/dev/null | tail -n +2)

    # UDP listening ports
    while IFS= read -r line; do
        STATE=$(echo "$line" | awk '{print $1}')
        LOCAL=$(echo "$line" | awk '{print $4}')
        PROC_INFO=$(echo "$line" | awk '{print $6}')

        # Parse local address and port
        LOCAL_ADDR=$(echo "$LOCAL" | rev | cut -d: -f2- | rev)
        LOCAL_PORT=$(echo "$LOCAL" | rev | cut -d: -f1 | rev)

        # Extract PID and process name
        PID=$(echo "$PROC_INFO" | grep -oP 'pid=\K\d+' | head -1)
        PROC_NAME=$(echo "$PROC_INFO" | grep -oP '\("?\K[^",)]+' | head -1)

        # Get ICS protocol
        ICS_PROTO=$(get_ics_protocol "$LOCAL_PORT" "UDP")

        # Skip loopback
        if [[ "$LOCAL_ADDR" != "127.0.0.1" && "$LOCAL_ADDR" != "::1" && "$LOCAL_ADDR" != "*" ]]; then
            append_csv_row "$CSV_PPS" "$LOCAL_ADDR" "" "UDP" "$LOCAL_PORT" "$LOCAL_PORT" "LISTENING" "$PID" "$PROC_NAME" "$ICS_PROTO"
            ((PPS_COUNT++))
        fi
    done < <(ss -unp 2>/dev/null | tail -n +2)

elif command_exists netstat; then
    # Fallback to netstat
    print_gray "  Using netstat (ss not available)..."

    while IFS= read -r line; do
        PROTO=$(echo "$line" | awk '{print $1}')
        LOCAL=$(echo "$line" | awk '{print $4}')
        REMOTE=$(echo "$line" | awk '{print $5}')
        STATE=$(echo "$line" | awk '{print $6}')
        PID_PROG=$(echo "$line" | awk '{print $7}')

        LOCAL_ADDR=$(echo "$LOCAL" | rev | cut -d: -f2- | rev)
        LOCAL_PORT=$(echo "$LOCAL" | rev | cut -d: -f1 | rev)
        REMOTE_ADDR=$(echo "$REMOTE" | rev | cut -d: -f2- | rev)
        REMOTE_PORT=$(echo "$REMOTE" | rev | cut -d: -f1 | rev)

        PID=$(echo "$PID_PROG" | cut -d/ -f1)
        PROC_NAME=$(echo "$PID_PROG" | cut -d/ -f2)

        ICS_PROTO=$(get_ics_protocol "$REMOTE_PORT" "$PROTO")

        if [[ "$LOCAL_ADDR" != "127.0.0.1" && "$LOCAL_ADDR" != "::1" ]]; then
            append_csv_row "$CSV_PPS" "$LOCAL_ADDR" "$REMOTE_ADDR" "$PROTO" "$LOCAL_PORT" "$REMOTE_PORT" "$STATE" "$PID" "$PROC_NAME" "$ICS_PROTO"
            ((PPS_COUNT++))
        fi
    done < <(netstat -tunp 2>/dev/null | tail -n +3)
else
    print_yellow "  Neither ss nor netstat available"
    WARNINGS+=("Network ports unavailable - neither ss nor netstat found")
fi

COLLECTED_ITEMS+=("Network Ports/Processes (${PPS_COUNT} connections)")
#endregion

#region Event Logs
print_green "Pulling Log Files: Collecting ${LOG_DAYS} days of logs"

write_csv_header "$CSV_LOGS" "Timestamp" "Priority" "Unit" "Message"

LOG_COUNT=0

if command_exists journalctl; then
    print_gray "  Using journalctl..."

    # Calculate date for log collection
    SINCE_DATE=$(date -d "${LOG_DAYS} days ago" '+%Y-%m-%d' 2>/dev/null || date -v-${LOG_DAYS}d '+%Y-%m-%d' 2>/dev/null)

    if [ -n "$SINCE_DATE" ]; then
        while IFS= read -r line; do
            # Parse JSON output from journalctl
            TIMESTAMP=$(echo "$line" | jq -r '.__REALTIME_TIMESTAMP // empty' 2>/dev/null)
            if [ -n "$TIMESTAMP" ]; then
                # Convert microseconds to readable date
                TIMESTAMP_SEC=$((TIMESTAMP / 1000000))
                TIMESTAMP_FMT=$(date -d "@$TIMESTAMP_SEC" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$TIMESTAMP")
            else
                TIMESTAMP_FMT=$(echo "$line" | jq -r '._SOURCE_REALTIME_TIMESTAMP // "N/A"' 2>/dev/null)
            fi

            PRIORITY=$(echo "$line" | jq -r '.PRIORITY // "N/A"' 2>/dev/null)
            UNIT=$(echo "$line" | jq -r '._SYSTEMD_UNIT // .SYSLOG_IDENTIFIER // "N/A"' 2>/dev/null)
            MESSAGE=$(echo "$line" | jq -r '.MESSAGE // "N/A"' 2>/dev/null | tr '\n' ' ' | cut -c1-500)

            # Map priority numbers to names
            case "$PRIORITY" in
                0) PRIORITY="EMERG" ;;
                1) PRIORITY="ALERT" ;;
                2) PRIORITY="CRIT" ;;
                3) PRIORITY="ERR" ;;
                4) PRIORITY="WARNING" ;;
                5) PRIORITY="NOTICE" ;;
                6) PRIORITY="INFO" ;;
                7) PRIORITY="DEBUG" ;;
            esac

            append_csv_row "$CSV_LOGS" "$TIMESTAMP_FMT" "$PRIORITY" "$UNIT" "$MESSAGE"
            ((LOG_COUNT++))
        done < <(journalctl --since="$SINCE_DATE" -p 0..4 -o json 2>/dev/null | head -5000)
    else
        WARNINGS+=("Could not calculate log date range")
    fi

    COLLECTED_ITEMS+=("Event Logs (${LOG_COUNT} entries, ${LOG_DAYS} days)")

elif [ -f /var/log/syslog ] || [ -f /var/log/messages ]; then
    print_gray "  Using syslog files..."

    LOG_FILE="/var/log/syslog"
    [ ! -f "$LOG_FILE" ] && LOG_FILE="/var/log/messages"

    if [ -r "$LOG_FILE" ]; then
        while IFS= read -r line; do
            TIMESTAMP=$(echo "$line" | awk '{print $1, $2, $3}')
            UNIT=$(echo "$line" | awk '{print $4}' | tr -d ':')
            MESSAGE=$(echo "$line" | cut -d: -f4- | cut -c1-500)

            append_csv_row "$CSV_LOGS" "$TIMESTAMP" "N/A" "$UNIT" "$MESSAGE"
            ((LOG_COUNT++))
        done < <(tail -5000 "$LOG_FILE" 2>/dev/null)

        COLLECTED_ITEMS+=("Event Logs (${LOG_COUNT} entries from syslog)")
    else
        print_yellow "  Cannot read log file (permission denied)"
        WARNINGS+=("Log collection limited - permission denied")
    fi
else
    print_yellow "  No supported log system found"
    WARNINGS+=("Log collection unavailable")
fi
#endregion

#region DISA SCC Scan
if [ "$RUN_SCC" = true ]; then
    print_green "Setting up DISA SCC (SCAP Compliance Checker)..."

    # Setup SCC - returns path to executable or empty string on failure
    SCC_EXE=$(setup_scc "$SCRIPT_DIR" "$SCAN_SAVE_DIR")

    if [ -n "$SCC_EXE" ] && [ -x "$SCC_EXE" ]; then
        run_scc_scan "$SCC_EXE" "$SCAN_SAVE_DIR"
        if [ $? -eq 0 ]; then
            COLLECTED_ITEMS+=("DISA SCC Compliance Scan")
        else
            WARNINGS+=("DISA SCC scan completed with warnings")
        fi
    else
        print_red "Failed to setup SCC"
        WARNINGS+=("DISA SCC scan skipped - setup failed")
    fi
fi
#endregion

#region OpenSCAP Scan
if [ "$RUN_SCAP" = true ]; then
    if command_exists oscap && [ -n "$SCAP_PROFILE" ] && [ -f "$SCAP_PROFILE" ]; then
        print_green "Running OpenSCAP: This may take a while..."

        SCAP_SAVE_DIR="${SCAN_SAVE_DIR}/SCAP"
        mkdir -p "$SCAP_SAVE_DIR"

        SCAP_RESULTS="${SCAP_SAVE_DIR}/scap-results.xml"
        SCAP_REPORT="${SCAP_SAVE_DIR}/scap-report.html"

        # Get the first available profile from the datastream
        PROFILE_ID=$(oscap info "$SCAP_PROFILE" 2>/dev/null | grep -oP 'Id:\s+\K\S+' | head -1)

        if [ -n "$PROFILE_ID" ]; then
            oscap xccdf eval --profile "$PROFILE_ID" --results "$SCAP_RESULTS" --report "$SCAP_REPORT" "$SCAP_PROFILE" 2>/dev/null

            if [ -f "$SCAP_RESULTS" ]; then
                print_green "OpenSCAP scan complete!"
                COLLECTED_ITEMS+=("OpenSCAP Compliance Scan")
            else
                print_yellow "OpenSCAP scan may have encountered issues"
                WARNINGS+=("OpenSCAP scan completed with warnings")
            fi
        else
            print_red "Could not determine SCAP profile ID"
            WARNINGS+=("OpenSCAP scan skipped - no profile found")
        fi
    else
        if [ "$RUN_SCAP" = true ]; then
            if ! command_exists oscap; then
                print_red "OpenSCAP (oscap) not installed"
                WARNINGS+=("OpenSCAP scan skipped - oscap not installed")
            elif [ -z "$SCAP_PROFILE" ] || [ ! -f "$SCAP_PROFILE" ]; then
                print_red "SCAP profile not found: $SCAP_PROFILE"
                WARNINGS+=("OpenSCAP scan skipped - profile not found")
            fi
        fi
    fi
fi
#endregion

#region Fix Permissions
print_green "Setting Permissions on Output Directory"
chmod -R 755 "$SCAN_SAVE_DIR" 2>/dev/null || true
#endregion

#region Summary Report
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
DURATION_MIN=$(echo "scale=2; $DURATION / 60" | bc 2>/dev/null || echo "$((DURATION / 60))")

echo ""
print_cyan "========================================================"
print_cyan "             MOAS SCAN SUMMARY REPORT"
print_cyan "========================================================"
echo ""
print_white "  Computer Name:    ${HOSTNAME}"
print_white "  Scan Date:        $(date '+%Y-%m-%d %H:%M:%S')"
print_white "  Duration:         ${DURATION_MIN} minutes"
print_white "  Output Directory: ${SCAN_SAVE_DIR}"
echo ""

print_green "  Data Collected:"
for item in "${COLLECTED_ITEMS[@]}"; do
    print_green "    [+] ${item}"
done
echo ""

# List output files
print_cyan "  Output Files:"
for file in "$SCAN_SAVE_DIR"/*; do
    if [ -f "$file" ]; then
        FILENAME=$(basename "$file")
        SIZE_KB=$(du -k "$file" 2>/dev/null | cut -f1)
        print_white "    - ${FILENAME} (${SIZE_KB} KB)"
    fi
done
echo ""

# Show warnings if any
if [ ${#WARNINGS[@]} -gt 0 ]; then
    print_yellow "  Warnings:"
    for warning in "${WARNINGS[@]}"; do
        print_yellow "    [!] ${warning}"
    done
    echo ""
fi

# Root status reminder
if [ "$IS_ROOT" = false ]; then
    print_yellow "  Note: Script ran without root privileges."
    print_yellow "        Some data may be incomplete."
    echo ""
fi

print_cyan "========================================================"
print_cyan "                    SCAN COMPLETE"
print_cyan "========================================================"
echo ""
#endregion
