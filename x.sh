#!/usr/bin/env bash
#===============================================================================
# OPENBSD + MIRAGE FIREWALL INSTALLER
#===============================================================================

set -euo pipefail
set -E
export LC_ALL=C

umask 027

readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_NAME="$(basename "$0")"

#===============================================================================
# PATHS
#===============================================================================

readonly LOG_FILE="/var/log/openbsd-mirage-installer.log"
readonly STATE_DIR="/var/lib/openbsd-mirage"
readonly LOCK_FILE="/var/run/openbsd-mirage-installer.lock"
readonly MIRAGE_INSTALL_DIR="/var/lib/qubes/vm-kernels/mirage-firewall"
readonly OPENBSD_SCRIPTS_DIR="/var/lib/openbsd-mirage/scripts"
readonly OPENBSD_LOGS_DIR="/var/lib/openbsd-mirage/logs"
readonly SNAPSHOT_NAME="clean-install"

#===============================================================================
# MIRAGE CONFIGURATION
#===============================================================================

readonly MIRAGE_RELEASE="v0.9.5"
readonly MIRAGE_FILENAME="qubes-firewall.xen"
readonly MIRAGE_CHECKSUM_FILE="qubes-firewall-release.sha256"
readonly MIRAGE_EXPECTED_HASH="2bfb49696e59a8ffbb660399e52bd82ffadbd02437d282eb8daab568b3261999"
readonly MIRAGE_GITHUB_URL="https://github.com/mirage/qubes-mirage-firewall"

#===============================================================================
# OPENBSD CONFIGURATION
#===============================================================================

readonly OPENBSD_VERSION="7.8"
readonly OPENBSD_ISO="install78.iso"
readonly OPENBSD_MIRROR="https://cdn.openbsd.org/pub/OpenBSD/7.8/amd64/install78.iso"

#===============================================================================
# DEFAULT CONFIG
#===============================================================================

OPENBSD_VM="sys-openbsd"
MIRAGE_TEMPLATE="mirage-tmpl"
MIRAGE_DVM_TEMPLATE="mirage-dvm"
MIRAGE_FW="sys-mirage-fw"
DOWNLOAD_VM="personal"
NET_DEVICE=""

DRY_RUN="false"
SKIP_OPENBSD_DOWNLOAD="false"
SKIP_MIRAGE="false"
SKIP_OPENBSD="false"
QUIET="false"

#===============================================================================
# COLORS + LOGGING
#===============================================================================

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

log_init() {
    mkdir -p "$(dirname "$LOG_FILE")" "$STATE_DIR" "$OPENBSD_SCRIPTS_DIR" "$OPENBSD_LOGS_DIR"
    chmod 750 "$STATE_DIR" 2>/dev/null || true
    {
        echo "==============================================================================="
        echo "OPENBSD+MIRAGE INSTALLER v${SCRIPT_VERSION} Started: $(date -Iseconds)"
        echo "Mode: DRY_RUN=$DRY_RUN QUIET=$QUIET"
        echo "PID: $$"
        echo "==============================================================================="
    } >> "$LOG_FILE"
}

log_info() {
    [[ "$QUIET" != "true" ]] && echo -e "${GREEN}[+]${NC} $1"
    echo "[$(date '+%H:%M:%S')] [INFO] $1" >> "$LOG_FILE"
}

log_warn() {
    [[ "$QUIET" != "true" ]] && echo -e "${YELLOW}[!]${NC} $1" >&2
    echo "[$(date '+%H:%M:%S')] [WARN] $1" >> "$LOG_FILE"
}

log_error() {
    echo -e "${BOLD}${RED}[-]${NC} $1" >&2
    echo "[$(date '+%H:%M:%S')] [ERROR] $1" >> "$LOG_FILE"
}

log_fatal() {
    echo -e "${BOLD}${RED}[FATAL]${NC} $1" >&2
    echo "[$(date '+%H:%M:%S')] [FATAL] $1" >> "$LOG_FILE"
}

log_debug() {
    echo "[$(date '+%H:%M:%S')] [DEBUG] $1" >> "$LOG_FILE"
}

log_section() {
    [[ "$QUIET" == "true" ]] && { echo "=== $1 ===" >> "$LOG_FILE"; return 0; }
    echo ""
    echo -e "${CYAN}${BOLD}+==================================================================+${NC}"
    printf "${CYAN}${BOLD}|${NC}  %-62s ${CYAN}${BOLD}|${NC}\n" "$1"
    echo -e "${CYAN}${BOLD}+==================================================================+${NC}"
    echo "=== $1 ===" >> "$LOG_FILE"
}

die() {
    log_fatal "${1:-Critical error}"
    exit "${2:-1}"
}

#===============================================================================
# TRAPS / LOCK / UTILS
#===============================================================================

cleanup() {
    local rc=$?
    rm -f "$LOCK_FILE" 2>/dev/null || true
    if (( rc != 0 )); then
        echo "[$(date '+%H:%M:%S')] Script exited with code $rc" >> "$LOG_FILE"
    fi
}

error_handler() {
    local line="${1:-0}"
    local code="${2:-1}"
    local cmd="${3:-${BASH_COMMAND:-}}"
    log_fatal "Error at line $line (exit $code): $cmd"
}

trap cleanup EXIT
trap 'error_handler ${LINENO} $? "${BASH_COMMAND}"' ERR
trap 'log_warn "Interrupted by user"; exit 130' INT
trap 'log_warn "Terminated"; exit 143' TERM

check_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local pid
        pid="$(cat "$LOCK_FILE" 2>/dev/null || true)"
        if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
            die "Script already running (PID: $pid)"
        fi
        log_warn "Stale lock file found, removing..."
        rm -f "$LOCK_FILE" || true
    fi
    echo $$ > "$LOCK_FILE"
}

require_dom0() {
    [[ "$(hostname)" == "dom0" ]] || die "This script must be run in dom0"
}

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

run_cmd() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] $*"
        return 0
    fi
    "$@"
}

#===============================================================================
# CLI
#===============================================================================

print_usage() {
    cat <<EOF
OPENBSD + MIRAGE FIREWALL INSTALLER v$SCRIPT_VERSION

Usage:
    sudo bash ./$SCRIPT_NAME <command> [options]

Commands:
    install                  Full installation
    snapshot-create          Create OpenBSD snapshot (after clean install)
    snapshot-reset           Reset OpenBSD to clean snapshot
    snapshot-status          Show snapshot information
    snapshot-delete          Remove snapshot
    help                     This help

Install Options:
    --dry-run                Show actions without applying
    --skip-mirage            Skip Mirage Firewall installation
    --skip-openbsd           Skip OpenBSD VM creation
    --skip-openbsd-download  Skip OpenBSD ISO download
    --download-vm <vm>       VM for downloads (default: sys-firewall)
    --openbsd-vm <name>      OpenBSD VM name (default: sys-openbsd)
    --mirage-vm <name>       Mirage VM name (default: sys-mirage-fw)
    --net-device <bdf>       PCI device BDF (e.g., 00:14.3)
    --quiet                  Less output

Schema:
    Internet -> [OpenBSD/pf] -> [Mirage DispVM] -> [AppVMs]

Examples:
    sudo ./$SCRIPT_NAME install
    sudo ./$SCRIPT_NAME install --net-device 00:14.3
    sudo ./$SCRIPT_NAME snapshot-create
    sudo ./$SCRIPT_NAME snapshot-reset
EOF
}

#===============================================================================
# PREFLIGHT
#===============================================================================

preflight_checks() {
    log_section "PREFLIGHT"

    require_dom0
    log_info "Running in dom0"

    if ! qvm-check "$DOWNLOAD_VM" &>/dev/null; then
        die "Download VM '$DOWNLOAD_VM' does not exist"
    fi
    log_info "Download VM: $DOWNLOAD_VM"

    local required_cmds=(qvm-create qvm-prefs qvm-run qvm-features qvm-volume lvs lvcreate)
    for cmd in "${required_cmds[@]}"; do
        has_cmd "$cmd" || die "Required command not found: $cmd"
    done
    log_info "Required commands available"

    if ! qvm-run -a --pass-io --no-gui "$DOWNLOAD_VM" "command -v curl" &>/dev/null; then
        die "curl not found in $DOWNLOAD_VM"
    fi
    log_info "curl available in download VM"
}

#===============================================================================
# NETWORK DEVICE
#===============================================================================

detect_net_device() {
    log_section "NETWORK DEVICE"

    if [[ -n "$NET_DEVICE" ]]; then
        log_info "Using specified device: $NET_DEVICE"
        return 0
    fi

    log_info "Available PCI network devices:"
    lspci | grep -iE "network|ethernet" | head -10 | while read -r line; do
        echo "    $line"
    done

    echo ""
    read -r -p "Enter device BDF (e.g., 00:14.3) or Enter to skip: " NET_DEVICE

    if [[ -z "$NET_DEVICE" ]]; then
        log_warn "No device selected. Attach manually later."
    else
        log_info "Selected: $NET_DEVICE"
    fi
}

#===============================================================================
# MIRAGE KERNEL
#===============================================================================

install_mirage_kernel() {
    log_section "MIRAGE KERNEL"

    if [[ "$SKIP_MIRAGE" == "true" ]]; then
        log_warn "Skipping (--skip-mirage)"
        return 0
    fi

    log_info "Downloading Mirage Firewall $MIRAGE_RELEASE..."
    run_cmd qvm-run -a --pass-io --no-gui "$DOWNLOAD_VM" \
        "curl -sLO ${MIRAGE_GITHUB_URL}/releases/download/${MIRAGE_RELEASE}/${MIRAGE_FILENAME}" || \
        die "Download failed"

    log_info "Downloading checksum..."
    run_cmd qvm-run -a --pass-io --no-gui "$DOWNLOAD_VM" \
        "curl -sLO ${MIRAGE_GITHUB_URL}/releases/download/${MIRAGE_RELEASE}/${MIRAGE_CHECKSUM_FILE}" || \
        die "Checksum download failed"

    log_info "Verifying checksum..."
    local actual_hash
    actual_hash=$(qvm-run -a --pass-io --no-gui "$DOWNLOAD_VM" \
        "sha256sum $MIRAGE_FILENAME | cut -d' ' -f1" | tr -d '[:space:]')

    if [[ "$actual_hash" != "$MIRAGE_EXPECTED_HASH" ]]; then
        die "Checksum mismatch: expected $MIRAGE_EXPECTED_HASH, got $actual_hash"
    fi
    log_info "Checksum OK"

    log_info "Installing to dom0..."
    if [[ "$DRY_RUN" != "true" ]]; then
        mkdir -p "$MIRAGE_INSTALL_DIR"
        qvm-run --pass-io --no-gui "$DOWNLOAD_VM" "cat $MIRAGE_FILENAME" > "$MIRAGE_INSTALL_DIR/vmlinuz"
        gzip -n9 < /dev/null > "$MIRAGE_INSTALL_DIR/initramfs"
    fi
    log_info "Installed to $MIRAGE_INSTALL_DIR"

    log_info "Cleanup..."
    run_cmd qvm-run -a --pass-io --no-gui "$DOWNLOAD_VM" "rm -f $MIRAGE_FILENAME $MIRAGE_CHECKSUM_FILE"
}

#===============================================================================
# OPENBSD ISO
#===============================================================================

download_openbsd_iso() {
    log_section "OPENBSD ISO"

    if [[ "$SKIP_OPENBSD_DOWNLOAD" == "true" ]]; then
        log_warn "Skipping (--skip-openbsd-download)"
        return 0
    fi

    log_info "Downloading OpenBSD $OPENBSD_VERSION (~700MB)..."
    run_cmd qvm-run -a --pass-io --no-gui "$DOWNLOAD_VM" \
        "curl -LO ${OPENBSD_MIRROR}/${OPENBSD_ISO}" || \
        die "ISO download failed"

    log_info "Downloading checksums..."
    run_cmd qvm-run -a --pass-io --no-gui "$DOWNLOAD_VM" \
        "curl -sLO ${OPENBSD_MIRROR}/SHA256" || \
        die "Checksum download failed"

    log_info "Verifying ISO..."
    local expected actual
    expected=$(qvm-run -a --pass-io --no-gui "$DOWNLOAD_VM" \
        "grep '($OPENBSD_ISO)' SHA256 | awk '{print \$4}'" | tr -d '[:space:]')
    actual=$(qvm-run -a --pass-io --no-gui "$DOWNLOAD_VM" \
        "sha256sum $OPENBSD_ISO | cut -d' ' -f1" | tr -d '[:space:]')

    if [[ "$actual" != "$expected" ]]; then
        die "ISO checksum mismatch"
    fi
    log_info "ISO checksum OK"
}

#===============================================================================
# OPENBSD VM
#===============================================================================

create_openbsd_vm() {
    log_section "OPENBSD VM"

    if [[ "$SKIP_OPENBSD" == "true" ]]; then
        log_warn "Skipping (--skip-openbsd)"
        return 0
    fi

    if qvm-check "$OPENBSD_VM" &>/dev/null; then
        log_warn "VM '$OPENBSD_VM' exists"
        read -r -p "Delete and recreate? [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            run_cmd qvm-kill "$OPENBSD_VM" 2>/dev/null || true
            run_cmd qvm-remove -f "$OPENBSD_VM"
        else
            die "Aborted"
        fi
    fi

    log_info "Creating $OPENBSD_VM..."
    run_cmd qvm-create \
        --class StandaloneVM \
        --property virt_mode=hvm \
        --property kernel='' \
        --property memory=512 \
        --property maxmem=512 \
        --property vcpus=2 \
        --property provides_network=True \
        --label=orange \
        "$OPENBSD_VM"

    log_info "Configuring VM..."
    run_cmd qvm-prefs "$OPENBSD_VM" netvm ''
    run_cmd qvm-volume resize "$OPENBSD_VM:root" 10G

    if [[ -n "$NET_DEVICE" ]]; then
        log_info "Attaching $NET_DEVICE..."
        if [[ "$DRY_RUN" != "true" ]]; then
            qvm-pci attach --persistent "$OPENBSD_VM" "dom0:${NET_DEVICE//:/_}" 2>/dev/null || \
                log_warn "Attach failed. Do it manually."
        fi
    fi

    log_info "Created: $OPENBSD_VM"
}

#===============================================================================
# MIRAGE DISPVM (DISPOSABLE)
#===============================================================================

create_mirage_dispvm() {
    log_section "MIRAGE DISPVM"

    if [[ "$SKIP_MIRAGE" == "true" ]]; then
        log_warn "Skipping (--skip-mirage)"
        return 0
    fi

    # Remove existing VMs if they exist
    for vm in "$MIRAGE_FW" "$MIRAGE_DVM_TEMPLATE" "$MIRAGE_TEMPLATE"; do
        if qvm-check "$vm" &>/dev/null; then
            log_warn "VM '$vm' exists"
            read -r -p "Delete and recreate? [y/N]: " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                run_cmd qvm-kill "$vm" 2>/dev/null || true
                run_cmd qvm-remove -f "$vm"
            else
                die "Aborted"
            fi
        fi
    done

    # Create Template VM
    log_info "Creating TemplateVM: $MIRAGE_TEMPLATE..."
    run_cmd qvm-create \
        --property kernel=mirage-firewall \
        --property kernelopts='' \
        --property memory=64 \
        --property maxmem=64 \
        --property vcpus=1 \
        --property virt_mode=pvh \
        --label=black \
        --class TemplateVM \
        "$MIRAGE_TEMPLATE"

    # Create Disposable Template
    log_info "Creating Disposable Template: $MIRAGE_DVM_TEMPLATE..."
    run_cmd qvm-create \
        --property template="$MIRAGE_TEMPLATE" \
        --property provides_network=True \
        --property template_for_dispvms=True \
        --label=orange \
        --class AppVM \
        "$MIRAGE_DVM_TEMPLATE"

    run_cmd qvm-features "$MIRAGE_DVM_TEMPLATE" qubes-firewall 1
    run_cmd qvm-features "$MIRAGE_DVM_TEMPLATE" no-default-kernelopts 1

    # Create Disposable Firewall VM
    log_info "Creating DispVM Firewall: $MIRAGE_FW..."
    run_cmd qvm-create \
        --property template="$MIRAGE_DVM_TEMPLATE" \
        --property provides_network=True \
        --property netvm='' \
        --label=orange \
        --class DispVM \
        "$MIRAGE_FW"

    log_info "Created Mirage DispVM chain:"
    log_info "  - $MIRAGE_TEMPLATE (TemplateVM - don't start)"
    log_info "  - $MIRAGE_DVM_TEMPLATE (Disposable Template)"
    log_info "  - $MIRAGE_FW (Disposable Firewall)"
}

#===============================================================================
# NETWORK TOPOLOGY
#===============================================================================

configure_topology() {
    log_section "NETWORK TOPOLOGY"

    if [[ "$SKIP_MIRAGE" == "true" ]] || [[ "$SKIP_OPENBSD" == "true" ]]; then
        log_warn "Skipping (VMs not created)"
        return 0
    fi

    log_info "Schema: Internet -> [$OPENBSD_VM] -> [$MIRAGE_FW] -> [AppVMs]"

    log_info "Setting $MIRAGE_FW netvm to $OPENBSD_VM..."
    run_cmd qvm-prefs "$MIRAGE_FW" netvm "$OPENBSD_VM"

    if [[ "$DRY_RUN" != "true" ]]; then
        sleep 2
        local mirage_ip openbsd_ip
        mirage_ip=$(qvm-prefs "$MIRAGE_FW" ip 2>/dev/null || echo "10.137.0.X")
        openbsd_ip=$(qvm-ls -n "$OPENBSD_VM" 2>/dev/null | tail -1 | awk '{print $4}' || echo "10.137.0.Y")

        log_info "Mirage IP: $mirage_ip"
        log_info "OpenBSD IP: $openbsd_ip"

        qvm-prefs --set "$MIRAGE_FW" -- kernelopts "--ipv4=$mirage_ip --ipv4-gw=$openbsd_ip" 2>/dev/null || \
            log_warn "kernelopts not set. Configure after OpenBSD boots."
    fi

    log_info "Topology configured"
}

#===============================================================================
# OPENBSD SCRIPTS
#===============================================================================

generate_openbsd_scripts() {
    log_section "OPENBSD SCRIPTS"

    mkdir -p "$OPENBSD_SCRIPTS_DIR"

    # Network setup script
    cat > "$OPENBSD_SCRIPTS_DIR/network-setup.sh" << 'EOF'
#!/bin/sh
# OpenBSD Network Setup for Qubes
# Configure variables below, then run as root

MIRAGE_IP="10.137.0.X"          # From: qvm-ls -n sys-mirage-fw
EXTERNAL_IF="em0"                # Physical NIC
INTERNAL_IF="xnf0"               # Xen interface
DNS="9.9.9.9"

echo "=== OpenBSD Network Setup ==="

sysctl net.inet.ip.forwarding=1
echo "net.inet.ip.forwarding=1" >> /etc/sysctl.conf

dhclient $EXTERNAL_IF
ifconfig $INTERNAL_IF $MIRAGE_IP netmask 255.255.255.0 up

echo "dhcp" > /etc/hostname.$EXTERNAL_IF
echo "inet $MIRAGE_IP 255.255.255.0 NONE" > /etc/hostname.$INTERNAL_IF
echo "nameserver $DNS" > /etc/resolv.conf

echo "Done. External: $EXTERNAL_IF, Internal: $INTERNAL_IF ($MIRAGE_IP)"
EOF

    # pf setup script
    cat > "$OPENBSD_SCRIPTS_DIR/pf-setup.sh" << 'EOF'
#!/bin/sh
# OpenBSD pf Firewall Setup

EXTERNAL_IF="em0"
INTERNAL_IF="xnf0"
INTERNAL_NET="10.137.0.0/16"

echo "=== OpenBSD pf Setup ==="

cp /etc/pf.conf /etc/pf.conf.backup 2>/dev/null

cat > /etc/pf.conf << PFCONF
ext_if = "$EXTERNAL_IF"
int_if = "$INTERNAL_IF"
internal_net = "$INTERNAL_NET"

set skip on lo
set block-policy drop
set loginterface \$ext_if

match in all scrub (no-df random-id)
match out on \$ext_if from \$internal_net to any nat-to (\$ext_if)

block log all
pass quick on lo0
pass in on \$int_if from \$internal_net to any
pass out on \$ext_if from any to any
pass in on \$ext_if proto { tcp, udp, icmp } from any to any keep state
pass inet proto icmp all
PFCONF

pfctl -e 2>/dev/null || true
pfctl -f /etc/pf.conf
echo "pf=YES" >> /etc/rc.conf.local 2>/dev/null || true

echo "pf configured. Check: pfctl -sr"
EOF

    # Boot script for rc.local
    cat > "$OPENBSD_SCRIPTS_DIR/rc.local-addition.sh" << 'EOF'
#!/bin/sh
# Add to /etc/rc.local

MIRAGE_IP="10.137.0.X"
INTERNAL_IF="xnf0"

sleep 2
ifconfig $INTERNAL_IF $MIRAGE_IP netmask 255.255.255.0 up
sysctl -w net.inet.ip.forwarding=1
pfctl -f /etc/pf.conf
EOF

    chmod +x "$OPENBSD_SCRIPTS_DIR"/*.sh
    log_info "Scripts created in $OPENBSD_SCRIPTS_DIR"
}

#===============================================================================
# SNAPSHOT FUNCTIONS
#===============================================================================

snapshot_create() {
    log_section "CREATE SNAPSHOT"

    if ! qvm-check "$OPENBSD_VM" &>/dev/null; then
        die "VM '$OPENBSD_VM' does not exist"
    fi

    if qvm-check --running "$OPENBSD_VM" 2>/dev/null; then
        log_warn "Shutting down $OPENBSD_VM..."
        qvm-shutdown --wait "$OPENBSD_VM"
        sleep 3
    fi

    # Find LVM volume
    local lv_path
    lv_path=$(lvs --noheadings -o lv_path 2>/dev/null | grep "$OPENBSD_VM" | grep -E "root$" | head -1 | tr -d ' ')

    if [[ -z "$lv_path" ]]; then
        # Try alternative naming
        lv_path=$(lvs --noheadings -o lv_path 2>/dev/null | grep "$OPENBSD_VM" | grep -E "private|root" | head -1 | tr -d ' ')
    fi

    if [[ -z "$lv_path" ]]; then
        die "Cannot find LVM volume for $OPENBSD_VM"
    fi

    log_info "LVM path: $lv_path"

    # Check if snapshot already exists
    local snap_exists
    snap_exists=$(lvs --noheadings -o lv_name 2>/dev/null | grep "${OPENBSD_VM}-${SNAPSHOT_NAME}" | tr -d ' ' || true)

    if [[ -n "$snap_exists" ]]; then
        log_warn "Snapshot already exists"
        read -r -p "Delete and recreate? [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            local old_snap
            old_snap=$(lvs --noheadings -o lv_path 2>/dev/null | grep "${OPENBSD_VM}-${SNAPSHOT_NAME}" | tr -d ' ')
            lvremove -f "$old_snap" || die "Failed to remove old snapshot"
            log_info "Old snapshot removed"
        else
            die "Aborted"
        fi
    fi

    log_info "Creating snapshot..."
    lvcreate -s -n "${OPENBSD_VM}-${SNAPSHOT_NAME}" -L 10G "$lv_path" || \
        die "Failed to create snapshot"

    log_info "Snapshot created: ${OPENBSD_VM}-${SNAPSHOT_NAME}"
    log_info "You can now reset anytime with: $SCRIPT_NAME snapshot-reset"
}

snapshot_reset() {
    log_section "RESET TO SNAPSHOT"

    log_warn "This will DESTROY all changes in $OPENBSD_VM!"
    read -r -p "Continue? [y/N]: " confirm

    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "Aborted"
        return 0
    fi

    # Backup logs before reset
    log_info "Backing up pf logs..."
    local backup_dir="$OPENBSD_LOGS_DIR/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$backup_dir"

    if qvm-check --running "$OPENBSD_VM" 2>/dev/null; then
        qvm-run --pass-io "$OPENBSD_VM" "cat /var/log/pflog" > "$backup_dir/pflog" 2>/dev/null || true
        qvm-run --pass-io "$OPENBSD_VM" "cat /var/log/messages" > "$backup_dir/messages" 2>/dev/null || true
        qvm-run --pass-io "$OPENBSD_VM" "cat /var/log/authlog" > "$backup_dir/authlog" 2>/dev/null || true
        log_info "Logs saved to $backup_dir"
    fi

    log_info "Stopping VMs..."
    qvm-shutdown --wait "$MIRAGE_FW" 2>/dev/null || true
    qvm-shutdown --wait "$OPENBSD_VM" 2>/dev/null || true
    sleep 3

    # Find volumes
    local lv_path snap_path
    lv_path=$(lvs --noheadings -o lv_path 2>/dev/null | grep "$OPENBSD_VM" | grep -v "$SNAPSHOT_NAME" | grep -E "root$|private$" | head -1 | tr -d ' ')
    snap_path=$(lvs --noheadings -o lv_path 2>/dev/null | grep "${OPENBSD_VM}-${SNAPSHOT_NAME}" | tr -d ' ')

    if [[ -z "$snap_path" ]]; then
        die "Snapshot not found. Run '$SCRIPT_NAME snapshot-create' first."
    fi

    log_info "Restoring from snapshot..."
    log_info "  Volume: $lv_path"
    log_info "  Snapshot: $snap_path"

    # Merge snapshot (restores original state)
    lvconvert --merge "$snap_path" || die "Failed to restore snapshot"

    log_info "Reset complete!"
    log_warn "Snapshot was consumed. Create new one after boot:"
    log_warn "  sudo $SCRIPT_NAME snapshot-create"

    log_info "Starting VMs..."
    qvm-start "$OPENBSD_VM" || log_warn "Could not start $OPENBSD_VM"
    sleep 5
    qvm-start "$MIRAGE_FW" || log_warn "Could not start $MIRAGE_FW"
}

snapshot_status() {
    log_section "SNAPSHOT STATUS"

    log_info "Looking for snapshots..."
    echo ""
    lvs 2>/dev/null | grep -E "$OPENBSD_VM|LV" || log_warn "No volumes found"
    echo ""

    local snap_path
    snap_path=$(lvs --noheadings -o lv_path 2>/dev/null | grep "${OPENBSD_VM}-${SNAPSHOT_NAME}" | tr -d ' ' || true)

    if [[ -n "$snap_path" ]]; then
        log_info "Snapshot exists: $snap_path"
        log_info "To reset: sudo $SCRIPT_NAME snapshot-reset"
    else
        log_warn "No snapshot found"
        log_info "To create: sudo $SCRIPT_NAME snapshot-create"
    fi

    echo ""
    log_info "Saved logs in: $OPENBSD_LOGS_DIR"
    ls -la "$OPENBSD_LOGS_DIR" 2>/dev/null || true
}

snapshot_delete() {
    log_section "DELETE SNAPSHOT"

    local snap_path
    snap_path=$(lvs --noheadings -o lv_path 2>/dev/null | grep "${OPENBSD_VM}-${SNAPSHOT_NAME}" | tr -d ' ' || true)

    if [[ -z "$snap_path" ]]; then
        log_warn "No snapshot found"
        return 0
    fi

    log_warn "Deleting snapshot: $snap_path"
    read -r -p "Continue? [y/N]: " confirm

    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        lvremove -f "$snap_path" || die "Failed to delete snapshot"
        log_info "Snapshot deleted"
    else
        log_info "Aborted"
    fi
}

#===============================================================================
# SUMMARY
#===============================================================================

print_summary() {
    log_section "COMPLETE"

    log_info "VMs created:"
    log_info "  - $OPENBSD_VM (OpenBSD HVM - persistent)"
    log_info "  - $MIRAGE_TEMPLATE (Mirage TemplateVM - don't start)"
    log_info "  - $MIRAGE_DVM_TEMPLATE (Mirage Disposable Template)"
    log_info "  - $MIRAGE_FW (Mirage DispVM Firewall - disposable)"

    log_info ""
    log_info "Network schema:"
    log_info "  Internet -> [$OPENBSD_VM] -> [$MIRAGE_FW] -> [AppVMs]"

    log_info ""
    log_info "Next steps:"
    log_info "  1. Boot OpenBSD from ISO:"
    log_info "     qvm-start $OPENBSD_VM --cdrom=$DOWNLOAD_VM:/home/user/$OPENBSD_ISO"
    log_info ""
    log_info "  2. Install OpenBSD (interface: xnf0, disk: sd0, MBR)"
    log_info ""
    log_info "  3. Run scripts from $OPENBSD_SCRIPTS_DIR"
    log_info ""
    log_info "  4. Create snapshot of clean OpenBSD:"
    log_info "     sudo $SCRIPT_NAME snapshot-create"
    log_info ""
    log_info "  5. Set AppVMs netvm:"
    log_info "     qvm-prefs <appvm> netvm $MIRAGE_FW"
    log_info ""
    log_info "  6. To reset OpenBSD later:"
    log_info "     sudo $SCRIPT_NAME snapshot-reset"

    log_info ""
    log_info "Log: $LOG_FILE"
}

#===============================================================================
# MAIN
#===============================================================================

main() {
    local command="${1:-}"

    case "$command" in
        install)
            shift
            # Parse remaining args
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --dry-run) DRY_RUN="true"; shift ;;
                    --skip-mirage) SKIP_MIRAGE="true"; shift ;;
                    --skip-openbsd) SKIP_OPENBSD="true"; shift ;;
                    --skip-openbsd-download) SKIP_OPENBSD_DOWNLOAD="true"; shift ;;
                    --download-vm) DOWNLOAD_VM="$2"; shift 2 ;;
                    --openbsd-vm) OPENBSD_VM="$2"; shift 2 ;;
                    --mirage-vm) MIRAGE_FW="$2"; shift 2 ;;
                    --net-device) NET_DEVICE="$2"; shift 2 ;;
                    --quiet) QUIET="true"; shift ;;
                    *) die "Unknown option: $1" ;;
                esac
            done

            log_init
            check_lock
            preflight_checks
            detect_net_device
            install_mirage_kernel
            download_openbsd_iso
            create_openbsd_vm
            create_mirage_dispvm
            configure_topology
            generate_openbsd_scripts
            print_summary
            ;;

        snapshot-create)
            log_init
            snapshot_create
            ;;

        snapshot-reset)
            log_init
            snapshot_reset
            ;;

        snapshot-status)
            log_init
            snapshot_status
            ;;

        snapshot-delete)
            log_init
            snapshot_delete
            ;;

        help|--help|-h)
            print_usage
            ;;

        "")
            print_usage
            ;;

        *)
            echo "Unknown command: $command"
            echo "Use '$SCRIPT_NAME help' for usage"
            exit 1
            ;;
    esac
}

main "$@"
