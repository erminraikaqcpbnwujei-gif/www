#!/usr/bin/env bash
#===============================================================================
# REALLY DISPOSABLE (RAM-BASED)
#===============================================================================

set -euo pipefail
set -E
export LC_ALL=C

umask 027

readonly SCRIPT_VERSION="1.1.0"
readonly SCRIPT_NAME="$(basename "$0")"

#===============================================================================
# PATHS
#===============================================================================

readonly LOG_FILE="/var/log/ram-disposable.log"
readonly STATE_DIR="/var/lib/ram-disposable"
readonly LOCK_FILE="/var/run/ram-disposable.lock"
readonly TEMPDIR_ROOT="${HOME}/tmp"
readonly LOGDIR="/var/log"

#===============================================================================
# DEFAULT CONFIGURATION
#===============================================================================

QUBE_NAME=""
TEMPLATE=""
COMMAND_TO_RUN=""
NETVM=""
TEMPSIZE="1G"
MEMORY="400"
LABEL="gray"
RAM_TEMPLATE=""
DEFAULT_DISPVM=""
POOL_NAME=""
TEMPDIR=""

DRY_RUN="false"
QUIET="false"
AUTO_LABEL="true"
DISABLE_TRACKER="true"
DISABLE_RECENT_FILES="true"
DISABLE_THUMBNAILS="true"
HARDENED_MODE="true"

#===============================================================================
# COLORS + LOGGING
#===============================================================================

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly PURPLE='\033[1;35m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

log_init() {
    mkdir -p "$(dirname "$LOG_FILE")" "$STATE_DIR" "$TEMPDIR_ROOT" 2>/dev/null || true
    chmod 750 "$STATE_DIR" 2>/dev/null || true
    {
        echo "==============================================================================="
        echo "RAM-DISPOSABLE v${SCRIPT_VERSION} Started: $(date -Iseconds)"
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
    notify_send "Error" "$1" "dialog-error"
}

log_fatal() {
    echo -e "${BOLD}${RED}[FATAL]${NC} $1" >&2
    echo "[$(date '+%H:%M:%S')] [FATAL] $1" >> "$LOG_FILE"
    notify_send "Fatal Error" "$1" "dialog-error"
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

notify_send() {
    local title="$1"
    local message="$2"
    local icon="${3:-dialog-information}"
    
    notify-send --expire-time 5000 \
        --icon="/usr/share/icons/Adwaita/256x256/legacy/${icon}.png" \
        "$title" "$message" 2>/dev/null || true
}

die() {
    log_fatal "${1:-Critical error}"
    exit "${2:-1}"
}

#===============================================================================
# TRAPS / LOCK / UTILS
#===============================================================================

cleanup_on_exit() {
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

trap cleanup_on_exit EXIT
trap 'error_handler ${LINENO} $? "${BASH_COMMAND}"' ERR
trap 'log_warn "Interrupted by user"; exit 130' INT
trap 'log_warn "Terminated"; exit 143' TERM

check_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local pid
        pid="$(cat "$LOCK_FILE" 2>/dev/null || true)"
        if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
            die "Another instance is running (PID: $pid). Wait or remove $LOCK_FILE"
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
${BOLD}RAM-BASED DISPOSABLE QUBES MANAGER v$SCRIPT_VERSION${NC}

Creates truly disposable qubes that run entirely in RAM.
No traces left on disk - everything vanishes after shutdown.
File indexing, recent files, and thumbnails are disabled.

${BOLD}Usage:${NC}
    $SCRIPT_NAME <command> [options]

${BOLD}Commands:${NC}
    launch              Create and run a RAM-based disposable qube
    cleanup             Clean up remnants from crashed/killed qubes
    list                List active RAM-based qubes
    pool-usage          Show RAM pool and volume usage
    help                This help

${BOLD}Launch Options:${NC}
    -t, --template <vm>       Template VM (required, must be a DVM template)
    -c, --command <cmd>       Command to execute (required)
    -q, --qubename <name>     Custom qube name [default: rdispNNNN]
    -n, --netvm <vm>          NetVM [default: none]
    -s, --tempsize <size>     RAM drive size: 1G, 2G, etc [default: 1G]
    -m, --memory <mb>         Qube memory in MB [default: 1000]
    -l, --label <color>       Label color [default: auto based on netvm]
    -v, --default-dispvm <vm> Default disposable VM [default: none]
    
${BOLD}Privacy Options:${NC}
    --no-hardened             Disable all privacy hardening
    --keep-tracker            Don't disable file indexing (Tracker)
    --keep-recent             Don't disable recent files history
    --keep-thumbnails         Don't disable thumbnail generation
    
${BOLD}Other Options:${NC}
    --dry-run                 Show actions without executing
    --quiet                   Minimal output

${BOLD}Cleanup Options:${NC}
    --all                     Clean ALL remnants (interactive)
    --qube <name>             Clean specific qube remnants

${BOLD}Auto Label Colors:${NC}
    gray    - No network (netvm=none)
    purple  - Whonix (netvm=sys-whonix)
    red     - Any other network

${BOLD}Privacy Features (enabled by default):${NC}
    - Tracker3 file indexing completely disabled
    - GNOME recent files history disabled
    - Thumbnail generation disabled
    - Bash history disabled
    - Core dumps disabled
    - All logs redirected to /dev/null

${BOLD}Examples:${NC}
    # Launch Tor Browser in RAM-based Whonix (maximum privacy)
    $SCRIPT_NAME launch -t whonix-workstation-17-dvm -n sys-whonix -c torbrowser

    # Launch Firefox with no network
    $SCRIPT_NAME launch -t fedora-40-dvm -c firefox

    # Launch with custom settings and 2GB RAM
    $SCRIPT_NAME launch -t debian-12-dvm -n sys-firewall -s 2G -m 2000 -c xterm

    # Launch without privacy hardening (not recommended)
    $SCRIPT_NAME launch -t fedora-40-dvm -c firefox --no-hardened

    # Clean up after crash
    $SCRIPT_NAME cleanup --all

    # Monitor RAM usage
    watch -c $SCRIPT_NAME pool-usage

${BOLD}How it works:${NC}
    1. Creates tmpfs (RAM disk) for qube storage
    2. Creates storage pool on that tmpfs
    3. Clones DVM template to RAM pool
    4. Redirects all logs to /dev/null
    5. Disables file indexing, recent files, thumbnails
    6. Runs qube entirely from RAM
    7. On shutdown: unmounts tmpfs, removes all traces

${BOLD}Security notes:${NC}
    - Swap is disabled during operation
    - No logs written to disk
    - Root volume is read-only
    - All data exists only in RAM
    - File indexing completely disabled
    - No recent files or thumbnails cached
EOF
}

#===============================================================================
# VALIDATION
#===============================================================================

validate_template() {
    local template="$1"
    
    if ! qvm-check "$template" &>/dev/null; then
        die "Template '$template' does not exist"
    fi
    
    local is_dvm_template
    is_dvm_template=$(qvm-prefs "$template" template_for_dispvms 2>/dev/null || echo "False")
    
    if [[ "$is_dvm_template" != "True" ]]; then
        die "'$template' is not a disposable VM template (template_for_dispvms != True)"
    fi
    
    log_debug "Template '$template' validated"
}

validate_netvm() {
    local netvm="$1"
    
    [[ -z "$netvm" ]] && return 0
    
    if ! qvm-check "$netvm" &>/dev/null; then
        die "NetVM '$netvm' does not exist"
    fi
    
    log_debug "NetVM '$netvm' validated"
}

generate_qube_name() {
    local name
    while : ; do
        name="rdisp$(/usr/bin/shuf --input-range=100-9999 --head-count=1)"
        if ! qvm-check "$name" &>/dev/null; then
            echo "$name"
            return 0
        fi
    done
}

auto_select_label() {
    if [[ "$AUTO_LABEL" != "true" ]]; then
        return 0
    fi
    
    if [[ -z "$NETVM" ]]; then
        LABEL="gray"
    elif [[ "$NETVM" == *"whonix"* ]]; then
        LABEL="purple"
    else
        LABEL="red"
    fi
    
    log_debug "Auto-selected label: $LABEL"
}

#===============================================================================
# PRIVACY HARDENING SCRIPT (runs inside qube)
#===============================================================================

generate_privacy_script() {
    cat << 'PRIVACY_EOF'
#!/bin/bash
#===============================================================================
# PRIVACY HARDENING SCRIPT - Runs inside disposable qube
#===============================================================================

set -e

# Disable Tracker3 file indexing completely
disable_tracker() {
    # Check if gsettings exists
    if ! command -v gsettings &>/dev/null; then
        return 0
    fi
    
    # Check if tracker schemas exist
    if ! gsettings list-schemas 2>/dev/null | grep -q "Tracker3"; then
        return 0
    fi
    
    # Disable crawling entirely
    gsettings set org.freedesktop.Tracker3.Miner.Files crawling-interval -2 2>/dev/null || true
    
    # Maximum initial sleep (delay startup)
    gsettings set org.freedesktop.Tracker3.Miner.Files initial-sleep 1000 2>/dev/null || true
    
    # Disable file monitoring
    gsettings set org.freedesktop.Tracker3.Miner.Files enable-monitors false 2>/dev/null || true
    
    # Set throttle to maximum (slowest)
    gsettings set org.freedesktop.Tracker3.Miner.Files throttle 20 2>/dev/null || true
    
    # Disable battery indexing
    gsettings set org.freedesktop.Tracker3.Miner.Files index-on-battery false 2>/dev/null || true
    gsettings set org.freedesktop.Tracker3.Miner.Files index-on-battery-first-time false 2>/dev/null || true
    
    # Disable removable device indexing
    gsettings set org.freedesktop.Tracker3.Miner.Files index-removable-devices false 2>/dev/null || true
    gsettings set org.freedesktop.Tracker3.Miner.Files index-optical-discs false 2>/dev/null || true
    
    # Set disk space limit to 100% (always "low disk space")
    gsettings set org.freedesktop.Tracker3.Miner.Files low-disk-space-limit 100 2>/dev/null || true
    
    # Point to non-existent directories
    gsettings set org.freedesktop.Tracker3.Miner.Files index-recursive-directories "['nonexistent1']" 2>/dev/null || true
    gsettings set org.freedesktop.Tracker3.Miner.Files index-single-directories "['nonexistent2']" 2>/dev/null || true
    
    # Ignore everything
    gsettings set org.freedesktop.Tracker3.Miner.Files ignored-directories "['*']" 2>/dev/null || true
    gsettings set org.freedesktop.Tracker3.Miner.Files ignored-directories-with-content "['*', '*.*', '.*']" 2>/dev/null || true
    gsettings set org.freedesktop.Tracker3.Miner.Files ignored-files "['*','*.*','.*']" 2>/dev/null || true
    
    # Clear removable data daily
    gsettings set org.freedesktop.Tracker3.Miner.Files removable-days-threshold 1 2>/dev/null || true
    
    # Disable application indexing
    gsettings set org.freedesktop.Tracker3.Miner.Files index-applications false 2>/dev/null || true
    
    # Disable FTS features
    gsettings set org.freedesktop.Tracker3.FTS enable-stemmer false 2>/dev/null || true
    gsettings set org.freedesktop.Tracker3.FTS enable-unaccent false 2>/dev/null || true
    
    # Disable extraction
    gsettings set org.freedesktop.Tracker3.Extract max-bytes 0 2>/dev/null || true
    gsettings set org.freedesktop.Tracker3.Extract text-allowlist '[]' 2>/dev/null || true
    gsettings set org.freedesktop.Tracker3.Extract wait-for-miner-fs true 2>/dev/null || true
    
    # Disable GNOME search providers
    gsettings set org.gnome.desktop.search-providers disable-external true 2>/dev/null || true
    gsettings set org.gnome.desktop.search-providers enabled "[]" 2>/dev/null || true
    
    # Reset and kill tracker
    if command -v tracker3 &>/dev/null; then
        tracker3 reset -s -r 2>/dev/null || true
        tracker3 daemon --kill 2>/dev/null || true
    fi
    
    # Also try tracker (older version)
    if command -v tracker &>/dev/null; then
        tracker reset -s -r 2>/dev/null || true
        tracker daemon -k 2>/dev/null || true
    fi
    
    # Mask tracker services
    systemctl --user mask tracker-miner-fs-3.service 2>/dev/null || true
    systemctl --user mask tracker-extract-3.service 2>/dev/null || true
    systemctl --user mask tracker-miner-fs.service 2>/dev/null || true
    systemctl --user mask tracker-extract.service 2>/dev/null || true
    systemctl --user mask tracker-store.service 2>/dev/null || true
}

# Disable recent files
disable_recent_files() {
    if ! command -v gsettings &>/dev/null; then
        return 0
    fi
    
    # Disable GTK recent files
    gsettings set org.gtk.Settings.FileChooser show-hidden false 2>/dev/null || true
    
    # Disable GNOME recent files
    gsettings set org.gnome.desktop.privacy remember-recent-files false 2>/dev/null || true
    gsettings set org.gnome.desktop.privacy recent-files-max-age 0 2>/dev/null || true
    
    # Clear and lock recently-used.xbel
    rm -f ~/.local/share/recently-used.xbel 2>/dev/null || true
    mkdir -p ~/.local/share 2>/dev/null || true
    ln -sf /dev/null ~/.local/share/recently-used.xbel 2>/dev/null || true
    
    # Disable Zeitgeist if present
    if command -v zeitgeist-daemon &>/dev/null; then
        zeitgeist-daemon --quit 2>/dev/null || true
    fi
    gsettings set org.gnome.desktop.privacy remember-app-usage false 2>/dev/null || true
}

# Disable thumbnails
disable_thumbnails() {
    if ! command -v gsettings &>/dev/null; then
        return 0
    fi
    
    # Disable GNOME thumbnail generation
    gsettings set org.gnome.desktop.thumbnailers disable-all true 2>/dev/null || true
    
    # Set thumbnail cache to minimum
    gsettings set org.gnome.desktop.thumbnail-cache maximum-size 0 2>/dev/null || true
    gsettings set org.gnome.desktop.thumbnail-cache maximum-age 0 2>/dev/null || true
    
    # Clear thumbnail cache
    rm -rf ~/.cache/thumbnails/* 2>/dev/null || true
    
    # Link thumbnail directory to /dev/null (prevent creation)
    rm -rf ~/.cache/thumbnails 2>/dev/null || true
    mkdir -p ~/.cache 2>/dev/null || true
    ln -sf /dev/null ~/.cache/thumbnails 2>/dev/null || true
}

# Disable bash history
disable_bash_history() {
    export HISTFILE=/dev/null
    export HISTSIZE=0
    export HISTFILESIZE=0
    export SAVEHIST=0
    
    # Clear existing history
    history -c 2>/dev/null || true
    
    # Link history files to /dev/null
    rm -f ~/.bash_history ~/.zsh_history 2>/dev/null || true
    ln -sf /dev/null ~/.bash_history 2>/dev/null || true
    ln -sf /dev/null ~/.zsh_history 2>/dev/null || true
}

# Disable core dumps
disable_core_dumps() {
    ulimit -c 0 2>/dev/null || true
    
    # Disable systemd coredump if possible
    mkdir -p ~/.config/systemd/coredump.conf.d/ 2>/dev/null || true
    echo -e "[Coredump]\nStorage=none\nProcessSizeMax=0" > ~/.config/systemd/coredump.conf.d/disable.conf 2>/dev/null || true
}

# Disable KDE/Plasma indexing (Baloo)
disable_baloo() {
    if command -v balooctl &>/dev/null; then
        balooctl disable 2>/dev/null || true
        balooctl purge 2>/dev/null || true
    fi
    
    # Disable via config
    mkdir -p ~/.config 2>/dev/null || true
    cat > ~/.config/baloofilerc 2>/dev/null << 'BALOOEOF' || true
[Basic Settings]
Indexing-Enabled=false

[General]
first run=false
BALOOEOF
}

# Clear various caches
clear_caches() {
    # Clear fontconfig cache
    rm -rf ~/.cache/fontconfig/* 2>/dev/null || true
    
    # Clear mesa shader cache
    rm -rf ~/.cache/mesa_shader_cache/* 2>/dev/null || true
    
    # Clear icon cache
    rm -rf ~/.cache/icon-cache.kcache 2>/dev/null || true
    
    # Clear GNOME cache
    rm -rf ~/.cache/gnome-software/* 2>/dev/null || true
    rm -rf ~/.cache/tracker3/* 2>/dev/null || true
    rm -rf ~/.cache/tracker/* 2>/dev/null || true
    
    # Clear evolution data
    rm -rf ~/.local/share/evolution/* 2>/dev/null || true
    rm -rf ~/.local/share/gnome-shell/application_state 2>/dev/null || true
}

# Main
main() {
    disable_tracker
    disable_recent_files
    disable_thumbnails
    disable_bash_history
    disable_core_dumps
    disable_baloo
    clear_caches
}

main "$@"
PRIVACY_EOF
}

#===============================================================================
# LOG FILES MANAGEMENT
#===============================================================================

get_log_files() {
    local qube="$1"
    echo "${LOGDIR}/libvirt/libxl/${qube}.log"
    echo "${LOGDIR}/qubes/guid.${qube}.log"
    echo "${LOGDIR}/qubes/qrexec.${qube}.log"
    echo "${LOGDIR}/qubes/qubesdb.${qube}.log"
    echo "${LOGDIR}/xen/console/guest-${qube}.log"
}

create_null_symlinks() {
    local qube="$1"
    
    log_debug "Creating /dev/null symlinks for logs"
    
    while IFS= read -r logfile; do
        sudo ln -sfT /dev/null "$logfile" 2>/dev/null || true
    done < <(get_log_files "$qube")
}

remove_log_files() {
    local qube="$1"
    
    log_debug "Removing log files for $qube"
    
    while IFS= read -r logfile; do
        sudo rm -f "$logfile" "${logfile}.old" 2>/dev/null || true
    done < <(get_log_files "$qube")
    
    # Also check for rotated logs (Qubes 4.2+)
    sudo find "${LOGDIR}/qubes" "${LOGDIR}/libvirt/libxl" "${LOGDIR}/xen/console" \
        -name "*${qube}*" -delete 2>/dev/null || true
}

remove_menu_files() {
    local qube="$1"
    local menudir="${HOME}/.config/menus/applications-merged"
    
    find "$menudir" \
        -regextype posix-egrep \
        -regex ".*\/user-qubes-(disp)?vm-directory(_|-)${qube}\.menu$" \
        -delete 2>/dev/null || true
}

#===============================================================================
# SYSTEM LOGS CLEANUP
#===============================================================================

cleanup_system_logs() {
    local qube="$1"
    
    log_debug "Cleaning system logs for $qube"
    
    # Journalctl — rotate and vacuum
    sudo journalctl --rotate 2>/dev/null || true
    sudo journalctl --vacuum-time=1s 2>/dev/null || true
    
    # Audit log — truncate if exists
    if [[ -f /var/log/audit/audit.log ]]; then
        sudo truncate -s 0 /var/log/audit/audit.log 2>/dev/null || true
    fi
}

#===============================================================================
# QUBE CLEANUP
#===============================================================================

cleanup_qube() {
    local qube="$1"
    local exit_code="${2:-0}"
    
    log_section "CLEANUP: $qube"
    
    set +e
    
    # Kill qube if running
    if qvm-check --running "$qube" &>/dev/null; then
        log_info "Killing qube..."
        qvm-kill "$qube" 2>/dev/null || true
        sleep 1
    fi
    
    # Remove qube
    if qvm-check "$qube" &>/dev/null; then
        log_info "Removing qube..."
        qvm-remove --force "$qube" 2>/dev/null || true
    fi
    
    # Remove RAM template if exists
    local ram_tpl="ram-tpl-${qube}"
    if qvm-check "$ram_tpl" &>/dev/null; then
        log_info "Removing RAM template..."
        qvm-remove --force "$ram_tpl" 2>/dev/null || true
    fi
    
    # Remove pool
    local pool="ram_pool_${qube}"
    if qvm-pool info "$pool" &>/dev/null; then
        log_info "Removing storage pool..."
        qvm-pool remove "$pool" 2>/dev/null || true
    fi
    
    # Unmount tmpfs
    local tempdir="${TEMPDIR_ROOT}/${qube}"
    if mountpoint -q "$tempdir" 2>/dev/null; then
        log_info "Unmounting RAM disk..."
        sudo umount "$tempdir" 2>/dev/null || true
    fi
    
    # Remove temp directory
    if [[ -d "$tempdir" ]]; then
        log_info "Removing temp directory..."
        sudo rm -rf "$tempdir" 2>/dev/null || true
    fi
    
    # Remove log files
    log_info "Removing log files..."
    remove_log_files "$qube"
    
    # Remove menu files
    log_info "Removing menu entries..."
    remove_menu_files "$qube"

    # Clean system logs (journalctl, audit)
    log_info "Cleaning system logs..."
    cleanup_system_logs "$qube"    
    
    # Remove audio control files
    sudo rm -rf "/run/qubes/audio-control.${qube}" 2>/dev/null || true
    
    # Clean up empty tempdir root
    rmdir --ignore-fail-on-non-empty "$TEMPDIR_ROOT" 2>/dev/null || true
    
    set -e
    
    notify_send "$qube" "RAM qube remnants cleared" "emblem-default-symbolic"
    log_info "Cleanup complete"
    
    return "$exit_code"
}

#===============================================================================
# APPLY PRIVACY HARDENING
#===============================================================================

apply_privacy_hardening() {
    local qube="$1"
    
    if [[ "$HARDENED_MODE" != "true" ]]; then
        log_debug "Privacy hardening disabled"
        return 0
    fi
    
    log_info "Applying privacy hardening inside qube..."
    
    local script
    script=$(generate_privacy_script)
    
    # Run privacy script inside qube
    qvm-run --pass-io "$qube" "bash -c '$script'" 2>/dev/null || {
        log_warn "Some privacy settings could not be applied (non-critical)"
    }
    
    log_debug "Privacy hardening applied"
}

#===============================================================================
# LAUNCH RAM-BASED QUBE
#===============================================================================

launch_qube() {
    log_section "LAUNCH RAM-BASED QUBE"
    
    # Validate inputs
    [[ -z "$TEMPLATE" ]] && die "Template is required (-t/--template)"
    [[ -z "$COMMAND_TO_RUN" ]] && die "Command is required (-c/--command)"
    
    validate_template "$TEMPLATE"
    validate_netvm "$NETVM"
    
    # Generate name if not provided
    if [[ -z "$QUBE_NAME" ]]; then
        QUBE_NAME=$(generate_qube_name)
    elif qvm-check "$QUBE_NAME" &>/dev/null; then
        die "Qube '$QUBE_NAME' already exists"
    fi
    
    POOL_NAME="ram_pool_${QUBE_NAME}"
    TEMPDIR="${TEMPDIR_ROOT}/${QUBE_NAME}"
    
    # Check if tempdir or pool already exist
    [[ -d "$TEMPDIR" ]] && die "Directory '$TEMPDIR' already exists"
    qvm-pool info "$POOL_NAME" &>/dev/null && die "Pool '$POOL_NAME' already exists"
    
    # Auto-select label based on netvm
    auto_select_label
    
    log_info "Configuration:"
    log_info "  Qube name:      $QUBE_NAME"
    log_info "  Template:       $TEMPLATE"
    log_info "  Command:        $COMMAND_TO_RUN"
    log_info "  NetVM:          ${NETVM:-none}"
    log_info "  RAM size:       $TEMPSIZE"
    log_info "  Memory:         ${MEMORY}MB"
    log_info "  Label:          $LABEL"
    log_info "  Privacy mode:   $HARDENED_MODE"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_warn "DRY-RUN mode - no changes will be made"
        return 0
    fi
    
    notify_send "$SCRIPT_NAME" "Creating RAM qube: $QUBE_NAME" "xfce4-timer-plugin"
    
    # Disable swap
    log_info "Disabling swap..."
    sudo swapoff --all 2>/dev/null || log_warn "Could not disable swap"
    
    # Create temp directory
    log_info "Creating RAM disk..."
    mkdir -p "$TEMPDIR"
    
    # Mount tmpfs
    sudo mount --types tmpfs \
        --options "size=${TEMPSIZE},mode=700" \
        "$POOL_NAME" \
        "$TEMPDIR" || die "Failed to mount tmpfs"
    
    # Create storage pool
    log_info "Creating storage pool..."
    qvm-pool add "$POOL_NAME" file \
        --option revisions_to_keep=1 \
        --option dir_path="$TEMPDIR" \
        --option ephemeral_volatile=True || {
            sudo umount "$TEMPDIR" 2>/dev/null || true
            rmdir "$TEMPDIR" 2>/dev/null || true
            die "Failed to create storage pool"
        }
    
    # Create null symlinks for logs
    log_info "Redirecting logs to /dev/null..."
    create_null_symlinks "$QUBE_NAME"
    
    # Create RAM-based template name
    RAM_TEMPLATE="ram-tpl-${QUBE_NAME}"
    
    # Clone template to RAM as disposable template
    log_info "Cloning template to RAM..."
    qvm-clone --quiet -P "$POOL_NAME" "$TEMPLATE" "$RAM_TEMPLATE" || {
        cleanup_qube "$QUBE_NAME" 1
        die "Failed to clone template"
    }
    
    # Enable as disposable template
    log_info "Configuring RAM template..."
    qvm-prefs "$RAM_TEMPLATE" template_for_dispvms True
    qvm-prefs "$RAM_TEMPLATE" include_in_backups False
    
    # Create DispVM from RAM template
    log_info "Creating disposable VM..."
    qvm-create \
        --class DispVM \
        --template "$RAM_TEMPLATE" \
        --label "$LABEL" \
        "$QUBE_NAME" || {
            cleanup_qube "$QUBE_NAME" 1
            die "Failed to create disposable VM"
        }
    
    # Configure qube properties
    log_info "Configuring qube properties..."
    
    qvm-prefs "$QUBE_NAME" memory "$MEMORY"
    
    if [[ -n "$NETVM" ]]; then
        qvm-prefs "$QUBE_NAME" netvm "$NETVM"
    else
        qvm-prefs "$QUBE_NAME" netvm ''
    fi
    
    if [[ -n "$DEFAULT_DISPVM" ]]; then
        qvm-prefs "$QUBE_NAME" default_dispvm "$DEFAULT_DISPVM"
    else
        qvm-prefs "$QUBE_NAME" default_dispvm ''
    fi
    
    # Start qube first to apply privacy settings
    log_info "Starting qube..."
    qvm-start "$QUBE_NAME" || {
        cleanup_qube "$QUBE_NAME" 1
        die "Failed to start qube"
    }
    
    # Apply privacy hardening
    apply_privacy_hardening "$QUBE_NAME"
    
    # Remove lock file before running command (allows parallel launches)
    rm -f "$LOCK_FILE" 2>/dev/null || true
    
    # Run the command
    log_info "Running command..."
    log_info "=========================================="
    
    set +e
    qvm-run --pass-io "$QUBE_NAME" "$COMMAND_TO_RUN"
    local run_exit_code=$?
    set -e
    
    log_info "=========================================="
    log_info "Qube finished (exit code: $run_exit_code)"
    
    # Cleanup
    cleanup_qube "$QUBE_NAME" "$run_exit_code"
    
    return "$run_exit_code"
}

#===============================================================================
# LIST ACTIVE RAM QUBES
#===============================================================================

list_ram_qubes() {
    log_section "ACTIVE RAM-BASED QUBES"
    
    local pools
    pools=$(qvm-pool list 2>/dev/null | grep -Eo '^ram_pool_[^ ]+' || true)
    
    if [[ -z "$pools" ]]; then
        log_info "No active RAM-based qubes found"
        return 0
    fi
    
    echo ""
    printf "${BOLD}%-20s %-15s %-12s %-10s${NC}\n" "QUBE" "POOL" "STATUS" "MEMORY"
    echo "---------------------------------------------------------------"
    
    while IFS= read -r pool; do
        local qube="${pool#ram_pool_}"
        local status="unknown"
        local mem="N/A"
        
        if qvm-check --running "$qube" &>/dev/null; then
            status="${GREEN}running${NC}"
            mem=$(qvm-prefs "$qube" memory 2>/dev/null || echo "N/A")
        elif qvm-check "$qube" &>/dev/null; then
            status="${YELLOW}stopped${NC}"
            mem=$(qvm-prefs "$qube" memory 2>/dev/null || echo "N/A")
        else
            status="${RED}orphaned${NC}"
        fi
        
        printf "%-20s %-15s %-12b %-10s\n" "$qube" "$pool" "$status" "${mem}MB"
    done <<< "$pools"
    
    echo ""
}

#===============================================================================
# POOL USAGE
#===============================================================================

pool_usage() {
    local pools
    pools=$(qvm-pool list 2>/dev/null | grep -Eo '^ram_pool_[^ ]+' || true)
    
    if [[ -z "$pools" ]]; then
        echo "No RAM pools found"
        return 0
    fi
    
    echo ""
    echo -e "Volatile volume: ${BOLD}${RED}non-ephemeral${NC} / ${GREEN}ephemeral${NC}"
    echo ""
    
    while IFS= read -r pool; do
        local qube="${pool#ram_pool_}"
        
        if ! qvm-check "$qube" &>/dev/null; then
            continue
        fi
        
        echo -e "${PURPLE}${qube}${NC}"
        
        # Pool info
        local pool_size pool_usage ephemeral_volatile
        pool_size=$(qvm-pool info "$pool" 2>/dev/null | grep -E '^size' | grep -Eo '[0-9]+' || echo "0")
        pool_usage=$(qvm-pool info "$pool" 2>/dev/null | grep -E '^usage' | grep -Eo '[0-9]+' || echo "0")
        ephemeral_volatile=$(qvm-pool info "$pool" 2>/dev/null | grep -E '^ephemeral_volatile' || echo "")
        
        local color="${RED}"
        [[ "$ephemeral_volatile" == *"True"* ]] && color="${GREEN}"
        
        if [[ "$pool_size" -gt 0 ]]; then
            local percent size_gb
            percent=$(awk -v u="$pool_usage" -v s="$pool_size" 'BEGIN {printf "%.2f", 100*u/s}')
            size_gb=$(awk -v s="$pool_size" 'BEGIN {printf "%.2f", s/1024/1024/1024}')
            
            local percent_color="${NC}"
            [[ "${percent%.*}" -gt 80 ]] && percent_color="${RED}"
            
            printf "  ${color}%-18s${NC} ${percent_color}%6.2f%%${NC} of %5.2f GiB\n" "$pool" "$percent" "$size_gb"
        fi
        
        # Volume info
        for volume in volatile private; do
            if qvm-volume info "${qube}:${volume}" &>/dev/null; then
                local vol_size vol_usage vol_ephemeral
                vol_size=$(qvm-volume info "${qube}:${volume}" size 2>/dev/null || echo "0")
                vol_usage=$(qvm-volume info "${qube}:${volume}" usage 2>/dev/null || echo "0")
                vol_ephemeral=$(qvm-volume info "${qube}:${volume}" ephemeral 2>/dev/null || echo "False")
                
                color="${RED}"
                [[ "$vol_ephemeral" == "True" ]] && color="${GREEN}"
                
                if [[ "$vol_size" -gt 0 ]]; then
                    percent=$(awk -v u="$vol_usage" -v s="$vol_size" 'BEGIN {printf "%.2f", 100*u/s}')
                    size_gb=$(awk -v s="$vol_size" 'BEGIN {printf "%.2f", s/1024/1024/1024}')
                    
                    percent_color="${NC}"
                    [[ "${percent%.*}" -gt 80 ]] && percent_color="${RED}"
                    
                    printf "  ${color}%-18s${NC} ${percent_color}%6.2f%%${NC} of %5.2f GiB\n" "$volume" "$percent" "$size_gb"
                fi
            fi
        done
        
        echo ""
    done <<< "$pools"
}

#===============================================================================
# CLEANUP ALL REMNANTS
#===============================================================================

cleanup_all_remnants() {
    log_section "CLEANUP ALL REMNANTS"
    
    echo -e "${RED}${BOLD}WARNING!${NC}"
    echo "This will search for and remove remnants of non-existing RAM qubes."
    echo "You will be asked to confirm each removal."
    echo ""
    read -r -p "Continue? [y/N]: " confirm
    [[ ! "$confirm" =~ ^[Yy]$ ]] && { log_info "Aborted"; return 0; }
    
    # Find orphaned pools
    log_info "Checking for orphaned RAM pools..."
    local pools
    pools=$(qvm-pool list 2>/dev/null | grep -Eo '^ram_pool_[^ ]+' || true)
    
    while IFS= read -r pool; do
        [[ -z "$pool" ]] && continue
        local qube="${pool#ram_pool_}"
        
        if ! qvm-check "$qube" &>/dev/null; then
            echo -e "Found orphaned pool: ${CYAN}$pool${NC}"
            read -r -p "  Remove? [y/N/q]: " ans
            case "$ans" in
                [Yy]*)
                    qvm-pool remove "$pool" 2>/dev/null || true
                    local tempdir="${TEMPDIR_ROOT}/${qube}"
                    sudo umount "$tempdir" 2>/dev/null || true
                    sudo rm -rf "$tempdir" 2>/dev/null || true
                    log_info "Removed pool $pool"
                    ;;
                [Qq]*)
                    log_info "Aborted"
                    return 0
                    ;;
            esac
        fi
    done <<< "$pools"
    
    # Find orphaned temp directories
    log_info "Checking for orphaned temp directories..."
    if [[ -d "$TEMPDIR_ROOT" ]]; then
        for dir in "$TEMPDIR_ROOT"/*/; do
            [[ ! -d "$dir" ]] && continue
            local qube="$(basename "$dir")"
            
            if ! qvm-check "$qube" &>/dev/null; then
                echo -e "Found orphaned directory: ${CYAN}$dir${NC}"
                read -r -p "  Remove? [y/N/q]: " ans
                case "$ans" in
                    [Yy]*)
                        sudo umount "$dir" 2>/dev/null || true
                        sudo rm -rf "$dir" 2>/dev/null || true
                        log_info "Removed directory $dir"
                        ;;
                    [Qq]*)
                        log_info "Aborted"
                        return 0
                        ;;
                esac
            fi
        done
    fi
    
    # Find orphaned log files
    log_info "Checking for orphaned log files..."
    local existing_qubes
    existing_qubes=$(qvm-ls --fields=name --raw-data 2>/dev/null | sort)
    
    local log_patterns=(
        "${LOGDIR}/qubes/*.log"
        "${LOGDIR}/libvirt/libxl/*.log"
        "${LOGDIR}/xen/console/guest-*.log"
    )
    
    for pattern in "${log_patterns[@]}"; do
        for logfile in $pattern; do
            [[ ! -f "$logfile" ]] && continue
            local filename="$(basename "$logfile")"
            
            # Extract qube name from filename
            local qube=""
            if [[ "$filename" =~ ^guest-(.+)\.log ]]; then
                qube="${BASH_REMATCH[1]}"
            elif [[ "$filename" =~ ^(guid|qrexec|qubesdb)\.(.+)\.log ]]; then
                qube="${BASH_REMATCH[2]}"
            elif [[ "$filename" =~ ^rdisp[0-9]+\.log$ ]]; then
                qube="${filename%.log}"
            fi
            
            [[ -z "$qube" ]] && continue
            [[ ! "$qube" =~ ^rdisp[0-9]+$ ]] && continue
            
            if ! echo "$existing_qubes" | grep -qx "$qube"; then
                echo -e "Found orphaned log: ${CYAN}$logfile${NC}"
                read -r -p "  Remove? [y/N/q]: " ans
                case "$ans" in
                    [Yy]*)
                        sudo rm -f "$logfile" "${logfile}.old" 2>/dev/null || true
                        log_info "Removed log $logfile"
                        ;;
                    [Qq]*)
                        log_info "Aborted"
                        return 0
                        ;;
                esac
            fi
        done
    done
    
    # Cleanup empty tempdir root
    rmdir --ignore-fail-on-non-empty "$TEMPDIR_ROOT" 2>/dev/null || true
 
    # Clean system logs
    log_info "Cleaning system logs (journalctl, audit)..."
    cleanup_system_logs "all"
    
    log_info "Cleanup complete"
}

#===============================================================================
# PREFLIGHT CHECKS
#===============================================================================

preflight_checks() {
    require_dom0
    
    local required_cmds=(qvm-create qvm-prefs qvm-run qvm-clone qvm-pool qvm-volume qvm-check qvm-kill qvm-remove qvm-start notify-send)
    for cmd in "${required_cmds[@]}"; do
        has_cmd "$cmd" || die "Required command not found: $cmd"
    done
}

#===============================================================================
# MAIN
#===============================================================================

main() {
    local command="${1:-}"
    
    case "$command" in
        launch)
            shift
            
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    -t|--template)
                        TEMPLATE="$2"
                        shift 2
                        ;;
                    -c|--command)
                        COMMAND_TO_RUN="$2"
                        shift 2
                        ;;
                    -q|--qubename)
                        QUBE_NAME="$2"
                        shift 2
                        ;;
                    -n|--netvm)
                        NETVM="$2"
                        shift 2
                        ;;
                    -s|--tempsize)
                        TEMPSIZE="$2"
                        shift 2
                        ;;
                    -m|--memory)
                        MEMORY="$2"
                        shift 2
                        ;;
                    -l|--label)
                        LABEL="$2"
                        AUTO_LABEL="false"
                        shift 2
                        ;;
                    -v|--default-dispvm)
                        DEFAULT_DISPVM="$2"
                        shift 2
                        ;;
                    --no-hardened)
                        HARDENED_MODE="false"
                        shift
                        ;;
                    --keep-tracker)
                        DISABLE_TRACKER="false"
                        shift
                        ;;
                    --keep-recent)
                        DISABLE_RECENT_FILES="false"
                        shift
                        ;;
                    --keep-thumbnails)
                        DISABLE_THUMBNAILS="false"
                        shift
                        ;;
                    --dry-run)
                        DRY_RUN="true"
                        shift
                        ;;
                    --quiet)
                        QUIET="true"
                        shift
                        ;;
                    *)
                        die "Unknown option: $1"
                        ;;
                esac
            done
            
            log_init
            check_lock
            preflight_checks
            launch_qube
            ;;
        
        list)
            log_init
            preflight_checks
            list_ram_qubes
            ;;
        
        pool-usage)
            preflight_checks
            pool_usage
            ;;
        
        cleanup)
            shift
            log_init
            preflight_checks
            
            local cleanup_all="false"
            local cleanup_qube=""
            
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --all)
                        cleanup_all="true"
                        shift
                        ;;
                    --qube)
                        cleanup_qube="$2"
                        shift 2
                        ;;
                    *)
                        die "Unknown option: $1"
                        ;;
                esac
            done
            
            if [[ "$cleanup_all" == "true" ]]; then
                cleanup_all_remnants
            elif [[ -n "$cleanup_qube" ]]; then
                cleanup_qube "$cleanup_qube"
            else
                echo "Specify --all or --qube <name>"
                echo "Use '$SCRIPT_NAME help' for usage"
                exit 1
            fi
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
