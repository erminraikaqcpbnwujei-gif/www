#!/usr/bin/env bash
#===============================================================================
# REALLY DISPOSABLE (RAM-BASED)
#===============================================================================

set -euo pipefail
set -E
export LC_ALL=C

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"

: "${XDG_RUNTIME_DIR:?XDG_RUNTIME_DIR is not set. Run from a logged-in user session in dom0.}"

umask 027

readonly SCRIPT_VERSION="1.1.0"
readonly SCRIPT_NAME="$(basename "$0")"

#===============================================================================
# PATHS
#===============================================================================

readonly LOG_FILE="/dev/null"
readonly TEMPDIR_ROOT="${XDG_RUNTIME_DIR}/ram-disposable-tmp"
readonly LOGDIR="/var/log"
readonly MAX_OUTPUT_SIZE="10M"

#===============================================================================
# DEFAULT CONFIGURATION
#===============================================================================

QUBE_NAME=""
TEMPLATE=""
NETVM=""
TEMPSIZE="1G"
MEMORY="400"
LABEL="gray"
RAM_TEMPLATE=""
DEFAULT_DISPVM=""
POOL_NAME=""
TEMPDIR=""
COMMAND_ARGS=()

DRY_RUN="false"
QUIET="false"
NOTIFY="true"
AUTO_LABEL="true"
HARDENED_MODE="true"
SANITIZE_OUTPUT="true"
WIPE_SYSTEM_LOGS="true"
FORCE_CLEANUP="false"

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
    # Only create a log directory if logging is actually enabled.
    if [[ "${LOG_FILE:-/dev/null}" != "/dev/null" ]]; then
        mkdir -p -- "$(dirname -- "$LOG_FILE")" 2>/dev/null || true
    fi

    mkdir -p -- "$TEMPDIR_ROOT" 2>/dev/null || true
    chmod 700 "$TEMPDIR_ROOT" 2>/dev/null || true
    {
        echo "==============================================================================="
        echo "RAM-DISPOSABLE v${SCRIPT_VERSION} Started: $(date -Iseconds)"
        echo "PID: $$"
        echo "==============================================================================="
    } >> "$LOG_FILE"
}

log_info() {
    if [[ "$QUIET" != "true" ]]; then
        printf '%b%s\n' "${GREEN}[+]${NC} " "$1"
    fi
    printf '[%s] [INFO] %s\n' "$(date '+%H:%M:%S')" "$1" >> "$LOG_FILE"
}

log_warn() {
    if [[ "$QUIET" != "true" ]]; then
        printf '%b%s\n' "${YELLOW}[!]${NC} " "$1" >&2
    fi
    printf '[%s] [WARN] %s\n' "$(date '+%H:%M:%S')" "$1" >> "$LOG_FILE"
}

log_error() {
    printf '%b%s\n' "${BOLD}${RED}[-]${NC} " "$1" >&2
    printf '[%s] [ERROR] %s\n' "$(date '+%H:%M:%S')" "$1" >> "$LOG_FILE"
    notify_send "RAM-Disposable" "An error occurred" "dialog-error"
}

log_fatal() {
    printf '%b%s\n' "${BOLD}${RED}[FATAL]${NC} " "$1" >&2
    printf '[%s] [FATAL] %s\n' "$(date '+%H:%M:%S')" "$1" >> "$LOG_FILE"
    notify_send "RAM-Disposable" "A fatal error occurred" "dialog-error"
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
    
    [[ "$NOTIFY" == "true" ]] || return 0
    [[ "$QUIET" != "true" ]] || return 0
    notify-send --expire-time 5000 --icon="$icon" "$title" "$message" 2>/dev/null || true
}

die() {
    log_fatal "${1:-Critical error}"
    exit "${2:-1}"
}

#===============================================================================
# TRAPS / LOCK / UTILS
#===============================================================================

# File descriptor for flock (initialized in log_init)
LOCK_FD=""
IN_CLEANUP="false"

cleanup_on_exit() {
    local rc=$?
    
    # Release flock if held
    if [[ -n "$LOCK_FD" ]]; then
        flock -u "$LOCK_FD" 2>/dev/null || true
    fi

    # Best-effort cleanup on abnormal exit (covers set -e / ERR trap exits)
    if (( rc != 0 )) && [[ "${IN_CLEANUP}" != "true" ]] && [[ -n "${QUBE_NAME:-}" ]]; then
        IN_CLEANUP="true"
        cleanup_qube "$QUBE_NAME" "$rc" 2>/dev/null || true
    fi
    
    if (( rc != 0 )); then
        echo "[$(date '+%H:%M:%S')] Script exited with code $rc" >> "$LOG_FILE"
    fi

    # If logging is disabled, never try to remove /dev/null or its directory.
    if [[ "${LOG_FILE:-}" == "/dev/null" ]]; then
        return 0
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

handle_interrupt() {
    local sig="$1"
    local code="$2"
    log_warn "Received signal $sig"
    if [[ -n "${QUBE_NAME:-}" ]]; then
        log_warn "Cleaning up partially created qube: $QUBE_NAME"
        cleanup_qube "$QUBE_NAME" "$code" 2>/dev/null || true
    fi
    exit "$code"
}

trap 'handle_interrupt INT 130' INT
trap 'handle_interrupt TERM 143' TERM

init_lock_fd() {
    # Initialize file descriptor for flock after directories exist
    local lock_fd_file="${XDG_RUNTIME_DIR}/ram-disposable.lockfd"
    (
        umask 077
        : > "$lock_fd_file"
        chmod 600 "$lock_fd_file" 2>/dev/null || true
    ) || die "Cannot create lock file"
    exec 200>"$lock_fd_file" || die "Cannot create lock file descriptor"
    LOCK_FD=200
}

check_lock() {
    # Atomic locking using flock
    if [[ -z "$LOCK_FD" ]]; then
        init_lock_fd
    fi
    
    if ! flock -n "$LOCK_FD" 2>/dev/null; then
        die "Another instance is running. Wait or check ${XDG_RUNTIME_DIR}/ram-disposable.lockfd"
    fi

}

release_lock() {
    [[ -n "$LOCK_FD" ]] && flock -u "$LOCK_FD" 2>/dev/null || true
}

require_dom0() {
    [[ "$(hostname)" == "dom0" ]] || die "This script must be run in dom0"
}

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

check_sudo() {
    if ! sudo -n true 2>/dev/null; then
        die "Passwordless sudo required in dom0. Check /etc/sudoers or polkit rules."
    fi
}

check_not_root() {
    [[ $EUID -ne 0 ]] || die "Do not run this script as root. Run as regular dom0 user."
}

#===============================================================================
# INPUT VALIDATION
#===============================================================================

# Validate qube/pool/template names - alphanumeric, dash, underscore only
validate_name() {
    local name="$1"
    local type="${2:-name}"
    
    # Empty is allowed for optional params
    [[ -z "$name" ]] && return 0
    
    if [[ ! "$name" =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ ]]; then
        die "Invalid $type: '$name'. Must start with letter, contain only [a-zA-Z0-9_-]"
    fi
    
    if [[ ${#name} -gt 31 ]]; then
        die "Invalid $type: '$name'. Maximum length is 31 characters"
    fi
    
    # Check for path traversal attempts
    if [[ "$name" == *".."* || "$name" == *"/"* ]]; then
        die "Invalid $type: '$name'. Path traversal detected"
    fi
}

# Validate size format (e.g., 1G, 512M)
validate_size() {
    local size="$1"
    if [[ ! "$size" =~ ^[0-9]+[MGK]$ ]]; then
        die "Invalid size format: '$size'. Use format like 1G, 512M, 256K"
    fi
}

# Validate memory (numeric, reasonable range)
validate_memory() {
    local mem="$1"
    if [[ ! "$mem" =~ ^[0-9]+$ ]]; then
        die "Invalid memory value: '$mem'. Must be numeric (MB)"
    fi
    # Prevent integer overflow in bash arithmetic
    if [[ ${#mem} -gt 5 ]]; then
        die "Invalid memory value: '$mem'. Value too large"
    fi
    if (( mem < 128 || mem > 65536 )); then
        die "Invalid memory value: '$mem'. Must be between 128 and 65536 MB"
    fi
}

# Validate label color
validate_label() {
    local label="$1"
    local valid_labels="red orange yellow green gray blue purple black"
    if [[ ! " $valid_labels " =~ " $label " ]]; then
        die "Invalid label: '$label'. Valid: $valid_labels"
    fi
}

# Validate path is under expected base (prevent sudo rm disasters)
validate_safe_path() {
    local path="$1"
    local base="$2"
    
    [[ -n "$path" ]] || die "Security: empty path provided"
    [[ -n "$base" ]] || die "Security: empty base provided"

    [[ "$path" != "/" ]] || die "Security: refusing to operate on root"
    [[ "$path" != "$base" ]] || die "Security: refusing to operate on base directory"

    # Detect real ".." path components only
    if [[ "$path" =~ (^|/)\.\.(/|$) ]]; then
        die "Security: path traversal detected in '$path'"
    fi

    command -v realpath >/dev/null 2>&1 || die "Security: realpath is required"

    local resolved_base resolved_path
    resolved_base="$(realpath -e -- "$base")" || die "Security: base path '$base' cannot be resolved"
    resolved_path="$(realpath -m -- "$path")" || die "Security: path '$path' cannot be resolved"

    [[ "$resolved_path" != "$resolved_base" ]] || die "Security: refusing to operate on base directory"
    [[ "$resolved_path" == "$resolved_base/"* ]] || die "Security: path '$path' resolves outside '$base'"
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
    -q, --qubename <name>     Custom qube name [default: rdispNNNN]
    -n, --netvm <vm>          NetVM [default: none]
    -s, --tempsize <size>     RAM drive size: 1G, 2G, etc [default: 1G]
    -m, --memory <mb>         Qube memory in MB [default: 400]
    -l, --label <color>       Label color [default: auto based on netvm]
    -v, --default-dispvm <vm> Default disposable VM [default: none]
    
${BOLD}Privacy Options:${NC}
    --no-hardened             Disable all privacy hardening
    --sanitize-output         Filter terminal escape sequences (default: on)
    --no-sanitize-output      Disable escape sequence filtering (colored output)
    
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
    $SCRIPT_NAME launch -t whonix-workstation-17-dvm -n sys-whonix -- torbrowser

    # Launch Firefox with no network (direct execution)
    $SCRIPT_NAME launch -t fedora-40-dvm -- firefox

    # Launch Firefox with arguments
    $SCRIPT_NAME launch -t fedora-40-dvm -- firefox --private-window https://example.com

    # Launch with custom settings and 2GB RAM
    $SCRIPT_NAME launch -t debian-12-dvm -n sys-firewall -s 2G -m 2000 -- xterm

    # Launch without privacy hardening (not recommended)
    $SCRIPT_NAME launch -t fedora-40-dvm --no-hardened -- firefox

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

${BOLD}Output Sanitization (enabled by default):${NC}
    Filters potentially malicious terminal escape sequences from VM output.
    Protects against terminal escape sequence attacks from compromised VMs.
    Use --no-sanitize-output if you need colored CLI output.

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
    
    # Also validate name format
    validate_name "$template" "template"
    
    log_debug "Template '$template' validated"
}

validate_netvm() {
    local netvm="$1"
    
    [[ -z "$netvm" ]] && return 0
    
    if ! qvm-check "$netvm" &>/dev/null; then
        die "NetVM '$netvm' does not exist"
    fi
    
    # Also validate name format
    validate_name "$netvm" "netvm"
    
    log_debug "NetVM '$netvm' validated"
}

generate_qube_name() {
    local name attempts=0 max_attempts=200
    while (( attempts++ < max_attempts )); do
        name="rdisp$(/usr/bin/shuf --input-range=100-9999 --head-count=1)"
        if ! qvm-check "$name" &>/dev/null; then
            echo "$name"
            return 0
        fi
    done
    die "Failed to generate unique qube name after $max_attempts attempts"
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
    
    # Avoid broad pattern deletes in /var/log. Keep deletion strictly scoped to known log paths above.
    # If you need rotated logs, implement exact-match patterns per expected filenames,
    # not "*${qube}*" which can remove unrelated files.
}

remove_menu_files() {
    local qube="$1"
    local menudir="${HOME}/.config/menus/applications-merged"
    
    # Escape regex special characters in qube name (defensive)
    local escaped_qube="${qube//./\\.}"
    escaped_qube="${escaped_qube//\*/\\*}"
    
    find "$menudir" \
        -regextype posix-egrep \
        -regex ".*\/user-qubes-(disp)?vm-directory(_|-)${escaped_qube}\.menu$" \
        -delete 2>/dev/null || true
}

#===============================================================================
# SYSTEM LOGS CLEANUP
#===============================================================================

cleanup_system_logs() {
    local qube="$1"

    if [[ "$WIPE_SYSTEM_LOGS" != "true" ]]; then
        log_debug "System log wiping disabled (WIPE_SYSTEM_LOGS=false)"
        return 0
    fi
    
    log_debug "Cleaning system logs for $qube"
    
    # Journalctl — rotate and vacuum
    sudo journalctl --rotate 2>/dev/null || true
    sync 2>/dev/null || true
    sudo journalctl --vacuum-time=1s 2>/dev/null || true
    
    # Force removal of recent journal files
    sudo find /var/log/journal -name "*.journal" -mmin -10 -delete 2>/dev/null || true
    sudo find /var/log/journal -name "*.journal~" -delete 2>/dev/null || true
    sudo find /run/log/journal -name "*.journal" -mmin -10 -delete 2>/dev/null || true
    
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

    # Refuse to delete arbitrary qubes by default
    if [[ "$FORCE_CLEANUP" != "true" ]]; then
        if [[ ! "$qube" =~ ^rdisp[0-9]+$ ]]; then
            # Allow if we can prove it's one of ours (pool/template remnants exist)
            if ! qvm-pool info "ram_pool_${qube}" &>/dev/null && ! qvm-check "ram-tpl-${qube}" &>/dev/null; then
                die "Refusing to cleanup non-RAM qube '$qube' without --force"
            fi
        fi
    fi
    
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
    
    # Remove temp directory (prefer rmdir; fallback to constrained rm)
    if [[ -e "$tempdir" ]]; then
        validate_safe_path "$tempdir" "$TEMPDIR_ROOT"
        if [[ -L "$tempdir" ]]; then
            log_warn "Refusing to remove symlink path: $tempdir"
        else
            log_info "Removing temp directory..."
            sudo rmdir -- "$tempdir" 2>/dev/null || \
                sudo rm -rf --one-file-system -- "$tempdir" 2>/dev/null || true
        fi
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

    # Never allow untrusted VM output to be rendered in dom0 terminal here.
    # A compromised VM could print malicious terminal escape sequences.
    if generate_privacy_script | qvm-run --pass-io --no-shell "$qube" -- /usr/bin/env bash -s >/dev/null 2>&1; then
        log_debug "Privacy hardening applied"
    else
        log_warn "Some privacy settings could not be applied (non-critical)"
    fi
}

#===============================================================================
# ENSURE VM VOLUMES ARE ON RAM POOL
#===============================================================================

ensure_qube_on_ram_pool() {
    local qube="$1"
    local pool="$2"

    # Move volumes that exist to the RAM pool. Root may already be correct via template clone.
    local vol cur_pool
    for vol in root private volatile; do
        if ! qvm-volume info "${qube}:${vol}" &>/dev/null; then
            continue
        fi
        cur_pool="$(qvm-volume info "${qube}:${vol}" pool 2>/dev/null || echo "")"
        if [[ "$cur_pool" != "$pool" ]]; then
            log_info "Moving volume ${qube}:${vol} to pool ${pool}..."
            qvm-volume move "${qube}:${vol}" "$pool" || die "Failed to move ${qube}:${vol} to ${pool}"
        fi
    done

    # Verify (fail closed)
    for vol in root private volatile; do
        if qvm-volume info "${qube}:${vol}" &>/dev/null; then
            cur_pool="$(qvm-volume info "${qube}:${vol}" pool 2>/dev/null || echo "")"
            [[ "$cur_pool" == "$pool" ]] || die "Volume ${qube}:${vol} is on pool '${cur_pool}', expected '${pool}'"
        fi
    done
}

#===============================================================================
# LAUNCH RAM-BASED QUBE
#===============================================================================

launch_qube() {
    log_section "LAUNCH RAM-BASED QUBE"
    
    # Validate inputs
    [[ -z "$TEMPLATE" ]] && die "Template is required (-t/--template)"
    if [[ ${#COMMAND_ARGS[@]} -eq 0 ]]; then
        die "Command required: use -- <command> [args]"
    fi

    # Defensive: avoid weird/ambiguous “command as option” cases
    if [[ -z "${COMMAND_ARGS[0]:-}" ]]; then
        die "Command required: use -- <command> [args]"
    fi
    if [[ "${COMMAND_ARGS[0]}" == "-"* ]]; then
        die "Refusing to run a command starting with '-': '${COMMAND_ARGS[0]}'"
    fi
    
    # Validate all input parameters
    validate_name "$TEMPLATE" "template"
    [[ -n "$QUBE_NAME" ]] && validate_name "$QUBE_NAME" "qube name"
    validate_name "$NETVM" "netvm"
    validate_name "$DEFAULT_DISPVM" "default-dispvm"
    validate_size "$TEMPSIZE"
    validate_memory "$MEMORY"
    # Label will be validated after auto_select_label
    
    validate_template "$TEMPLATE"
    validate_netvm "$NETVM"
    
    # Generate name if not provided
    if [[ -z "$QUBE_NAME" ]]; then
        QUBE_NAME=$(generate_qube_name)
    fi
    
    POOL_NAME="ram_pool_${QUBE_NAME}"
    TEMPDIR="${TEMPDIR_ROOT}/${QUBE_NAME}"
    
    # Check if tempdir or pool already exist
    [[ -d "$TEMPDIR" ]] && die "Directory '$TEMPDIR' already exists"
    qvm-pool info "$POOL_NAME" &>/dev/null && die "Pool '$POOL_NAME' already exists"
    
    # Auto-select label based on netvm
    auto_select_label
    validate_label "$LABEL"
    
    # Validate the tempdir path will be safe
    validate_safe_path "$TEMPDIR" "$TEMPDIR_ROOT"
    
    log_info "Configuration:"
    log_info "  Qube name:      $QUBE_NAME"
    log_info "  Template:       $TEMPLATE"
    log_info "  Command:        ${COMMAND_ARGS[*]}"
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
    if ! sudo swapoff --all 2>/dev/null; then
        log_warn "Could not disable swap"
    fi
    
    # Verify swap is actually disabled
    if [[ -n "$(swapon --show 2>/dev/null)" ]]; then
        die "Swap is still active. RAM qube data may leak to disk. Disable swap manually or use --force-with-swap (not implemented)"
    fi
    log_debug "Swap verified disabled"
    
    # Create temp directory
    log_info "Creating RAM disk..."
    mkdir -p -- "$TEMPDIR"
    # Refuse symlink mountpoints
    [[ ! -L "$TEMPDIR" ]] || die "Refusing to mount on symlink: $TEMPDIR"
    
    # Mount tmpfs
    sudo mount --types tmpfs \
        --options "size=${TEMPSIZE},mode=700" \
        "$POOL_NAME" \
        "$TEMPDIR" || die "Failed to mount tmpfs"

    # Verify mount is in place and is tmpfs
    mountpoint -q -- "$TEMPDIR" || die "Failed to verify tmpfs mountpoint: $TEMPDIR"
    [[ "$(findmnt -n -o FSTYPE -- "$TEMPDIR" 2>/dev/null || true)" == "tmpfs" ]] || \
        die "Unexpected filesystem type at $TEMPDIR (expected tmpfs)"
    
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
    qvm-prefs "$RAM_TEMPLATE" template_for_dispvms True || {
        cleanup_qube "$QUBE_NAME" 1; die "Failed to configure RAM template"; }
    qvm-prefs "$RAM_TEMPLATE" include_in_backups False || {
        cleanup_qube "$QUBE_NAME" 1; die "Failed to configure RAM template"; }
    
    # Create DispVM from RAM template
    log_info "Creating disposable VM..."
    qvm-create \
        --class DispVM \
        --template "$RAM_TEMPLATE" \
        --label "$LABEL" \
        "$QUBE_NAME" 2>&1 || {
            # Handle race condition: name might have been taken
            if qvm-check "$QUBE_NAME" &>/dev/null; then
                cleanup_qube "$QUBE_NAME" 1
                die "Qube '$QUBE_NAME' was created by another process (race condition)"
            fi
            cleanup_qube "$QUBE_NAME" 1
            die "Failed to create disposable VM"
        }


    # Ensure all volumes actually live in the RAM-backed pool (fail closed)
    ensure_qube_on_ram_pool "$QUBE_NAME" "$POOL_NAME"
    
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
    # Timeout prevents infinite hang if qube fails to start
    timeout 120 qvm-start "$QUBE_NAME" || {
        cleanup_qube "$QUBE_NAME" 1
        die "Failed to start qube"
    }
    
    # Apply privacy hardening
    apply_privacy_hardening "$QUBE_NAME"
    
    # Release lock before running command (allows parallel launches)
    release_lock
    
    # Run the command
    log_info "Running command..."
    log_info "=========================================="
    
    local run_exit_code=0
    set +e
    if [[ "$SANITIZE_OUTPUT" == "true" ]]; then
        log_debug "Output sanitization enabled"
        log_debug "Output limited to $MAX_OUTPUT_SIZE"
        # Strict output sanitization:
        # 1. Limit output size to prevent DoS
        # 2. Remove ALL non-printable characters except tab, newline, carriage return
        # 3. This is more aggressive but safer than regex-based filtering
        qvm-run --pass-io --no-shell "$QUBE_NAME" -- "${COMMAND_ARGS[@]}" 2>&1 | \
            head -c "$MAX_OUTPUT_SIZE" | \
            LC_ALL=C tr -cd '\011\012\015\040-\176'
        # Preserve exit code of qvm-run, not of head/tr
        run_exit_code=${PIPESTATUS[0]}
    else
        # Even without sanitization, limit output size
        qvm-run --pass-io --no-shell "$QUBE_NAME" -- "${COMMAND_ARGS[@]}" 2>&1 | \
            head -c "$MAX_OUTPUT_SIZE"
        # Preserve exit code of qvm-run, not of head
        run_exit_code=${PIPESTATUS[0]}
    fi

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
        pool_size=$(qvm-pool info "$pool" 2>/dev/null | awk -F': *' '$1=="size"{print $2; exit}' | awk '/^[0-9]+$/{print; exit} END{if(NR==0)print 0}')
        pool_usage=$(qvm-pool info "$pool" 2>/dev/null | awk -F': *' '$1=="usage"{print $2; exit}' | awk '/^[0-9]+$/{print; exit} END{if(NR==0)print 0}')
        ephemeral_volatile=$(qvm-pool info "$pool" 2>/dev/null | awk -F': *' '$1=="ephemeral_volatile"{print $2; exit}')
        
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
                    local tempdir="${TEMPDIR_ROOT}/${qube}"
                    # Validate before removal
                    validate_safe_path "$tempdir" "$TEMPDIR_ROOT"
                    
                    qvm-pool remove "$pool" 2>/dev/null || true
                    sudo umount "$tempdir" 2>/dev/null || true
                    sudo rmdir -- "$tempdir" 2>/dev/null || \
                        sudo rm -rf --one-file-system -- "$tempdir" 2>/dev/null || true
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
        local base_real
        base_real="$(realpath -e -- "$TEMPDIR_ROOT")" || die "Cannot resolve base dir: $TEMPDIR_ROOT"

        # Use find -P to avoid following symlinks; do NOT use "$TEMPDIR_ROOT"/*/ (symlink+trailing-slash risk)
        while IFS= read -r -d '' dir; do
            [[ -z "$dir" ]] && continue

            # Refuse to operate on symlinks at all
            if [[ -L "$dir" ]]; then
                log_warn "Refusing to handle symlinked directory: $dir"
                continue
            fi

            local dir_real qube
            dir_real="$(realpath -e -- "$dir")" || { log_warn "Cannot resolve dir: $dir"; continue; }
            [[ "$dir_real" == "$base_real/"* ]] || { log_warn "Skipping outside-base path: $dir_real"; continue; }

            qube="$(basename -- "$dir_real")"
            [[ -z "$qube" ]] && continue

            if ! qvm-check "$qube" &>/dev/null; then
                echo -e "Found orphaned directory: ${CYAN}$dir_real${NC}"
                read -r -p "  Remove? [y/N/q]: " ans
                case "$ans" in
                    [Yy]*)
                        # Validate before removal (defense-in-depth)
                        validate_safe_path "$dir_real" "$TEMPDIR_ROOT"

                        sudo umount -- "$dir_real" 2>/dev/null || true
                        sudo rmdir -- "$dir_real" 2>/dev/null || \
                            sudo rm -rf --one-file-system -- "$dir_real" 2>/dev/null || true
                        log_info "Removed directory $dir_real"
                        ;;
                    [Qq]*)
                        log_info "Aborted"
                        return 0
                        ;;
                esac
            fi
        done < <(find -P "$TEMPDIR_ROOT" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)
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
        while IFS= read -r -d '' logfile; do
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
    done < <(find "$(dirname "$pattern")" -maxdepth 1 -name "$(basename "$pattern")" -print0 2>/dev/null)
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
    check_not_root
    check_sudo
    
    local required_cmds=(qvm-create qvm-prefs qvm-run qvm-clone qvm-pool qvm-volume qvm-check qvm-kill qvm-remove qvm-start timeout realpath findmnt mountpoint)
    for cmd in "${required_cmds[@]}"; do
        has_cmd "$cmd" || die "Required command not found: $cmd"
    done
    if [[ "$NOTIFY" == "true" ]]; then
        has_cmd notify-send || die "Required command not found: notify-send"
    fi
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
                    --sanitize-output)
                        SANITIZE_OUTPUT="true"
                        shift
                        ;;
                    --no-sanitize-output)
                        SANITIZE_OUTPUT="false"
                        shift
                        ;;
                    --dry-run)
                        DRY_RUN="true"
                        shift
                        ;;
                    --wipe-system-logs)
                        WIPE_SYSTEM_LOGS="true"
                        shift
                        ;;
                    --quiet)
                        QUIET="true"
                        shift
                        ;;
                    --no-notify)
                        NOTIFY="false"
                        shift
                        ;;
                    --)
                        shift
                        COMMAND_ARGS=("$@")
                        break
                        ;;
                    *)
                        die "Unknown option: $1"
                        ;;
                esac
            done
            
            # Validate: need -- args
            [[ ${#COMMAND_ARGS[@]} -eq 0 ]] && die "Command required: use -- <command> [args]"
            
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
                    --force)
                        FORCE_CLEANUP="true"
                        shift
                        ;;
                    *)
                        die "Unknown option: $1"
                        ;;
                esac
            done
            
            if [[ "$cleanup_all" == "true" ]]; then
                cleanup_all_remnants
            elif [[ -n "$cleanup_qube" ]]; then
                validate_name "$cleanup_qube" "qube name"
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
