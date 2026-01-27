#!/usr/bin/env bash
#===============================================================================
# OPENBSD + MIRAGE FIREWALL INSTALLER
#===============================================================================

set -euo pipefail
set -E
export LC_ALL=C
umask 027

readonly SCRIPT_VERSION="2.6.2-merged"
readonly SCRIPT_NAME="$(basename "$0")"

#===============================================================================
# PATHS
#===============================================================================

readonly STATE_DIR="/var/lib/openbsd-mirage"
readonly MIRAGE_INSTALL_DIR="/var/lib/qubes/vm-kernels/mirage-firewall"
readonly SNAPSHOT_NAME="clean-install"

# Files live inside DOWNLOAD_VM only
readonly DOWNLOAD_VM_DIR="/home/user"

#===============================================================================
# TIMEOUTS / LIMITS
#===============================================================================

readonly QVM_RUN_TIMEOUT_SEC=600
readonly STREAM_TIMEOUT_SEC=300   # full pipeline timeout (adopted from v3 idea)

readonly MAX_OPENBSD_ISO_BYTES=$((2 * 1024 * 1024 * 1024))
readonly MIN_OPENBSD_ISO_BYTES=$((200 * 1024 * 1024))

readonly MAX_MIRAGE_KERNEL_BYTES=$((128 * 1024 * 1024))
readonly MIN_MIRAGE_KERNEL_BYTES=$((256 * 1024))

#===============================================================================
# MIRAGE CONFIGURATION
#===============================================================================

readonly MIRAGE_RELEASE="v0.9.5"
readonly MIRAGE_FILENAME="qubes-firewall.xen"
readonly MIRAGE_EXPECTED_HASH="2bfb49696e59a8ffbb660399e52bd82ffadbd02437d282eb8daab568b3261999"
readonly MIRAGE_GITHUB_URL="https://github.com/mirage/qubes-mirage-firewall"

#===============================================================================
# OPENBSD CONFIGURATION
#===============================================================================

readonly OPENBSD_VERSION="7.8"
readonly OPENBSD_ISO="install78.iso"
readonly OPENBSD_EXPECTED_HASH="a228d0a1ef558b4d9ec84c698f0d3ffd13cd38c64149487cba0f1ad873be07b2"
readonly OPENBSD_MIRROR="https://cdn.openbsd.org/pub/OpenBSD/7.8/amd64"

#===============================================================================
# DEFAULT CONFIG
#===============================================================================

OPENBSD_VM="sys-openbsd"
MIRAGE_TEMPLATE="mirage-tmpl"
MIRAGE_DVM_TEMPLATE="mirage-dvm"
MIRAGE_FW="sys-mirage-fw"
DOWNLOAD_VM="sys-whonix"
NET_DEVICE=""

DRY_RUN="false"
SKIP_OPENBSD_DOWNLOAD="false"
SKIP_MIRAGE="false"
SKIP_OPENBSD="false"
ASSUME_YES="false"
FORCE="false"
VERBOSE="false"

#===============================================================================
# LOGGING (adopted from v3 idea, lightweight)
#===============================================================================

log_debug() { [[ "$VERBOSE" == "true" ]] && echo "[DEBUG] $*" >&2 || true; }
log_info()  { echo "[INFO] $*"; }
log_warn()  { echo "[WARN] $*" >&2; }
log_error() { echo "[ERROR] $*" >&2; }

#===============================================================================
# TEMP FILE REGISTRY (cleanup on any exit/error)
#===============================================================================

TEMP_FILES=()
add_temp_file() { TEMP_FILES+=("$1"); }
remove_temp_file_from_registry() {
    local target="$1"
    local out=() f
    for f in "${TEMP_FILES[@]:-}"; do
        [[ "$f" == "$target" ]] || out+=("$f")
    done
    TEMP_FILES=("${out[@]:-}")
}

#===============================================================================
# TRAPS / BASICS
#===============================================================================

cleanup() {
    local f
    for f in "${TEMP_FILES[@]:-}"; do
        rm -f -- "$f" 2>/dev/null || true
    done
}
error_handler() {
    log_error "FATAL: error at line ${1:-?}: ${3:-?} (exit ${2:-?})"
}
trap cleanup EXIT
trap 'error_handler ${LINENO} $? "${BASH_COMMAND:-}"' ERR
trap 'log_error "Interrupted"; exit 130' INT
trap 'log_error "Terminated"; exit 143' TERM

die() { log_error "FATAL: ${1:-error}"; exit "${2:-1}"; }

require_dom0() { [[ "$(hostname)" == "dom0" ]] || die "Run in dom0"; }
require_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run as root (sudo)"; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }

run_cmd() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] $*"
        return 0
    fi
    "$@"
}

need_arg() { [[ -n "${2:-}" ]] || die "Missing argument for $1"; }

confirm() {
    local prompt="$1"
    if [[ "$ASSUME_YES" == "true" ]]; then
        log_info "[--yes] $prompt : yes"
        return 0
    fi
    local ans
    read -r -p "$prompt [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]]
}

#===============================================================================
# LOCKING (directory fd flock; avoids lockfile path TOCTOU)
#===============================================================================

ensure_state_dir() {
    install -d -m 0700 -o root -g root "$STATE_DIR"
    [[ -d "$STATE_DIR" ]] || die "STATE_DIR is not a directory: $STATE_DIR"
    [[ ! -L "$STATE_DIR" ]] || die "Refusing symlink STATE_DIR: $STATE_DIR"
}

check_lock() {
    ensure_state_dir
    exec 200<"$STATE_DIR"
    flock -n 200 || die "Script already running (lock: $STATE_DIR)"
    log_debug "Lock acquired on $STATE_DIR"
}

#===============================================================================
# INPUT VALIDATION
#===============================================================================

validate_vm_name() {
    local name="$1"
    [[ -n "$name" ]] || return 1
    [[ "$name" != "-"* ]] || return 1
    [[ "${#name}" -le 48 ]] || return 1
    # allow dot/underscore/dash like typical Qubes names
    [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || return 1
}

validate_all_names() {
    validate_vm_name "$DOWNLOAD_VM" || die "Unsafe --download-vm: '$DOWNLOAD_VM'"
    validate_vm_name "$OPENBSD_VM" || die "Unsafe --openbsd-vm: '$OPENBSD_VM'"
    validate_vm_name "$MIRAGE_FW" || die "Unsafe --mirage-vm: '$MIRAGE_FW'"
    validate_vm_name "$MIRAGE_TEMPLATE" || die "Unsafe internal name: '$MIRAGE_TEMPLATE'"
    validate_vm_name "$MIRAGE_DVM_TEMPLATE" || die "Unsafe internal name: '$MIRAGE_DVM_TEMPLATE'"

    [[ "$OPENBSD_VM" != "$DOWNLOAD_VM" ]] || die "OPENBSD_VM must not equal DOWNLOAD_VM"
    [[ "$MIRAGE_FW" != "$DOWNLOAD_VM" ]] || die "MIRAGE_FW must not equal DOWNLOAD_VM"
    [[ "$MIRAGE_FW" != "$OPENBSD_VM" ]] || die "MIRAGE_FW must not equal OPENBSD_VM"
}

validate_bdf() {
    local bdf="$1"
    [[ "$bdf" =~ ^([0-9a-fA-F]{4}:)?[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$ ]]
}
normalize_bdf() { local bdf="$1"; echo "${bdf#0000:}"; }
bdf_to_qvm_pci_id() { local bdf; bdf="$(normalize_bdf "$1")"; echo "${bdf/:/_}"; }

#===============================================================================
# qvm-run runs via shell in VM: strict quoting + strict remote path policy
#===============================================================================

shell_quote_sh() {
    local s="$1"
    printf "'%s'" "$(printf '%s' "$s" | sed "s/'/'\\\\''/g")"
}

# (Stricter than v2.6.1; adopted from v3 idea)
assert_safe_remote_path() {
    local p="$1"
    [[ -n "$p" ]] || die "Empty remote path"
    [[ "${#p}" -le 4096 ]] || die "Remote path too long"
    # absolute only, safe charset
    [[ "$p" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "Unsafe remote path (refusing): $p"
    # reject traversal/normalization pitfalls
    [[ "$p" != *".."* ]] || die "Remote path contains '..' (refusing): $p"
    [[ "$p" != *"//"* ]] || die "Remote path contains '//' (refusing): $p"
    [[ "$p" != "/" ]] || die "Remote path must not be '/': $p"
}

#===============================================================================
# QVM-RUN WRAPPERS (timeout)
#===============================================================================

qvm_run_io() {
    local vm="$1"
    local cmd="$2"
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] timeout $QVM_RUN_TIMEOUT_SEC qvm-run -a --pass-io --no-gui $vm $cmd"
        return 0
    fi
    timeout "$QVM_RUN_TIMEOUT_SEC" qvm-run -a --pass-io --no-gui "$vm" "$cmd"
}

qvm_run_quiet() {
    local vm="$1"
    local cmd="$2"
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] timeout $QVM_RUN_TIMEOUT_SEC qvm-run -a --no-gui $vm $cmd"
        return 0
    fi
    timeout "$QVM_RUN_TIMEOUT_SEC" qvm-run -a --no-gui "$vm" "$cmd"
}

#===============================================================================
# DOWNLOAD-VM FILE OPS (do not mask errors)
#===============================================================================

linux_vm_file_size_bytes() {
    local vm="$1"
    local remote_path="$2"
    assert_safe_remote_path "$remote_path"
    local out
    out="$(qvm_run_io "$vm" "stat -c %s -- $(shell_quote_sh "$remote_path")" | tr -d '[:space:]' | head -c 32)"
    [[ "$out" =~ ^[0-9]{1,12}$ ]] || die "Invalid size from VM (got: '$out')"
    echo "$out"
}

sha256_in_vm() {
    local vm="$1"
    local remote_path="$2"
    assert_safe_remote_path "$remote_path"
    local out
    out="$(
        qvm_run_io "$vm" "sha256sum -- $(shell_quote_sh "$remote_path") | awk '{print \$1}'" \
        | tr -d '[:space:]' | tr 'A-F' 'a-f' | head -c 80
    )"
    [[ "$out" =~ ^[0-9a-f]{64}$ ]] || die "Invalid sha256 from VM (got: '$out')"
    echo "$out"
}

#===============================================================================
# PREFLIGHT
#===============================================================================

preflight_checks() {
    require_dom0
    require_root
    validate_all_names

    local required_cmds=(
        qvm-check qvm-create qvm-prefs qvm-run qvm-features qvm-volume qvm-ls
        qvm-kill qvm-remove qvm-pci qvm-shutdown qvm-start
        lvs lvcreate lvremove lvconvert
        flock lspci sha256sum awk sed timeout mktemp install head tr tee wc stat findmnt
        mv df dirname basename bash
    )
    local cmd
    for cmd in "${required_cmds[@]}"; do
        has_cmd "$cmd" || die "Missing dom0 command: $cmd"
    done

    qvm-check "$DOWNLOAD_VM" &>/dev/null || die "Download VM not found: $DOWNLOAD_VM"

    # Ensure download VM has tools we call
    qvm_run_io "$DOWNLOAD_VM" "command -v curl >/dev/null && command -v sha256sum >/dev/null && command -v stat >/dev/null && command -v head >/dev/null && command -v awk >/dev/null" \
        >/dev/null || die "Download VM lacks required tools (need: curl sha256sum stat head awk)"

    qvm_run_quiet "$DOWNLOAD_VM" "mkdir -p $(shell_quote_sh "$DOWNLOAD_VM_DIR")" >/dev/null || true
    log_info "Preflight checks passed"
}

#===============================================================================
# Guardrails for destructive operations (blast radius)
#===============================================================================

get_vm_pref() { qvm-prefs "$1" "$2" 2>/dev/null | tr -d '\r'; }
get_vm_class() { qvm-ls --raw-data --fields class "$1" 2>/dev/null | tail -n 1 | tr -d '\r'; }

assert_ok_to_delete_vm() {
    local vm="$1"
    local expected_kind="$2"
    [[ "$FORCE" == "true" ]] && return 0

    local cls kernel virt provides_network template
    cls="$(get_vm_class "$vm")"
    kernel="$(get_vm_pref "$vm" kernel)"
    virt="$(get_vm_pref "$vm" virt_mode)"
    provides_network="$(get_vm_pref "$vm" provides_network)"
    template="$(get_vm_pref "$vm" template)"

    case "$expected_kind" in
        openbsd)
            [[ "$cls" == "StandaloneVM" ]] || die "Refusing to delete '$vm': not StandaloneVM (use --force)"
            [[ "$virt" == "hvm" ]] || die "Refusing to delete '$vm': virt_mode not hvm (use --force)"
            [[ -z "$kernel" ]] || die "Refusing to delete '$vm': kernel is set (use --force)"
            [[ "$provides_network" == "True" ]] || die "Refusing to delete '$vm': provides_network not True (use --force)"
            ;;
        mirage-template)
            [[ "$cls" == "TemplateVM" ]] || die "Refusing to delete '$vm': not TemplateVM (use --force)"
            [[ "$kernel" == "mirage-firewall" ]] || die "Refusing to delete '$vm': kernel not mirage-firewall (use --force)"
            ;;
        mirage-dvm-template)
            [[ "$cls" == "AppVM" ]] || die "Refusing to delete '$vm': not AppVM (use --force)"
            [[ -n "$template" ]] || die "Refusing to delete '$vm': no template set (use --force)"
            ;;
        mirage-fw)
            [[ "$cls" == "DispVM" ]] || die "Refusing to delete '$vm': not DispVM (use --force)"
            [[ "$provides_network" == "True" ]] || die "Refusing to delete '$vm': provides_network not True (use --force)"
            ;;
        *)
            die "Internal error: unknown expected_kind '$expected_kind'"
            ;;
    esac
}

#===============================================================================
# NETWORK DEVICE
#===============================================================================

detect_net_device() {
    if [[ -n "$NET_DEVICE" ]]; then
        validate_bdf "$NET_DEVICE" || die "Invalid --net-device: '$NET_DEVICE'"
        local bdf_norm
        bdf_norm="$(normalize_bdf "$NET_DEVICE")"
        lspci -s "$bdf_norm" >/dev/null 2>&1 || die "PCI device not found: $bdf_norm"
        log_info "Using NIC: $NET_DEVICE"
        return 0
    fi

    if [[ "$ASSUME_YES" == "true" ]]; then
        log_warn "No --net-device provided; skipping (attach manually later)."
        return 0
    fi

    echo "Available PCI network devices (first 10):"
    ( lspci | grep -iE "network|ethernet" | head -10 || true ) | sed 's/^/  /'
    echo ""
    read -r -p "Enter device BDF (e.g., 00:14.3) or Enter to skip: " NET_DEVICE
    [[ -z "$NET_DEVICE" ]] && { log_info "No device selected."; return 0; }

    validate_bdf "$NET_DEVICE" || die "Invalid BDF format: '$NET_DEVICE'"
    local bdf_norm
    bdf_norm="$(normalize_bdf "$NET_DEVICE")"
    lspci -s "$bdf_norm" >/dev/null 2>&1 || die "PCI device not found: $bdf_norm"
    log_info "Selected NIC: $NET_DEVICE"
}

#===============================================================================
# SAFE TEMP FILES (subshell umask; no restore window)
#===============================================================================

mktemp_private() {
    local template="$1"
    local dir="${2:-/tmp}"
    ( umask 077; exec mktemp --tmpdir="$dir" "$template" )
}

#===============================================================================
# MIRAGE INSTALL (stronger dir checks + atomic writes + no unverified disk write)
#===============================================================================

ensure_safe_mirage_install_dir() {
    install -d -m 0755 -o root -g root "$MIRAGE_INSTALL_DIR"
    [[ -d "$MIRAGE_INSTALL_DIR" ]] || die "Not a directory: $MIRAGE_INSTALL_DIR"
    [[ ! -L "$MIRAGE_INSTALL_DIR" ]] || die "Refusing symlink install dir: $MIRAGE_INSTALL_DIR"

    local u g
    u="$(stat -c '%u' "$MIRAGE_INSTALL_DIR")"
    g="$(stat -c '%g' "$MIRAGE_INSTALL_DIR")"
    [[ "$u" == "0" && "$g" == "0" ]] || die "Install dir must be owned by root:root"

    local hex mode perm
    hex="$(stat -c '%f' "$MIRAGE_INSTALL_DIR")"
    mode=$((16#$hex))
    perm=$((mode & 07777))
    (( (perm & 07000) == 0 )) || die "Install dir has suid/sgid/sticky bits set (unsafe)"
    (( (perm & 00022) == 0 )) || die "Install dir is group/other-writable (unsafe)"
}

require_dev_shm_tmpfs() {
    [[ -d /dev/shm ]] || die "/dev/shm does not exist"
    [[ -w /dev/shm ]] || die "/dev/shm not writable; refusing"

    local fstype
    fstype="$(findmnt -n -o FSTYPE --target /dev/shm 2>/dev/null || true)"
    [[ "$fstype" == "tmpfs" ]] || die "/dev/shm is not tmpfs (fstype=$fstype); refusing"

    local source
    source="$(findmnt -n -o SOURCE --target /dev/shm 2>/dev/null || true)"
    [[ "$source" == "tmpfs" || "$source" == "shm" || "$source" == "none" || -z "$source" ]] || \
        die "/dev/shm has unexpected source '$source' (possible bind mount); refusing"

    local avail_kb
    avail_kb="$(df -k /dev/shm 2>/dev/null | awk 'NR==2 {print $4}')"
    if [[ "$avail_kb" =~ ^[0-9]+$ ]]; then
        local avail_bytes=$((avail_kb * 1024))
        local required=$((MAX_MIRAGE_KERNEL_BYTES + 1024*1024))
        if (( avail_bytes < required )); then
            die "/dev/shm has insufficient space: ${avail_kb}KB available, need $((required/1024))KB"
        fi
    fi
}

atomic_replace_file() {
    local src="$1"
    local dest="$2"
    local d
    d="$(dirname "$dest")"

    [[ -d "$d" ]] || die "Destination directory not found: $d"
    [[ ! -L "$d" ]] || die "Refusing symlink directory: $d"

    mv -T -f -- "$src" "$dest"
}

create_empty_file_atomic() {
    local dest="$1"
    local dir
    dir="$(dirname "$dest")"
    local tmp
    tmp="$(mktemp_private ".tmp.$(basename "$dest").XXXXXXXXXXXX" "$dir")"
    add_temp_file "$tmp"
    : > "$tmp"
    chmod 0644 "$tmp"
    chown root:root "$tmp" 2>/dev/null || true
    atomic_replace_file "$tmp" "$dest"
    remove_temp_file_from_registry "$tmp"
}

# Full-pipeline streaming with timeout (adopted from v3 idea)
stream_kernel_to_shm_and_hash() {
    local vm="$1"
    local remote_path="$2"
    local max_bytes="$3"
    local out_file="$4"

    assert_safe_remote_path "$remote_path"
    [[ -n "$out_file" ]] || die "Internal: empty out_file"

    # validate vm name to avoid weird injection via printf %q
    validate_vm_name "$vm" || die "Unsafe VM name: '$vm'"

    local vm_q out_q remote_q
    vm_q="$(printf '%q' "$vm")"
    out_q="$(printf '%q' "$out_file")"
    remote_q="$(shell_quote_sh "$remote_path")"   # for remote shell

    # We run a bash -o pipefail subshell so timeout applies to the entire pipeline.
    # qvm-run has its own timeout elsewhere, but pipeline can still hang (tee/sha256sum).
    timeout "$STREAM_TIMEOUT_SEC" bash -o pipefail -c \
        "qvm-run -a --pass-io --no-gui $vm_q \"head -c $max_bytes -- $remote_q\" \
         | tee $out_q \
         | sha256sum | awk '{print \$1}'"
}

install_mirage_kernel() {
    [[ "$SKIP_MIRAGE" == "true" ]] && { log_info "Skipping Mirage."; return 0; }

    local remote_kernel="$DOWNLOAD_VM_DIR/$MIRAGE_FILENAME"
    assert_safe_remote_path "$remote_kernel"

    log_info "Downloading Mirage kernel into $DOWNLOAD_VM:$DOWNLOAD_VM_DIR ..."
    run_cmd timeout "$QVM_RUN_TIMEOUT_SEC" qvm-run -a --pass-io --no-gui "$DOWNLOAD_VM" \
        "cd $(shell_quote_sh "$DOWNLOAD_VM_DIR") && curl --proto '=https' --tlsv1.2 -fL --retry 3 --retry-delay 2 --connect-timeout 20 -O $(shell_quote_sh "${MIRAGE_GITHUB_URL}/releases/download/${MIRAGE_RELEASE}/${MIRAGE_FILENAME}")" \
        >/dev/null

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would verify Mirage and install into dom0: $MIRAGE_INSTALL_DIR/vmlinuz"
        return 0
    fi

    local vm_size
    vm_size="$(linux_vm_file_size_bytes "$DOWNLOAD_VM" "$remote_kernel")"
    if (( vm_size < MIN_MIRAGE_KERNEL_BYTES || vm_size > MAX_MIRAGE_KERNEL_BYTES )); then
        die "Mirage kernel size out of bounds (VM reported): ${vm_size} bytes"
    fi

    local vm_hash
    vm_hash="$(sha256_in_vm "$DOWNLOAD_VM" "$remote_kernel")"
    [[ "$vm_hash" == "$MIRAGE_EXPECTED_HASH" ]] || die "Mirage checksum mismatch (in VM)"

    ensure_safe_mirage_install_dir
    require_dev_shm_tmpfs

    local tmp_shm
    tmp_shm="$(mktemp_private "mirage-kernel.XXXXXXXXXXXX" "/dev/shm")"
    add_temp_file "$tmp_shm"

    log_info "Streaming Mirage kernel from $DOWNLOAD_VM (timeout ${STREAM_TIMEOUT_SEC}s), hashing during stream..."
    local stream_hash
    stream_hash="$(
        stream_kernel_to_shm_and_hash "$DOWNLOAD_VM" "$remote_kernel" "$MAX_MIRAGE_KERNEL_BYTES" "$tmp_shm" \
        | tr -d '[:space:]' | tr 'A-F' 'a-f' | head -c 80
    )"
    [[ "$stream_hash" =~ ^[0-9a-f]{64}$ ]] || die "Invalid streamed sha256 in dom0"
    [[ "$stream_hash" == "$MIRAGE_EXPECTED_HASH" ]] || die "Mirage checksum mismatch (streamed in dom0)"

    local got_bytes
    got_bytes="$(wc -c < "$tmp_shm" | tr -d '[:space:]')"
    [[ "$got_bytes" =~ ^[0-9]+$ ]] || die "Cannot read received byte count"
    if (( got_bytes < MIN_MIRAGE_KERNEL_BYTES || got_bytes > MAX_MIRAGE_KERNEL_BYTES )); then
        die "Received kernel size out of bounds: $got_bytes bytes"
    fi

    local stage
    stage="$(mktemp_private ".vmlinuz.stage.XXXXXXXXXXXX" "$MIRAGE_INSTALL_DIR")"
    add_temp_file "$stage"
    install -m 0644 -o root -g root -- "$tmp_shm" "$stage"

    atomic_replace_file "$stage" "$MIRAGE_INSTALL_DIR/vmlinuz"
    remove_temp_file_from_registry "$stage"

    create_empty_file_atomic "$MIRAGE_INSTALL_DIR/initramfs"

    log_info "Mirage kernel installed: $MIRAGE_INSTALL_DIR/vmlinuz"
}

#===============================================================================
# OPENBSD ISO (NO COPY TO DOM0; VERIFY IN DOWNLOAD VM)
#===============================================================================

verify_openbsd_iso_in_download_vm() {
    local remote_iso="$DOWNLOAD_VM_DIR/$OPENBSD_ISO"
    assert_safe_remote_path "$remote_iso"

    local isosize vm_hash
    isosize="$(linux_vm_file_size_bytes "$DOWNLOAD_VM" "$remote_iso")"
    if (( isosize < MIN_OPENBSD_ISO_BYTES || isosize > MAX_OPENBSD_ISO_BYTES )); then
        die "ISO size out of bounds: ${isosize} bytes"
    fi

    vm_hash="$(sha256_in_vm "$DOWNLOAD_VM" "$remote_iso")"
    [[ "$vm_hash" == "$OPENBSD_EXPECTED_HASH" ]] || die "ISO checksum mismatch (in VM)"
}

download_openbsd_iso() {
    [[ "$SKIP_OPENBSD_DOWNLOAD" == "true" ]] && { log_info "Skipping OpenBSD ISO download."; return 0; }

    local iso_url="${OPENBSD_MIRROR}/${OPENBSD_ISO}"
    local remote_iso="$DOWNLOAD_VM_DIR/$OPENBSD_ISO"
    assert_safe_remote_path "$remote_iso"

    log_info "Downloading OpenBSD ISO into $DOWNLOAD_VM:$DOWNLOAD_VM_DIR ..."
    run_cmd timeout "$QVM_RUN_TIMEOUT_SEC" qvm-run -a --pass-io --no-gui "$DOWNLOAD_VM" \
        "cd $(shell_quote_sh "$DOWNLOAD_VM_DIR") && curl --proto '=https' --tlsv1.2 -fL --retry 3 --retry-delay 2 --connect-timeout 20 -O $(shell_quote_sh "$iso_url")" \
        >/dev/null

    [[ "$DRY_RUN" == "true" ]] && { log_info "[DRY-RUN] Would verify ISO sha256 inside $DOWNLOAD_VM"; return 0; }

    verify_openbsd_iso_in_download_vm
    log_info "OpenBSD ISO verified inside $DOWNLOAD_VM"
}

openbsd_start() {
    local remote_iso="$DOWNLOAD_VM_DIR/$OPENBSD_ISO"
    assert_safe_remote_path "$remote_iso"

    qvm-check "$OPENBSD_VM" &>/dev/null || die "OpenBSD VM not found: $OPENBSD_VM"
    qvm-check "$DOWNLOAD_VM" &>/dev/null || die "Download VM not found: $DOWNLOAD_VM"
    qvm-check --running "$OPENBSD_VM" &>/dev/null && die "OpenBSD VM already running: $OPENBSD_VM"

    log_info "Verifying ISO in $DOWNLOAD_VM immediately before start..."
    verify_openbsd_iso_in_download_vm

    log_info "Starting OpenBSD installer..."
    run_cmd qvm-start "$OPENBSD_VM" --cdrom="$DOWNLOAD_VM:$remote_iso"
}

#===============================================================================
# OPENBSD VM
#===============================================================================

create_openbsd_vm() {
    [[ "$SKIP_OPENBSD" == "true" ]] && { log_info "Skipping OpenBSD VM creation."; return 0; }

    if qvm-check "$OPENBSD_VM" &>/dev/null; then
        log_info "VM exists: $OPENBSD_VM"
        confirm "Delete and recreate '$OPENBSD_VM'?" || die "Aborted"
        assert_ok_to_delete_vm "$OPENBSD_VM" "openbsd"
        run_cmd qvm-kill "$OPENBSD_VM" 2>/dev/null || true
        run_cmd qvm-remove -f "$OPENBSD_VM"
    fi

    log_info "Creating OpenBSD VM: $OPENBSD_VM ..."
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

    run_cmd qvm-prefs "$OPENBSD_VM" netvm ''
    run_cmd qvm-volume resize "$OPENBSD_VM:root" 12G

    if [[ -n "$NET_DEVICE" ]]; then
        local pci_id
        pci_id="$(bdf_to_qvm_pci_id "$NET_DEVICE")"
        log_info "Attaching PCI NIC: $NET_DEVICE"
        if [[ "$DRY_RUN" != "true" ]]; then
            qvm-pci attach --persistent "$OPENBSD_VM" "dom0:${pci_id}" 2>/dev/null || \
                log_warn "attach failed; attach manually with qvm-pci"
        fi
    else
        log_warn "No NIC attached; attach manually for sys-net role."
    fi
}

#===============================================================================
# MIRAGE DISPVM CHAIN
#===============================================================================

create_mirage_dispvm() {
    [[ "$SKIP_MIRAGE" == "true" ]] && { log_info "Skipping Mirage VMs."; return 0; }

    if qvm-check "$MIRAGE_FW" &>/dev/null; then
        log_info "VM exists: $MIRAGE_FW"
        confirm "Delete and recreate '$MIRAGE_FW'?" || die "Aborted"
        assert_ok_to_delete_vm "$MIRAGE_FW" "mirage-fw"
        run_cmd qvm-kill "$MIRAGE_FW" 2>/dev/null || true
        run_cmd qvm-remove -f "$MIRAGE_FW"
    fi

    if qvm-check "$MIRAGE_DVM_TEMPLATE" &>/dev/null; then
        log_info "VM exists: $MIRAGE_DVM_TEMPLATE"
        confirm "Delete and recreate '$MIRAGE_DVM_TEMPLATE'?" || die "Aborted"
        assert_ok_to_delete_vm "$MIRAGE_DVM_TEMPLATE" "mirage-dvm-template"
        run_cmd qvm-kill "$MIRAGE_DVM_TEMPLATE" 2>/dev/null || true
        run_cmd qvm-remove -f "$MIRAGE_DVM_TEMPLATE"
    fi

    if qvm-check "$MIRAGE_TEMPLATE" &>/dev/null; then
        log_info "VM exists: $MIRAGE_TEMPLATE"
        confirm "Delete and recreate '$MIRAGE_TEMPLATE'?" || die "Aborted"
        assert_ok_to_delete_vm "$MIRAGE_TEMPLATE" "mirage-template"
        run_cmd qvm-kill "$MIRAGE_TEMPLATE" 2>/dev/null || true
        run_cmd qvm-remove -f "$MIRAGE_TEMPLATE"
    fi

    log_info "Creating Mirage TemplateVM: $MIRAGE_TEMPLATE"
    run_cmd qvm-create \
        --property kernel=mirage-firewall \
        --property kernelopts='' \
        --property memory=32 \
        --property maxmem=32 \
        --property vcpus=1 \
        --property virt_mode=pvh \
        --label=black \
        --class TemplateVM \
        "$MIRAGE_TEMPLATE"

    run_cmd qvm-prefs "$MIRAGE_TEMPLATE" netvm ''
    run_cmd qvm-prefs "$MIRAGE_TEMPLATE" updatevm ''
    run_cmd qvm-prefs "$MIRAGE_TEMPLATE" autostart False

    log_info "Creating Mirage Disposable Template: $MIRAGE_DVM_TEMPLATE"
    run_cmd qvm-create \
        --property template="$MIRAGE_TEMPLATE" \
        --property template_for_dispvms=True \
        --property memory=32 \
        --property maxmem=32 \
        --property vcpus=1 \
        --label=orange \
        --class AppVM \
        "$MIRAGE_DVM_TEMPLATE"

    run_cmd qvm-prefs "$MIRAGE_DVM_TEMPLATE" netvm ''
    run_cmd qvm-prefs "$MIRAGE_DVM_TEMPLATE" updatevm ''
    run_cmd qvm-prefs "$MIRAGE_DVM_TEMPLATE" autostart False

    run_cmd qvm-features "$MIRAGE_DVM_TEMPLATE" qubes-firewall 1
    run_cmd qvm-features "$MIRAGE_DVM_TEMPLATE" no-default-kernelopts 1

    log_info "Creating Mirage Firewall DispVM: $MIRAGE_FW"
    run_cmd qvm-create \
        --property template="$MIRAGE_DVM_TEMPLATE" \
        --property provides_network=True \
        --property netvm='' \
        --property memory=64 \
        --property maxmem=64 \
        --property vcpus=1 \
        --label=orange \
        --class DispVM \
        "$MIRAGE_FW"
}

#===============================================================================
# TOPOLOGY
#===============================================================================

configure_topology() {
    if [[ "$SKIP_MIRAGE" == "true" ]] || [[ "$SKIP_OPENBSD" == "true" ]]; then
        log_info "Skipping topology (VMs not created)."
        return 0
    fi
    run_cmd qvm-prefs "$MIRAGE_FW" netvm "$OPENBSD_VM"
    log_info "Topology: Internet -> [$OPENBSD_VM] -> [$MIRAGE_FW] -> [AppVMs]"
}

#===============================================================================
# SNAPSHOTS (vid validation hardened)
#===============================================================================

validate_vid() {
    local vid="$1"
    [[ "$vid" =~ ^qubes_dom0/vm-[A-Za-z0-9_.-]+-root$ ]]
}

get_root_vid() {
    local vid
    vid="$(qvm-volume info "$OPENBSD_VM:root" 2>/dev/null | awk -F': ' '/^vid:/{print $2}' | tr -d '[:space:]')"
    [[ -n "$vid" ]] || die "Cannot read volume vid for $OPENBSD_VM:root"
    validate_vid "$vid" || die "Unexpected/unsafe vid format: '$vid'"

    if [[ "$vid" != *"vm-${OPENBSD_VM}-root" && "$FORCE" != "true" ]]; then
        die "vid does not match expected VM name (got '$vid', expected contains 'vm-${OPENBSD_VM}-root'). Use --force to override."
    fi
    echo "$vid"
}

get_root_lv_path() {
    local vid
    vid="$(get_root_vid)"
    local vg="${vid%%/*}"
    [[ "$vg" == "qubes_dom0" ]] || die "Unexpected VG in vid: $vg"
    [[ -d "/dev/$vg" ]] || die "VG device path missing: /dev/$vg"
    echo "/dev/$vid"
}

get_snap_lv_path() {
    local root_lv vg lv
    root_lv="$(get_root_lv_path)"
    vg="$(dirname "$root_lv")"
    lv="$(basename "$root_lv")"
    echo "$vg/${lv}-${SNAPSHOT_NAME}"
}

snapshot_create() {
    qvm-check "$OPENBSD_VM" &>/dev/null || die "VM not found: $OPENBSD_VM"
    assert_ok_to_delete_vm "$OPENBSD_VM" "openbsd" || true

    if qvm-check --running "$OPENBSD_VM" &>/dev/null; then
        log_info "Shutting down $OPENBSD_VM ..."
        qvm-shutdown --wait "$OPENBSD_VM"
        sleep 3
    fi

    local root_lv snap_lv
    root_lv="$(get_root_lv_path)"
    snap_lv="$(get_snap_lv_path)"
    [[ -e "$root_lv" ]] || die "Root LV not found: $root_lv"

    if lvs "$snap_lv" &>/dev/null; then
        log_info "Snapshot exists: $snap_lv"
        confirm "Delete and recreate snapshot?" || die "Aborted"
        lvremove -f "$snap_lv" || die "Failed to remove old snapshot"
    fi

    log_info "Creating snapshot: $snap_lv"
    lvcreate -s -n "$(basename "$snap_lv")" -L 10G "$root_lv" || die "Failed to create snapshot"
    log_info "Snapshot created."
}

snapshot_reset() {
    confirm "This will DESTROY all changes in $OPENBSD_VM. Continue?" || { log_info "Aborted"; return 0; }
    assert_ok_to_delete_vm "$OPENBSD_VM" "openbsd" || true

    qvm-shutdown --wait "$MIRAGE_FW" 2>/dev/null || true
    qvm-shutdown --wait "$OPENBSD_VM" 2>/dev/null || true
    sleep 3

    local snap_lv
    snap_lv="$(get_snap_lv_path)"
    lvs "$snap_lv" &>/dev/null || die "Snapshot not found: $snap_lv (run snapshot-create first)"

    log_info "Merging snapshot: $snap_lv"
    lvconvert --merge "$snap_lv" || die "Failed to restore snapshot"
    log_info "Reset complete (snapshot consumed)."
}

snapshot_status() {
    local snap_lv
    snap_lv="$(get_snap_lv_path)"
    if lvs "$snap_lv" &>/dev/null; then
        log_info "Snapshot exists: $snap_lv"
    else
        log_info "No snapshot found."
    fi
}

snapshot_delete() {
    local snap_lv
    snap_lv="$(get_snap_lv_path)"
    if ! lvs "$snap_lv" &>/dev/null; then
        log_info "No snapshot found."
        return 0
    fi
    confirm "Delete snapshot $snap_lv?" || { log_info "Aborted"; return 0; }
    lvremove -f "$snap_lv" || die "Failed to delete snapshot"
    log_info "Snapshot deleted."
}

#===============================================================================
# USAGE / MAIN
#===============================================================================

print_usage() {
    cat <<EOF
OPENBSD + MIRAGE INSTALLER v$SCRIPT_VERSION

Usage:
  sudo bash ./$SCRIPT_NAME <command> [options]

Commands:
  install
  openbsd-verify
  openbsd-start
  snapshot-create
  snapshot-reset
  snapshot-status
  snapshot-delete
  help

Options:
  --dry-run
  --yes
  --force
  --verbose
  --skip-mirage
  --skip-openbsd
  --skip-openbsd-download
  --download-vm <vm>
  --openbsd-vm <name>
  --mirage-vm <name>
  --net-device <bdf>

Notes:
  - ISO is verified inside DOWNLOAD_VM, not copied to dom0.
  - Mirage kernel install requires /dev/shm to be writable tmpfs with sufficient free space.
  - Streaming has a full pipeline timeout: ${STREAM_TIMEOUT_SEC}s.
EOF
}

parse_common_options() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) DRY_RUN="true"; shift ;;
            --yes) ASSUME_YES="true"; shift ;;
            --force) FORCE="true"; shift ;;
            --verbose) VERBOSE="true"; shift ;;
            --skip-mirage) SKIP_MIRAGE="true"; shift ;;
            --skip-openbsd) SKIP_OPENBSD="true"; shift ;;
            --skip-openbsd-download) SKIP_OPENBSD_DOWNLOAD="true"; shift ;;
            --download-vm) need_arg "$1" "${2:-}"; DOWNLOAD_VM="$2"; shift 2 ;;
            --openbsd-vm) need_arg "$1" "${2:-}"; OPENBSD_VM="$2"; shift 2 ;;
            --mirage-vm) need_arg "$1" "${2:-}"; MIRAGE_FW="$2"; shift 2 ;;
            --net-device) need_arg "$1" "${2:-}"; NET_DEVICE="$2"; shift 2 ;;
            *) die "Unknown option: $1" ;;
        esac
    done
}

main() {
    local command="${1:-}"
    case "$command" in
        install)
            shift
            parse_common_options "$@"
            check_lock
            preflight_checks
            detect_net_device
            install_mirage_kernel
            download_openbsd_iso
            create_openbsd_vm
            create_mirage_dispvm
            configure_topology
            log_info "DONE."
            echo "Start OpenBSD installer (verify+start):"
            echo "  sudo $SCRIPT_NAME openbsd-start --download-vm $DOWNLOAD_VM --openbsd-vm $OPENBSD_VM"
            ;;

        openbsd-verify)
            shift
            parse_common_options "$@"
            check_lock
            preflight_checks
            verify_openbsd_iso_in_download_vm
            log_info "OK: ISO verified inside $DOWNLOAD_VM"
            ;;

        openbsd-start)
            shift
            parse_common_options "$@"
            check_lock
            preflight_checks
            openbsd_start
            ;;

        snapshot-create)
            shift; parse_common_options "$@"
            check_lock; preflight_checks; snapshot_create
            ;;

        snapshot-reset)
            shift; parse_common_options "$@"
            check_lock; preflight_checks; snapshot_reset
            ;;

        snapshot-status)
            shift; parse_common_options "$@"
            check_lock; preflight_checks; snapshot_status
            ;;

        snapshot-delete)
            shift; parse_common_options "$@"
            check_lock; preflight_checks; snapshot_delete
            ;;

        help|--help|-h|"")
            print_usage
            ;;

        *)
            die "Unknown command: $command"
            ;;
    esac
}

main "$@"
