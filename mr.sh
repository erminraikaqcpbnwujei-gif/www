#!/bin/bash

# mirage-firewall with DispVM (PrivSec.dev style)

# ============================================
# VARIABLES - adjust if needed
# ============================================
Release=v0.9.5
DownloadVM=sys-whonix

GithubUrl=https://github.com/mirage/qubes-mirage-firewall
Filename=qubes-firewall.xen
Checksum=qubes-firewall-release.sha256
ExpectedHash=2bfb49696e59a8ffbb660399e52bd82ffadbd02437d282eb8daab568b3261999
DownloadBinary=$GithubUrl/releases/download/$Release/$Filename
DownloadChecksum=$GithubUrl/releases/download/$Release/$Checksum
MirageInstallDir=/var/lib/qubes/vm-kernels/mirage-firewall

# VM names
TemplateVM=mirage-tmpl
DispTmpl=mirage-dvm
FirewallVM=sys-mirage-fw

# ============================================
# DOWNLOAD
# ============================================
echo "[1/7] Downloading $Filename in $DownloadVM..."
qvm-run -a --pass-io --no-gui $DownloadVM "curl -sLO $DownloadBinary"
qvm-run -a --pass-io --no-gui $DownloadVM "curl -sLO $DownloadChecksum"

# ============================================
# VERIFY CHECKSUM
# ============================================
echo "[2/7] Verifying checksum..."
ActualHash=$(qvm-run -a --pass-io --no-gui $DownloadVM "sha256sum $Filename | cut -d' ' -f1")

if [ "$ActualHash" != "$ExpectedHash" ]; then
    echo "ERROR: Checksum mismatch!"
    echo "Expected: $ExpectedHash"
    echo "Got:      $ActualHash"
    exit 1
fi
echo "Checksum OK!"

# ============================================
# INSTALL KERNEL TO DOM0
# ============================================
echo "[3/7] Installing mirage kernel to dom0..."
mkdir -p $MirageInstallDir
cd $MirageInstallDir
qvm-run --pass-io --no-gui $DownloadVM "cat $Filename" > vmlinuz
gzip -n9 < /dev/null > initramfs

# ============================================
# CREATE TEMPLATE VM
# ============================================
echo "[4/7] Creating TemplateVM: $TemplateVM..."
qvm-create \
  --property kernel=mirage-firewall \
  --property kernelopts='' \
  --property memory=64 \
  --property maxmem=64 \
  --property vcpus=1 \
  --property virt_mode=pvh \
  --label=black \
  --class TemplateVM \
  $TemplateVM

# ============================================
# CREATE DISPOSABLE TEMPLATE
# ============================================
echo "[5/7] Creating Disposable Template: $DispTmpl..."
qvm-create \
  --property template=$TemplateVM \
  --property provides_network=True \
  --property template_for_dispvms=True \
  --label=orange \
  --class AppVM \
  $DispTmpl

qvm-features $DispTmpl qubes-firewall 1
qvm-features $DispTmpl no-default-kernelopts 1

# ============================================
# CREATE DISPOSABLE FIREWALL VM
# ============================================
echo "[6/7] Creating DispVM Firewall: $FirewallVM..."
qvm-create \
  --property template=$DispTmpl \
  --property provides_network=True \
  --property netvm=sys-net \
  --label=orange \
  --class DispVM \
  $FirewallVM

# ============================================
# CLEANUP
# ============================================
echo "[7/7] Cleaning up $DownloadVM..."
qvm-run -a --pass-io --no-gui $DownloadVM "rm -f $Filename $Checksum"

echo ""
echo "=========================================="
echo "DONE! Mirage Firewall (DispVM) installed."
echo "=========================================="
echo ""
echo "Created VMs:"
echo "  - $TemplateVM (TemplateVM - don't start)"
echo "  - $DispTmpl (Disposable Template)"
echo "  - $FirewallVM (Disposable Firewall)"
echo ""
echo "To use it, set netvm for your AppVMs:"
echo "  qvm-prefs --set <your-appvm> netvm $FirewallVM"
