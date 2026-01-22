#!/bin/bash

# mirage-firewall

# ============================================
# VARIABLES - adjust if needed
# ============================================
Release=v0.9.5
DownloadVM=sys-whonix
MirageFW=sys-mirage-fw

GithubUrl=https://github.com/mirage/qubes-mirage-firewall
Filename=qubes-firewall.xen
Checksum=qubes-firewall-release.sha256
ExpectedHash=2bfb49696e59a8ffbb660399e52bd82ffadbd02437d282eb8daab568b3261999
DownloadBinary=$GithubUrl/releases/download/$Release/$Filename
DownloadChecksum=$GithubUrl/releases/download/$Release/$Checksum
MirageInstallDir=/var/lib/qubes/vm-kernels/mirage-firewall

# ============================================
# DOWNLOAD
# ============================================
echo "[1/5] Downloading $Filename in $DownloadVM..."
qvm-run -a --pass-io --no-gui $DownloadVM "wget -q $DownloadBinary"
qvm-run -a --pass-io --no-gui $DownloadVM "wget -q $DownloadChecksum"

# ============================================
# VERIFY CHECKSUM
# ============================================
echo "[2/5] Verifying checksum..."
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
echo "[3/5] Installing mirage kernel to dom0..."
mkdir -p $MirageInstallDir
cd $MirageInstallDir
qvm-run --pass-io --no-gui $DownloadVM "cat $Filename" > vmlinuz
gzip -n9 < /dev/null > initramfs

# ============================================
# CREATE VM
# ============================================
echo "[4/5] Creating $MirageFW VM..."
qvm-create \
  --property kernel=mirage-firewall \
  --property kernelopts='' \
  --property memory=32 \
  --property maxmem=32 \
  --property netvm=sys-net \
  --property provides_network=True \
  --property vcpus=1 \
  --property virt_mode=pvh \
  --property audiovm='' \
  --label=green \
  --class StandaloneVM \
  $MirageFW

qvm-features $MirageFW qubes-firewall 1
qvm-features $MirageFW no-default-kernelopts 1
qvm-features $MirageFW skip-update 1

# ============================================
# CLEANUP
# ============================================
echo "[5/5] Cleaning up $DownloadVM..."
qvm-run -a --pass-io --no-gui $DownloadVM "rm -f $Filename $Checksum"

echo ""
echo "=========================================="
echo "DONE! Mirage Firewall installed."
echo "=========================================="
echo ""
echo "To use it, set netvm for your AppVMs:"
echo "  qvm-prefs --set <your-appvm> netvm $MirageFW"
echo ""
echo "Or make it default firewall in Qubes Global Settings."
