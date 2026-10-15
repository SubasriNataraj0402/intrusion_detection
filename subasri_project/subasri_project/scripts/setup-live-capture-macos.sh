#!/bin/bash
# One-time setup that lets the AI-NIDS backend capture packets on macOS WITHOUT
# running as root every time. This is the same fix Wireshark's own installer
# applies: create an `access_bpf` group, put the real (non-root) user in it,
# and install a LaunchDaemon that keeps /dev/bpf* readable/writable by that
# group across reboots (macOS regenerates the BPF device nodes on every boot,
# so a one-off `chmod` alone would not survive a restart).
#
# Run with:  sudo bash scripts/setup-live-capture-macos.sh
#
# After it finishes, log out and back in (or reboot) so your shell picks up
# the new group membership, then verify with:  id | grep access_bpf

set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "This script needs sudo. Run: sudo bash scripts/setup-live-capture-macos.sh" >&2
  exit 1
fi

# SUDO_USER is the human account that invoked sudo; fall back to $USER if unset.
TARGET_USER="${SUDO_USER:-$USER}"
GROUP_NAME="access_bpf"
DAEMON_LABEL="io.nidsplatform.chmodbpf"
SCRIPT_DIR="/Library/Application Support/NIDSChmodBPF"
SCRIPT_PATH="${SCRIPT_DIR}/ChmodBPF"
PLIST_PATH="/Library/LaunchDaemons/${DAEMON_LABEL}.plist"

echo "==> Target user: ${TARGET_USER}"

echo "==> Creating group '${GROUP_NAME}' (if missing)..."
if ! dscl . -read "/Groups/${GROUP_NAME}" >/dev/null 2>&1; then
  dseditgroup -q -o create "${GROUP_NAME}"
else
  echo "    already exists"
fi

echo "==> Adding ${TARGET_USER} to '${GROUP_NAME}'..."
dseditgroup -q -o edit -a "${TARGET_USER}" -t user "${GROUP_NAME}"

echo "==> Installing permission-fix script at ${SCRIPT_PATH}..."
mkdir -p "${SCRIPT_DIR}"
cat > "${SCRIPT_PATH}" <<'EOF'
#!/bin/bash
# Re-applied on every boot (and right now) so newly created /dev/bpf* nodes
# stay readable/writable by the access_bpf group.
chgrp access_bpf /dev/bpf* 2>/dev/null || true
chmod g+rw /dev/bpf* 2>/dev/null || true
EOF
chmod +x "${SCRIPT_PATH}"

echo "==> Installing LaunchDaemon at ${PLIST_PATH}..."
cat > "${PLIST_PATH}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${DAEMON_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${SCRIPT_PATH}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>WatchPaths</key>
  <array>
    <string>/dev</string>
  </array>
</dict>
</plist>
EOF
chmod 644 "${PLIST_PATH}"
chown root:wheel "${PLIST_PATH}"

echo "==> Loading LaunchDaemon and applying permissions now..."
launchctl bootout system "${PLIST_PATH}" >/dev/null 2>&1 || true
launchctl bootstrap system "${PLIST_PATH}" 2>/dev/null || launchctl load -w "${PLIST_PATH}"
"${SCRIPT_PATH}"

echo ""
echo "Done. /dev/bpf* permissions:"
ls -la /dev/bpf0

echo ""
echo "IMPORTANT: log out and back in (or reboot) so your shell session picks up"
echo "the new '${GROUP_NAME}' group membership. Then verify with:  id | grep ${GROUP_NAME}"
