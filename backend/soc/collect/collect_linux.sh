#!/usr/bin/env bash
# Collect logs from one Ubuntu machine for the SOC engine. READ-ONLY: it copies logs; it changes nothing.
#
#   sudo bash soc/collect/collect_linux.sh /tmp/soc-logs ubu01
#
# Writes <name>_auth.log, <name>_ufw.log, <name>_syslog, <name>_dpkg.log into the output folder.
# Uses /var/log files when they exist (rsyslog); otherwise exports the same messages from journald.
set -euo pipefail
OUT="${1:-/tmp/soc-logs}"
NAME="${2:-$(hostname -s)}"
SINCE="${SINCE:-48 hours ago}"
mkdir -p "$OUT"

copy_log() {   # copy_log <base file> <target>: rotated part (.1) first, then the current file
  local base="$1" target="$2"
  : > "$target"
  [ -f "$base.1" ] && cat "$base.1" >> "$target"
  [ -f "$base" ] && cat "$base" >> "$target"
  return 0
}

if [ -f /var/log/auth.log ]; then
  copy_log /var/log/auth.log "$OUT/${NAME}_auth.log"
else
  journalctl --since "$SINCE" -t sshd -t sudo -t useradd -o short-iso-precise --no-pager > "$OUT/${NAME}_auth.log"
fi

if [ -f /var/log/ufw.log ]; then
  copy_log /var/log/ufw.log "$OUT/${NAME}_ufw.log"
else
  journalctl --since "$SINCE" -k -g 'UFW ' -o short-iso-precise --no-pager > "$OUT/${NAME}_ufw.log" || true
fi

if [ -f /var/log/syslog ]; then
  copy_log /var/log/syslog "$OUT/${NAME}_syslog"
else
  journalctl --since "$SINCE" -t systemd -o short-iso-precise --no-pager > "$OUT/${NAME}_syslog"
fi

copy_log /var/log/dpkg.log "$OUT/${NAME}_dpkg.log"

echo "Logs from $(hostname) written to $OUT:"
ls -l "$OUT" | grep "${NAME}_"
