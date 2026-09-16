#!/usr/bin/env bash
# Install (or remove) the weekly refresh timer. Idempotent: re-running reinstalls the same units.
#
#   sudo scripts/install-timer.sh            install and enable
#   sudo scripts/install-timer.sh --remove   stop, disable and delete the units
#   scripts/install-timer.sh --status        what is installed and when it next runs (no root needed)
#
# The timer regenerates the data and the page. It never publishes: republishing the page stays a deliberate act.
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
UNIT_DIR=/etc/systemd/system
UNITS=(hp-refresh.service hp-refresh.timer)

die() { printf 'install-timer: error: %s\n' "$*" >&2; exit 1; }

case "${1:-}" in
  --status)
    systemctl list-timers hp-refresh.timer --all --no-pager 2>/dev/null || true
    systemctl status hp-refresh.timer --no-pager 2>/dev/null | head -5 || printf 'not installed\n'
    exit 0
    ;;
  --remove)
    [[ $EUID -eq 0 ]] || die "removing needs root: sudo $0 --remove"
    systemctl disable --now hp-refresh.timer 2>/dev/null || true
    rm -f "${UNITS[@]/#/$UNIT_DIR/}"
    systemctl daemon-reload
    printf 'install-timer: removed\n'
    exit 0
    ;;
  "") ;;
  -h | --help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  *) die "unknown option $1 (see --help)" ;;
esac

[[ $EUID -eq 0 ]] || die "installing needs root: sudo $0"
for unit in "${UNITS[@]}"; do
  [[ -f "$REPO/systemd/$unit" ]] || die "$REPO/systemd/$unit not found"
done

# Fail early rather than installing a timer whose job cannot run.
[[ -x "$REPO/scripts/refresh.sh" ]] || die "scripts/refresh.sh is not executable"
[[ -f "$REPO/config/redactions.txt" ]] || die "config/redactions.txt is missing; the refresh would refuse to run"

install -m 0644 "$REPO/systemd/hp-refresh.service" "$UNIT_DIR/hp-refresh.service"
install -m 0644 "$REPO/systemd/hp-refresh.timer" "$UNIT_DIR/hp-refresh.timer"
systemctl daemon-reload
systemctl enable --now hp-refresh.timer
printf 'install-timer: installed and enabled\n\n'
systemctl list-timers hp-refresh.timer --all --no-pager
