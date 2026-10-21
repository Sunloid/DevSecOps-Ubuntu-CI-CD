#!/usr/bin/env bash
# =============================================================================
# harden.sh - idempotent hardening for an Ubuntu 22.04 / 24.04 Docker host
#
#   sudo ./harden.sh plan      # show exactly what would change; touches nothing
#   sudo ./harden.sh apply     # apply (safe to re-run; unchanged files are skipped)
#   sudo ./harden.sh verify    # audit the live system, exit 1 on any FAIL
#
# Options
#   --admin-user NAME      account that keeps SSH access (default: $SUDO_USER or "ubuntu")
#   --ssh-allow-cidr CIDR  only allow SSH from this network (default: anywhere, rate-limited)
#   --no-web               do not open 80/443
#   --auto-reboot HH:MM    let unattended-upgrades reboot at this time when needed (default: never)
#   --harden-docker        also write /etc/docker/daemon.json hardening (needs a docker restart)
#
# What it does:  SSH hardening | UFW firewall | fail2ban | unattended security
#                updates | kernel (sysctl) hardening | optional Docker daemon hardening
#
# LOCKOUT SAFETY: refuses to run unless the admin user already has an
# authorized_keys entry, validates sshd config with `sshd -t` before reloading,
# and rolls the change back if validation fails. Still: keep your current SSH
# session open and test a second login before you close it.
# =============================================================================
set -Eeuo pipefail

MODE="apply"
DRY=0
ADMIN_USER="${SUDO_USER:-ubuntu}"
SSH_CIDR=""
NO_WEB=0
AUTO_REBOOT=""
HARDEN_DOCKER=0

# Test hooks (used by tests/server/): relocate /etc writes and skip service/package operations.
ROOT="${HARDEN_ETC_ROOT:-}"
TEST="${HARDEN_TEST_MODE:-0}"

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die()  { printf '[FATAL] %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while (($#)); do
  case "$1" in
    apply|verify) MODE="$1" ;;
    plan) MODE="apply"; DRY=1 ;;
    --dry-run) DRY=1 ;;
    --admin-user) ADMIN_USER="${2:?--admin-user needs a value}"; shift ;;
    --ssh-allow-cidr) SSH_CIDR="${2:?--ssh-allow-cidr needs a value}"; shift ;;
    --no-web) NO_WEB=1 ;;
    --auto-reboot) AUTO_REBOOT="${2:?--auto-reboot needs HH:MM}"; shift ;;
    --harden-docker) HARDEN_DOCKER=1 ;;
    -h|--help) usage 0 ;;
    *) warn "unknown argument: $1"; usage 2 ;;
  esac
  shift
done

[[ -z "$AUTO_REBOOT" || "$AUTO_REBOOT" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || die "--auto-reboot must be HH:MM (24h)"
[[ -z "$SSH_CIDR" || "$SSH_CIDR" =~ ^[0-9a-fA-F:.]+(/[0-9]{1,3})?$ ]] || die "--ssh-allow-cidr must look like 203.0.113.7/32"

# ----------------------------------------------------------------- helpers
run() { if ((DRY)); then log "DRY-RUN: $*"; else "$@"; fi; }
svc() { if ((TEST)); then log "test-mode: skip systemctl $*"; else run systemctl "$@"; fi; }

# write_managed <path> <mode>  (content on stdin)
# Returns 0 if the file changed (or would change), 1 if it was already up to date.
write_managed() {
  local path="$ROOT$1" mode="$2" tmp
  tmp="$(mktemp)"
  cat >"$tmp"
  if [[ -f "$path" ]] && cmp -s "$tmp" "$path"; then
    log "unchanged   $1"; rm -f "$tmp"; return 1
  fi
  if ((DRY)); then
    log "would write $1"
    diff -u "$path" "$tmp" 2>/dev/null | sed 's/^/      /' || true
    rm -f "$tmp"; return 0
  fi
  mkdir -p "$(dirname "$path")"
  if [[ -f "$path" ]]; then cp -a "$path" "$path.bak.$(date +%Y%m%d%H%M%S)"; fi
  install -m "$mode" "$tmp" "$path"
  rm -f "$tmp"; log "wrote       $1"; return 0
}

sshd_check() {
  if [[ -n "${HARDEN_SSHD_CONFIG:-}" ]]; then sshd -t -f "$HARDEN_SSHD_CONFIG"; else sshd -t; fi
}
sshd_effective() {
  if [[ -n "${HARDEN_SSHD_CONFIG:-}" ]]; then sshd -T -f "$HARDEN_SSHD_CONFIG"; else sshd -T; fi
}
ssh_port() { sshd_effective 2>/dev/null | awk '$1=="port"{print $2; exit}' | grep -E '^[0-9]+$' || echo 22; }

preflight() {
  ((EUID == 0)) || die "run as root (sudo)"
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    [[ "${ID:-}" == "ubuntu" ]] || warn "tested on Ubuntu only (found: ${ID:-unknown}); continuing"
    case "${VERSION_ID:-}" in 22.04|24.04) ;; *) warn "tested on 22.04/24.04 (found: ${VERSION_ID:-unknown})" ;; esac
  fi
  getent passwd "$ADMIN_USER" >/dev/null || die "admin user '$ADMIN_USER' does not exist (use --admin-user)"
}

# ------------------------------------------------------------------ packages
install_packages() {
  if ((TEST)); then log "test-mode: skip apt install"; return 0; fi
  log "installing ufw fail2ban unattended-upgrades"
  run env DEBIAN_FRONTEND=noninteractive apt-get update -qq
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends ufw fail2ban unattended-upgrades
}

# ----------------------------------------------------------------------- ssh
harden_ssh() {
  log "== SSH"
  local home keys conf backup=""
  home="$(getent passwd "$ADMIN_USER" | cut -d: -f6)"
  keys="$home/.ssh/authorized_keys"
  [[ -s "$keys" ]] || die "$keys is missing or empty. Disabling password login now would lock you out. Add your public key first."

  # Drop-ins are read in lexical order and the FIRST value wins, so "00-" beats
  # cloud-init's 50-cloud-init.conf (which can re-enable PasswordAuthentication).
  conf="/etc/ssh/sshd_config.d/00-securepipe-hardening.conf"
  [[ -f "$ROOT$conf" ]] && backup="$ROOT$conf.pre-apply"; [[ -z "$backup" ]] || cp -a "$ROOT$conf" "$backup"

  local changed=0
  write_managed "$conf" 0644 <<EOF && changed=1
# Managed by securepipe harden.sh - manual edits will be overwritten on the next run.
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitEmptyPasswords no
AllowUsers ${ADMIN_USER}
MaxAuthTries 3
MaxSessions 4
LoginGraceTime 20
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding local
PermitTunnel no
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no
LogLevel VERBOSE
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
EOF
  ((changed)) || { [[ -n "$backup" ]] && rm -f "$backup"; return 0; }
  ((DRY)) && return 0

  if ! sshd_check; then
    warn "sshd rejected the new configuration - rolling back"
    if [[ -n "$backup" ]]; then mv -f "$backup" "$ROOT$conf"; else rm -f "$ROOT$conf"; fi
    die "SSH configuration invalid; nothing was changed"
  fi
  [[ -z "$backup" ]] || rm -f "$backup"
  svc try-reload-or-restart ssh
  log "ssh reloaded. KEEP THIS SESSION OPEN and test a new login from a second terminal."
}

# ------------------------------------------------------------------ firewall
harden_firewall() {
  log "== UFW firewall"
  if ((TEST)); then log "test-mode: skip ufw"; return 0; fi
  command -v ufw >/dev/null || die "ufw not installed"
  local port; port="$(ssh_port)"

  run sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
  run ufw default deny incoming
  run ufw default allow outgoing
  # SSH rules go in BEFORE enabling the firewall, or the session dies.
  if [[ -n "$SSH_CIDR" ]]; then
    run ufw allow from "$SSH_CIDR" to any port "$port" proto tcp comment 'ssh (admin network)'
  else
    run ufw limit "${port}/tcp" comment 'ssh (rate-limited)'
  fi
  if ((!NO_WEB)); then
    run ufw allow 80/tcp comment 'http'
    run ufw allow 443/tcp comment 'https'
  fi
  run ufw logging low
  run ufw --force enable
  warn "Docker publishes ports through iptables and BYPASSES ufw. Bind containers to 127.0.0.1 (see hardened/docker-compose.yml)."
}

# ------------------------------------------------------------------ fail2ban
harden_fail2ban() {
  log "== fail2ban"
  local port ignore="127.0.0.1/8 ::1"
  port="$(ssh_port)"
  # Never ban the admin who is running this script over SSH.
  if [[ -n "${SSH_CONNECTION:-}" ]]; then ignore="$ignore ${SSH_CONNECTION%% *}"; fi
  local changed=0
  write_managed /etc/fail2ban/jail.d/10-securepipe.local 0644 <<EOF && changed=1
# Managed by securepipe harden.sh
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 4
ignoreip = ${ignore}
# Repeat offenders are banned for longer each time (up to a week).
bantime.increment = true
bantime.factor    = 2
bantime.maxtime   = 1w

[sshd]
enabled = true
backend = systemd
mode    = aggressive
port    = ${port}
EOF
  if ((TEST)); then return 0; fi
  svc enable fail2ban
  if ((changed)); then svc restart fail2ban; else svc start fail2ban; fi
}

# ------------------------------------------------- unattended security updates
harden_updates() {
  log "== unattended security updates"
  write_managed /etc/apt/apt.conf.d/20auto-upgrades 0644 <<'EOF' || true
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
  local reboot="false" reboot_time=""
  if [[ -n "$AUTO_REBOOT" ]]; then reboot="true"; reboot_time="Unattended-Upgrade::Automatic-Reboot-Time \"${AUTO_REBOOT}\";"; fi
  # The stock 50unattended-upgrades already limits origins to the *-security pockets;
  # this drop-in only tightens housekeeping and reboot behaviour.
  write_managed /etc/apt/apt.conf.d/52securepipe-unattended 0644 <<EOF || true
// Managed by securepipe harden.sh
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "${reboot}";
${reboot_time}
EOF
  svc enable --now unattended-upgrades
}

# --------------------------------------------------------------------- sysctl
harden_sysctl() {
  log "== kernel parameters"
  local changed=0
  write_managed /etc/sysctl.d/99-securepipe.conf 0644 <<'EOF' && changed=1
# Managed by securepipe harden.sh
# (net.ipv4.ip_forward is deliberately NOT touched: Docker needs it.)
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.log_martians = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
fs.suid_dumpable = 0
EOF
  if ((changed)) && ! ((TEST)); then run sysctl -q -e -p /etc/sysctl.d/99-securepipe.conf; fi
  return 0
}

# --------------------------------------------------------------------- docker
harden_docker() {
  ((HARDEN_DOCKER)) || { log "== docker daemon: skipped (pass --harden-docker to enable)"; return 0; }
  log "== docker daemon"
  command -v docker >/dev/null || { log "docker not installed - skipping"; return 0; }
  local file="$ROOT/etc/docker/daemon.json" out
  out="$(python3 - "$file" "$DRY" <<'PY'
import json, os, sys
path, dry = sys.argv[1], sys.argv[2] == "1"
want = {
    "no-new-privileges": True,
    "live-restore": True,
    "userland-proxy": False,
    "log-driver": "json-file",
    "log-opts": {"max-size": "10m", "max-file": "3"},
}
cur = json.load(open(path)) if os.path.exists(path) and os.path.getsize(path) else {}
new = {**cur, **want}
if new == cur:
    print("unchanged"); sys.exit(0)
if not dry:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    json.dump(new, open(path, "w"), indent=2); open(path, "a").write("\n")
print("would-change" if dry else "changed")
PY
)"
  log "daemon.json: $out"
  [[ "$out" == "changed" ]] && warn "restart docker to apply (this restarts containers unless live-restore was already on): sudo systemctl restart docker"
  return 0
}

# --------------------------------------------------------------------- verify
verify() {
  log "== verify"
  local fails=0 eff
  chk() { local d=$1; shift; if "$@" >/dev/null 2>&1; then printf '  PASS  %s\n' "$d"; else printf '  FAIL  %s\n' "$d"; fails=$((fails + 1)); fi; }
  eff="$(sshd_effective 2>/dev/null || true)"
  chk "ssh: root login disabled"             grep -qx 'permitrootlogin no' <<<"$eff"
  chk "ssh: password auth disabled"          grep -qx 'passwordauthentication no' <<<"$eff"
  chk "ssh: keyboard-interactive disabled"   grep -qx 'kbdinteractiveauthentication no' <<<"$eff"
  chk "ssh: public-key auth enabled"         grep -qx 'pubkeyauthentication yes' <<<"$eff"
  chk "ssh: max auth tries <= 3"             grep -Eqx 'maxauthtries [1-3]' <<<"$eff"
  chk "ssh: X11 forwarding disabled"         grep -qx 'x11forwarding no' <<<"$eff"
  chk "ssh: access limited to named users"   grep -q '^allowusers ' <<<"$eff"
  if ((!TEST)); then
    local ufw_status; ufw_status="$(ufw status verbose 2>/dev/null || true)"
    chk "ufw: active"                        grep -q '^Status: active' <<<"$ufw_status"
    chk "ufw: default deny incoming"         grep -q 'deny (incoming)' <<<"$ufw_status"
    chk "fail2ban: running"                  systemctl is-active --quiet fail2ban
    chk "fail2ban: sshd jail loaded"         fail2ban-client status sshd
    chk "updates: unattended-upgrades enabled" systemctl is-enabled --quiet unattended-upgrades
    chk "updates: daily upgrade timer enabled" systemctl is-enabled --quiet apt-daily-upgrade.timer
    chk "sysctl: tcp_syncookies=1"           test "$(sysctl -n net.ipv4.tcp_syncookies)" = 1
    chk "sysctl: rp_filter=1"                test "$(sysctl -n net.ipv4.conf.all.rp_filter)" = 1
    chk "sysctl: kptr_restrict=2"            test "$(sysctl -n kernel.kptr_restrict)" = 2
    if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
      # Anything published on 0.0.0.0 other than 80/443 bypasses ufw.
      chk "docker: no unexpected ports on 0.0.0.0" bash -c \
        "! docker ps --format '{{.Ports}}' | tr ',' '\n' | grep -E '0\\.0\\.0\\.0:[0-9]+' | grep -Evq '0\\.0\\.0\\.0:(80|443)->'"
    fi
  fi
  if ((fails)); then log "verify: ${fails} check(s) FAILED"; return 1; fi
  log "verify: all checks passed"
}

# ----------------------------------------------------------------------- main
preflight
if [[ "$MODE" == "verify" ]]; then verify; exit $?; fi

((DRY)) && log "PLAN MODE - nothing will be modified"
log "admin user: ${ADMIN_USER}"
install_packages
harden_ssh
harden_firewall
harden_fail2ban
harden_updates
harden_sysctl
harden_docker
((DRY)) && { log "plan complete (re-run with 'apply' to make these changes)"; exit 0; }
verify || { warn "some checks failed - review the output above"; exit 1; }
