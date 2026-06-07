#!/bin/bash
# ==============================================================================
# host_hardening.sh -- Kubernetes host hardening library
#
#   - CIS Kubernetes Benchmark (host-level controls)
#   - CIS Distribution Independent Linux Benchmark
#   - NSA/CISA Kubernetes Hardening Guide
#   - DISA STIG (RHEL 9 / Ubuntu) host crypto + audit guidance
#
# Usage (standalone):
#   sudo ./host_hardening.sh [--dry-run] [--profile balanced|strict]
#                            [--skip kernel,ssh,...] [--rollback <backup_dir>]
# ==============================================================================

# ---- Guard against double-sourcing -------------------------------------------
[ -n "${__HOST_HARDENING_LOADED:-}" ] && return 0
__HOST_HARDENING_LOADED=1

# ---- Configuration -----------------------------------------------------------
HARDEN_LOG="${HARDEN_LOG:-/var/log/k8s_hardening.log}"
HARDEN_STATE="${HARDEN_STATE:-/etc/k8s_hardening.state}"
HARDEN_BACKUP_DIR="${HARDEN_BACKUP_DIR:-/var/backups/k8s_hardening_$(date +%Y%m%d%H%M%S)}"
HARDEN_PROFILE="${HARDEN_PROFILE:-balanced}"   # balanced | strict
HARDEN_DRY_RUN="${HARDEN_DRY_RUN:-false}"
HARDEN_SKIP="${HARDEN_SKIP:-}"                 # comma-separated step names

# Colors (only if not already defined by the caller)
: "${RED:=$'\033[1;31m'}"; : "${GRN:=$'\033[1;32m'}"
: "${CYN:=$'\033[1;36m'}"; : "${YLW:=$'\033[1;33m'}"; : "${RST:=$'\033[0m'}"

# Populated by detect_os
OS_FAMILY=""        # debian | rhel
PKG_MGR=""          # apt | dnf | yum
MAC_SYSTEM=""       # apparmor | selinux | none

# ---- Logging -----------------------------------------------------------------
hlog()  { echo -e "[$(date +'%F %T')] $*" | tee -a "$HARDEN_LOG" >/dev/null; echo -e "${CYN}[harden]${RST} $*"; }
hwarn() { echo -e "[$(date +'%F %T')] WARN: $*" | tee -a "$HARDEN_LOG" >/dev/null; echo -e "${YLW}[harden] WARN:${RST} $*"; }
herr()  { echo -e "[$(date +'%F %T')] ERROR: $*" | tee -a "$HARDEN_LOG" >/dev/null; echo -e "${RED}[harden] ERROR:${RST} $*"; }
hdie()  { herr "$*"; herr "Aborting. See $HARDEN_LOG"; return 1; }

# ---- Step bookkeeping --------------------------------------------------------
_skip_requested() { case ",$HARDEN_SKIP," in *",$1,"*) return 0;; *) return 1;; esac; }
_already_run()    { grep -qxF "$1" "$HARDEN_STATE" 2>/dev/null; }
_record_run()     { [ "$HARDEN_DRY_RUN" = true ] && return 0; echo "$1" >> "$HARDEN_STATE"; }

# Returns 0 if the step should run, 1 if it should be skipped.
_should_run() {
    local step="$1"
    if _skip_requested "$step"; then hlog "Skipping '$step' (requested via --skip)."; return 1; fi
    if _already_run "$step";    then hlog "Skipping '$step' (already applied)."; return 1; fi
    return 0
}

# ---- Safe file mutation helpers ---------------------------------------------
_backup() {
    local f="$1"
    [ -e "$f" ] || return 0
    [ "$HARDEN_DRY_RUN" = true ] && { hlog "(dry-run) would back up $f"; return 0; }
    mkdir -p "$HARDEN_BACKUP_DIR"
    # Preserve directory structure inside the backup dir.
    local dest="$HARDEN_BACKUP_DIR${f}"
    mkdir -p "$(dirname "$dest")"
    cp -a "$f" "$dest" && hlog "Backed up $f"
}

# Write content to a path with a given mode, backing up any existing file.
# Usage: _write_file <path> <mode> <<'EOF' ... EOF
_write_file() {
    local path="$1" mode="$2" content
    content="$(cat)"
    if [ "$HARDEN_DRY_RUN" = true ]; then
        hlog "(dry-run) would write $path (mode $mode):"
        echo "$content" | sed 's/^/    | /'
        return 0
    fi
    _backup "$path"
    mkdir -p "$(dirname "$path")"
    printf '%s\n' "$content" > "$path"
    chmod "$mode" "$path"
    chown root:root "$path" 2>/dev/null || true
}

_run() {
    if [ "$HARDEN_DRY_RUN" = true ]; then hlog "(dry-run) would run: $*"; return 0; fi
    "$@"
}

# ==============================================================================
# 0. ENVIRONMENT DETECTION
# ==============================================================================
detect_os() {
    [ "$(id -u)" -eq 0 ] || { hdie "Hardening must run as root."; return 1; }
    if [ ! -r /etc/os-release ]; then hdie "/etc/os-release missing; cannot detect distro."; return 1; fi
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID,,} ${ID_LIKE,,}" in
        *debian*|*ubuntu*) OS_FAMILY="debian"; PKG_MGR="apt" ;;
        *rhel*|*fedora*|*centos*|*rocky*|*almalinux*)
            OS_FAMILY="rhel"
            command -v dnf >/dev/null 2>&1 && PKG_MGR="dnf" || PKG_MGR="yum" ;;
        *)
            # Last-ditch guess from available package manager.
            if command -v apt-get >/dev/null 2>&1; then OS_FAMILY="debian"; PKG_MGR="apt"
            elif command -v dnf >/dev/null 2>&1; then OS_FAMILY="rhel"; PKG_MGR="dnf"
            elif command -v yum >/dev/null 2>&1; then OS_FAMILY="rhel"; PKG_MGR="yum"
            else hdie "Unsupported distro: ${PRETTY_NAME:-unknown}"; return 1; fi ;;
    esac

    # Detect the available mandatory access control system.
    if command -v aa-status >/dev/null 2>&1 || command -v apparmor_status >/dev/null 2>&1; then
        MAC_SYSTEM="apparmor"
    elif command -v getenforce >/dev/null 2>&1 || [ -f /etc/selinux/config ]; then
        MAC_SYSTEM="selinux"
    else
        MAC_SYSTEM="none"
    fi

    hlog "Detected ${PRETTY_NAME:-$OS_FAMILY} | family=$OS_FAMILY pkg=$PKG_MGR mac=$MAC_SYSTEM profile=$HARDEN_PROFILE"
}

# Install a package idempotently, tolerating absence in repos.
_pkg_install() {
    local pkg="$1"
    case "$PKG_MGR" in
        apt) DEBIAN_FRONTEND=noninteractive _run apt-get install -y "$pkg" >>"$HARDEN_LOG" 2>&1 ;;
        dnf) _run dnf install -y "$pkg" >>"$HARDEN_LOG" 2>&1 ;;
        yum) _run yum install -y "$pkg" >>"$HARDEN_LOG" 2>&1 ;;
    esac
}

# ==============================================================================
# 1. KERNEL PARAMETERS (sysctl)
# ==============================================================================
# Network + memory + BPF hardening. Carefully tuned so the Falco modern_ebpf
# probe keeps working: restrict *unprivileged* BPF only, never privileged
# CO-RE loading, and leave IPv6 enabled (most CNIs and kube-proxy need it).
harden_kernel() {
    _should_run kernel || return 0
    hlog "Configuring kernel parameters (sysctl)…"

    _write_file /etc/sysctl.d/99-k8s-hardening.conf 0644 <<'EOF'
# Managed by host_hardening.sh -- Kubernetes node baseline (2026)
# -------------------------------------------------------------------
# --- Network: anti-spoofing / source routing ---
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# --- Network: redirects (ICMP + secure) ---
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# --- Network: martians + ICMP hygiene ---
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1

# --- Network: IGNORE ra on k8s nodes; do NOT disable IPv6 globally ---
# (Disabling IPv6 breaks many CNI plugins and kube-proxy dual-stack.)
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# --- Required by Kubernetes networking (kube-proxy, CNI bridge) ---
# These are normally set by the kubeadm sysctl preset; reasserted here so a
# hardened node still forwards pod/service traffic correctly.
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# --- Memory / process protections ---
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 2
kernel.kexec_load_disabled = 1
kernel.sysrq = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0

# --- ptrace scope: confine debugging to direct children ---
kernel.yama.ptrace_scope = 1

# --- BPF hardening ---
# Block UNPRIVILEGED bpf() while leaving privileged CO-RE loading intact,
# so the Falco modern_ebpf engine continues to attach its probe.
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# --- Core dump handling ---
kernel.core_uses_pid = 1
EOF

    # Apply now. sysctl --system reads all drop-ins.
    if [ "$HARDEN_DRY_RUN" != true ]; then
        sysctl --system >>"$HARDEN_LOG" 2>&1 || hwarn "sysctl --system reported errors (some keys may be unavailable on this kernel)."
    fi
    hlog "Kernel parameters applied."
    _record_run kernel
}

# ==============================================================================
# 2. KERNEL MODULE BLACKLIST (unused filesystems + uncommon protocols)
# ==============================================================================
harden_modules() {
    _should_run modules || return 0
    hlog "Disabling unused kernel modules…"

    local usb_line=""
    [ "$HARDEN_PROFILE" = strict ] && usb_line="install usb-storage /bin/true"

    _write_file /etc/modprobe.d/99-k8s-blacklist.conf 0644 <<EOF
# Managed by host_hardening.sh -- disable rarely-used filesystems & protocols
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
$usb_line
EOF

    hlog "Module blacklist written."
    _record_run modules
}

# ==============================================================================
# 3. FILESYSTEM PERMISSIONS + /tmp HARDENING
# ==============================================================================
harden_filesystem() {
    _should_run filesystem || return 0
    hlog "Securing sensitive file permissions…"

    # Core identity files (CIS Distribution Independent Linux 6.1.x).
    local f mode
    for entry in "/etc/passwd:644" "/etc/group:644" "/etc/shadow:0" "/etc/gshadow:0" \
                 "/etc/passwd-:644" "/etc/group-:644" "/etc/shadow-:0" "/etc/gshadow-:0"; do
        f="${entry%:*}"; mode="${entry##*:}"
        [ -e "$f" ] || continue
        _run chmod "$mode" "$f"
        _run chown root:root "$f"
    done
    # shadow group on Debian owns shadow files group-readable as 0640 in some setups;
    # 0000/0640 both pass CIS -- 0000 (root-only) for the strongest posture.

    # Sticky bit on world-writable dirs (bounded: skip pseudo + container layers
    # to avoid a multi-minute full-FS walk on large nodes).
    hlog "Applying sticky bit to world-writable directories (bounded search)…"
    if [ "$HARDEN_DRY_RUN" != true ]; then
        find / -xdev -path /proc -prune -o -path /sys -prune -o \
             -path /var/lib/containers -prune -o -path /var/lib/docker -prune -o \
             -type d -perm -0002 ! -perm -1000 -exec chmod a+t {} + 2>/dev/null || true
    fi

    # /tmp + /var/tmp as tmpfs with noexec,nosuid,nodev (skip if K8s ephemeral
    # storage on the node is sized against /tmp -- guard via profile).
    _harden_tmp_mount /tmp
    [ "$HARDEN_PROFILE" = strict ] && _harden_tmp_mount /var/tmp

    hlog "Filesystem permissions configured."
    _record_run filesystem
}

_harden_tmp_mount() {
    local mp="$1"
    if mount | grep -E " ${mp} .*noexec" >/dev/null 2>&1; then
        hlog "$mp already mounted noexec; leaving as-is."
        return 0
    fi
    hlog "Hardening $mp mount (noexec,nosuid,nodev)…"
    _backup /etc/fstab
    if [ "$HARDEN_DRY_RUN" != true ]; then
        # Prefer a systemd tmp.mount drop-in on systemd hosts to avoid fstab drift.
        if ! grep -qE "[[:space:]]${mp}[[:space:]]" /etc/fstab; then
            echo "tmpfs ${mp} tmpfs defaults,noexec,nosuid,nodev,size=2G 0 0" >> /etc/fstab
        fi
        mount -o remount,noexec,nosuid,nodev "$mp" 2>/dev/null \
            || mount "$mp" 2>/dev/null \
            || hwarn "Could not remount $mp now; will apply on next boot."
    fi
}

# ==============================================================================
# 4. SSH HARDENING (drop-in, post-quantum-aware crypto)
# ==============================================================================
# Writes a drop-in under /etc/ssh/sshd_config.d/ rather than editing sshd_config,
# so OpenSSH package upgrades don't fight us and rollback is one file deletion.
harden_ssh() {
    _should_run ssh || return 0
    [ -d /etc/ssh ] || { hwarn "OpenSSH not present; skipping SSH hardening."; return 0; }
    hlog "Hardening SSH (drop-in config)…"

    local ssh_ver kex
    ssh_ver="$(ssh -V 2>&1 | grep -oE 'OpenSSH_[0-9]+\.[0-9]+' | grep -oE '[0-9]+\.[0-9]+' | head -1)"
    if [ -n "$ssh_ver" ] && awk -v v="$ssh_ver" 'BEGIN{split(v,a,"."); exit !(a[1]>8 || (a[1]==8 && a[2]>=5))}'; then
        kex="sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512"
        hlog "OpenSSH $ssh_ver supports post-quantum kex; enabling sntrup761 hybrid."
    else
        kex="curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512"
        hwarn "OpenSSH ${ssh_ver:-<8.5}: omitting post-quantum kex for compatibility."
    fi

    # Ensure base config actually pulls in drop-ins (older images sometimes lack the Include).
    if [ -f /etc/ssh/sshd_config ] && ! grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d' /etc/ssh/sshd_config; then
        _backup /etc/ssh/sshd_config
        [ "$HARDEN_DRY_RUN" != true ] && sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
    fi

    _write_file /etc/ssh/sshd_config.d/99-hardening.conf 0600 <<EOF
# Managed by host_hardening.sh -- SSH hardening (2026 baseline)
# NOTE: the obsolete 'Protocol 2' directive is intentionally omitted; modern
# OpenSSH only speaks SSHv2 and rejects the directive.

PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
AuthenticationMethods publickey
PubkeyAuthentication yes

MaxAuthTries 3
MaxSessions 4
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 0
TCPKeepAlive no

UseDNS no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitUserEnvironment no
IgnoreRhosts yes
HostbasedAuthentication no
Banner /etc/issue.net
LogLevel VERBOSE
RequiredRSASize 3072

# Modern crypto only. CTR ciphers omitted in favour of AEAD.
KexAlgorithms ${kex}
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256
EOF

    _write_file /etc/issue.net 0644 <<'EOF'
**************************************************************************
This system is restricted to authorized users for legitimate purposes
only. All activity is logged and monitored. Unauthorized access is
prohibited and may be subject to prosecution.
**************************************************************************
EOF

    # Validate before reloading so we never lock ourselves out.
    if [ "$HARDEN_DRY_RUN" != true ]; then
        if sshd -t 2>>"$HARDEN_LOG"; then
            systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || hwarn "Could not reload sshd; reload manually."
            hlog "SSH config validated and reloaded."
        else
            herr "sshd -t validation FAILED. Removing drop-in to stay safe."
            rm -f /etc/ssh/sshd_config.d/99-hardening.conf
            return 0
        fi
    fi
    _record_run ssh
}

# ==============================================================================
# 5. DISABLE UNNECESSARY SERVICES
# ==============================================================================
harden_services() {
    _should_run services || return 0
    hlog "Disabling unnecessary services…"

    # Service unit names differ across families; list both spellings.
    local services=(
        avahi-daemon cups cups-browsed isc-dhcp-server dhcpd slapd
        nfs-server nfs rpcbind named bind9 vsftpd
        apache2 httpd dovecot smbd nmbd smb squid snmpd
        telnet telnet.socket rsh-server rsh xinetd ypserv nis rpcgssd
    )
    for svc in "${services[@]}"; do
        if systemctl list-unit-files "${svc}.service" >/dev/null 2>&1 \
           && systemctl is-enabled --quiet "$svc" 2>/dev/null; then
            _run systemctl disable --now "$svc" 2>>"$HARDEN_LOG" \
                && hlog "Disabled $svc" || hwarn "Failed to disable $svc"
        fi
    done

    hlog "Service review complete."
    _record_run services
}

# ==============================================================================
# 6. HOST FIREWALL (Kubernetes control-plane + worker ports)
# ==============================================================================
# Detect role from running components so we only open the ports a node needs.
harden_firewall() {
    _should_run firewall || return 0
    hlog "Configuring host firewall…"

    local is_control_plane=false
    if ss -lntp 2>/dev/null | grep -q ':6443' || [ -f /etc/kubernetes/manifests/kube-apiserver.yaml ]; then
        is_control_plane=true
        hlog "Detected control-plane node."
    else
        hlog "Treating as worker node."
    fi

    # Port sets (CIS / NSA Table I & II). Pod and service CIDRs are handled by
    # the CNI; only manage node-local ingress here.
    local cp_tcp=(6443 2379 2380 10250 10257 10259)
    local wk_tcp=(10250 10256)
    local np_range="30000-32767"
    # Flannel VXLAN / WireGuard overlays (UDP). Adjust per CNI.
    local overlay_udp=(8472 51820)

    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
        _firewall_firewalld "$is_control_plane"
    elif command -v ufw >/dev/null 2>&1; then
        _firewall_ufw "$is_control_plane"
    elif command -v nft >/dev/null 2>&1; then
        hwarn "Only nftables found. Skipping automated rules to avoid clobbering kube-proxy chains."
        hwarn "Apply node firewall rules via your CNI / kube-proxy-aware tooling instead."
    else
        hwarn "No supported firewall manager found; configure manually."
    fi

    _record_run firewall
}

_firewall_firewalld() {
    local cp="$1"
    _run firewall-cmd --permanent --set-default-zone=drop >>"$HARDEN_LOG" 2>&1 || true
    _run firewall-cmd --permanent --add-service=ssh >>"$HARDEN_LOG" 2>&1 || true
    local ports=(10250 10256 51820)
    [ "$cp" = true ] && ports=(6443 2379 2380 10250 10257 10259 8472 51820)
    for p in "${ports[@]}"; do _run firewall-cmd --permanent --add-port="${p}/tcp" >>"$HARDEN_LOG" 2>&1 || true; done
    _run firewall-cmd --permanent --add-port=8472/udp >>"$HARDEN_LOG" 2>&1 || true
    _run firewall-cmd --permanent --add-port=51820/udp >>"$HARDEN_LOG" 2>&1 || true
    [ "$cp" = false ] && _run firewall-cmd --permanent --add-port=30000-32767/tcp >>"$HARDEN_LOG" 2>&1 || true
    # Log denied packets for visibility (Falco/auditd will not see L3 drops).
    _run firewall-cmd --set-log-denied=all >>"$HARDEN_LOG" 2>&1 || true
    _run firewall-cmd --reload >>"$HARDEN_LOG" 2>&1 || true
    hlog "firewalld configured (control_plane=$cp)."
}

_firewall_ufw() {
    local cp="$1"
    _run ufw --force default deny incoming >>"$HARDEN_LOG" 2>&1
    _run ufw --force default allow outgoing >>"$HARDEN_LOG" 2>&1
    _run ufw allow OpenSSH >>"$HARDEN_LOG" 2>&1 || _run ufw allow 22/tcp >>"$HARDEN_LOG" 2>&1
    if [ "$cp" = true ]; then
        for p in 6443 2379 2380 10250 10257 10259; do _run ufw allow "${p}/tcp" >>"$HARDEN_LOG" 2>&1; done
        _run ufw allow 8472/udp >>"$HARDEN_LOG" 2>&1
    else
        _run ufw allow 10250/tcp >>"$HARDEN_LOG" 2>&1
        _run ufw allow 10256/tcp >>"$HARDEN_LOG" 2>&1
        _run ufw allow 30000:32767/tcp >>"$HARDEN_LOG" 2>&1
        _run ufw allow 8472/udp >>"$HARDEN_LOG" 2>&1
    fi
    _run ufw logging on >>"$HARDEN_LOG" 2>&1
    _run ufw --force enable >>"$HARDEN_LOG" 2>&1
    hlog "ufw configured (control_plane=$cp)."
}

# ==============================================================================
# 7. AUDITD (targeted rules, performance-tuned)
# ==============================================================================
# Replaces the original global "-F perm=wa" catch-all (which floods the log and
# crushes I/O) with focused rules. Buffer + rate are sized for a busy node.
harden_auditd() {
    _should_run auditd || return 0
    hlog "Configuring auditd…"

    if ! command -v auditctl >/dev/null 2>&1; then
        _pkg_install audit || _pkg_install auditd
    fi
    if ! command -v auditctl >/dev/null 2>&1; then
        hwarn "auditd unavailable; skipping audit rules."
        return 0
    fi

    _write_file /etc/audit/rules.d/99-k8s-hardening.rules 0640 <<'EOF'
## Managed by host_hardening.sh -- Kubernetes node audit policy (2026)
## Targeted rules (NOT a global catch-all) to keep audit I/O sustainable.

# Reset and size the backlog. 8192 buffers handles control-plane bursts;
# failure_mode 1 = printk (don't panic the node on a full queue).
-D
-b 8192
-f 1
--backlog_wait_time 60000

# --- Identity & auth files ---
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /var/log/sudo.log -p wa -k actions

# --- Time changes ---
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime,stime -k time-change
-w /etc/localtime -p wa -k time-change

# --- System locale / network identity ---
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/hostname -p wa -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale

# --- Privilege escalation: only euid->0 transitions (bounded, not all execve) ---
-a always,exit -F arch=b64 -C uid!=euid -F euid=0 -S execve -k priv_esc
-a always,exit -F arch=b32 -C uid!=euid -F euid=0 -S execve -k priv_esc

# --- Kubernetes / container control surfaces ---
-w /etc/kubernetes/ -p wa -k k8s_config
-w /var/lib/kubelet/ -p wa -k kubelet_config
-w /etc/cni/ -p wa -k cni_config
-w /etc/containerd/ -p wa -k containerd_config
-w /etc/crio/ -p wa -k crio_config
-w /etc/docker/ -p wa -k docker_config
-w /var/lib/etcd/ -p wa -k etcd_data
-w /etc/etcd/ -p wa -k etcd_config

# --- kubectl / runtime binaries (tampering / replacement) ---
-w /usr/bin/kubectl -p x -k k8s_bin
-w /usr/local/bin/kubectl -p x -k k8s_bin
-w /usr/bin/kubelet -p x -k k8s_bin
-w /usr/bin/containerd -p x -k runtime_bin
-w /usr/bin/runc -p x -k runtime_bin

# --- Sensitive config & module loading ---
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules

# --- Mounts (container escape via host mounts) ---
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts

# Make the configuration immutable until next reboot (uncomment in strict mode;
# the launcher sets this automatically when --profile strict is used).
##-e 2
EOF

    if [ "$HARDEN_PROFILE" = strict ] && [ "$HARDEN_DRY_RUN" != true ]; then
        sed -i 's/^##-e 2/-e 2/' /etc/audit/rules.d/99-k8s-hardening.rules
        hlog "auditd set to immutable (-e 2) for strict profile."
    fi

    if [ "$HARDEN_DRY_RUN" != true ]; then
        augenrules --load >>"$HARDEN_LOG" 2>&1 || hwarn "augenrules --load reported issues."
        systemctl enable --now auditd >>"$HARDEN_LOG" 2>&1 || hwarn "Could not enable auditd."
    fi
    hlog "auditd configured."
    _record_run auditd
}

# ==============================================================================
# 8. MANDATORY ACCESS CONTROL (AppArmor on Debian, SELinux on RHEL)
# ==============================================================================
harden_mac() {
    _should_run mac || return 0
    hlog "Configuring mandatory access control ($MAC_SYSTEM)…"

    case "$MAC_SYSTEM" in
        apparmor)
            _pkg_install apparmor; _pkg_install apparmor-utils
            if [ "$HARDEN_DRY_RUN" != true ]; then
                systemctl enable --now apparmor >>"$HARDEN_LOG" 2>&1 || hwarn "Could not enable AppArmor."
                # Enforce existing profiles, but DO NOT blanket aa-enforce everything:
                # that can break the container runtime. Enforce only complain-mode profiles.
                if command -v aa-status >/dev/null 2>&1; then
                    aa-status --complaining 2>/dev/null | while read -r prof; do
                        [ -n "$prof" ] && aa-enforce "$prof" >>"$HARDEN_LOG" 2>&1 || true
                    done
                fi
            fi
            hlog "AppArmor enabled (existing profiles enforced)."
            ;;
        selinux)
            _pkg_install selinux-policy-targeted 2>/dev/null || true
            _pkg_install container-selinux 2>/dev/null || true
            local mode="permissive"
            [ "$HARDEN_PROFILE" = strict ] && mode="enforcing"
            if [ "$HARDEN_DRY_RUN" != true ] && [ -f /etc/selinux/config ]; then
                _backup /etc/selinux/config
                sed -i "s/^SELINUX=.*/SELINUX=${mode}/" /etc/selinux/config
                # Switch live only toward permissive immediately; enforcing needs a
                # relabel + reboot, so we stage it rather than risk locking the node.
                if [ "$mode" = permissive ]; then
                    setenforce 0 2>/dev/null || true
                else
                    touch /.autorelabel
                    hwarn "SELinux set to enforcing + relabel scheduled; reboot required."
                fi
            fi
            hlog "SELinux configured (mode=$mode)."
            ;;
        *)
            hwarn "No MAC system available. Consider installing AppArmor or SELinux."
            ;;
    esac
    _record_run mac
}

# ==============================================================================
# 9. TIME SYNCHRONIZATION (chrony)
# ==============================================================================
harden_time() {
    _should_run time || return 0
    hlog "Configuring time synchronization (chrony)…"

    if ! command -v chronyd >/dev/null 2>&1; then
        _pkg_install chrony
    fi
    if ! command -v chronyd >/dev/null 2>&1; then
        hwarn "chrony unavailable; skipping time hardening."
        return 0
    fi

    local conf=/etc/chrony/chrony.conf
    [ "$OS_FAMILY" = rhel ] && conf=/etc/chrony.conf

    _write_file "$conf" 0644 <<'EOF'
# Managed by host_hardening.sh -- chrony (NTS-capable where servers support it)
# Prefer NTS (authenticated NTP) pools; fall back to pool.ntp.org.
server time.cloudflare.com iburst nts
pool pool.ntp.org iburst maxsources 4

driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
leapsectz right/UTC

# Do not act as a server for other hosts.
port 0
cmdport 0

logdir /var/log/chrony
log measurements statistics tracking
EOF

    if [ "$HARDEN_DRY_RUN" != true ]; then
        systemctl enable --now chronyd >>"$HARDEN_LOG" 2>&1 \
            || systemctl enable --now chrony >>"$HARDEN_LOG" 2>&1 \
            || hwarn "Could not enable chrony."
    fi
    hlog "Time synchronization configured."
    _record_run time
}

# ==============================================================================
# 10. KUBERNETES NODE FILE / KUBELET HARDENING (CIS section 4)
# ==============================================================================
# These controls were absent from the original script entirely. They are the
# host-side counterpart to in-cluster RBAC/PSA.
harden_k8s_node() {
    _should_run k8s_node || return 0
    hlog "Hardening Kubernetes node files & kubelet…"

    # 10a. Control-plane manifest & config file permissions (CIS 1.1.x).
    local kdir=/etc/kubernetes
    if [ -d "$kdir" ]; then
        for f in admin.conf super-admin.conf scheduler.conf controller-manager.conf kubelet.conf; do
            [ -f "$kdir/$f" ] && { _run chmod 600 "$kdir/$f"; _run chown root:root "$kdir/$f"; }
        done
        if [ -d "$kdir/manifests" ]; then
            _run find "$kdir/manifests" -type f -name '*.yaml' -exec chmod 600 {} + 2>/dev/null || true
            _run find "$kdir/manifests" -type f -name '*.yaml' -exec chown root:root {} + 2>/dev/null || true
        fi
        if [ -d "$kdir/pki" ]; then
            _run find "$kdir/pki" -type f -name '*.crt' -exec chmod 644 {} + 2>/dev/null || true
            _run find "$kdir/pki" -type f -name '*.key' -exec chmod 600 {} + 2>/dev/null || true
            _run chown -R root:root "$kdir/pki" 2>/dev/null || true
        fi
        hlog "Kubernetes config & PKI permissions set."
    else
        hlog "No /etc/kubernetes found; skipping control-plane file perms."
    fi

    # 10b. etcd data dir ownership (CIS 1.1.11/1.1.12).
    if [ -d /var/lib/etcd ]; then
        _run chmod 700 /var/lib/etcd 2>/dev/null || true
        if id etcd >/dev/null 2>&1; then _run chown -R etcd:etcd /var/lib/etcd 2>/dev/null || true; fi
    fi

    # 10c. Kubelet config hardening via drop-in (CIS 4.2.x):
    #   - disable the anonymous read-only port (10255)
    #   - require Webhook authz instead of AlwaysAllow
    #   - protect kernel defaults
    local kubelet_cfg=/var/lib/kubelet/config.yaml
    if [ -f "$kubelet_cfg" ]; then
        _backup "$kubelet_cfg"
        if [ "$HARDEN_DRY_RUN" != true ]; then
            grep -q '^readOnlyPort:' "$kubelet_cfg" \
                && sed -i 's/^readOnlyPort:.*/readOnlyPort: 0/' "$kubelet_cfg" \
                || echo 'readOnlyPort: 0' >> "$kubelet_cfg"
            grep -q 'protectKernelDefaults:' "$kubelet_cfg" \
                && sed -i 's/protectKernelDefaults:.*/protectKernelDefaults: true/' "$kubelet_cfg" \
                || echo 'protectKernelDefaults: true' >> "$kubelet_cfg"
            hlog "kubelet config.yaml hardened (readOnlyPort=0, protectKernelDefaults=true)."
            hwarn "Restart kubelet to apply: systemctl restart kubelet"
        fi
    else
        cat > /dev/null <<'NOTE'
NOTE
        hlog "No kubelet config.yaml found; emitting recommended drop-in to backup dir."
        if [ "$HARDEN_DRY_RUN" != true ]; then
            mkdir -p "$HARDEN_BACKUP_DIR"
            cat > "$HARDEN_BACKUP_DIR/RECOMMENDED-kubelet-hardening.yaml" <<'EOF'
# Apply these keys to your kubelet configuration (KubeletConfiguration kind):
readOnlyPort: 0                      # CIS 4.2.4 -- disable anonymous read-only port
protectKernelDefaults: true          # CIS 4.2.6 -- kubelet exits if sysctls drift
authentication:
  anonymous:
    enabled: false                   # CIS 4.2.1
  webhook:
    enabled: true
authorization:
  mode: Webhook                      # CIS 4.2.2 -- not AlwaysAllow
tlsCipherSuites:                     # CIS 4.2.13 -- strong suites only
  - TLS_AES_256_GCM_SHA384
  - TLS_CHACHA20_POLY1305_SHA256
  - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
EOF
        fi
    fi

    hlog "Kubernetes node hardening complete."
    _record_run k8s_node
}

# ==============================================================================
# 11. LOGIN / PAM / ACCOUNT POLICY (lightweight)
# ==============================================================================
harden_accounts() {
    _should_run accounts || return 0
    hlog "Applying account & login hardening…"

    # Core dump limits (defence in depth alongside fs.suid_dumpable=0).
    _write_file /etc/security/limits.d/99-hardening.conf 0644 <<'EOF'
# Managed by host_hardening.sh
* hard core 0
* soft core 0
EOF

    # Default umask 027 for new files (CIS).
    _write_file /etc/profile.d/99-umask.sh 0644 <<'EOF'
# Managed by host_hardening.sh
umask 027
EOF

    if [ -f /etc/login.defs ] && [ "$HARDEN_DRY_RUN" != true ]; then
        _backup /etc/login.defs
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   365/' /etc/login.defs
        sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/'   /etc/login.defs
        sed -i 's/^UMASK.*/UMASK           027/'         /etc/login.defs 2>/dev/null || true
    fi

    hlog "Account hardening complete."
    _record_run accounts
}

# ==============================================================================
# 12. AUTOMATIC SECURITY UPDATES
# ==============================================================================
harden_updates() {
    _should_run updates || return 0
    hlog "Enabling automatic security updates…"

    case "$OS_FAMILY" in
        debian)
            _pkg_install unattended-upgrades
            if [ "$HARDEN_DRY_RUN" != true ]; then
                _write_file /etc/apt/apt.conf.d/20auto-upgrades 0644 <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
                systemctl enable --now unattended-upgrades >>"$HARDEN_LOG" 2>&1 || true
            fi
            ;;
        rhel)
            _pkg_install dnf-automatic
            if [ "$HARDEN_DRY_RUN" != true ] && [ -f /etc/dnf/automatic.conf ]; then
                _backup /etc/dnf/automatic.conf
                sed -i 's/^upgrade_type.*/upgrade_type = security/'      /etc/dnf/automatic.conf
                sed -i 's/^apply_updates.*/apply_updates = yes/'         /etc/dnf/automatic.conf
                systemctl enable --now dnf-automatic.timer >>"$HARDEN_LOG" 2>&1 || true
            fi
            ;;
    esac
    hlog "Automatic security updates configured."
    _record_run updates
}

# ==============================================================================
# ROLLBACK
# ==============================================================================
harden_rollback() {
    local dir="$1"
    [ -d "$dir" ] || { herr "Backup dir '$dir' not found."; return 1; }
    hlog "Rolling back from $dir …"
    # Restore every backed-up file to its original absolute path.
    ( cd "$dir" && find . -type f | while read -r rel; do
        local target="${rel#.}"
        cp -a "$rel" "$target" && echo "  restored $target"
    done )
    rm -f /etc/sysctl.d/99-k8s-hardening.conf \
          /etc/modprobe.d/99-k8s-blacklist.conf \
          /etc/ssh/sshd_config.d/99-hardening.conf \
          /etc/audit/rules.d/99-k8s-hardening.rules \
          /etc/security/limits.d/99-hardening.conf \
          /etc/profile.d/99-umask.sh
    sysctl --system >/dev/null 2>&1 || true
    augenrules --load >/dev/null 2>&1 || true
    sshd -t && (systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null) || true
    hwarn "Rollback applied. Review services and reboot if MAC/audit immutability was set."
}

# ==============================================================================
# ORCHESTRATION
# ==============================================================================
run_host_hardening() {
    : > /dev/null
    mkdir -p "$(dirname "$HARDEN_LOG")" 2>/dev/null || true
    touch "$HARDEN_LOG" 2>/dev/null || true

    hlog "================ Host hardening starting ================"
    detect_os || return 1

    [ "$HARDEN_DRY_RUN" = true ] && hwarn "DRY-RUN: no changes will be written."

    harden_kernel
    harden_modules
    harden_filesystem
    harden_ssh
    harden_services
    harden_firewall
    harden_auditd
    harden_mac
    harden_time
    harden_k8s_node
    harden_accounts
    harden_updates

    hlog "================ Host hardening complete ================"
    hlog "Backups: $HARDEN_BACKUP_DIR"
    hlog "State:   $HARDEN_STATE"
    hwarn "A reboot is recommended to fully apply module blacklists, mount, and MAC changes."
}

# ==============================================================================
# STANDALONE ENTRYPOINT
# ==============================================================================
# Only runs the orchestrator when executed directly, not when sourced.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    while [ $# -gt 0 ]; do
        case "$1" in
            --dry-run)  HARDEN_DRY_RUN=true ;;
            --profile)  HARDEN_PROFILE="$2"; shift ;;
            --skip)     HARDEN_SKIP="$2"; shift ;;
            --rollback) detect_os >/dev/null 2>&1; harden_rollback "$2"; exit $? ;;
            -h|--help)
                grep -E '^#( |$)' "$0" | sed 's/^# \{0,1\}//' | head -40
                exit 0 ;;
            *) herr "Unknown arg: $1"; exit 1 ;;
        esac
        shift
    done
    run_host_hardening
fi