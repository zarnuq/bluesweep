# Local linPEAS coverage comparison

Reference: `/home/miles/notes/CYBER/linpeas.sh`, 10,128 lines, reviewed locally.
SHA-256: `e59effc3dbb71d69afb1f517f10648e544f48394747f4e6a2ed6c119a8d77395`.

Scale of the reference, derived so it can be rechecked:

```sh
rg -c 'print_[0-9]*title' linpeas.sh                          # 480 occurrences
rg -c '^\s*(function\s+)?print_[0-9]*title\s*\(' linpeas.sh    # 3 are function definitions
rg -o 'print_[0-9]*title\s+"[^"]+"' linpeas.sh | sed 's/.*"\(.*\)"/\1/' | sort -u | wc -l
```

That is **477 heading call sites, 448 unique heading strings**. Neither is a coverage
figure — they size the reference, not what bluesweep implements. The per-area ledger
below is the actual scope statement.

This is a coverage ledger, **not a claim of full linPEAS parity**. Filename patterns
are inventory data; finding a config file is not equivalent to implementing its
application-specific parser. bluesweep independently implements the local defensive
checks below and incorporates the reference's 271 unique filename patterns into
bounded filesystem candidate selection and ARTIFACT observations. No linPEAS code
is executed, sourced, or bundled.

## Implemented defensive coverage

| Area | bluesweep checks / behavior |
|---|---|
| Bash/Zsh/Fish/Ksh/Csh/session startup | RC001/RC002, PER003, STARTUP_FILE fingerprints; profiles, environment, logout, X/session files, orphan homes, hooks |
| Processes and kernel inconsistencies | PROC/PROC_ID, RK*, PRC*, KRN*; exe/argv/PPID/start ticks, deleted binaries, PID comparisons, modules, taint, ftrace |
| Network | NET*, CONNECTION, IFACE, FIREWALL; local listeners/peers, packet sockets, promiscuity, firewall/NAT rules |
| Accounts and privilege policy | ACC*, PRIV*, GROUP, SHADOW_META; UID duplication, password state, sudoers, doas, polkit, D-Bus rules, sensitive groups |
| Persistence | CRON/UNIT*/RCLINE/CONFIG, PER*, ART*; cron, timers, systemd, generators, udev, package hooks, loader config, mail forwarding |
| SSH | SSH*, SSHKEY; default/custom key files, forced commands, sshd/drop-ins, SSH rc and environment |
| File integrity | SUI*, FS*, INT*, ACL*, CAP*; set-ID, unsafe modes, ownership, hashes, extended ACLs, capabilities, immutable attributes, package verification |
| Services | SRV*, DNS*, SMTP*, FTP*, SQL*, PG*, REDIS*, MONGO*, MQTT*, RSYNC*, SUP*, SNMP*, ES*, CI*, LDAP*, NFS*, SMB*, WEB* |
| Containers and local cloud artifacts | CTR*, PROCESS_SECURITY; runtime socket modes, service-account/config presence, process capabilities/seccomp, host-access configuration |
| Credentials and application files | ARTIFACT, SEC*; 271 filename patterns, permission checks, redacted secret-assignment/private-key indicators |
| Logs / sessions | LOG*, SESSION; empty logs/history redirection, audit rules, controlling terminals; bounded evidence exports |
| Defender telemetry | AGT*, AGENT; process state and local enrollment metadata; running-to-stopped drift is CRIT |
| Repeated response | Baseline/diff, NDJSON, evidence manifests, IR skeleton, commented review guidance |

## Deliberate exclusions

No network scanning, cloud IMDS/token retrieval, login/password guessing through
`su` or `sudo`, database connections/UDF execution, exploit execution, clipboard,
browser-cookie/keychain extraction, or memory credential dumping. Those behaviors
conflict with this project's offline, detection-only scope. The opt-in weak-password
check compares a bounded candidate list to readable local hashes without logging in.
Windows/macOS/BSD-specific logic is outside the Linux target scope.

Version-only CVE matching is not shipped: distribution backports make an upstream
version comparison unreliable. Package versions and verification observations are
provided for comparison with distribution advisories on a trusted host.

## Remaining depth limits

- Complex service config grammars, arbitrary Include graphs, dynamic shell sourcing,
  authenticated SQL grants/triggers/UDFs and server-side agent enrollment need review.
- SUID library/RPATH dependency analysis and writable executable-chain resolution are
  not implemented. Untrusted binaries are never executed through `ldd`.
- Browser/vault/databases are inventoried by filename; stored records are not decrypted
  or dumped. Generic credential matches are heuristic and redact their values.
- Runtime cloud posture, traffic capture, kernel exploit probes, and exploit-registry
  coverage are not provided. Kernel inconsistency findings have race/namespace limits.
- All coverage is subject to mode, read permissions, candidate/depth/size/time limits.

## Reference heading ledger

Each reference heading is mapped below. “Inventory / partial” explicitly means the
corresponding linPEAS behavior is not fully reproduced. Line references identify the
reviewed local copy; they are not external web links.

| Reference line | linPEAS heading | Coverage disposition |
|---:|---|---|
| 337 | Basic information | Inventory / partial or manual review; no dedicated parity claim |
| 447 | Basic Network Info | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 505 | Internal Network Discovery - Finding hosts and scanning ports | Excluded: active probing/login attempts or credential extraction |
| 539 | Network Port Scanning | Excluded: active probing/login attempts or credential extraction |
| 563 | Network Discovery | Excluded: active probing/login attempts or credential extraction |
| 658 | Scanning local networks (using /24) | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 666 | Discovering hosts in $local_ip/24 | Excluded: active probing/login attempts or credential extraction |
| 686 | Scanning top ports of host.docker.internal | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 1966 | Matched CVEs | Inventory / partial: versions/config evidence; no exploit or version-only CVE verdict |
| 2563 | Searching $title... | Inventory / partial or manual review; no dedicated parity claim |
| 2593 | System Information | Inventory / partial or manual review; no dedicated parity claim |
| 2594 | Operative system | Inventory / partial or manual review; no dedicated parity claim |
| 2603 | Sudo version | Implemented account/group/static policy checks; no authentication attempts |
| 2612 | USBCreator | Inventory / partial or manual review; no dedicated parity claim |
| 2629 | PATH | Inventory / partial or manual review; no dedicated parity claim |
| 2639 | Date & uptime | Inventory / partial or manual review; no dedicated parity claim |
| 2645 | CPU info | Inventory / partial or manual review; no dedicated parity claim |
| 2651 | Unmounted file-system? | Inventory / partial or manual review; no dedicated parity claim |
| 2658 | Any sd*/disk* disk in /dev? (limit 20) | Inventory / partial or manual review; no dedicated parity claim |
| 2663 | Mounted SMB Shares | Inventory / partial or manual review; no dedicated parity claim |
| 2669 | Mounted disks information | Inventory / partial or manual review; no dedicated parity claim |
| 2674 | System stats | Inventory / partial or manual review; no dedicated parity claim |
| 2678 | Inode usage | Inventory / partial or manual review; no dedicated parity claim |
| 2683 | Environment | Inventory / partial or manual review; no dedicated parity claim |
| 2689 | Searching Signature verification failed in dmesg | Inventory / partial or manual review; no dedicated parity claim |
| 2696 | Kernel Extensions not belonging to apple | Excluded: platform or interactive-secret extraction outside scope |
| 2699 | Unsigned Kernel Extensions | Inventory / partial or manual review; no dedicated parity claim |
| 2705 | Brew Doctor Suggestions | Excluded: platform or interactive-secret extraction outside scope |
| 2731 | Protections | Implemented /proc and kernel consistency checks; memory extraction excluded |
| 2845 | Kernel Modules Information | Implemented /proc and kernel consistency checks; memory extraction excluded |
| 2848 | Loaded kernel modules | Implemented /proc and kernel consistency checks; memory extraction excluded |
| 2860 | Kernel modules with weak perms? | Implemented /proc and kernel consistency checks; memory extraction excluded |
| 2871 | Kernel modules loadable?  | Implemented /proc and kernel consistency checks; memory extraction excluded |
| 2882 | Module signature enforcement?  | Implemented /proc and kernel consistency checks; memory extraction excluded |
| 2900 | Kernel Exploit Registry | Inventory / partial: versions/config evidence; no exploit or version-only CVE verdict |
| 2911 | Container | Inventory / partial or manual review; no dedicated parity claim |
| 2912 | Container related tools present (if any): | Inventory / partial or manual review; no dedicated parity claim |
| 2950 | Listing mounted tokens | Inventory / partial or manual review; no dedicated parity claim |
| 2968 | Container details | Inventory / partial or manual review; no dedicated parity claim |
| 3044 | Docker Container details | Inventory / partial or manual review; no dedicated parity claim |
| 3060 | Docker Overlays | Inventory / partial or manual review; no dedicated parity claim |
| 3067 | Container & breakout enumeration | Inventory / partial or manual review; no dedicated parity claim |
| 3075 | Security Mechanisms | Inventory / partial or manual review; no dedicated parity claim |
| 3101 | Known Vulnerabilities | Inventory / partial: versions/config evidence; no exploit or version-only CVE verdict |
| 3108 | Runtime Vulnerabilities | Inventory / partial: versions/config evidence; no exploit or version-only CVE verdict |
| 3139 | Breakout via mounts | Inventory / partial or manual review; no dedicated parity claim |
| 3165 | Capability Checks | Implemented FS/INT/SUI/ACL/CAP/PRIV checks over bounded candidate set; dependency analysis excluded |
| 3185 | Namespace Checks | Inventory / partial or manual review; no dedicated parity claim |
| 3217 | Additional Breakout Vectors | Inventory / partial or manual review; no dedicated parity claim |
| 3225 | Extra Breakout Vectors | Inventory / partial or manual review; no dedicated parity claim |
| 3260 | Kubernetes Specific Checks | Inventory / partial or manual review; no dedicated parity claim |
| 3286 | Interesting Files & Mounts | Inventory / partial or manual review; no dedicated parity claim |
| 3297 | Container - Writable bind mounts w/o nosuid (SUID persistence risk) | Implemented FS/INT/SUI/ACL/CAP/PRIV checks over bounded candidate set; dependency analysis excluded |
| 3328 | Cloud | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3360 | AWS EC2 Enumeration | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3385 | Account Info | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3388 | Network Info | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3402 | IAM Role | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3410 | User Data | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3413 | EC2 Security Credentials | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3415 | SSM Runnig | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3422 | AWS ECS Enumeration | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3432 | Container Info | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3435 | Task Info | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3442 | IAM Role | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3448 | ECS task metadata hints | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3470 | IMDS reachability from this task | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3525 | ECS agent IMDS settings | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3553 | DOCKER-USER IMDS filtering | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3583 | AWS Lambda Enumeration | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3596 | AWS Codebuild Enumeration | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3607 | Credentials | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3611 | Container Info | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3629 | Google Cloud Platform Enumeration | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3644 | Service Accounts | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3667 | Google Cloud Platform Enumeration | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3717 | Interfaces | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3727 | User Data | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3731 | Service Accounts | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3746 | Azure VM Enumeration | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3759 | Instance details | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3762 | Load Balancer details | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3765 | User Data | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3768 | Custom Data and other configs (root needed) | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3771 | Management token | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3775 | Graph token | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3779 | Vault token | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3783 | Storage token | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3793 | Azure App Service Enumeration | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3804 | Management token | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3807 | Graph token | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3810 | Vault token | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3813 | Storage token | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3821 | Azure Automation Account Service Enumeration | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3832 | Management token | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3835 | Graph token | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3838 | Vault token | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3841 | Storage token | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3848 | DO Droplet Enumeration | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3886 | Aliyun ECS Enumeration | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3889 | Instance Info | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3906 | Network Info | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3931 | Service account  | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3938 | Possbile admin ssh Public keys | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3948 | IBM Cloud Enumeration | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3964 | Instance Details | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3966 | Keys and User data | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3969 | Placement Groups | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3971 | IAM credentials | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3987 | Tencent CVM Enumeration | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 3991 | Instance Info | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 4009 | Network Info | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 4026 | Service account  | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 4033 | Possbile admin ssh Public keys | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 4040 | User Data | Local config/credential artifact inventory only; no cloud API or metadata calls |
| 4051 | Processes, Crons, Timers, Services and Sockets | Implemented local static persistence checks; effective runtime/include resolution partial |
| 4053 | Running processes (cleaned) | Implemented /proc and kernel consistency checks; memory extraction excluded |
| 4245 | Processes with unusual configurations | Implemented /proc and kernel consistency checks; memory extraction excluded |
| 4272 | Processes with credentials in memory (root req) | Excluded: active probing/login attempts or credential extraction |
| 4286 | Opened Files by processes | Implemented /proc and kernel consistency checks; memory extraction excluded |
| 4326 | Processes with memory-mapped credential files | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 4351 | Binary processes permissions (non 'root root' and not belonging to current user) | Implemented FS/INT/SUI/ACL/CAP/PRIV checks over bounded candidate set; dependency analysis excluded |
| 4387 | Processes whose PPID belongs to a different user (not root) | Implemented account/group/static policy checks; no authentication attempts |
| 4428 | Files opened by processes belonging to other users | Implemented account/group/static policy checks; no authentication attempts |
| 4471 | Different processes executed during 1 min (interesting is low number of repetitions) | Implemented /proc and kernel consistency checks; memory extraction excluded |
| 4486 | Check for vulnerable cron jobs | Inventory / partial: versions/config evidence; no exploit or version-only CVE verdict |
| 4488 | Cron jobs list | Implemented local static persistence checks; effective runtime/include resolution partial |
| 4500 | Checking for specific cron jobs vulnerabilities | Inventory / partial: versions/config evidence; no exploit or version-only CVE verdict |
| 4685 | Cron jobs | Implemented local static persistence checks; effective runtime/include resolution partial |
| 4693 | Third party LaunchAgents & LaunchDemons | Excluded: platform or interactive-secret extraction outside scope |
| 4766 | StartupItems | Excluded: platform or interactive-secret extraction outside scope |
| 4779 | Login Items | Excluded: platform or interactive-secret extraction outside scope |
| 4792 | SPStartupItemDataType | Inventory / partial or manual review; no dedicated parity claim |
| 4803 | Emond scripts | Excluded: platform or interactive-secret extraction outside scope |
| 4814 | Periodic tasks | Inventory / partial or manual review; no dedicated parity claim |
| 4831 | System timers | Implemented local static persistence checks; effective runtime/include resolution partial |
| 4916 | Active timers: | Implemented local static persistence checks; effective runtime/include resolution partial |
| 4933 | Disabled timers: | Implemented local static persistence checks; effective runtime/include resolution partial |
| 4945 | Additional timer files: | Implemented local static persistence checks; effective runtime/include resolution partial |
| 4956 | Services and Service Files | Implemented local static persistence checks; effective runtime/include resolution partial |
| 5054 | Active services: | Implemented local static persistence checks; effective runtime/include resolution partial |
| 5071 | Disabled services: | Implemented local static persistence checks; effective runtime/include resolution partial |
| 5089 | Additional service files: | Implemented local static persistence checks; effective runtime/include resolution partial |
| 5099 | Service versions and status: | Implemented local static persistence checks; effective runtime/include resolution partial |
| 5117 | Systemd Information | Implemented local static persistence checks; effective runtime/include resolution partial |
| 5240 | Systemd PATH | Implemented local static persistence checks; effective runtime/include resolution partial |
| 5257 | Analyzing .socket files | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 5376 | Unix Sockets Analysis | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 5490 | D-Bus Analysis | Inventory / partial or manual review; no dedicated parity claim |
| 5651 | D-Bus Configuration Files | Inventory / partial or manual review; no dedicated parity claim |
| 5666 | D-Bus Session Bus Analysis | Inventory / partial: LOG/SESSION checks and bounded evidence; no complete event reconstruction |
| 5688 | Legacy r-commands (rsh/rlogin/rexec) and host-based trust | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 5690 | Listening r-services (TCP 512-514) | Implemented local static persistence checks; effective runtime/include resolution partial |
| 5699 | systemd units exposing r-services | Implemented local static persistence checks; effective runtime/include resolution partial |
| 5707 | inetd/xinetd configuration for r-services | Implemented local static persistence checks; effective runtime/include resolution partial |
| 5730 | Installed r-service server packages | Implemented local static persistence checks; effective runtime/include resolution partial |
| 5739 | /etc/hosts.equiv and /etc/shosts.equiv | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 5755 | Per-user .rhosts files | Implemented account/group/static policy checks; no authentication attempts |
| 5774 | PAM rhosts authentication | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 5785 | SSH HostbasedAuthentication | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 5796 | Potential DNS control indicators (local) | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 5802 | Crontab UI (root) misconfiguration checks | Implemented local static persistence checks; effective runtime/include resolution partial |
| 5897 | Deleted files still open | Implemented /proc and kernel consistency checks; memory extraction excluded |
| 5902 | Deleted files still open | Implemented /proc and kernel consistency checks; memory extraction excluded |
| 5915 | Network Information | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 5963 | Interfaces | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 5974 | Routing & policy quick view | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 5979 | Virtual/overlay interfaces quick view | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 5981 | Network namespaces quick view | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 5985 | Forwarding status | Inventory / partial or manual review; no dedicated parity claim |
| 5991 | Hostname Information | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6009 | Hosts File Information | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6020 | DNS Configuration | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6068 | Hostname, hosts and DNS | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6076 | Routing Table (from /proc/net/route) | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6099 | ARP Table (from /proc/net/arp) | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6119 | Networks and neighbours | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6121 | Routing Information | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6144 | ARP Information | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6157 | Additional Neighbor Information | Inventory / partial or manual review; no dedicated parity claim |
| 6215 | Active $proto Ports (from /proc/net/$proto) | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6270 | Active Ports | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6274 | Active Ports (netstat) | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6277 | Active Ports (ss) | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6285 | Local-only listeners (loopback) | Inventory / partial or manual review; no dedicated parity claim |
| 6291 | Unique listener bind addresses | Inventory / partial or manual review; no dedicated parity claim |
| 6318 | Potential local forwarders/relays | Inventory / partial or manual review; no dedicated parity claim |
| 6322 | Additional Port Information | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6372 | Network Capabilities | Implemented FS/INT/SUI/ACL/CAP/PRIV checks over bounded candidate set; dependency analysis excluded |
| 6375 | Network Interfaces and Configuration | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6379 | Network Locations | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6383 | Network Extensions | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6389 | Network Security | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6407 | Network Preferences | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6413 | Network Statistics | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6417 | Network Routes | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6421 | Network Interfaces Details | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6425 | Network Kernel Extensions | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6445 | MacOS Sharing Services Status | Excluded: platform or interactive-secret extraction outside scope |
| 6489 | VPN Information | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6504 | Firewall Information | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6522 | Additional Network Information | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6595 | Network Traffic Analysis Capabilities | Implemented FS/INT/SUI/ACL/CAP/PRIV checks over bounded candidate set; dependency analysis excluded |
| 6598 | Available Sniffing Tools | Inventory / partial or manual review; no dedicated parity claim |
| 6648 | Network Interfaces Sniffing Capabilities | Implemented FS/INT/SUI/ACL/CAP/PRIV checks over bounded candidate set; dependency analysis excluded |
| 6686 | Sensitive Traffic Detection | Excluded: active probing/login attempts or credential extraction |
| 6714 | Running sniffing/traffic reconstruction processes | Implemented /proc and kernel consistency checks; memory extraction excluded |
| 6719 | Additional Network Analysis Information | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6746 | Iptables Rules | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6781 | Nftables Rules | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6811 | Firewalld Rules | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6843 | UFW Rules | Inventory / partial or manual review; no dedicated parity claim |
| 6865 | Firewall Rules Analysis | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6872 | Forwarding and rp_filter | Inventory / partial or manual review; no dedicated parity claim |
| 6883 | Additional Firewall Information | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 6917 | Inetd Services | Implemented local static persistence checks; effective runtime/include resolution partial |
| 6951 | Xinetd Services | Implemented local static persistence checks; effective runtime/include resolution partial |
| 7005 | Running Inetd/Xinetd Services | Implemented local static persistence checks; effective runtime/include resolution partial |
| 7024 | Inetd/Xinetd Services Analysis | Implemented local static persistence checks; effective runtime/include resolution partial |
| 7033 | Additional Inetd/Xinetd Information | Inventory / partial or manual review; no dedicated parity claim |
| 7057 | Hardware Ports | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 7060 | VLANs | Inventory / partial or manual review; no dedicated parity claim |
| 7063 | Wifi Info | Inventory / partial or manual review; no dedicated parity claim |
| 7066 | Check Enabled Proxies | Inventory / partial or manual review; no dedicated parity claim |
| 7069 | Wifi Proxy URL | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 7072 | Wifi Web Proxy | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 7077 | Internet Access? | Excluded: active probing/login attempts or credential extraction |
| 7097 | Is hostname malicious or leaked? | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 7102 | Proxy discovery | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 7115 | Users Information | Implemented account/group/static policy checks; no authentication attempts |
| 7117 | Current user Login and Logout hooks | Implemented local static persistence checks; effective runtime/include resolution partial |
| 7122 | My user | Implemented account/group/static policy checks; no authentication attempts |
| 7128 | All Login and Logout hooks | Implemented local static persistence checks; effective runtime/include resolution partial |
| 7139 | Keychains | Excluded: platform or interactive-secret extraction outside scope |
| 7154 | SystemKey | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7166 | PGP Keys and Related Files | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7199 | Clipboard and Highlighted Text | Excluded: platform or interactive-secret extraction outside scope |
| 7235 | Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d | Implemented account/group/static policy checks; no authentication attempts |
| 7266 | Checking sudo tokens | Implemented account/group/static policy checks; no authentication attempts |
| 7303 | Doas Configuration | Implemented account/group/static policy checks; no authentication attempts |
| 7339 | Checking Pkexec and Polkit | Implemented account/group/static policy checks; no authentication attempts |
| 7342 | Polkit Binary | Implemented account/group/static policy checks; no authentication attempts |
| 7362 | Polkit Policies | Implemented account/group/static policy checks; no authentication attempts |
| 7381 | Polkit Authentication Agent | Implemented account/group/static policy checks; no authentication attempts |
| 7385 | Superusers and UID 0 Users | Implemented account/group/static policy checks; no authentication attempts |
| 7389 | Users with UID 0 in /etc/passwd | Implemented account/group/static policy checks; no authentication attempts |
| 7401 | Users with sudo privileges in sudoers | Implemented account/group/static policy checks; no authentication attempts |
| 7405 | Users with console | Implemented account/group/static policy checks; no authentication attempts |
| 7443 | All users & groups | Implemented account/group/static policy checks; no authentication attempts |
| 7451 | Currently Logged in Users | Implemented account/group/static policy checks; no authentication attempts |
| 7454 | Basic user information | Implemented account/group/static policy checks; no authentication attempts |
| 7458 | Active sessions | Inventory / partial: LOG/SESSION checks and bounded evidence; no complete event reconstruction |
| 7464 | Logged in users (utmp) | Implemented account/group/static policy checks; no authentication attempts |
| 7470 | SSH sessions | Inventory / partial: LOG/SESSION checks and bounded evidence; no complete event reconstruction |
| 7476 | Screen sessions | Inventory / partial: LOG/SESSION checks and bounded evidence; no complete event reconstruction |
| 7482 | Tmux sessions | Inventory / partial: LOG/SESSION checks and bounded evidence; no complete event reconstruction |
| 7488 | Last Logons and Login History | Inventory / partial: LOG/SESSION checks and bounded evidence; no complete event reconstruction |
| 7491 | Last logins | Inventory / partial: LOG/SESSION checks and bounded evidence; no complete event reconstruction |
| 7497 | Failed login attempts | Inventory / partial: LOG/SESSION checks and bounded evidence; no complete event reconstruction |
| 7503 | Recent logins from auth.log (limit 20) | Inventory / partial: LOG/SESSION checks and bounded evidence; no complete event reconstruction |
| 7510 | Last time logon each user | Implemented account/group/static policy checks; no authentication attempts |
| 7526 | Password policy | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7530 | Relevant last user info and user configs | Implemented account/group/static policy checks; no authentication attempts |
| 7533 | Guest user status | Implemented account/group/static policy checks; no authentication attempts |
| 7542 | Testing 'su' as other users with shell using as passwords: null pwd, the username and top2000pwds\n | Excluded: active probing/login attempts or credential extraction |
| 7554 | Do not forget to test 'su' as any other user with shell: without password and with their names as password (I don't do it in FAST mode...)\n | Excluded: active probing/login attempts or credential extraction |
| 7556 | Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!\n | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7565 | Software Information | Inventory / partial or manual review; no dedicated parity claim |
| 7567 | Useful software | Inventory / partial or manual review; no dedicated parity claim |
| 7573 | Installed Compilers | Inventory / partial or manual review; no dedicated parity claim |
| 7577 | Vulnerable Packages | Inventory / partial: versions/config evidence; no exploit or version-only CVE verdict |
| 7582 | Brew Installed Packages | Excluded: platform or interactive-secret extraction outside scope |
| 7589 | Writable Installed Applications | Implemented FS/INT/SUI/ACL/CAP/PRIV checks over bounded candidate set; dependency analysis excluded |
| 7603 | Analyzing Apache-Nginx Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7619 | Check aws-vault | Inventory / partial or manual review; no dedicated parity claim |
| 7623 | Browser Profiles | Implemented local static persistence checks; effective runtime/include resolution partial |
| 7630 | Firefox profiles ($h) | Implemented local static persistence checks; effective runtime/include resolution partial |
| 7661 | Chromium profiles ($chrome_base) | Implemented local static persistence checks; effective runtime/include resolution partial |
| 7671 | Searching AD cached hashes | Excluded: active probing/login attempts or credential extraction |
| 7679 | Checking if containerd(ctr) is available | Inventory / partial or manual review; no dedicated parity claim |
| 7690 | Searching docker files (limit 70) | Inventory / partial or manual review; no dedicated parity claim |
| 7704 | Searching dovecot files | Inventory / partial or manual review; no dedicated parity claim |
| 7719 | Analyzing MariaDB Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7726 | Analyzing Varnish Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7732 | Analyzing Apache-Airflow Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7739 | Analyzing X11 Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7745 | Analyzing Wordpress Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7751 | Analyzing Drupal Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7757 | Analyzing Moodle Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7763 | Analyzing Tomcat Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7769 | Analyzing Mongo Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7777 | Analyzing Rocketchat Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7783 | Analyzing Supervisord Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7789 | Analyzing Cesi Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7795 | Analyzing Rsync Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7802 | Analyzing Rpcd Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7808 | Analyzing Bitcoin Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7814 | Analyzing Hostapd Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7820 | Analyzing Wifi Connections Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7826 | Analyzing PAM Auth Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7832 | Analyzing NFS Exports Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7839 | Analyzing GlusterFS Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7847 | Analyzing Anaconda ks Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7853 | Analyzing Terraform Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7861 | Analyzing Racoon Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7868 | Analyzing Kubernetes Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7883 | Analyzing VNC Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7893 | Analyzing Ldap Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7900 | Analyzing OpenVPN Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7906 | Analyzing Cloud Credentials Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7938 | Analyzing Road Recon Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7944 | Analyzing Kibana Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7950 | Analyzing Grafana Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7956 | Analyzing Knockd Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7962 | Analyzing Elasticsearch Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7969 | Analyzing CouchDB Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7975 | Analyzing Redis Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7983 | Analyzing Mosquitto Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7989 | Analyzing Neo4j Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 7995 | Analyzing Cloud Init Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8001 | Analyzing Erlang Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8007 | Analyzing SIP Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8016 | Analyzing GMV Auth Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8022 | Analyzing IPSec Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8029 | Analyzing IRSSI Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8035 | Analyzing Keyring Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8044 | Analyzing Virtual Disks Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8052 | Analyzing Filezilla Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8060 | Analyzing Backup Manager Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8067 | Analyzing Git Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8073 | Analyzing Atlantis Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8079 | Analyzing Cache Vi Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8086 | Analyzing Firefox Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8093 | Analyzing Chrome Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8100 | Analyzing Opera Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8106 | Analyzing Safari Files (limit 70) | Excluded: platform or interactive-secret extraction outside scope |
| 8112 | Analyzing Autologin Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8119 | Analyzing FastCGI Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8125 | Analyzing Fat-Free Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8131 | Analyzing Shodan Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8137 | Analyzing Concourse Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8145 | Analyzing Boto Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8151 | Analyzing SNMP Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8157 | Analyzing Pypirc Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8163 | Analyzing Postfix Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8169 | Analyzing CloudFlare Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8175 | Analyzing Http conf Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8181 | Analyzing Htpasswd Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8187 | Analyzing Ldaprc Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8193 | Analyzing Env Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8199 | Analyzing Proxy Config Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8207 | Analyzing Sniffing Artifacts Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8216 | Analyzing Msmtprc Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8222 | Analyzing InfluxDB Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8228 | Analyzing Zabbix Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8236 | Analyzing Github Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8245 | Analyzing Svn Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8251 | Analyzing Keepass Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8260 | Analyzing Pre-Shared Keys Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8266 | Analyzing Pass Store Directories Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8272 | Analyzing FTP Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8286 | Analyzing Samba Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8293 | Analyzing DNS Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8299 | Analyzing SeedDMS Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8305 | Analyzing Ddclient Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8311 | Analyzing Sentry Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8318 | Analyzing Strapi Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8324 | Analyzing Cacti Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8330 | Analyzing Roundcube Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8336 | Analyzing Passbolt Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8342 | Analyzing Jetty Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8348 | Analyzing Jenkins Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8358 | Analyzing Wget Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8364 | Analyzing Interesting logs Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8371 | Analyzing Other Interesting Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8385 | Analyzing Windows Files (limit 70) | Excluded: platform or interactive-secret extraction outside scope |
| 8441 | Analyzing Crontab-UI Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8450 | Analyzing FreeIPA Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8458 | Searching GitLab related files | Inventory / partial or manual review; no dedicated parity claim |
| 8490 | Analyzing kcpassword files | Excluded: platform or interactive-secret extraction outside scope |
| 8503 | Searching kerberos conf files and tickets | Inventory / partial or manual review; no dedicated parity claim |
| 8553 | Searching Log4Shell vulnerable libraries | Inventory / partial: versions/config evidence; no exploit or version-only CVE verdict |
| 8561 | Searching logstash files | Inventory / partial: LOG/SESSION checks and bounded evidence; no complete event reconstruction |
| 8575 | Searching mysql credentials and exec | Excluded: active probing/login attempts or credential extraction |
| 8621 | MySQL version | Inventory / partial or manual review; no dedicated parity claim |
| 8685 | Analyzing PGP-GPG Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8703 | Analyzing PHP Sessions Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8711 | Passwords inside pam.d | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8717 | Analyzing PostgreSQL Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8748 | PostgreSQL event trigger ownership & postgres_fdw hooks | Inventory / partial or manual review; no dedicated parity claim |
| 8804 | Checking if runc is available | Inventory / partial or manual review; no dedicated parity claim |
| 8814 | S/Key authentication | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8828 | Searching screen sessions | Inventory / partial: LOG/SESSION checks and bounded evidence; no complete event reconstruction |
| 8838 | Checking other users screen sessions | Implemented account/group/static policy checks; no authentication attempts |
| 8852 | Searching uncommon passwd files (splunk) | Inventory / partial or manual review; no dedicated parity claim |
| 8863 | Searching ssl/ssh files | Inventory / partial or manual review; no dedicated parity claim |
| 8883 | Analyzing SSH Files (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8909 | Possible private SSH keys were found! | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 8917 | Some certificates were found (out limited): | Inventory / partial or manual review; no dedicated parity claim |
| 8923 | Some client certificates were found: | Inventory / partial or manual review; no dedicated parity claim |
| 8928 | Some SSH Agent files were found: | Inventory / partial or manual review; no dedicated parity claim |
| 8933 | Potential SSH agent sockets were found: | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 8938 | Listing SSH Agents | Inventory / partial or manual review; no dedicated parity claim |
| 8943 | Listing gpg keys cached in gpg-agent | Excluded: active probing/login attempts or credential extraction |
| 8948 | Writable ssh and gpg agents | Implemented FS/INT/SUI/ACL/CAP/PRIV checks over bounded candidate set; dependency analysis excluded |
| 8952 | Some home ssh config file was found | Inventory / partial or manual review; no dedicated parity claim |
| 8957 | /etc/hosts.denied file found, read the rules: | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 8963 | /etc/hosts.allow file found, trying to read the rules: | Inventory / partial: kernel sockets/interfaces/resolver/firewall observations; no active probes |
| 8979 | Searching tmux sessions | Inventory / partial: LOG/SESSION checks and bounded evidence; no complete event reconstruction |
| 8990 | Searching Vault-ssh files | Inventory / partial or manual review; no dedicated parity claim |
| 9000 | YubiKey authentication | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 9018 | Files with Interesting Permissions | Implemented FS/INT/SUI/ACL/CAP/PRIV checks over bounded candidate set; dependency analysis excluded |
| 9019 | SUID - Check easy privesc, exploits and write perms | Inventory / partial: versions/config evidence; no exploit or version-only CVE verdict |
| 9102 | SGID | Implemented FS/INT/SUI/ACL/CAP/PRIV checks over bounded candidate set; dependency analysis excluded |
| 9179 | Files with ACLs (limited to 50) | Implemented FS/INT/SUI/ACL/CAP/PRIV checks over bounded candidate set; dependency analysis excluded |
| 9192 | Capabilities | Implemented FS/INT/SUI/ACL/CAP/PRIV checks over bounded candidate set; dependency analysis excluded |
| 9195 | Current shell capabilities | Implemented FS/INT/SUI/ACL/CAP/PRIV checks over bounded candidate set; dependency analysis excluded |
| 9247 | Processes with capability sets (non-zero CapEff/CapAmb, limit 40) | Implemented FS/INT/SUI/ACL/CAP/PRIV checks over bounded candidate set; dependency analysis excluded |
| 9277 | Current shell capabilities | Implemented FS/INT/SUI/ACL/CAP/PRIV checks over bounded candidate set; dependency analysis excluded |
| 9280 | Parent proc capabilities | Implemented FS/INT/SUI/ACL/CAP/PRIV checks over bounded candidate set; dependency analysis excluded |
| 9308 | Users with capabilities | Implemented FS/INT/SUI/ACL/CAP/PRIV checks over bounded candidate set; dependency analysis excluded |
| 9326 | Checking misconfigurations of ld.so | Implemented FS/INT/SUI/ACL/CAP/PRIV checks over bounded candidate set; dependency analysis excluded |
| 9391 | Files (scripts) in /etc/profile.d/ | Implemented local static persistence checks; effective runtime/include resolution partial |
| 9402 | Permissions in init, init.d, systemd, and rc.d | Implemented local static persistence checks; effective runtime/include resolution partial |
| 9418 | AppArmor binary profiles | Implemented local static persistence checks; effective runtime/include resolution partial |
| 9471 | Searching root files in home dirs (limit 30) | Inventory / partial or manual review; no dedicated parity claim |
| 9477 | Searching folders owned by me containing others files on it (limit 100) | Inventory / partial or manual review; no dedicated parity claim |
| 9483 | Readable files belonging to root and readable by me but not world readable | Inventory / partial or manual review; no dedicated parity claim |
| 9489 | Interesting writable files owned by me or writable by everyone (not in Home) (max 200) | Implemented FS/INT/SUI/ACL/CAP/PRIV checks over bounded candidate set; dependency analysis excluded |
| 9505 | Interesting GROUP writable files (not in Home) (max 200) | Implemented FS/INT/SUI/ACL/CAP/PRIV checks over bounded candidate set; dependency analysis excluded |
| 9547 | IGEL OS SUID setup/date privilege escalation surface | Implemented FS/INT/SUI/ACL/CAP/PRIV checks over bounded candidate set; dependency analysis excluded |
| 9588 | Writable root-owned executables I can modify (max 200) | Implemented FS/INT/SUI/ACL/CAP/PRIV checks over bounded candidate set; dependency analysis excluded |
| 9615 | Other Interesting Files | Inventory / partial or manual review; no dedicated parity claim |
| 9617 | .sh files in path | Inventory / partial or manual review; no dedicated parity claim |
| 9633 | Broken links in path | Inventory / partial or manual review; no dedicated parity claim |
| 9642 | Files datetimes inside the firmware (limit 50) | Inventory / partial or manual review; no dedicated parity claim |
| 9648 | Executable files potentially added by user (limit 70) | Implemented account/group/static policy checks; no authentication attempts |
| 9657 | Unsigned Applications | Inventory / partial or manual review; no dedicated parity claim |
| 9663 | Unexpected in /opt (usually empty) | Inventory / partial or manual review; no dedicated parity claim |
| 9670 | Unexpected in root | Inventory / partial or manual review; no dedicated parity claim |
| 9679 | Modified interesting files in the last 5mins (limit 100) | Inventory / partial or manual review; no dedicated parity claim |
| 9684 | Writable log files (logrotten) (limit 50) | Implemented FS/INT/SUI/ACL/CAP/PRIV checks over bounded candidate set; dependency analysis excluded |
| 9700 | Syslog configuration (limit 50) | Inventory / partial: LOG/SESSION checks and bounded evidence; no complete event reconstruction |
| 9709 | Auditd configuration (limit 50) | Inventory / partial: LOG/SESSION checks and bounded evidence; no complete event reconstruction |
| 9716 | Log files with potentially weak perms (limit 50) | Inventory / partial: LOG/SESSION checks and bounded evidence; no complete event reconstruction |
| 9721 | Files inside $HOME (limit 20) | Inventory / partial or manual review; no dedicated parity claim |
| 9727 | Files inside others home (limit 20) | Inventory / partial or manual review; no dedicated parity claim |
| 9733 | Searching installed mail applications | Inventory / partial or manual review; no dedicated parity claim |
| 9739 | Mails (limit 50) | Inventory / partial or manual review; no dedicated parity claim |
| 9746 | Backup folders | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 9755 | Backup files (limited 100) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 9765 | Reading messages database | Inventory / partial or manual review; no dedicated parity claim |
| 9771 | Searching tables inside readable .db/.sql/.sqlite files (limit 100) | Inventory / partial or manual review; no dedicated parity claim |
| 9820 | Downloaded Files | Inventory / partial or manual review; no dedicated parity claim |
| 9825 | Downloaded Files | Inventory / partial or manual review; no dedicated parity claim |
| 9830 | Web files?(output limit) | Inventory / partial or manual review; no dedicated parity claim |
| 9838 | All relevant hidden files (not in /sys/ or the ones listed in the previous check) (limit 70) | Inventory / partial or manual review; no dedicated parity claim |
| 9843 | Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 9850 | Searching passwords in history cmd | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 9856 | Searching passwords in history files | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 9862 | Searching passwords in config PHP files | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 9868 | Searching *password* or *credential* files in home (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 9874 | Checking for TTY (sudo/su) passwords in audit logs | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 9881 | Checking for TTY (sudo/su) passwords in audit logs | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 9888 | Searching emails inside logs (limit 70) | Inventory / partial: LOG/SESSION checks and bounded evidence; no complete event reconstruction |
| 9894 | Searching passwords inside logs (limit 70) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 9901 | Searching possible password variables inside key folders (limit 140) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 9911 | Searching possible password in config files (if k8s secrets are found you need to read the file) | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 9927 | Checking all env variables in /proc/*/environ removing duplicates and filtering out useless env vars | Inventory / partial or manual review; no dedicated parity claim |
| 9942 | API Keys Regex | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 9944 | Searching Hashed Passwords | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 9956 | Searching Raw Hashes | Inventory / partial or manual review; no dedicated parity claim |
| 9960 | Searching APIs | Inventory / partial: ARTIFACT/SEC filename and redacted content checks; see service table |
| 10108 | Searching Misc | Inventory / partial or manual review; no dedicated parity claim |
