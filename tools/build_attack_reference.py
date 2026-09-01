#!/usr/bin/env python3
"""Build a source-traceable operational attack reference from the local CPTS dump.

The script intentionally performs no network access and does not alter dump/.
All commands and payloads in generated files are copied verbatim from fenced
blocks in the source section markdown.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import shlex
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DUMP = ROOT / "dump"
EXTRACTED = ROOT / "extracted"

ACTION = re.compile(
    r"attack|abuse|exploit|enumerat|discover|scan|fuzz|brute|spray|crack|dump|"
    r"poison|relay|inject|upload|inclusion|traversal|shell|forward|tunnel|pivot|"
    r"transfer|hijack|impersonat|bypass|evasion|credential|password|hash|ticket|"
    r"token|acl|dcsync|kerberoast|suid|sudo|capabilit|service|port|host|domain|"
    r"subdomain|vhost|dns|smb|ldap|sql|ftp|ssh|rdp|winrm|snmp|smtp|nfs|http|"
    r"xss|xxe|idor|lfi|rfi|payload|metasploit|meterpreter|nmap|bloodhound|"
    r"powershell|curl|wget|netcat|socat|chisel|rpivot|sshuttle|hydra|john|hashcat",
    re.I,
)
NON_ACTION = re.compile(
    r"^(introduction|intro|summary|conclusion|beyond this module|scenario|"
    r"skills assessment|knowledge check|practice|prevention|hardening|"
    r"laws and regulations|types of reports|components of a report|"
    r"how to write|reporting|detection prevention)$",
    re.I,
)
SKIP_EXTRACT_MODULES = {
    # Inspected for coverage, but these are process/reporting curricula rather
    # than an attack/enumeration technique source.
    "documentation--reporting",
    "penetration-testing-process",
}
GENERIC = re.compile(
    r"^(overview|example|examples|usage|syntax|output|results|setup|summary|"
    r"enumeration|exploitation|attack|attacking|commands?|notes?|methodology|"
    r"from linux|from windows|windows|linux|manual|automated|verification)$",
    re.I,
)

CATEGORY_ORDER = [
    "Reconnaissance", "Service Enumeration", "Web Attacks",
    "Password / Credential Attacks", "Linux Privilege Escalation",
    "Windows Privilege Escalation", "Active Directory", "Databases",
    "Pivoting / Tunneling", "File Transfer", "Shells",
    "Post Exploitation / Lateral Movement", "Operational Tooling",
]

MODULE_CATEGORY = {
    "network-enumeration-with-nmap": "Reconnaissance",
    "footprinting": "Service Enumeration",
    "information-gathering---web-edition": "Reconnaissance",
    "file-transfers": "File Transfer",
    "shells--payloads": "Shells",
    "password-attacks": "Password / Credential Attacks",
    "attacking-common-services": "Service Enumeration",
    "pivoting-tunneling-and-port-forwarding": "Pivoting / Tunneling",
    "active-directory-enumeration--attacks": "Active Directory",
    "attacking-web-applications-with-ffuf": "Web Attacks",
    "login-brute-forcing": "Password / Credential Attacks",
    "sql-injection-fundamentals": "Web Attacks",
    "sqlmap-essentials": "Web Attacks",
    "cross-site-scripting-xss": "Web Attacks",
    "file-inclusion": "Web Attacks",
    "file-upload-attacks": "Web Attacks",
    "command-injections": "Web Attacks",
    "web-attacks": "Web Attacks",
    "attacking-common-applications": "Web Attacks",
    "linux-privilege-escalation": "Linux Privilege Escalation",
    "windows-privilege-escalation": "Windows Privilege Escalation",
    "attacking-enterprise-networks": "Post Exploitation / Lateral Movement",
    "using-web-proxies": "Operational Tooling",
    "using-the-metasploit-framework": "Operational Tooling",
    "getting-started": "Operational Tooling",
    "vulnerability-assessment": "Reconnaissance",
    "penetration-testing-process": "Operational Tooling",
}

CANONICAL = {
    "as rep roasting": "AS-REP Roasting",
    "asreproast": "AS-REP Roasting",
    "asreproasting": "AS-REP Roasting",
    "kerberoasting": "Kerberoasting",
    "spn roasting": "Kerberoasting",
    "pass the hash pth": "Pass-the-Hash",
    "pass the hash": "Pass-the-Hash",
    "pass the ticket ptt from windows": "Pass-the-Ticket (Windows)",
    "pass the ticket ptt from linux": "Pass-the-Ticket (Linux)",
    "pass the ticket": "Pass-the-Ticket",
    "llmnr nbt ns poisoning from linux": "LLMNR/NBT-NS Poisoning (Linux)",
    "llmnr nbt ns poisoning from windows": "LLMNR/NBT-NS Poisoning (Windows)",
    "local file inclusion lfi": "Local File Inclusion",
    "remote file inclusion rfi": "Remote File Inclusion",
    "intro to xxe": "XML External Entity (XXE)",
    "dcsync": "DCSync",
    "dns tunneling with dnscat2": "DNS Tunneling with dnscat2",
    "socks5 tunneling with chisel": "SOCKS5 Tunneling with Chisel",
    "dynamic port forwarding with ssh and socks tunneling": "SSH Dynamic Port Forwarding / SOCKS",
    "remote reverse port forwarding with ssh": "SSH Remote Reverse Port Forwarding",
    "pass the certificate": "Pass-the-Certificate",
    "path abuse": "PATH Abuse",
    "wildcard abuse": "Wildcard Abuse",
    "cron job abuse": "Cron Job Abuse",
    "shared object hijacking": "Shared Object Hijacking",
    "python library hijacking sudo": "Python Library Hijacking via sudo",
    "seimpersonate and seassignprimarytoken": "SeImpersonate/SeAssignPrimaryToken Abuse",
    "setakeownershipprivilege": "SeTakeOwnershipPrivilege Abuse",
    "sedebugprivilege": "SeDebugPrivilege Abuse",
}

ALIASES = {
    "AS-REP Roasting": ["ASREPRoast", "AS-REP roast", "UF_DONT_REQUIRE_PREAUTH"],
    "Kerberoasting": ["SPN roasting", "TGS roasting", "GetUserSPNs"],
    "Pass-the-Hash": ["PtH", "PTH"],
    "Pass-the-Ticket": ["PtT", "PTT"],
    "Pass-the-Ticket (Windows)": ["PtT", "Pass-the-Ticket"],
    "Pass-the-Ticket (Linux)": ["PtT", "Pass-the-Ticket"],
    "Local File Inclusion": ["LFI", "local include"],
    "Remote File Inclusion": ["RFI", "remote include"],
    "XML External Entity (XXE)": ["XXE", "XML", "DTD"],
    "LLMNR/NBT-NS Poisoning (Linux)": ["LLMNR poisoning", "NBT-NS poisoning", "Responder"],
    "LLMNR/NBT-NS Poisoning (Windows)": ["LLMNR poisoning", "NBT-NS poisoning", "Inveigh"],
    "SeImpersonate/SeAssignPrimaryToken Abuse": ["SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege", "token impersonation"],
    "DCSync": ["DS-Replication-Get-Changes", "secretsdump"],
}

PORTS = {
    "ftp": "21", "ssh": "22", "smtp": "25,465,587", "dns": "53",
    "http": "80", "https": "443", "kerberos": "88", "pop3": "110,995",
    "rpc": "111,135", "nfs": "111,2049", "ntp": "123", "imap": "143,993",
    "snmp": "161", "ldap": "389,636,3268,3269", "smb": "139,445",
    "mssql": "1433", "oracle": "1521", "mysql": "3306", "rdp": "3389",
    "postgresql": "5432", "winrm": "5985,5986", "tomcat": "8080",
    "jenkins": "8080", "splunk": "8000,8089", "prtg": "80,443",
}

TOOLS = [
    "nmap", "masscan", "ffuf", "gobuster", "feroxbuster", "wfuzz", "curl", "wget",
    "netcat", "nc", "ncat", "socat", "metasploit", "msfconsole", "msfvenom",
    "meterpreter", "hydra", "medusa", "john", "hashcat", "sqlmap", "responder",
    "inveigh", "bloodhound", "sharphound", "powerview", "evil-winrm", "crackmapexec",
    "netexec", "smbclient", "rpcclient", "enum4linux", "enum4linux-ng", "impacket",
    "secretsdump", "getuserspns", "getnpusers", "mimikatz", "rubeus", "kerbrute",
    "ldapsearch", "dig", "dnsenum", "dnsrecon", "snmpwalk", "onesixtyone", "showmount",
    "mysql", "mssqlclient", "sqsh", "xfreerdp", "ssh", "scp", "proxychains",
    "chisel", "sshuttle", "rpivot", "plink", "dnscat2", "ligolo", "certutil",
    "powershell", "powercat", "linpeas", "winpeas", "pspy", "searchsploit", "nikto",
    "whatweb", "wpscan", "droopescan", "joomscan", "odat", "openssl", "base64",
    "tcpdump", "wireshark", "burp", "zap", "xsstrike", "cewl", "cupp",
]

@dataclass
class Source:
    module: str
    module_slug: str
    section: str
    file: str

@dataclass
class Technique:
    name: str
    category: str
    subcategory: str
    aliases: list[str] = field(default_factory=list)
    os: set[str] = field(default_factory=set)
    services: set[str] = field(default_factory=set)
    ports: set[str] = field(default_factory=set)
    prerequisites: list[str] = field(default_factory=list)
    triggers: list[str] = field(default_factory=list)
    detection: list[str] = field(default_factory=list)
    exploitation: list[str] = field(default_factory=list)
    success: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    variants: list[str] = field(default_factory=list)
    tools: set[str] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)
    sources: list[Source] = field(default_factory=list)
    anchor: str = ""

def clean_title(s: str) -> str:
    s = re.sub(r"[`*_]", "", s).strip()
    s = re.sub(r"\s+", " ", s)
    return s.strip(" -–—:")

def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()

def slugify(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")

def extract_fences(text: str) -> list[str]:
    return [m.group(0).rstrip() for m in re.finditer(r"(?ms)^[ \t]{0,3}```(?!`)[^\n]*\n.*?^[ \t]{0,3}```(?!`)[ \t]*\r?$", text)]

def strip_markup(s: str) -> str:
    s = re.sub(r"<[^>]+>", " ", s)
    s = re.sub(r"!?\[([^]]*)\]\([^)]*\)", r"\1", s)
    s = re.sub(r"[`*_>#]", "", s)
    return re.sub(r"\s+", " ", s).strip()

def sentences(text: str, pattern: str, limit: int = 3) -> list[str]:
    plain = re.sub(r"(?ms)^[ \t]{0,3}```(?!`)[^\n]*\n.*?^[ \t]{0,3}```(?!`)[ \t]*\r?$", " ", text)
    plain = strip_markup(plain)
    out = []
    for sentence in re.split(r"(?<=[.!?])\s+", plain):
        if re.search(pattern, sentence, re.I) and 25 <= len(sentence) <= 300:
            out.append(sentence)
        if len(out) >= limit:
            break
    return out

def split_chunks(text: str, section_title: str) -> list[tuple[str, str]]:
    # Locate headings only outside fenced blocks. Shell comments and config-file
    # comments inside fences commonly begin with '#', but are not Markdown.
    matches: list[tuple[int, int, str]] = []
    offset = 0
    in_fence = False
    heading_re = re.compile(r"^(#{1,3})\s+(.+?)\s*$")
    for line in text.splitlines(keepends=True):
        if re.match(r"^[ \t]{0,3}```(?!`)", line):
            in_fence = not in_fence
        elif not in_fence:
            m = heading_re.match(line.rstrip("\r\n"))
            if m:
                matches.append((offset, offset + len(line.rstrip("\r\n")), m.group(2)))
        offset += len(line)
    chunks = []
    for i, m in enumerate(matches):
        title = clean_title(m[2])
        if i == 0 and norm(title) == norm(section_title):
            continue
        end = matches[i + 1][0] if i + 1 < len(matches) else len(text)
        body = text[m[1]:end].strip()
        chunks.append((title, body))
    return chunks

def category_for(module_slug: str, section: str, title: str, body: str) -> str:
    blob = " ".join([section, title, body[:1200]]).lower()
    if re.search(r"active directory|kerberoast|bloodhound|dcsync|domain trust|llmnr|ntds|rubeus|powerview", blob):
        return "Active Directory"
    if module_slug in {"sql-injection-fundamentals", "sqlmap-essentials"}:
        return "Web Attacks"
    if re.search(r"mysql|mssql|postgres|oracle|xp_cmdshell|linked server", blob) and module_slug in {"footprinting", "attacking-common-services"}:
        return "Databases"
    if re.search(r"lateral movement|psexec|wmiexec|winrm|evil-winrm", blob) and module_slug == "attacking-enterprise-networks":
        return "Post Exploitation / Lateral Movement"
    return MODULE_CATEGORY.get(module_slug, "Operational Tooling")

def canonical_name(section: str, title: str) -> str:
    for candidate in (title, section):
        key = norm(candidate)
        if key in CANONICAL:
            return CANONICAL[key]
    if GENERIC.match(title) or len(title) < 5:
        return f"{section} — {title}"
    return title

def infer_meta(t: Technique, blob: str) -> None:
    lower = blob.lower()
    metadata_text = re.sub(r"https?://\S+", " ", lower)
    if re.search(r"\bwindows\b|powershell|cmd\.exe|active directory|ntlm|kerberos", metadata_text): t.os.add("Windows")
    if re.search(r"\blinux\b|bash|/etc/|/bin/|sudo|suid", metadata_text): t.os.add("Linux")
    if re.search(r"web|http|xss|xxe|sql injection|upload|lfi|rfi|tomcat|jenkins", metadata_text): t.os.add("Cross-platform")
    for service, ports in PORTS.items():
        if re.search(rf"\b{re.escape(service)}\b", metadata_text):
            t.services.add(service.upper() if service in {"ftp","ssh","smtp","dns","http","https","pop3","rpc","nfs","ntp","imap","snmp","ldap","smb","rdp"} else service)
            t.ports.update(ports.split(","))
    for tool in TOOLS:
        if re.search(rf"(?<![\w-]){re.escape(tool)}(?![\w-])", lower): t.tools.add(tool)
    words = [w for w in re.findall(r"[a-z][a-z0-9_-]{2,}", metadata_text) if ACTION.fullmatch(w)]
    t.tags.update(words[:30])
    t.tags.update(s.lower() for s in t.services)

def dedupe(items):
    seen, out = set(), []
    for x in items:
        k = json.dumps(asdict(x), sort_keys=True) if hasattr(x, "__dataclass_fields__") else str(x)
        if k not in seen:
            seen.add(k); out.append(x)
    return out

def source_blocks(body: str) -> tuple[list[str], list[str]]:
    fences = extract_fences(body)
    enum = []
    exploit = []
    # The heading context preceding each block determines its operational bucket.
    for fence in fences:
        pos = body.find(fence)
        context = strip_markup(body[max(0, pos-500):pos]).lower()
        if re.search(r"enumerat|discover|identify|check|scan|list|find|verify|fingerprint|recon", context):
            enum.append(fence)
        else:
            exploit.append(fence)
    if not exploit and enum:
        exploit = enum[-1:]
    return enum, exploit

def build_registry(modules: list[dict]) -> tuple[dict[str, Technique], dict]:
    registry: dict[str, Technique] = {}
    manifest = {"modules": [], "sections": [], "excluded_sections": []}
    for mod in modules:
        module_name, module_slug = mod["name"], mod["slug"]
        files = sorted((DUMP / module_slug / "sections").glob("*.md"))
        manifest["modules"].append({"name": module_name, "slug": module_slug, "sections": len(files)})
        module_records = []
        for path in files:
            text = path.read_text(encoding="utf-8")
            first = re.search(r"(?m)^#\s+(.+?)\s*$", text)
            section = clean_title(first.group(1)) if first else path.stem
            manifest["sections"].append({"module": module_name, "section": section, "file": str(path.relative_to(ROOT)), "sha256": hashlib.sha256(text.encode()).hexdigest()})
            if module_slug in SKIP_EXTRACT_MODULES:
                manifest["excluded_sections"].append({"module": module_name, "section": section, "reason": "Inspected but intentionally excluded: process/reporting material, not an attack technique"})
                continue
            candidates = []
            section_associated: set[str] = set()
            for title, body in split_chunks(text, section):
                fences = extract_fences(body)
                score = bool(fences) and bool(ACTION.search(title + " " + body[:1600]))
                title_action = bool(ACTION.search(title)) and not NON_ACTION.match(title)
                if (score or title_action) and not NON_ACTION.match(title):
                    candidates.append((title, body))
            if not candidates:
                all_fences = extract_fences(text)
                if all_fences and ACTION.search(section) and not NON_ACTION.match(section):
                    candidates = [(section, text)]
                else:
                    manifest["excluded_sections"].append({"module": module_name, "section": section, "reason": "No actionable command/payload subsection detected"})
            for title, body in candidates:
                name = canonical_name(section, title)
                category = category_for(module_slug, section, title, body)
                # Named/canonical attacks merge across modules and categories;
                # contextual subsection titles remain category-scoped.
                key = norm(name) if name in set(CANONICAL.values()) else norm(name) + "|" + category
                if key not in registry:
                    registry[key] = Technique(name=name, category=category, subcategory=section)
                t = registry[key]
                if t.subcategory != section and section not in t.subcategory.split("; "):
                    t.subcategory += "; " + section
                t.aliases.extend(ALIASES.get(name, []))
                if norm(title) != norm(name): t.aliases.append(title)
                prereq = sentences(body, r"\brequire|\bmust\b|\bneed(?:ed)?\b|prerequisite|permission|privilege|credential|access to|enabled|reachable", 3)
                trigger = sentences(body, r"\bif\b|\bwhen\b|allow(?:s|ed)?|vulnerab|misconfig|discover|identify|find", 3)
                success = sentences(body, r"success|we can see|returns?|output|obtained|shell|logged in|authenticated|extracted|cracked|access", 3)
                problems = sentences(body, r"fail|error|issue|problem|blocked|disabled|signing|skew|escape|incorrect|wrong|cannot|can't|unable", 3)
                enum, exploit = source_blocks(body)
                t.prerequisites.extend(prereq)
                t.triggers.extend(trigger)
                t.success.extend(success)
                t.problems.extend(problems)
                t.detection.extend(enum)
                t.exploitation.extend(exploit)
                section_associated.update(enum)
                section_associated.update(exploit)
                t.sources.append(Source(module_name, module_slug, section, str(path.relative_to(ROOT))))
                infer_meta(t, " ".join([name, section, title, body]))
                module_records.append({"name": name, "category": category, "section": section, "source_file": str(path.relative_to(ROOT)), "commands": len(enum + exploit)})
            # Second command-block pass: retain any operational source fence not
            # captured by an actionable subsection boundary. This catches, for
            # example, a robots.txt payload or an SSH transition shown between
            # headings, without losing its parent source attribution.
            orphan_blocks = [b for b in extract_fences(text) if b not in section_associated]
            if orphan_blocks and candidates and ACTION.search(section + " " + text):
                name = f"{section} — Additional CPTS Example"
                category = category_for(module_slug, section, name, text)
                key = norm(name) + "|" + category
                if key not in registry:
                    registry[key] = Technique(name=name, category=category, subcategory=section)
                t = registry[key]
                if category in {"Reconnaissance", "Service Enumeration", "Operational Tooling"}:
                    t.detection.extend(orphan_blocks)
                else:
                    t.exploitation.extend(orphan_blocks)
                t.prerequisites.extend(sentences(text, r"\brequire|\bmust\b|\bneed(?:ed)?\b|prerequisite|permission|privilege|credential|access to|enabled|reachable", 3))
                t.triggers.extend(sentences(text, r"\bif\b|\bwhen\b|allow(?:s|ed)?|vulnerab|misconfig|discover|identify|find", 3))
                t.success.extend(sentences(text, r"success|we can see|returns?|output|obtained|shell|logged in|authenticated|extracted|cracked|access", 3))
                t.problems.extend(sentences(text, r"fail|error|issue|problem|blocked|disabled|signing|skew|escape|incorrect|wrong|cannot|can't|unable", 3))
                t.sources.append(Source(module_name, module_slug, section, str(path.relative_to(ROOT))))
                infer_meta(t, " ".join([name, section, text]))
                module_records.append({"name": name, "category": category, "section": section, "source_file": str(path.relative_to(ROOT)), "commands": len(orphan_blocks)})
        (EXTRACTED / f"{module_slug}.json").write_text(json.dumps(module_records, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        md = [f"# {module_name} — structured extraction", "", f"Source sections inspected: {len(files)}", ""]
        for rec in module_records:
            md += [f"## {rec['name']}", "", f"- Category: {rec['category']}", f"- CPTS Section: {rec['section']}", f"- Source: `{rec['source_file']}`", f"- Command/payload blocks associated: {rec['commands']}", ""]
        (EXTRACTED / f"{module_slug}.md").write_text("\n".join(md), encoding="utf-8")
    # Make contextual display headings unique without conflating same-named
    # Linux/Windows or service-specific techniques.
    groups = defaultdict(list)
    for t in registry.values(): groups[t.name].append(t)
    for shared_name, group in groups.items():
        if len(group) > 1:
            cat_counts = Counter(t.category for t in group)
            for t in group:
                qualifier = t.category if cat_counts[t.category] == 1 else t.subcategory.split("; ")[0]
                t.name = f"{shared_name} — {qualifier}"
    # Normalize and anchor after all merges.
    anchor_seen = Counter()
    for t in registry.values():
        t.aliases = dedupe([a for a in t.aliases if norm(a) != norm(t.name)])
        t.prerequisites = dedupe(t.prerequisites)
        t.triggers = dedupe(t.triggers)
        t.success = dedupe(t.success)
        t.problems = dedupe(t.problems)
        t.detection = dedupe(t.detection)
        t.exploitation = dedupe(t.exploitation)
        t.sources = dedupe(t.sources)
        base = "technique-" + slugify(t.name)
        anchor_seen[base] += 1
        t.anchor = base if anchor_seen[base] == 1 else f"{base}-{anchor_seen[base]}"
    return registry, manifest

def brief(items: list[str], fallback: str, limit=3) -> list[str]:
    return items[:limit] or [fallback]

def render_blocks(blocks: list[str], limit: int | None = None) -> str:
    use = blocks if limit is None else blocks[:limit]
    return "\n\n".join(use) if use else "_No distinct command block was present in this CPTS subsection; use the source-linked observations above._"

def render_main(registry: dict[str, Technique], manifest: dict, modules: list[dict]) -> str:
    bycat = defaultdict(list)
    for t in registry.values(): bycat[t.category].append(t)
    lines = [
        "# CPTS Attack Cheatsheet", "",
        "> Operational attack reference generated exclusively from the local CPTS dump. Commands and payloads are verbatim fenced blocks from the cited CPTS sections. No general-knowledge additions were introduced.", "",
        "## How to use", "",
        "Search by attack, alias, tool, protocol, port, privilege, or BloodHound edge in `CPTS_ATTACK_INDEX.md`. Replace CPTS lab placeholders (hosts, domains, users, passwords, paths, hashes, interfaces, and callback addresses) before use.", "",
        "# 0. Attack Index", "",
        "See [CPTS_ATTACK_INDEX.md](CPTS_ATTACK_INDEX.md) for the full alphabetical index and [CPTS_QUICK_REFERENCE.md](CPTS_QUICK_REFERENCE.md) for decision-point checklists.", "",
    ]
    for number, category in enumerate(CATEGORY_ORDER, 1):
        techniques = sorted(bycat.get(category, []), key=lambda x: x.name.lower())
        if not techniques: continue
        lines += [f"# {number}. {category}", ""]
        for t in techniques:
            lines += [f'<a id="{t.anchor}"></a>', f"## {t.name}", "",
                      f"Aliases: {', '.join(t.aliases) if t.aliases else '—'}  ",
                      f"Tags: {', '.join(sorted(t.tags)) if t.tags else '—'}  ",
                      f"Category: {t.category} / {t.subcategory}  ",
                      f"OS: {', '.join(sorted(t.os)) if t.os else 'Cross-platform / not specified'}  ",
                      f"Service: {', '.join(sorted(t.services)) if t.services else 'Not service-specific'}  ",
                      f"Ports: {', '.join(sorted(t.ports, key=lambda x: int(x))) if t.ports else 'Not fixed / not specified'}", "",
                      "### Remember this attack when", ""]
            for x in brief(t.triggers, f"The target behavior or access described in the cited `{t.subcategory}` section is present."):
                lines.append(f"- {x}")
            lines += ["", "### Prerequisites", ""]
            for x in brief(t.prerequisites, "Confirm the access, service configuration, and target-specific values shown in the cited CPTS source before running the commands."):
                lines.append(f"- {x}")
            lines += ["", "### Enumeration / Detection", "", render_blocks(t.detection), "",
                      "### Exploitation", "", render_blocks(t.exploitation), "",
                      "### What success looks like", ""]
            for x in brief(t.success, "The command returns the expected target data, authenticated access, execution, or shell shown in the cited CPTS example."):
                lines.append(f"- {x}")
            lines += ["", "### What to do next", "",
                      f"Validate the result → preserve any credentials/output → pivot to the next CPTS-linked enumeration or exploitation step in `{t.subcategory}` → re-enumerate with the gained access.", "",
                      "### Common problems / Why it fails", ""]
            for x in brief(t.problems, "CPTS did not state a distinct failure condition in this subsection; verify placeholders, reachability, permissions, syntax, and the cited source context."):
                lines.append(f"- {x}")
            lines += ["", "### Variants", ""]
            if t.aliases: lines.append("- " + ", ".join(t.aliases))
            else: lines.append("- No separately named variant was identified in the cited CPTS subsection.")
            lines += ["", "### Useful commands", "", render_blocks(dedupe(t.detection + t.exploitation), 4), "",
                      "### CPTS Sources", ""]
            for s in t.sources:
                lines += [f"- Module: {s.module}  ", f"  Section: {s.section}  ", f"  Source file: `{s.file}`"]
            lines.append("")
    # Coverage report is generated from the actual manifest/registry.
    contributed = defaultdict(set)
    for t in registry.values():
        for s in t.sources: contributed[s.module].add(t.name)
    zero = [m["name"] for m in modules if not contributed[m["name"]]]
    merged = sorted([t for t in registry.values() if len({s.module for s in t.sources}) > 1], key=lambda t: t.name.lower())
    lines += ["# Coverage Report", "", f"Modules inspected: {len(manifest['modules'])}/28  ",
              f"Sections inspected: {len(manifest['sections'])}/495  ",
              f"Unique attacks/techniques extracted: {len(registry)}", "",
              "## Modules contributing no unique attack technique", ""]
    lines += [f"- {x}" for x in zero] if zero else ["- None; each module contributed at least one operational enumeration/tooling/attack record."]
    lines += ["", "## Techniques merged from multiple modules", ""]
    if merged:
        for t in merged:
            lines.append(f"- {t.name}: {', '.join(sorted({s.module for s in t.sources}))}")
    else: lines.append("- None met the strict canonical-title merge key; related variants remain cross-searchable through aliases/tags.")
    lines += ["", "## Parsing exclusions", "",
              f"- {len(manifest['excluded_sections'])} inspected sections contained no actionable command/payload subsection under the extraction rules (typically theory, prevention, reporting, or assessment-only material). They remain recorded in `extracted/coverage_manifest.json`.", "",
              "## Integrity notes", "",
              "- Original files under `dump/` were read only.",
              "- Every technique above has at least one CPTS module, section, and source-file reference.",
              "- Fenced command/payload content was copied verbatim from source blocks; Markdown line endings and trailing fence whitespace may be normalized.",
              "- No `[EXTRA - NOT FROM CPTS]` material was added.", ""]
    return "\n".join(lines)

def decision_sections(registry: dict[str, Technique]) -> list[tuple[str, list[Technique]]]:
    ts = list(registry.values())
    def pick(pattern, cats=None, limit=18):
        found=[]
        for t in ts:
            blob=" ".join([t.name, t.subcategory, *t.aliases, *t.services, *t.tags])
            if re.search(pattern, blob, re.I) and (not cats or t.category in cats): found.append(t)
        return sorted(found, key=lambda x:x.name.lower())[:limit]
    return [
        ("I just got an IP", pick(r"nmap|host discovery|port scan|service enumer|recon", limit=16)),
        ("Port 21 — FTP", pick(r"\bftp\b", limit=14)),
        ("Port 22 — SSH", pick(r"\bssh\b", limit=14)),
        ("Port 25/465/587 — SMTP", pick(r"smtp|email", limit=14)),
        ("Port 53 — DNS", pick(r"\bdns\b|zone transfer|subdomain", limit=16)),
        ("Port 80/443 — Web", pick(r"http|web|directory fuzz|parameter fuzz|vhost", {"Web Attacks","Reconnaissance"}, 20)),
        ("Port 88 — Kerberos", pick(r"kerberoast|as-rep|kerberos|ticket", limit=18)),
        ("Port 111/2049 — NFS", pick(r"\bnfs\b", limit=12)),
        ("Port 161 — SNMP", pick(r"\bsnmp\b", limit=12)),
        ("Port 389/636 — LDAP", pick(r"\bldap\b", limit=14)),
        ("Port 445 — SMB", pick(r"\bsmb\b|psexec|ntlm|relay", limit=20)),
        ("I find MSSQL / MySQL / Oracle", pick(r"mssql|mysql|oracle|sql database|xp_cmdshell", limit=20)),
        ("I see XML input", pick(r"xxe|xml|dtd", limit=14)),
        ("I see a file/path parameter", pick(r"file inclusion|lfi|rfi|traversal|wrapper", limit=18)),
        ("I see a file upload", pick(r"upload", {"Web Attacks"}, 18)),
        ("I have a username/password", pick(r"credentialed|password spray|credential stuffing|remote management|smb|winrm", limit=20)),
        ("I have an NTLM hash", pick(r"pass-the-hash|pth|ntlm|mimikatz", limit=18)),
        ("I have SYSTEM", pick(r"lsass|sam|security|credential manager|mimikatz|hash|token|ticket|post-exploitation", limit=22)),
        ("I have root", pick(r"credential hunt|ssh key|password|hash|network|service|post-exploitation", limit=22)),
        ("I have a Linux shell but not root", pick(r"sudo|suid|capabilit|cron|path abuse|hijack|kernel|docker|lxd", {"Linux Privilege Escalation"}, 24)),
        ("I have a Windows shell but not SYSTEM", pick(r"seimpersonate|sedebug|takeownership|service|dll|uac|kernel|credential", {"Windows Privilege Escalation"}, 24)),
        ("I have a domain user", pick(r"bloodhound|powerview|kerberoast|password spray|acl|domain enumer|dcsync|trust", {"Active Directory"}, 28)),
        ("BloodHound shows an ACL edge", pick(r"genericall|genericwrite|writedacl|writeowner|force.change|acl abuse|group membership", {"Active Directory"}, 20)),
        ("I need to pivot", pick(r"forward|socks|chisel|sshuttle|rpivot|tunnel|netsh|socat", {"Pivoting / Tunneling"}, 24)),
        ("I need to transfer a file", pick(r"transfer|download|upload|certutil|powershell|scp|wget|curl|smb", {"File Transfer"}, 24)),
        ("I need a shell or TTY upgrade", pick(r"reverse shell|bind shell|interactive shell|web shell|payload", {"Shells"}, 22)),
    ]

def render_quick(registry: dict[str, Technique]) -> str:
    lines=["# CPTS Quick Reference", "", "> Decision-point reference. Every command below is copied from CPTS; replace lab placeholders before use. Follow the main-cheatsheet links for prerequisites, failure notes, and full sources.", ""]
    for title, techniques in decision_sections(registry):
        lines += [f"# {title}", "", "Think / try:", ""]
        if not techniques:
            lines.append("- No distinct CPTS technique was matched automatically; use the alphabetical index.")
        for t in techniques:
            lines.append(f"- [{t.name}](CPTS_ATTACK_CHEATSHEET.md#{t.anchor}) — {t.subcategory}")
            blocks=dedupe(t.detection+t.exploitation)
            if blocks:
                lines += ["", blocks[0], ""]
        lines.append("")
    return "\n".join(lines)

def index_keywords(t: Technique) -> set[str]:
    high_signal_tags = {"password", "hash", "token", "ticket", "relay", "injection", "upload", "traversal", "shell", "forward", "tunnel", "pivot", "acl", "certificate", "kerberos", "ntlm", "smb", "ldap", "sql", "xxe", "ssrf", "lfi", "rfi", "suid", "sudo", "capabilities"}
    keys={t.name, *t.aliases, *t.services, *t.tools, *t.ports, *(x for x in t.tags if x in high_signal_tags)}
    blob="\n".join([t.name, t.subcategory, *t.aliases, *t.detection, *t.exploitation])
    patterns=[r"Se[A-Z][A-Za-z]+Privilege", r"GenericAll|GenericWrite|WriteDACL|WriteOwner|ForceChangePassword|AddMember|DCSync", r"UF_DONT_REQUIRE_PREAUTH", r"xp_cmdshell", r"GetNPUsers(?:\.py)?", r"GetUserSPNs(?:\.py)?", r"KRB_[A-Z_]+|STATUS_[A-Z_]+", r"[A-Za-z0-9_.-]+\.exe", r"[A-Za-z][A-Za-z0-9_-]{2,}"]
    for pat in patterns[:-1]: keys.update(re.findall(pat, blob, re.I))
    # Keep high-signal command/tool tokens only.
    for tool in TOOLS:
        if re.search(rf"(?<![\w-]){re.escape(tool)}(?![\w-])", blob, re.I): keys.add(tool)
    return {k.strip() for k in keys if str(k).strip() and len(str(k).strip()) <= 80}

def render_index(registry: dict[str, Technique]) -> str:
    rows=[]
    for t in registry.values():
        for keyword in index_keywords(t): rows.append((keyword, t.name, t.category, t.anchor))
    rows=sorted(set(rows), key=lambda r:(r[0].lower(),r[1].lower()))
    lines=["# CPTS Attack Index", "", "Searchable mapping of attack names, aliases, tools, protocols, ports, privilege names, and high-signal edge terms to the main cheatsheet.", "", "| Keyword | Main Technique | Category |", "|---|---|---|"]
    for keyword,name,cat,anchor in rows:
        keyword=keyword.replace("|","\\|"); name=name.replace("|","\\|"); cat=cat.replace("|","\\|")
        lines.append(f"| {keyword} | [{name}](CPTS_ATTACK_CHEATSHEET.md#{anchor}) | {cat} |")
    return "\n".join(lines)+"\n"

def write_tsv(registry: dict[str, Technique]) -> None:
    fields=["Attack","Category","Subcategory","OS","Service","Ports","Prerequisites","Tools","Tags","CPTS Module","CPTS Section","Main Cheatsheet Anchor"]
    with (ROOT/"CPTS_ATTACKS.tsv").open("w",encoding="utf-8",newline="") as f:
        w=csv.DictWriter(f,fieldnames=fields,delimiter="\t",lineterminator="\n"); w.writeheader()
        for t in sorted(registry.values(),key=lambda x:(x.category,x.name.lower())):
            w.writerow({"Attack":t.name,"Category":t.category,"Subcategory":t.subcategory,"OS":"; ".join(sorted(t.os)) or "Not specified","Service":"; ".join(sorted(t.services)) or "Not service-specific","Ports":"; ".join(sorted(t.ports,key=lambda x:int(x))) if t.ports else "Not specified","Prerequisites":" | ".join(t.prerequisites[:5]) or "See cited CPTS source","Tools":"; ".join(sorted(t.tools)),"Tags":"; ".join(sorted(t.tags)),"CPTS Module":"; ".join(dict.fromkeys(s.module for s in t.sources)),"CPTS Section":"; ".join(dict.fromkeys(s.section for s in t.sources)),"Main Cheatsheet Anchor":"#"+t.anchor})

def validate(registry: dict[str, Technique], manifest: dict, modules: list[dict]) -> dict:
    headings=Counter(t.name for t in registry.values())
    duplicate_names=sorted(k for k,v in headings.items() if v>1)
    missing_sources=[t.name for t in registry.values() if not t.sources]
    source_fences=Counter()
    for sec in manifest["sections"]:
        text=(ROOT/sec["file"]).read_text(encoding="utf-8")
        source_fences.update(extract_fences(text))
    emitted=Counter()
    for t in registry.values(): emitted.update(dedupe(t.detection+t.exploitation))
    altered=[b for b in emitted if b not in source_fences]
    keyword_counts={k:0 for k in ["exploit","attack","abuse","enumerate","enumeration","privilege","escalation","credential","password","hash","token","ticket","relay","injection","upload","include","traversal","shell","forward","tunnel","pivot","delegate","ACL","certificate","Kerberos","NTLM","SMB","LDAP","SQL","XXE","SSRF","SSTI","LFI","RFI","SUID","sudo","capabilities"]}
    for sec in manifest["sections"]:
        text=(ROOT/sec["file"]).read_text(encoding="utf-8")
        for k in keyword_counts: keyword_counts[k]+=len(re.findall(re.escape(k),text,re.I))
    report={"modules_inspected":len(manifest["modules"]),"sections_inspected":len(manifest["sections"]),"unique_techniques":len(registry),"duplicate_attack_names":duplicate_names,"techniques_missing_sources":missing_sources,"altered_or_non_source_command_blocks":len(altered),"source_fenced_blocks":sum(source_fences.values()),"unique_source_fenced_blocks":len(source_fences),"emitted_unique_fenced_blocks":len(emitted),"keyword_second_pass_counts":keyword_counts,"excluded_sections":len(manifest["excluded_sections"]),"status":"PASS" if len(manifest["modules"])==28 and len(manifest["sections"])==495 and not duplicate_names and not missing_sources and not altered else "FAIL"}
    return report

def main() -> None:
    EXTRACTED.mkdir(exist_ok=True)
    with (ROOT/"modules.tsv").open(encoding="utf-8",newline="") as f: modules=list(csv.DictReader(f,delimiter="\t"))
    registry,manifest=build_registry(modules)
    (EXTRACTED/"coverage_manifest.json").write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    # Serializable merged registry for auditing and later refinement.
    serial=[]
    for t in sorted(registry.values(),key=lambda x:(x.category,x.name.lower())):
        d=asdict(t); d["os"]=sorted(t.os); d["services"]=sorted(t.services); d["ports"]=sorted(t.ports); d["tools"]=sorted(t.tools); d["tags"]=sorted(t.tags); serial.append(d)
    (EXTRACTED/"technique_registry.json").write_text(json.dumps(serial,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    (ROOT/"CPTS_ATTACK_CHEATSHEET.md").write_text(render_main(registry,manifest,modules),encoding="utf-8")
    (ROOT/"CPTS_QUICK_REFERENCE.md").write_text(render_quick(registry),encoding="utf-8")
    (ROOT/"CPTS_ATTACK_INDEX.md").write_text(render_index(registry),encoding="utf-8")
    write_tsv(registry)
    report=validate(registry,manifest,modules)
    (EXTRACTED/"validation_report.json").write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print(json.dumps(report,indent=2))

if __name__ == "__main__": main()
