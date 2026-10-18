# Cheat Papers

Operational penetration-testing runbooks for authorized labs, HTB/CPTS-style machines, CTFs, and systems where testing permission exists.

## Start here

- [Linux privilege escalation](cheatsheets/LINUX_PRIVESC.md)
- [Windows privilege escalation](cheatsheets/WINDOWS_PRIVESC.md)
- [Web discovery to foothold](cheatsheets/WEB.md)
- [Active Directory](cheatsheets/AD.md)
- [Ports and services](cheatsheets/PORTS.md)
- [Shells and payloads](cheatsheets/SHELLS.md)
- [File transfer](cheatsheets/FILE_TRANSFER.md)
- [Documentation and reporting](cheatsheets/REPORTING.md)

The runbooks are designed to be followed from top to bottom during a machine. Large files use searchable headers such as `[SUDO]`, `[SYSTEMD SERVICES]`, `[SEIMPERSONATE]`, `[LFI]`, `[XXE]`, `[SSRF]`, and `[FINAL QA]`.

## Additional reference data

- [Full CPTS attack reference](reference/CPTS_ATTACK_CHEATSHEET.md)
- [Quick reference](reference/CPTS_QUICK_REFERENCE.md)
- [Searchable attack index](reference/CPTS_ATTACK_INDEX.md)
- [Machine-readable attack table](data/CPTS_ATTACKS.tsv)

## Generation

The scripts in [`tools/`](tools/) reproduce the generated references when run beside the expected local CPTS source layout. The raw source dump, PDFs, cookies, and fetched website assets are intentionally not included in this repository.

## Safety

Use only against systems you own or have explicit permission to test. Prefer read-only validation before commands that modify files, ACLs, services, tasks, registry settings, or system configuration.
