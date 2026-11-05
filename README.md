# AutoRecon + SysReptor plugins (OSCP-style enumeration → report)

Eight [AutoRecon](https://github.com/Tib3rius/AutoRecon) plugins that add enumeration and report-ready output,
and a [SysReptor](https://github.com/Syslifters/sysreptor) plugin that imports that output (or raw Nmap XML)
into a report by drag and drop. Built for the **OffSec OSCP+ Exam Report v2.1** SysReptor design; works on the
SysReptor **Community** edition. Tested with AutoRecon 2.0.36 and SysReptor 2026.102.

Use only against systems you are authorized to test.

## AutoRecon plugins (`autorecon-plugins/`)

All are tagged `local-addition` (exclude them together with `--exclude-tags local-addition`). Each adds output that the
stock AutoRecon plugins do not produce; where stock already covers something (SMB host facts, null shares and password
policy via nmap-smb / enum4linux-ng, the LDAP RootDSE, SNMP community discovery) the plugins and reports read the stock
output instead of repeating it.

| File | Slug | Type | Automatic behaviour |
|---|---|---|---|
| `nxc-smb.py` | `netexec-smb` | ServiceScan | RID cycling with a null session; guest `--shares` and guest RID cycling; writes `smb_rid_users.txt` |
| `ftp-anon-tree.py` | `ftp-anonymous-tree` | ServiceScan | Recursive anonymous FTP listing (depth 6, 3000 entries, 120 s); downloads nothing |
| `ldap-anon.py` | `ldap-anonymous` | ServiceScan | Naming context, then (if anonymous bind reads the tree) a full paged dump of accounts incl. description/info/password fields, computers and groups |
| `kerberos-userenum.py` | `kerberos-user-enumeration` | ServiceScan | `kerbrute userenum --safe`; domain from `--global.domain`, LDAP RootDSE or the NetExec banner; writes `kerberos_valid_users.txt`, then AS-REP check (`impacket-GetNPUsers -no-pass`) → `kerberos_asrep_hashes.txt` |
| `snmp-community-walk.py` | `snmp-discovered-community-walk` | ServiceScan | Reuses the stock onesixtyone result (own run only if that plugin is excluded), then full / NET-SNMP-EXTEND / process-args / software / user walks for each community other than `public` |
| `reporting-searchsploit.py` | `searchsploit-versions` | Report | Offline `searchsploit --nmap` on the target's Nmap XML → `scans/_searchsploit_versions.txt` |
| `reporting-triage.py` | `triage-summary` | Report | One-page `<target>/_triage.md` built from saved output only |
| `reporting-sysreptor.py` | `sysreptor-overview` | Report | `<target>/_sysreptor.json/.md` (finding fields incl. **Enumeration Commands**) and `<output>/_sysreptor_overview.json/.md` |

Install: copy the files into AutoRecon's plugin directory (default `~/.local/share/AutoRecon/plugins/`) and check
with `autorecon --list`. Dependencies: `nxc` (NetExec), `ldapsearch`, `kerbrute`, Impacket (`GetNPUsers`), `onesixtyone`, Net-SNMP tools,
`searchsploit`.

Notes:
- AutoRecon only scans UDP when run as root; the SNMP plugins need udp/161 to be detected (or
  `--force-services udp/161/snmp`). Running AutoRecon with `sudo` uses root's plugin directory.
- `reporting-sysreptor.py` lists only the commands behind the results it reports: Nmap command lines from the Nmap
  XML `args`, other commands from AutoRecon's `scans/_commands.log`. The FTP tree is produced in-process, so it is
  given as a standard-tool reproduction (`wget -r -l 6 --spider -nd ftp://…`).

## SysReptor plugin (`sysreptor-plugin/autoreconimport/`)

Frontend-only plugin: adds **Plugins → AutoRecon / Nmap import** to each project. Drop `_sysreptor.json`,
`_sysreptor_overview.json`, Nmap `-oX` XML or whole folders (only those files are used). It previews the plan, then
writes through SysReptor's REST API with the user's session:

- **Notes** (default): new page tree “AutoRecon import <time> — <IPs>”; always additive.
- **Target findings**: one finding per IP (Target Name, IP Address, Target Type, Service Enumeration). Existing text
  is never replaced: a template field is filled, otherwise content goes into a block between invisible
  `<!-- autorecon:begin/end -->` markers that later imports refresh.
- **Methodologies**: Information Gathering target list and Service Enumeration table, accumulated by IP across
  imports (one scan per host, later hosts after a pivot).

Install (Docker deployment):

1. Copy `sysreptor-plugin/autoreconimport` to `<deploy>/custom_plugins/autoreconimport`.
2. Copy `sysreptor-deploy/docker-compose.override.yml.example` to `<deploy>/docker-compose.override.yml`
   (bind-mounts `custom_plugins` and sets `PLUGIN_DIRS=/app/plugins/,/app/custom_plugins/`).
3. `docker compose up -d app`, then add `autoreconimport` to **Enabled Plugins** (Settings) or `ENABLED_PLUGINS`.
4. After editing plugin files run `docker compose restart app` (static files are collected at startup).

`plugin_id` in `apps.py` is a fixed UUID; generate a new one (`python3 -m uuid`) if you fork it into a different plugin.

## Licence

AutoRecon is GPL-3.0 and these plugins use its plugin API.
