from autorecon.plugins import Report
import glob, os, re
import xml.etree.ElementTree as ET

# Local addition 2026-11-04. Writes <target>/_triage.md: a one-page summary of what the scan
# found, built ONLY from files AutoRecon already saved (no network traffic). Read this first,
# then the files it points to. Findings are leads, not proof.

def _services(scandir):
	rows = {}
	for x in sorted(glob.glob(os.path.join(scandir, '**', 'xml', '*.xml'), recursive=True)):
		try:
			root = ET.parse(x).getroot()
		except Exception:
			continue
		for port in root.iter('port'):
			st = port.find('state')
			if st is None or 'open' not in st.get('state', ''):
				continue
			svc = port.find('service')
			key = (port.get('protocol'), int(port.get('portid')))
			info = {k: (svc.get(k, '') if svc is not None else '') for k in ('name', 'product', 'version', 'extrainfo', 'tunnel')}
			old = rows.get(key)
			if not old or len(' '.join(info.values())) > len(' '.join(old.values())):
				rows[key] = info
	return rows

def _read(path, limit=200000):
	try:
		with open(path, errors='replace') as fh:
			return fh.read(limit)
	except OSError:
		return ''

def _find(scandir, pattern):
	return sorted(glob.glob(os.path.join(scandir, '**', pattern), recursive=True))

# --- facts shared by the triage and SysReptor reports (same code in both plugins) ---
def smb_facts(sd):
	"""Host facts from stock outputs: enum4linux-ng (YAML-style lines) first, Nmap smb NSE second."""
	e4 = re.sub(r'\x1b\[[0-9;]*m', '', ''.join(_read(f) for f in _find(sd, 'enum4linux-ng.txt')))
	nm = ''.join(_read(f) for f in _find(sd, '*smb_nmap.txt'))
	def g(pat, txt):
		m = re.search(pat, txt, re.M | re.I)
		v = m.group(1).strip().strip("'\"") if m else ''
		return '' if v.lower() in ('', 'null', 'none') else v
	f = {
		'host': g(r'^\s*NetBIOS computer name:\s*(.+)$', e4) or g(r'^\|\s+NetBIOS computer name:\s*([^\\\s]+)', nm) or g(r'^\|\s+Computer name:\s*(\S+)', nm),
		'domain': g(r'^\s*DNS domain:\s*(.+)$', e4) or g(r'^\|\s+Domain name:\s*(\S+)', nm) or g(r'^\s*NetBIOS domain name:\s*(.+)$', e4),
		'fqdn': g(r'^\s*FQDN:\s*(.+)$', e4) or g(r'^\|\s+FQDN:\s*(\S+)', nm),
		'signing': '', 'smb1': '',
	}
	s = g(r'^\s*SMB signing required:\s*(\S+)', e4)
	if s:
		f['signing'] = 'required' if s.lower() == 'true' else 'not required'
	elif re.search(r'signing enabled and required', nm, re.I):
		f['signing'] = 'required'
	elif re.search(r'signing enabled but not required|message_signing: disabled', nm, re.I):
		f['signing'] = 'not required'
	v1 = g(r'^\s*SMB 1\.0:\s*(\S+)', e4)
	if v1:
		f['smb1'] = 'enabled' if v1.lower() == 'true' else 'disabled'
	elif re.search(r'^\|\s+NT LM 0\.12|smb-security-mode:', nm, re.M):
		f['smb1'] = 'enabled'
	return f

def null_shares(sd):
	"""Shares enum4linux-ng could map with a null session."""
	t = re.sub(r'\x1b\[[0-9;]*m', '', ''.join(_read(f) for f in _find(sd, 'enum4linux-ng.txt')))
	return [(s, 'READ' if l == 'OK' else 'map only') for s, l in re.findall(r'Testing share (\S+)\s*\n(?:(?!.*Testing share).*\n){0,4}?\s*\[\+\]\s*Mapping: OK, Listing: (\S+)', t) if s.upper() not in ('IPC$', 'PRINT$')]

def guest_shares(sd):
	out = []
	for f in _find(sd, '*nxc_smb_guest_shares.txt'):
		out += [(s, a.split()[0]) for s, a in re.findall(r'^\S+\s+\S+\s+\d+\s+\S+\s+(\S+)\s+((?:READ|WRITE)[^\n]*)$', _read(f), re.M) if s.upper() not in ('IPC$', 'PRINT$')]
	return out

def lines_of(sd, name):
	return [l.strip() for f in _find(sd, name) for l in _read(f).splitlines() if l.strip()]

def ldap_facts(sd):
	t = ''.join(_read(f) for f in _find(sd, '*ldap_naming_context.txt'))
	d = re.search(r'^defaultNamingContext:\s*(\S+)', t, re.M | re.I) or re.search(r'^namingContexts:\s*(\S+)', t, re.M | re.I)
	h = re.search(r'^dnsHostName:\s*(\S+)', t, re.M | re.I)
	users = ''.join(_read(f) for f in _find(sd, '*ldap_anonymous_users.txt'))
	notes = [(a, v.strip()) for a, v in re.findall(r'^(description|info|comment|userPassword|unixUserPassword)::?\s*(.+)$', users, re.M | re.I)]
	return {
		'dn': d.group(1) if d else '', 'dc': h.group(1) if h else '',
		'objects': len(re.findall(r'^dn: ', users, re.M)),
		'accounts': lines_of(sd, 'ldap_anonymous_usernames.txt'),
		'fields': notes,
		'computers': re.findall(r'^dNSHostName:\s*(\S+)', ''.join(_read(f) for f in _find(sd, '*ldap_anonymous_computers.txt')), re.M),
	}

def asrep_users(sd):
	return [re.sub(r'^\$krb5asrep\$\d+\$', '', h).split('@')[0].split(':')[0] for h in lines_of(sd, 'kerberos_asrep_hashes.txt')]
# --- end shared facts ---

class TriageReport(Report):

	def __init__(self):
		super().__init__()
		self.name = 'Triage Summary'
		self.tags = ['default', 'safe', 'report', 'local-addition']

	async def run(self, targets):
		for target in targets:
			sd = target.scandir
			out = os.path.join(os.path.dirname(sd.rstrip('/')), '_triage.md')
			L = [f'# Triage — {target.address}', '', 'Generated from saved AutoRecon output only. Leads, not proof.', '']

			svc = _services(sd)
			L += ['## Open services', '', '| Port | Service | Product / version |', '|---|---|---|']
			for (proto, port), s in sorted(svc.items(), key=lambda k: (k[0][0], k[0][1])):
				name = (s['tunnel'] + '/' if s['tunnel'] else '') + s['name']
				L.append(f"| {port}/{proto} | {name} | {' '.join(v for v in (s['product'], s['version'], s['extrainfo']) if v)} |")
			if not svc:
				L.append('| — | no open ports parsed | check scans/_full_tcp_nmap.txt |')
			if not any(p == 'udp' for p, _ in svc):
				L += ['', '> **UDP not covered.** AutoRecon scans UDP only as root. Run: `sudo nmap -sU -sV --top-ports 100 -oA scans/udp-top100 ' + target.address + '`']

			hits = []
			pat = _read(os.path.join(sd, '_patterns.log'))
			hits += [l.strip() for l in pat.splitlines() if l.strip()][:25]
			L += ['', '## Pattern matches (`scans/_patterns.log`)', ''] + ([f'- {h}' for h in hits] or ['- none'])

			ss = _read(os.path.join(sd, '_searchsploit_versions.txt'))
			n_ss = len([l for l in ss.splitlines() if re.search(r'\|\s*\S+\.(?:py|rb|c|txt|sh|pl|php|md|html|go|java|cpp|js)\b', l)])
			L += ['', '## Exploit-DB leads', '', f'- {n_ss} candidate entries in `scans/_searchsploit_versions.txt`' if ss else '- searchsploit report not present yet (see `scans/_searchsploit_versions.txt` after the run)']

			# SNMP: communities found by onesixtyone -> ready commands (the extended snmpwalk plugin uses "public" only).
			comms = set()
			for f in _find(sd, '*onesixtyone*.txt') + _find(sd, '*snmp_community_discovery.txt'):
				for l in _read(f).splitlines():
					m = re.match(r'^\S+\s+\[([^\]]+)\]', l)
					if m:
						comms.add(m.group(1))
			snmp_files = _find(sd, '*snmp_snmpwalk_extend_output.txt')
			if comms or snmp_files or any(p == 161 for _, p in svc):
				L += ['', '## SNMP', '']
				L.append('- Communities found by onesixtyone: ' + (', '.join(f'`{c}`' for c in sorted(comms)) or 'none recorded'))
				for c in sorted(comms - {'public'}):
					tag = re.sub(r'[^A-Za-z0-9._-]', '_', c)
					walked = _find(sd, f'*snmp_comm-{tag}_*.txt')
					if walked:
						ext = [l for f2 in walked if f2.endswith('_extend.txt') for l in _read(f2).splitlines() if 'STRING' in l]
						L.append(f'  - `{c}` walked automatically ({len(walked)} files, `*snmp_comm-{tag}_*.txt`)' + (f'; extend STRING lines: {len(ext)} **← read these**' if ext else ''))
					else:
						L.append(f'  - `{c}` not walked yet: `snmpbulkwalk -v2c -c {c} {target.address} .1 > snmp-full-{c}.txt`')
				for f in snmp_files:
					body = [l for l in _read(f).splitlines() if 'STRING' in l]
					L.append(f'- NET-SNMP-EXTEND output lines: {len(body)} (`{os.path.relpath(f, sd)}`)' + (' **← read these: often credentials**' if body else ''))

			for f in _find(sd, '*ftp_anon_tree.txt'):
				t = _read(f)
				if 'ACCEPTED' in t:
					n = len([l for l in t.splitlines() if l.strip() and not l.lstrip().startswith('#')])
					L += ['', '## FTP', '', f'- **Anonymous login accepted** — {n} entries listed in `{os.path.relpath(f, sd)}`']

			f = smb_facts(sd)
			smb = []
			for kind, sh in (('null', null_shares(sd)), ('guest', guest_shares(sd))):
				if sh:
					smb.append(f'- {kind} session share access: ' + ', '.join(f'`{n}` ({x})' for n, x in sh))
			rid = lines_of(sd, 'smb_rid_users.txt')
			if rid:
				smb.append(f'- **RID cycling listed {len(rid)} accounts** without credentials (`smb_rid_users.txt`): ' + ', '.join(f'`{u}`' for u in rid[:12]) + (' …' if len(rid) > 12 else ''))
			if smb or any(f.values()):
				L += ['', '## SMB', '']
				if any(f.values()):
					L.append('- ' + ', '.join(x for x in (f'host `{f["host"]}`' if f['host'] else '', f'domain `{f["domain"]}`' if f['domain'] else '', f'FQDN `{f["fqdn"]}`' if f['fqdn'] else '', f'signing {f["signing"]}' if f['signing'] else '', f'SMBv1 {f["smb1"]}' if f['smb1'] else '') if x) + ' (from enum4linux-ng / Nmap)')
					if f['signing'] == 'not required':
						L.append('- SMB signing not required: relay target if you capture a hash elsewhere')
				L += smb
				L.append('- Full null-session detail (users, groups, policy): `enum4linux-ng.txt`')

			for f in _find(sd, 'kerberos_valid_users.txt'):
				users = [u for u in _read(f).splitlines() if u.strip()]
				L += ['', '## Kerberos', '', f'- kerbrute confirmed {len(users)} usernames (`{os.path.relpath(f, sd)}`)' + (': ' + ', '.join(f'`{u}`' for u in users[:12]) + (' …' if len(users) > 12 else '') if users else '')]
				nopre = asrep_users(sd)
				if nopre:
					L.append('- **No pre-authentication: ' + ', '.join(f'`{u}`' for u in nopre) + '** — hashes in `kerberos_asrep_hashes.txt` (hashcat -m 18200)')
				elif users and _find(sd, '*_kerberos_asrep_check.txt'):
					L.append('- AS-REP check found no account without pre-authentication. Recheck with names from LDAP/RID cycling if those found more.')
				elif users:
					L.append('- AS-REP roasting not run automatically (attack step): run it by hand from `_manual_commands.txt` with `kerberos_asrep_candidates.txt`, and document it.')
			ld = ldap_facts(sd)
			if ld['dn'] or ld['dc'] or ld['objects']:
				L += ['', '## LDAP / AD', '', f'- Naming context `{ld["dn"] or "?"}`, DC `{ld["dc"] or "?"}` — add the DC FQDN to /etc/hosts; pass `--global.domain` on reruns']
				if ld['objects']:
					L.append(f'- **Anonymous bind reads the directory**: {ld["objects"]} account objects, {len(ld["accounts"])} usernames in `ldap_anonymous_usernames.txt`' + (f', {len(ld["computers"])} computers' if ld['computers'] else ''))
					for a, v in ld['fields'][:15]:
						L.append(f'  - {a}: `{v[:120]}`')
					if len(ld['fields']) > 15:
						L.append(f'  - … {len(ld["fields"]) - 15} more in `*_ldap_anonymous_users.txt`')

			mc = os.path.join(sd, '_manual_commands.txt')
			L += ['', '## Next', '', f'- Manual suggestions (not run): `{os.path.relpath(mc, os.path.dirname(sd))}`' if os.path.exists(mc) else '- No manual suggestions file.']
			with open(out, 'w') as fh:
				fh.write('\n'.join(L) + '\n')
