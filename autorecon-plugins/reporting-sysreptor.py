from autorecon.plugins import Report
from autorecon.config import config
import datetime, difflib, glob, hashlib, json, os, re, shlex, sys
import xml.etree.ElementTree as ET

# Local addition 2026-11-05. Report-ready enumeration text for the SysReptor
# "OffSec OSCP+ Exam Report v2.1" design, built only from files AutoRecon already saved:
#   <target>/_sysreptor.md / .json      -> finding fields: Target Name, IP Address, Service Enumeration
#   <output>/_sysreptor_overview.md / .json -> Methodologies: Information Gathering, Service Enumeration
# Paste the .md, or send the .json with:  sysreptor-push push --project "NAME" <output dir>
# Contains only what the scans observed; the access/escalation narrative stays yours.

REPO = 'https://github.com/grepmysanity/Autorecon-expansion-plugins'
PLUGINS = [
	('netexec-smb', 'NetExec null-session and guest RID cycling, guest share access'),
	('ftp-anonymous-tree', 'recursive anonymous FTP listing (Python ftplib, read-only)'),
	('ldap-anonymous', 'paged anonymous LDAP dump of accounts, computers and groups (ldapsearch)'),
	('kerberos-user-enumeration', 'kerbrute user enumeration (AS-REP request with Impacket GetNPUsers only when explicitly enabled)'),
	('snmp-discovered-community-walk', 'Net-SNMP walks with non-default communities found by onesixtyone'),
	('searchsploit-versions', 'offline searchsploit lookup of detected versions'),
	('triage-summary / sysreptor-overview', 'summaries of saved output; no network traffic'),
]

def citation():
	try:
		import importlib.metadata as md
		ver = ' ' + md.version('autorecon')
	except Exception:
		ver = ''
	rows = '\n'.join(f'| `{s}` | {d} |' for s, d in PLUGINS)
	try:
		mod = [n for n, _, st, _ in custom_files() if st.startswith('modified')]
	except Exception:
		mod = []
	if os.environ.get('AUTORECON_EXAM_CMD'):
		how = 'started through the custom `autorecon-exam` launcher'
	elif os.geteuid() == 0:
		how = 'run as root (`sudo autorecon`) so that UDP was scanned on every host,'
	else:
		how = 'run directly (`autorecon`)'
	return {'title': 'Tools and Custom Scripts', 'content':
		'<span id="tools-and-custom-scripts"></span>\n\n'
		f'Every host in scope was enumerated with **AutoRecon{ver}** (Tib3rius, GPL-3.0, <https://github.com/Tib3rius/AutoRecon>), '
		+ how + f' and customised with: the plugins published at <{REPO}>'
		+ (f', {len(mod)} modified stock plugin(s) (' + ', '.join(f'`{x}`' for x in mod) + ')' if mod else '')
		+ ' and changed configuration (exam-safety plugin exclusions, thread counts). The plugins run standard, publicly available enumeration tools '
		'and summarise their saved output; they perform no exploitation. Every command behind a reported result is listed '
		'under **Enumeration Commands** in the Service Enumeration section of each target, so every step can be reproduced '
		'without the plugins. The full source code of every custom or modified script, with SHA-256 hashes and the '
		'changes made to stock AutoRecon plugins, is reproduced in the appendix **Custom Tool Source Code**.\n\n| Plugin | Purpose |\n| ------- | ------- |\n' + rows + '\n\n'
		'Exploits and scripts used for initial access or privilege escalation are cited in the step where they were used '
		'(URL for unmodified public code; full modified code, the original URL and the changes for modified code).\n'}

def _stock_dirs():
	# Stock plugins of every AutoRecon install (the running one first): pipx for the user, Kali's apt
	# package under sudo. A plugin identical to any of them counts as stock.
	import autorecon
	homes = [os.path.expanduser('~')] + ([os.path.expanduser('~' + os.environ['SUDO_USER'])] if os.environ.get('SUDO_USER') else [])
	cands = [os.path.join(os.path.dirname(autorecon.__file__), 'default-plugins')]
	for h in homes:
		cands += sorted(glob.glob(os.path.join(h, '.local/share/pipx/venvs/autorecon/lib/python3*/site-packages/autorecon/default-plugins')))
	cands += sorted(glob.glob('/usr/lib/python3*/dist-packages/autorecon/default-plugins'))
	return [d for d in dict.fromkeys(cands) if os.path.isdir(d)]

def custom_files():
	"""(name, path, status, diff) for every plugin that is not byte-identical to stock AutoRecon, plus the launcher."""
	out, stocks = [], _stock_dirs()
	for f in sorted(glob.glob(os.path.join(config.get('plugins_dir') or '', '*.py'))):
		b = os.path.basename(f)
		mine = open(f, 'rb').read()
		refs = [os.path.join(d, b) for d in stocks if os.path.exists(os.path.join(d, b))]
		if not refs:
			out.append((b, f, 'custom plugin', ''))
		elif not any(open(r, 'rb').read() == mine for r in refs):
			ref = min(refs, key=lambda r: sum(1 for l in difflib.unified_diff(open(r, errors='replace').readlines(), mine.decode('utf-8', 'replace').splitlines(True)) if l[:1] in '+-'))
			d = ''.join(difflib.unified_diff(open(ref, errors='replace').readlines(), mine.decode('utf-8', 'replace').splitlines(True), 'stock/' + b, 'used/' + b))
			out.append((b, f, 'modified stock AutoRecon plugin', d))
	lp = os.environ.get('AUTORECON_EXAM_PATH')
	if lp and os.path.isfile(lp):
		out.append((os.path.basename(lp), lp, 'custom launcher script', ''))
	return out

def config_changes():
	"""(name, path, diff) for AutoRecon config files that differ from the stock ones, plus added wordlists."""
	import autorecon
	pkg = os.path.dirname(autorecon.__file__)
	cdir = config.get('config_dir') or os.path.dirname(config.get('config_file') or '')
	out = []
	for name in ('config.toml', 'global.toml'):
		mine, stock = os.path.join(cdir, name), os.path.join(pkg, name)
		if os.path.isfile(mine) and os.path.isfile(stock) and open(mine, 'rb').read() != open(stock, 'rb').read():
			d = ''.join(difflib.unified_diff(open(stock, errors='replace').readlines(), open(mine, errors='replace').readlines(), 'stock/' + name, 'used/' + name))
			out.append((name, mine, d))
	wl_stock = set(os.listdir(os.path.join(pkg, 'wordlists'))) if os.path.isdir(os.path.join(pkg, 'wordlists')) else set()
	wl_dir = os.path.join(config.get('data_dir') or '', 'wordlists')
	added = sorted(set(os.listdir(wl_dir)) - wl_stock) if os.path.isdir(wl_dir) else []
	return out, [(w, os.path.join(wl_dir, w)) for w in added]

def _fence(text):
	runs = [len(m) for m in re.findall(r'`+', text)]
	return '`' * max(3, (max(runs) + 1) if runs else 3)

def source_appendix():
	P = ['<span id="custom-tool-source-code"></span>', '', 'Full source code of every custom or modified script used for enumeration, reproduced exactly as it was run '
		'(OffSec requires the full code, commands and output of custom scripts and tools). Modified stock AutoRecon '
		'plugins also show their changes against the stock plugin as a diff.', '']
	cfg, added = config_changes()
	if cfg or added:
		P += ['**AutoRecon configuration changes** (settings, not code; shown as diffs against the stock files):', '']
		for name, path, d in cfg:
			fd = _fence(d)
			P += [f'`{name}`, SHA-256 `{hashlib.sha256(open(path, "rb").read()).hexdigest()}`', '', fd + 'diff', d.rstrip(), fd, '']
		for w, path in added:
			n = sum(1 for _ in open(path, 'rb'))
			P += [f'Added wordlist `{w}` ({n} lines, SHA-256 `{hashlib.sha256(open(path, "rb").read()).hexdigest()}`): data only, used by suggested manual commands.', '']
		P += ['**Custom and modified code:**', '']
	for name, path, status, diff in custom_files():
		data = open(path, 'rb').read()
		P += [f'**{name}** — {status}, SHA-256 `{hashlib.sha256(data).hexdigest()}`', '']
		if diff:
			fd = _fence(diff)
			P += ['Changes against stock AutoRecon:', '', fd + 'diff', diff.rstrip(), fd, '']
		text = data.decode('utf-8', 'replace').rstrip()
		fc = _fence(text)
		P += [fc + ('python' if name.endswith('.py') else 'bash'), text, fc, '']
	return {'title': 'Custom Tool Source Code', 'content': '\n'.join(P)}

def invocation():
	cmd = os.environ.get('AUTORECON_EXAM_CMD')
	if cmd:
		return _home_short(cmd)
	argv = [os.path.basename(sys.argv[0])] + sys.argv[1:]
	return _home_short(('sudo ' if os.geteuid() == 0 else '') + ' '.join(shlex.quote(a) for a in argv))

def _home_short(text):
	# Show the operator's home as ~ (keeps the local account layout out of the report; also under sudo).
	homes = {os.path.expanduser('~')}
	if os.environ.get('SUDO_USER'):
		homes.add(os.path.expanduser('~' + os.environ['SUDO_USER']))
	for h in sorted(homes, key=len, reverse=True):
		if h and h != '/':
			text = text.replace(h.rstrip('/') + '/', '~/')
	return text

def invocations(sd):
	# Every AutoRecon start for this target, oldest first (reruns append; duplicates kept once).
	f = os.path.join(os.path.dirname(sd.rstrip('/')), '_autorecon_invocations.txt')
	seen = [l.strip() for l in _read(f).splitlines() if l.strip()]
	cur = invocation()
	if cur not in seen:
		seen.append(cur)
		with open(f, 'a') as fh:
			fh.write(cur + '\n')
	return seen

def _read(p, cap=300000):
	try:
		with open(p, errors='replace') as fh:
			return fh.read(cap)
	except OSError:
		return ''

def _find(sd, pattern):
	return sorted(glob.glob(os.path.join(sd, '**', pattern), recursive=True))

def udp_scanned(sd):
	"""True when any UDP scan ran: AutoRecon's own (as root: xml/_top_100_udp_nmap.xml or _custom_ports_udp_nmap.xml)
	or a separate scan saved as udp-top100.xml."""
	return bool(_find(sd, 'udp-top100.xml') or _find(sd, os.path.join('xml', '_top_100_udp_nmap.xml')) or _find(sd, os.path.join('xml', '_custom_ports_udp_nmap.xml')))

def ftp_files(text, limit=8):
	"""File names from an ftp_anon_tree listing (directories skipped)."""
	names = []
	for l in text.splitlines():
		s = l.strip()
		if not s or s.startswith('#') or s.startswith('[D]') or s.startswith('[!]'):
			continue
		names.append(s.split('  ')[0])
	return names[:limit], len(names)

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
	def ldif(name):
		# Join LDIF continuation lines (older runs wrapped at 76 chars) and decode base64 (attr::) values.
		import base64
		text = re.sub(r'\n (?=\S)', '', ''.join(_read(f) + '\n' for f in _find(sd, name)))
		out = []
		for a, b64, v in re.findall(r'^([A-Za-z][\w-]*):(:?)\s*(.*)$', text, re.M):
			if b64:
				try:
					v = base64.b64decode(v).decode('utf-8', 'replace')
				except Exception:
					pass
			out.append((a, v.strip()))
		return out
	users = ldif('*ldap_anonymous_users.txt')
	keep = ('description', 'info', 'comment', 'userpassword', 'unixuserpassword')
	return {
		'dn': d.group(1) if d else '', 'dc': h.group(1) if h else '',
		'objects': len({v for a, v in users if a.lower() == 'dn'}),
		'accounts': list(dict.fromkeys(lines_of(sd, 'ldap_anonymous_usernames.txt'))),
		'fields': list(dict.fromkeys((a, v) for a, v in users if a.lower() in keep and v)),
		'computers': list(dict.fromkeys(v for a, v in ldif('*ldap_anonymous_computers.txt') if a.lower() == 'dnshostname')),
	}

def asrep_users(sd):
	return [re.sub(r'^\$krb5asrep\$\d+\$', '', h).split('@')[0].split(':')[0] for h in lines_of(sd, 'kerberos_asrep_hashes.txt')]
# --- end shared facts ---

def services(sd):
	rows = {}
	xmls = _find(sd, os.path.join('xml', '*.xml')) + _find(sd, 'udp-top100.xml')
	for x in xmls:
		try:
			root = ET.parse(x).getroot()
		except Exception:
			continue
		for port in root.iter('port'):
			st = port.find('state')
			if st is None or st.get('state') != 'open':
				continue
			svc = port.find('service')
			key = (port.get('protocol'), int(port.get('portid')))
			info = {k: (svc.get(k, '') if svc is not None else '') for k in ('name', 'product', 'version', 'extrainfo', 'tunnel', 'hostname')}
			old = rows.get(key)
			if not old or len(''.join(info.values())) > len(''.join(old.values())):
				rows[key] = info
	return rows

def notes(sd):
	out = []
	cats = {}                       # which result categories appear -> used to pick the commands to show
	f = smb_facts(sd)
	host = f['host'] or None
	if any(f.values()):
		cats['smb'] = True
		bits = [f'host `{f["host"]}`' if f['host'] else '', f'domain `{f["domain"]}`' if f['domain'] else '',
			f'signing {f["signing"]}' if f['signing'] else '', f'SMBv1 {f["smb1"]}' if f['smb1'] else '']
		out.append('SMB: ' + ', '.join(b for b in bits if b) + '.')
	for kind, sh in (('null', null_shares(sd)), ('guest', guest_shares(sd))):
		if sh:
			cats['smb'] = True
			out.append(f'SMB {kind} session: ' + ', '.join(f'`{n}` ({a})' for n, a in sh) + '.')
	rid = lines_of(sd, 'smb_rid_users.txt')
	if rid:
		cats['smb'] = True
		out.append(f'SMB: RID cycling without credentials listed {len(rid)} accounts (' + ', '.join(f'`{u}`' for u in rid[:10]) + (' …' if len(rid) > 10 else '') + ').')
	for f in _find(sd, '*ftp_anon_tree.txt'):
		t = _read(f)
		if 'ACCEPTED' in t:
			n = len([l for l in t.splitlines() if l.strip() and not l.lstrip().startswith('#')])
			port = re.search(r'_(\d+)_ftp_anon_tree', f)
			cats.setdefault('ftp', []).append(port.group(1) if port else '21')
			names, nfiles = ftp_files(t)
			out.append(f'FTP{" (" + port.group(1) + ")" if port else ""}: anonymous login accepted; {n} entries listed' + (': ' + ', '.join(f'`{x}`' for x in names) + (' …' if nfiles > len(names) else '') if names else '') + '.')
	ld = ldap_facts(sd)
	if ld['dn'] or ld['dc']:
		cats['ldap'] = True
		out.append(f'LDAP: naming context `{ld["dn"] or "?"}`' + (f', DC `{ld["dc"]}`' if ld['dc'] else '') + '.')
		host = host or ld['dc'] or None
	if ld['objects']:
		cats['ldap'] = True
		out.append(f'LDAP: anonymous bind can read the directory ({ld["objects"]} account objects' + (f', {len(ld["computers"])} computer' + ('s' if len(ld['computers']) != 1 else '') if ld['computers'] else '') + (f'; {len(ld["fields"])} description/info/password attributes' if ld['fields'] else '') + ').')
	for f in _find(sd, 'kerberos_valid_users.txt'):
		users = [u for u in _read(f).splitlines() if u.strip()]
		if users:
			cats['kerberos'] = True
			out.append(f'Kerberos: {len(users)} valid usernames confirmed with kerbrute (' + ', '.join(f'`{u}`' for u in users[:10]) + (' …' if len(users) > 10 else '') + ').')
	nopre = asrep_users(sd)
	if nopre:
		cats['kerberos'] = True
		out.append('Kerberos: pre-authentication not required for ' + ', '.join(f'`{u}`' for u in nopre) + ' (AS-REP hash obtained without a password).')
	comms = set()
	for f in _find(sd, '*onesixtyone*.txt') + _find(sd, '*snmp_community_discovery.txt'):
		comms |= set(re.findall(r'^\s*\S+\s+\[([^\]]+)\]', _read(f), re.M))
	if comms:
		cats['snmp'] = True
		ext = sum(1 for f in _find(sd, '*extend*.txt') for l in _read(f).splitlines() if 'STRING' in l)
		out.append('SNMP: communities ' + ', '.join(f'`{c}`' for c in sorted(comms)) + (f'; NET-SNMP-EXTEND output readable ({ext} values).' if ext else '.'))
	return out, host, cats

# Commands shown in the report: only those that produced what the report states.
# Port scans come from the Nmap XML "args" (exact command line); enumeration commands come
# from AutoRecon's scans/_commands.log, filtered to the categories that appear in the results.
CMD_FILTERS = {
	'smb': [r'^enum4linux-ng\b', r'(^|/)nmap\b.*smb\*', r'^nxc smb\b.*(--rid-brute|--shares)'],
	'ldap': [r'(^|\s)ldapsearch\b'],
	'kerberos': [r'^kerbrute userenum\b', r'GetNPUsers'],
	'snmp': [r'^onesixtyone\b', r'^snmp(bulk)?walk\b.*\s(\.1|1\.3\.6\.1\.4\.1\.8072\.1\.3\.2)(\s|$)'],
}

def _tidy(cmd, sd):
	base = os.path.dirname(sd.rstrip('/'))
	cmd = cmd.replace(sd.rstrip('/') + '/', 'scans/').replace(base.rstrip('/') + '/', '')
	cmd = re.sub(r'^\S*/nmap(\s)', r'nmap\1', cmd).replace(' --privileged', '')
	return re.sub(r'\s+2>&1\s*$', '', cmd).strip()

def commands(address, sd, cats):
	out, seen = [], set()
	def add(c):
		c = _home_short(c) if c else c
		if c and c not in seen:
			seen.add(c); out.append(c)
	add('# enumeration started with (custom launcher / AutoRecon; source code in the appendix):')
	for c in invocations(sd):
		add(c)
	add('# commands run by AutoRecon behind the results above:')
	scans = [x for x in _find(sd, os.path.join('xml', '_*.xml'))] + _find(sd, 'udp-top100.xml')
	for x in scans:
		try:
			args = ET.parse(x).getroot().get('args', '')
		except Exception:
			continue
		c = _tidy(args, sd)
		if c and re.search(r'(^|\s)-sU(\s|$)', c) and not c.startswith('sudo '):
			c = 'sudo ' + c                      # UDP scans need root
		add(c)
	logged = [c.strip() for c in _read(os.path.join(sd, '_commands.log')).split('\n\n') if c.strip()]
	for cat, pats in CMD_FILTERS.items():
		if cat in cats:
			for c in logged:
				if any(re.search(p, c) for p in pats):
					add(_tidy(c, sd))
	for port in cats.get('ftp', []):
		add('# anonymous FTP tree: listed in-process by the ftp-anonymous-tree plugin (Python ftplib); reproduce with standard tools:')
		add(f'wget -r -l 6 --spider -nd --no-verbose ftp://anonymous:anonymous@{address}:{port}/')
	return out

def target_block(address, sd):
	svc = services(sd)
	tcp = ', '.join(str(p) for (pr, p) in sorted(svc) if pr == 'tcp') or '—'
	udp = ', '.join(str(p) for (pr, p) in sorted(svc) if pr == 'udp') or ('not scanned' if not udp_scanned(sd) else '—')
	L = ['**Port Scan Results**', '', '| IP Address | Ports Open |', '| ------- | ------- |', f'| {address} | **TCP:** {tcp} **UDP:** {udp} |', '']
	if svc:
		L += ['**Service Details**', '', '| Port | Service | Product / Version |', '| ------- | ------- | ------- |']
		for (pr, p), s in sorted(svc.items()):
			name = (s['tunnel'] + '/' if s['tunnel'] else '') + s['name']
			L.append(f"| {p}/{pr} | {name or '—'} | {' '.join(v for v in (s['product'], s['version'], s['extrainfo']) if v) or '—'} |")
		L.append('')
	obs, host, cats = notes(sd)
	if obs:
		L += ['**Enumeration Results**', ''] + [f'* {o}' for o in obs] + ['']
	cmds = commands(address, sd, cats)
	if cmds:
		L += ['**Enumeration Commands**', '', '```bash'] + cmds + ['```', '',
			'Custom scripts used here are cited in [Tools and Custom Scripts](#tools-and-custom-scripts); their full source code is in '
			'the appendix [Custom Tool Source Code](#custom-tool-source-code) (once per report).', '']
	return '\n'.join(L).rstrip() + '\n', svc, host

class SysreptorReport(Report):

	def __init__(self):
		super().__init__()
		self.name = 'SysReptor Overview'
		self.tags = ['default', 'safe', 'report', 'local-addition']

	async def run(self, targets):
		stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
		for target in targets:
			sd = target.scandir
			base = os.path.dirname(sd.rstrip('/'))
			md, svc, host = target_block(target.address, sd)
			ports = {p for (_, p) in svc}
			data = {
				'schema': 1, 'generated_utc': stamp, 'ip': target.address,
				'title': host or target.address,
				'target_type_guess': 'activedirectoryset' if ({88, 389} <= ports or 3268 in ports) else 'independent',
				'tcp': sorted(p for (pr, p) in svc if pr == 'tcp'), 'udp': sorted(p for (pr, p) in svc if pr == 'udp'),
				'udp_scanned': udp_scanned(sd) or any(pr == 'udp' for (pr, _) in svc),
				'serviceenum': md,
				'citation': citation(),
				'appendix': [citation(), source_appendix()],
			}
			with open(os.path.join(base, '_sysreptor.json'), 'w') as fh:
				json.dump(data, fh, indent=1)
			with open(os.path.join(base, '_sysreptor.md'), 'w') as fh:
				fh.write(f'<!-- SysReptor (OffSec OSCP+ v2.1) finding fields for {target.address}. Generated {stamp} from AutoRecon output. -->\n\n'
					f'Target Name: {data["title"]}\nIP Address: {target.address}\nTarget Type (guess): {data["target_type_guess"]}\n\n'
					'--- Service Enumeration (paste into the finding field) ---\n\n' + md)
		self.overview(config['output'], stamp)

	@staticmethod
	def overview(outdir, stamp):
		items = []
		for f in sorted(glob.glob(os.path.join(outdir, '*', '_sysreptor.json'))):
			try:
				items.append(json.load(open(f)))
			except Exception:
				continue
		if not items:
			return
		ips = [i['ip'] for i in items]
		info = '**Exam Network:**\n' + '\n'.join(f'* {ip}' for ip in ips) + '\n'
		udp_all = all(i.get('udp_scanned', True) for i in items)
		udp_any = any(i.get('udp_scanned', True) for i in items)
		udp_txt = ' and a top-100 UDP scan' if udp_all else (' and, where noted, a top-100 UDP scan' if udp_any else '; UDP was not scanned')
		enum = ('Each target was scanned with AutoRecon (all TCP ports, service and version detection, per-service enumeration)'
			+ udp_txt + '.\n\n| IP Address | Ports Open |\n| ------- | ------- |\n'
			+ '\n'.join(f"| {i['ip']} | **TCP:** {', '.join(map(str, i['tcp'])) or '—'} **UDP:** {', '.join(map(str, i['udp'])) or ('—' if i.get('udp_scanned', True) else 'not scanned')} |" for i in items) + '\n')
		data = {'schema': 1, 'generated_utc': stamp, 'targets': ips, 'infogathering': info, 'serviceenum': enum, 'citation': citation(), 'appendix': [citation(), source_appendix()]}
		with open(os.path.join(outdir, '_sysreptor_overview.json'), 'w') as fh:
			json.dump(data, fh, indent=1)
		with open(os.path.join(outdir, '_sysreptor_overview.md'), 'w') as fh:
			fh.write(f'<!-- SysReptor Methodologies fields, generated {stamp}. -->\n\n--- Information Gathering (target list) ---\n\n{info}\n--- Service Enumeration (overview) ---\n\n{enum}' + ''.join(f'\n--- Appendix: {e["title"]} ---\n\n{e["content"]}\n' for e in data['appendix']))
