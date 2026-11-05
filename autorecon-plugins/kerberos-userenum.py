from autorecon.plugins import ServiceScan
from autorecon.config import config
from shutil import which
import os, re

# Under sudo, PATH is reset to sudo's secure_path (no /usr/local/bin, no ~/.local/bin), so tools
# installed for the user (pipx NetExec, kerbrute) are not found. Append those directories; the
# change applies to every command AutoRecon starts from this process. Existing PATH order is kept.
_extra = ['/usr/local/bin'] + ([os.path.expanduser('~' + os.environ['SUDO_USER']) + '/.local/bin'] if os.environ.get('SUDO_USER') else [])
os.environ['PATH'] = os.pathsep.join(dict.fromkeys(os.environ.get('PATH', '').split(os.pathsep) + [d for d in _extra if os.path.isdir(d)]))

# Local addition 2026-11-04. Kerberos username enumeration with kerbrute (AS-REQ without
# pre-authentication data): tells which usernames exist without trying any password, so it does
# not add to badPwdCount; it does create 4768 events on the DC. --safe aborts if an account is
# reported locked. Domain: --global.domain, else LDAP RootDSE, else the NetExec SMB banner.
# Overlap with stock: nmap-kerberos runs krb5-enum-users only when --global.domain is given and
# with a short built-in list. This plugin adds: domain auto-detection, a large wordlist, --safe,
# a reusable valid-user list, and - only with --kerberos-user-enumeration.asrep (off by default since
# 2026-11-05: it obtains crackable hashes, an attack step) - an AS-REP check (impacket-GetNPUsers -no-pass, one request
# per known user: kerbrute hits plus names already saved by RID cycling / anonymous LDAP; no password)
# - stock AutoRecon has no AS-REP check. Domain is read from saved enum4linux-ng / LDAP output first.
# Output: *_kerbrute_userenum.txt, kerberos_valid_users.txt (one name per line),
#         kerberos_asrep_hashes.txt (hashcat mode 18200) when an account has no pre-auth.

def domain_from_rootdse(lines):
	for l in lines:
		m = re.match(r'^\s*defaultNamingContext:\s*(DC=.+?)\s*$', l, re.I)
		if m:
			return '.'.join(p.split('=', 1)[1] for p in m.group(1).split(',') if p.upper().startswith('DC='))
	return None

def domain_from_nxc(lines):
	for l in lines:
		m = re.search(r'\(domain:([A-Za-z0-9.-]+\.[A-Za-z]{2,})\)', l)
		if m:
			return m.group(1)
	return None

def valid_users(text):
	users = []
	for m in re.finditer(r'VALID USERNAME:\s+(\S+?)@', text):
		if m.group(1) not in users:
			users.append(m.group(1))
	return users

def asrep_hashes(text):
	return list(dict.fromkeys(re.findall(r'(\$krb5asrep\$\S+)', text)))

def domain_from_saved(scandir):
	# Domain already recorded by stock enum4linux-ng or the ldap-anonymous plugin: no extra traffic.
	import glob
	for f in glob.glob(os.path.join(scandir, '**', 'enum4linux-ng.txt'), recursive=True):
		m = re.search(r'^\s*DNS domain:\s*([A-Za-z0-9.-]+\.[A-Za-z]{2,})\s*$', open(f, errors='replace').read(), re.M)
		if m:
			return m.group(1)
	for f in glob.glob(os.path.join(scandir, '**', '*ldap_naming_context.txt'), recursive=True):
		d = domain_from_rootdse(open(f, errors='replace').read().splitlines())
		if d:
			return d
	return None

def known_names(scandir):
	import glob
	names = []
	for pat in ('smb_rid_users.txt', 'ldap_anonymous_usernames.txt'):
		for f in glob.glob(os.path.join(scandir, '**', pat), recursive=True):
			names += [l.strip() for l in open(f, errors='replace') if re.fullmatch(r'[A-Za-z0-9._-]{1,64}', l.strip())]
	return names

class KerberosUserEnum(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Kerberos User Enumeration'
		self.tags = ['default', 'safe', 'kerberos', 'active-directory', 'local-addition']

	def configure(self):
		self.add_option('wordlist', default='/usr/share/seclists/Usernames/Names/names.txt', help='Usernames to test. Default: %(default)s')
		self.add_option('threads', default='10', help='kerbrute threads. Default: %(default)s')
		self.add_true_option('asrep', help='Also request AS-REP hashes (impacket-GetNPUsers -no-pass) for the users found. Off by default: it retrieves crackable credential material, which is an attack step to run and document by hand. Default: %(default)s')
		self.match_service_name(['^kerberos', '^kerberos-sec'])
		self.run_once(True)

	def check(self):
		if which('kerbrute') is None:
			self.error('kerbrute not found in PATH (https://github.com/ropnop/kerbrute).')
			return False

	def manual(self, service, plugin_was_run):
		service.add_manual_commands('Kerberos follow-ups: AS-REP roasting check by hand (no password; users from kerbrute, RID cycling and anonymous LDAP are in kerberos_asrep_candidates.txt):', [
			'impacket-GetNPUsers DOMAIN/ -dc-ip {address} -usersfile users.txt -no-pass -format hashcat -outputfile asrep.txt',
			'kerbrute userenum -d DOMAIN --dc {address} --safe /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt   # larger list',
		])

	async def run(self, service):
		target = service.target
		domain = self.get_global('domain', default=None) or domain_from_saved(target.scandir)
		if not domain:
			_, out, _ = await service.execute('ldapsearch -x -o nettimeout=8 -H ldap://{address}:389 -s base -b "" defaultNamingContext 2>&1', outfile='{protocol}_{port}_kerberos_domain_rootdse.txt')
			domain = domain_from_rootdse(await out.readlines())
		if not domain and which('nxc'):
			_, out, _ = await service.execute('nxc smb {address} 2>&1', outfile='{protocol}_{port}_kerberos_domain_nxc.txt')
			domain = domain_from_nxc(await out.readlines())
		if not domain or not re.fullmatch(r'[A-Za-z0-9.-]+\.[A-Za-z]{2,}', domain):
			service.error('Kerberos user enumeration skipped: domain unknown. Rerun with --global.domain corp.local')
			return
		wordlist = self.get_option('wordlist')
		threads = str(int(self.get_option('threads')))
		_, out, _ = await service.execute('kerbrute userenum -d ' + domain + ' --dc {address} --safe -t ' + threads + ' ' + wordlist + ' 2>&1', outfile='{protocol}_{port}_kerbrute_userenum.txt')
		text = '\n'.join(await out.readlines())
		users = valid_users(text)
		scandir = target.scandir if config['no_port_dirs'] else os.path.join(target.scandir, service.protocol + str(service.port))
		with open(os.path.join(scandir, 'kerberos_valid_users.txt'), 'w') as fh:
			fh.write('\n'.join(users) + ('\n' if users else ''))
		hashes = []
		npu = which('impacket-GetNPUsers') or which('GetNPUsers.py')
		cands = list(dict.fromkeys(users + known_names(target.scandir)))   # + names from RID cycling / anonymous LDAP, if already saved
		if cands:
			with open(os.path.join(scandir, 'kerberos_asrep_candidates.txt'), 'w') as fh:
				fh.write('\n'.join(cands) + '\n')
		if cands and npu and self.get_option('asrep'):
			_, out, _ = await service.execute(os.path.basename(npu) + ' ' + domain + '/ -dc-ip {address} -no-pass -format hashcat -usersfile "' + os.path.join(scandir, 'kerberos_asrep_candidates.txt') + '" 2>&1', outfile='{protocol}_{port}_kerberos_asrep_check.txt')
			hashes = asrep_hashes('\n'.join(await out.readlines()))
		if hashes:
			with open(os.path.join(scandir, 'kerberos_asrep_hashes.txt'), 'w') as fh:
				fh.write('\n'.join(hashes) + '\n')
			service.info('{bred}Kerberos: ' + str(len(hashes)) + ' account(s) without pre-authentication{rst} -> kerberos_asrep_hashes.txt (hashcat -m 18200)')
		service.info('{byellow}Kerberos: ' + str(len(users)) + ' valid usernames{rst} for ' + domain)
