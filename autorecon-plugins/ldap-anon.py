from autorecon.plugins import ServiceScan
from autorecon.config import config
from shutil import which
import os, re

# Local addition 2026-11-04, reworked 2026-11-05 to add only what stock AutoRecon does not.
# Stock nmap-ldap already saves the RootDSE (ldap-rootdse) and the first 20 objects
# (ldap-search, maxobjects 20). This plugin:
#  1) reads only the naming context and DC host name (needed for step 2; small file);
#  2) if anonymous bind can read the directory, dumps ALL accounts with paging, including
#     the fields where passwords and hints are left (description, info, comment, userPassword),
#     plus computers (hosts behind a pivot) and group membership.
# Read-only; no credentials are tried.
# Output: *_ldap_naming_context.txt, *_ldap_anonymous_{users,computers,groups}.txt,
#         ldap_anonymous_usernames.txt (one account per line)

USER_ATTRS = 'sAMAccountName userPrincipalName uid cn description info comment userPassword unixUserPassword memberOf userAccountControl pwdLastSet'

def naming_context(lines):
	for key in ('defaultNamingContext', 'rootDomainNamingContext', 'namingContexts'):
		for l in lines:
			m = re.match(r'^\s*' + key + r':\s*(\S.*?)\s*$', l, re.I)
			if m and re.match(r'^(DC|O|OU)=', m.group(1), re.I):
				return m.group(1)
	return None

def accounts(lines):
	found = []
	for l in lines:
		m = re.match(r'^(?:sAMAccountName|uid):\s*(\S+)\s*$', l, re.I)
		if m and not m.group(1).endswith('$') and m.group(1) not in found:
			found.append(m.group(1))
	return found

class LdapAnon(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'LDAP Anonymous'
		self.tags = ['default', 'safe', 'ldap', 'local-addition']

	def configure(self):
		self.match_service_name('^ldap')

	def check(self):
		if which('ldapsearch') is None:
			self.error('ldapsearch not found (apt install ldap-utils).')
			return False

	def manual(self, service, plugin_was_run):
		service.add_manual_commands('LDAP with a credential (domain users can read most of the directory):', [
			'nxc ldap {address} -u USER -p PASS --users --groups --get-desc-users',
			'ldapsearch -x -H ldap://{address}:{port} -D USER@DOMAIN -w PASS -E pr=500/noprompt -b "DC=..." "(objectClass=user)" ' + USER_ATTRS,
		])

	async def run(self, service):
		secure = bool(service.secure) or service.port in (636, 3269)
		base = ('LDAPTLS_REQCERT=never ' if secure else '') + 'ldapsearch -x -o nettimeout=15 -H ' + ('ldaps' if secure else 'ldap') + '://{address}:{port} '
		_, stdout, _ = await service.execute(base + '-s base -b "" "(objectClass=*)" defaultNamingContext rootDomainNamingContext namingContexts dnsHostName 2>&1', outfile='{protocol}_{port}_ldap_naming_context.txt')
		dn = naming_context(await stdout.readlines())
		if not dn or not re.fullmatch(r'[A-Za-z0-9=,._ -]+', dn):
			return
		_, stdout, _ = await service.execute(base + '-E pr=500/noprompt -b "' + dn + '" "(|(objectClass=user)(objectClass=person)(objectClass=posixAccount))" ' + USER_ATTRS + ' 2>&1', outfile='{protocol}_{port}_ldap_anonymous_users.txt')
		lines = await stdout.readlines()
		users = accounts(lines)
		if not any(l.startswith('dn: ') for l in lines):
			return                      # anonymous bind cannot read the tree; nothing more to try
		await service.execute(base + '-E pr=500/noprompt -b "' + dn + '" "(objectClass=computer)" dNSHostName operatingSystem operatingSystemVersion 2>&1', outfile='{protocol}_{port}_ldap_anonymous_computers.txt')
		await service.execute(base + '-E pr=500/noprompt -b "' + dn + '" "(|(objectClass=group)(objectClass=posixGroup)(objectClass=groupOfNames))" cn member memberUid 2>&1', outfile='{protocol}_{port}_ldap_anonymous_groups.txt')
		if users:
			scandir = service.target.scandir if config['no_port_dirs'] else os.path.join(service.target.scandir, service.protocol + str(service.port))
			with open(os.path.join(scandir, 'ldap_anonymous_usernames.txt'), 'w') as fh:
				fh.write('\n'.join(users) + '\n')
		desc = sum(1 for l in lines if re.match(r'^(description|info|comment|userPassword|unixUserPassword):', l, re.I))
		service.info('{byellow}LDAP anonymous bind reads the directory: ' + str(len(users)) + ' accounts, ' + str(desc) + ' description/info/password fields{rst}')
