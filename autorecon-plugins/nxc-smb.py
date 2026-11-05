from autorecon.plugins import ServiceScan
from autorecon.config import config
from shutil import which
import os, re

# Under sudo, PATH is reset to sudo's secure_path (no /usr/local/bin, no ~/.local/bin), so tools
# installed for the user (pipx NetExec, kerbrute) are not found. Append those directories; the
# change applies to every command AutoRecon starts from this process. Existing PATH order is kept.
_extra = ['/usr/local/bin'] + ([os.path.expanduser('~' + os.environ['SUDO_USER']) + '/.local/bin'] if os.environ.get('SUDO_USER') else [])
os.environ['PATH'] = os.pathsep.join(dict.fromkeys(os.environ.get('PATH', '').split(os.pathsep) + [d for d in _extra if os.path.isdir(d)]))

# Local addition 2026-11-04, reworked 2026-11-05 to add only what stock AutoRecon does not:
#  - stock nmap-smb (smb-os-discovery, smb2-security-mode), enum4linux-ng -A (null-session
#    users/groups/shares/password policy) and smbclient -L already give host facts, null
#    shares and the password policy, so this plugin no longer repeats them.
#  - NEW 1: RID cycling (LSA SID lookups) with a null session. enum4linux-ng -A does not
#    include -R; it often lists users when SAMR user enumeration is denied.
#  - NEW 2: guest-account share access and RID cycling (stock tools only try null sessions;
#    smbmap is excluded by the exam launcher).
# Read-only; one null and at most two guest authentications (no real user's lockout budget).
# Output: *_nxc_smb_null_ridbrute.txt, *_nxc_smb_guest_shares.txt, *_nxc_smb_guest_ridbrute.txt,
#         smb_rid_users.txt (one account per line, machine accounts dropped)

def rid_accounts(lines):
	found = []
	for l in lines:
		m = re.search(r'\d+:\s+[^\\\s]+\\(\S+)\s+\(SidTypeUser\)', l)
		if m and not m.group(1).endswith('$') and m.group(1) not in found:
			found.append(m.group(1))
	return found

def logged_in(lines):
	return any(re.search(r'\[\+\]\s+\S*\\guest', l, re.I) for l in lines)

class NxcSMB(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'NetExec SMB'
		self.tags = ['default', 'safe', 'smb', 'local-addition']

	def configure(self):
		self.add_option('rid-max', default='4000', help='Highest RID to look up. Default: %(default)s')
		self.match_service_name(['^smb', '^microsoft\\-ds', '^netbios'])
		self.run_once(True)

	def check(self):
		if which('nxc') is None:
			self.error('nxc (NetExec) not found.')
			return False

	def manual(self, service, plugin_was_run):
		service.add_manual_commands('NetExec SMB follow-ups (pick the identity that worked; spider_plus downloads metadata, not files):', [
			'nxc smb {address} --port {port} -u guest -p \'\' -M spider_plus',
			'nxc smb {address} --port {port} -u USER -p PASS --shares --users --pass-pol --rid-brute',
		])

	async def run(self, service):
		rid = str(int(self.get_option('rid-max')))
		users = []
		_, out, _ = await service.execute('nxc smb {address} --port {port} -u \'\' -p \'\' --rid-brute ' + rid + ' 2>&1', outfile='{protocol}_{port}_nxc_smb_null_ridbrute.txt')
		users += rid_accounts(await out.readlines())
		_, out, _ = await service.execute('nxc smb {address} --port {port} -u \'guest\' -p \'\' --shares 2>&1', outfile='{protocol}_{port}_nxc_smb_guest_shares.txt')
		if logged_in(await out.readlines()):
			_, out, _ = await service.execute('nxc smb {address} --port {port} -u \'guest\' -p \'\' --rid-brute ' + rid + ' 2>&1', outfile='{protocol}_{port}_nxc_smb_guest_ridbrute.txt')
			users += [u for u in rid_accounts(await out.readlines()) if u not in users]
		if users:
			scandir = service.target.scandir if config['no_port_dirs'] else os.path.join(service.target.scandir, service.protocol + str(service.port))
			with open(os.path.join(scandir, 'smb_rid_users.txt'), 'w') as fh:
				fh.write('\n'.join(users) + '\n')
			service.info('{byellow}SMB RID cycling: ' + str(len(users)) + ' accounts{rst} -> smb_rid_users.txt')
