from autorecon.plugins import ServiceScan
from autorecon.config import config
from shutil import which
import asyncio, os, re

# Local addition 2026-11-04, reworked 2026-11-05 to avoid repeating stock AutoRecon.
# Community discovery is the stock onesixtyone plugin's job: this plugin waits for its output
# (*_snmp_onesixtyone.txt) and runs its own onesixtyone only if that plugin was excluded.
# NEW: the high-value walks repeated with every community OTHER than "public" (the extended
# snmpwalk plugin walks "public" only). Read-only GET/GETNEXT/GETBULK; nothing is written to the agent.
# Output per community: *_snmp_comm-<name>_<walk>.txt

WALKS = [
	('full', '.1'),
	('extend', '1.3.6.1.4.1.8072.1.3.2'),
	('process_params', '1.3.6.1.2.1.25.4.2.1.5'),
	('installed_software', '1.3.6.1.2.1.25.6.3.1.2'),
	('user_accounts', '1.3.6.1.4.1.77.1.2.25'),
]

def communities(lines):
	found = []
	for l in lines:
		m = re.match(r'^\s*\S+\s+\[([^\]]+)\]', l)
		if m and m.group(1) not in found:
			found.append(m.group(1))
	return found

class SnmpCommunityWalk(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'SNMP Discovered Community Walk'
		self.tags = ['default', 'safe', 'snmp', 'local-addition']

	def configure(self):
		self.add_option('community-strings', default='/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt', help='Community strings to try. Default: %(default)s')
		self.match_service_name('^snmp')
		self.run_once(True)

	def check(self):
		for tool in ('onesixtyone', 'snmpbulkwalk', 'snmpwalk'):
			if which(tool) is None:
				self.error(tool + ' not found.')
				return False

	async def stock_discovery(self, service):
		# Returns the stock onesixtyone output lines once that scan has finished, or None if it never ran.
		scandir = service.target.scandir if config['no_port_dirs'] else os.path.join(service.target.scandir, service.protocol + str(service.port))
		path = os.path.join(scandir, service.protocol + '_' + str(service.port) + '_snmp_onesixtyone.txt')
		pattern = 'onesixtyone .*' + re.escape(service.target.address) + '( |$)'
		for waited in range(0, 900, 5):
			proc = await asyncio.create_subprocess_exec('pgrep', '-f', pattern, stdout=asyncio.subprocess.DEVNULL)
			running = (await proc.wait()) == 0
			if os.path.exists(path) and not running:
				with open(path, errors='replace') as fh:
					return fh.read().splitlines()
			if not running and not os.path.exists(path) and waited >= 60:
				return None
			await asyncio.sleep(5)
		return None

	async def run(self, service):
		lines = await self.stock_discovery(service)
		if lines is None:
			_, out, _ = await service.execute('onesixtyone -p {port} -c ' + self.get_option('community-strings') + ' {address} 2>&1', outfile='{protocol}_{port}_snmp_community_discovery.txt')
			lines = await out.readlines()
		found = [c for c in communities(lines) if c != 'public']
		safe = [c for c in found if re.fullmatch(r'[A-Za-z0-9._@#%+=:-]{1,64}', c)]
		if not safe:
			return
		service.info('{byellow}SNMP communities besides public: ' + ', '.join(safe) + '{rst} — walking them')
		for c in safe:
			tag = re.sub(r'[^A-Za-z0-9._-]', '_', c)
			# Pick v2c (bulk, fast) if the agent answers it; otherwise v1.
			_, probe, _ = await service.execute("snmpget -v2c -t 3 -r 1 -c '" + c + "' {address}:{port} 1.3.6.1.2.1.1.1.0 2>&1", outfile='{protocol}_{port}_snmp_comm-' + tag + '_probe.txt')
			v2 = any('STRING' in l or '=' in l for l in await probe.readlines())
			walker = "snmpbulkwalk -v2c" if v2 else "snmpwalk -v1"
			for name, oid in WALKS:
				await service.execute(walker + " -t 5 -r 1 -c '" + c + "' {address}:{port} " + oid + ' 2>&1', outfile='{protocol}_{port}_snmp_comm-' + tag + '_' + name + '.txt')
