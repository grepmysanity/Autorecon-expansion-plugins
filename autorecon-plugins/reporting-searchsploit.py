from autorecon.plugins import Report
from autorecon.config import config
import glob, os, shutil, subprocess

# Added 2026-11-04 (local exam prep). Offline only: reads the Nmap XML that AutoRecon
# already wrote and asks the local Exploit-DB copy for matching product/version entries.
# It sends nothing to the target and runs no exploit. Results are LEADS to read and
# verify by hand (version match, prerequisites, OS), not findings.
#
# Output per target:  <target>/scans/_searchsploit_versions.txt
# Fallback if this plugin is missing/disabled:
#   searchsploit --disable-colour --nmap results/<ip>/scans/xml/_full_tcp_nmap.xml

class SearchsploitVersions(Report):

	def __init__(self):
		super().__init__()
		self.name = 'Searchsploit Versions'
		self.tags = ['default', 'safe', 'report']

	async def run(self, targets):
		exe = shutil.which('searchsploit')
		if exe is None:
			return
		for target in targets:
			xmls = sorted(set(glob.glob(os.path.join(target.scandir, 'xml', '*.xml'))))
			# Only Nmap runs that recorded service versions are useful here.
			xmls = [x for x in xmls if os.path.getsize(x) > 0 and 'version=' in open(x, errors='replace').read()]
			if not xmls:
				continue
			out = os.path.join(target.scandir, '_searchsploit_versions.txt')
			with open(out, 'w') as fh:
				fh.write('# Offline Exploit-DB lookup of service versions found by AutoRecon.\n')
				fh.write('# Leads only: confirm exact version, prerequisites and target OS before using anything.\n')
				fh.write('# Read an entry: searchsploit -x EDB-ID   Copy it: searchsploit -m EDB-ID\n\n')
				for xml in xmls:
					fh.write('=' * 78 + '\n# ' + os.path.basename(xml) + '\n' + '=' * 78 + '\n')
					fh.flush()
					try:
						res = subprocess.run([exe, '--disable-colour', '--nmap', xml], capture_output=True, text=True, timeout=300)
						fh.write(res.stdout)
						if res.stderr.strip():
							fh.write('\n[stderr]\n' + res.stderr)
					except subprocess.TimeoutExpired:
						fh.write('[!] searchsploit timed out on this file; run it manually.\n')
					fh.write('\n')
