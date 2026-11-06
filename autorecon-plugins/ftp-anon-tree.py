from autorecon.plugins import ServiceScan
from autorecon.config import config
import asyncio, ftplib, os, re, ssl

# Local addition 2026-11-04. If anonymous FTP login works, record the WHOLE directory tree
# (names, sizes, dates) — Nmap's ftp-anon only lists the top folder. Listing only: nothing is
# downloaded or written on the target. Limits: depth 6, 3000 entries, 120 s.

MAX_DEPTH, MAX_ENTRIES, TIMEOUT = 6, 3000, 120

def _walk(host, port, secure):
	lines, count = [], 0
	ftp = ftplib.FTP_TLS(timeout=15) if secure else ftplib.FTP(timeout=15)
	if secure:
		ftp.context = ssl._create_unverified_context()
	ftp.connect(host, port)
	banner = ftp.getwelcome()
	for user, pw in (('anonymous', 'anonymous'), ('ftp', 'ftp')):
		try:
			ftp.login(user, pw)
			break
		except ftplib.error_perm:
			user = None
	if user is None:
		return [f'# Banner: {banner}', '# Anonymous login refused (anonymous / ftp).'], False
	if secure:
		ftp.prot_p()
	lines += [f'# Banner: {banner}', f'# Anonymous login ACCEPTED as {user!r}. PWD: {ftp.pwd()}', '']

	def ls(path, depth):
		nonlocal count
		if depth > MAX_DEPTH or count >= MAX_ENTRIES:
			return
		try:
			entries = list(ftp.mlsd(path, facts=['type', 'size', 'modify']))
			rows = [(n, f.get('type'), f.get('size', ''), f.get('modify', '')) for n, f in entries if n not in ('.', '..')]
		except ftplib.Error:
			raw = []
			try:
				ftp.retrlines('LIST ' + path, raw.append)
			except ftplib.Error as e:
				lines.append(f'{"  " * depth}[!] cannot list {path}: {e}')
				return
			rows = []
			for r in raw:
				dos = re.match(r'^(\d{2}-\d{2}-\d{2,4})\s+(\d{1,2}:\d{2}[AP]M)\s+(<DIR>|\d+)\s+(.+)$', r)   # IIS / MS-DOS style
				if dos:
					if dos.group(4) not in ('.', '..'):
						rows.append((dos.group(4), 'dir' if dos.group(3) == '<DIR>' else 'file', '' if dos.group(3) == '<DIR>' else dos.group(3), dos.group(1) + ' ' + dos.group(2)))
					continue
				parts = r.split(None, 8)
				if len(parts) == 9 and parts[8] not in ('.', '..'):
					rows.append((parts[8], 'dir' if r.startswith('d') else 'file', parts[4], ' '.join(parts[5:8])))
		for name, kind, size, mod in sorted(rows):
			count += 1
			full = (path.rstrip('/') + '/' + name) if path != '/' else '/' + name
			lines.append(f'{"  " * depth}{"[D] " if kind in ("dir", "cdir", "pdir") else "    "}{full}  {size}  {mod}'.rstrip())
			if kind == 'dir':
				ls(full, depth + 1)
	ls('/', 0)
	if count >= MAX_ENTRIES:
		lines.append(f'# Stopped at {MAX_ENTRIES} entries.')
	try:
		ftp.quit()
	except Exception:
		pass
	return lines, True

class FtpAnonTree(ServiceScan):

	def __init__(self):
		super().__init__()
		self.name = 'FTP Anonymous Tree'
		self.tags = ['default', 'safe', 'ftp', 'local-addition']

	def configure(self):
		self.match_service_name('^ftp(?!-data)')   # control channel only; ftp-data (20/tcp) never accepts a login

	def manual(self, service, plugin_was_run):
		service.add_manual_commands('Download an anonymous FTP tree only when a listed file is needed:', [
			'wget -m --no-passive-ftp ftp://anonymous:anonymous@{address}:{port}/  # or omit --no-passive-ftp',
		])

	async def run(self, service):
		target = service.target
		scandir = target.scandir if config['no_port_dirs'] else os.path.join(target.scandir, service.protocol + str(service.port))
		os.makedirs(scandir, exist_ok=True)
		out = os.path.join(scandir, f'{service.protocol}_{service.port}_ftp_anon_tree.txt')
		try:
			lines, ok = await asyncio.wait_for(asyncio.to_thread(_walk, target.ip or target.address, service.port, bool(service.secure)), TIMEOUT)
		except Exception as e:
			lines, ok = [f'# Error: {type(e).__name__}: {e}'], False
		with open(out, 'w') as fh:
			fh.write('\n'.join(lines) + '\n')
		if ok:
			service.info('{byellow}Anonymous FTP login accepted{rst} — tree saved to ' + out)
