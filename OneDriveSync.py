#!/usr/bin/python
# -*- coding: utf_8 -*-  
'''
OneDriveSync

Sync files in local directory to a One Drive directory.
'''
import codecs
import json
import math
import fnmatch
import sys
import os
import shutil
import logging
import datetime
import traceback
import pytz, tzlocal
import unicodedata
import threading
import time
import types
import urllib
import webbrowser
import FileLock

try:
	from ConfigParser import ConfigParser
except Exception:
	from configparser import ConfigParser

import onedrivesdk
from onedrivesdk.helpers import GetAuthCodeServer

LTZ = tzlocal.get_localzone()
SENC = sys.getdefaultencoding()
FENC = sys.getfilesystemencoding()
DT1970 = datetime.datetime.fromtimestamp(0)
SMALL = 2 * 1024 * 1024
LOG = None

if sys.version_info >= (3, 0):
	def unicode(s):
		return str(s)
	def raw_input(s):
		return input(s)
	def quote(s):
		return urllib.parse.quote(s)
else:
	def quote(s):
		return urllib.quote(s)

def normpath(s):
	return unicodedata.normalize('NFC', s)

LOCK = threading.Lock()
def uprint(s):
	with LOCK:
		try:
			print(s)
		except Exception:
			try:
				print(s.encode(SENC))
			except Exception:
				print(s.encode('utf-8'))

def tprint(i, s):
	n = datetime.datetime.now().strftime('%H:%M:%S ')
	uprint(u'%s %s %s' % (i, n, s))

def udebug(s):
	return
	tprint('-', s)
	if LOG:
		LOG.debug(s)

def uinfo(s):
	tprint('>', s)
	if LOG:
		LOG.info(s)

def uwarn(s):
	tprint('+', s)
	if LOG:
		LOG.warn(s)

def uerror(s):
	tprint('!', s)
	if LOG:
		LOG.error(s)

def uexception(ex):
	traceback.print_exc()
	if LOG:
		LOG.exception(ex)


def szstr(n):
	return "{:,}".format(n)

def tmstr(t):
	return t.strftime('%Y-%m-%d %H:%M:%S')

def mtstr(t):
	return LTZ.localize(t).astimezone(pytz.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')

def mtime(p):
	return datetime.datetime.fromtimestamp(os.path.getmtime(p)).replace(microsecond=0)

def ftime(dt):
	return tseconds(dt - DT1970)

def tseconds(td):
	return (td.seconds + td.days * 24 * 3600)

def touch(p, d = None):
	atime = ftime(datetime.datetime.now())
	mtime = atime if d is None else ftime(d)
	os.utime(p, ( atime, mtime ))

def mkpdirs(p):
	d = os.path.dirname(p)
	if not os.path.exists(d):
		os.makedirs(d)

def trimdir(p):
	if p == '':
		return p

	if p[-1] == os.path.sep:
		p = p[:-1]
	return unicode(p)

class Config:
	"""Singleton style/static initialisation wrapper thing"""
	def __init__(self):
		self.dict = ConfigParser()
		paths = (os.path.abspath('.onedrivesync.ini'), os.path.expanduser('~/.onedrivesync.ini'))
		for filename in paths:
			if os.path.exists(filename):
				uprint('using onedrivesync.ini file "%s"' % os.path.abspath(filename))
				fp = codecs.open(filename, "r", "utf-8")
				self.dict.readfp(fp)
				fp.close()
				break

		# debug
		self.debug_log = self.get('debug_log', '')
		
		# error
		self.error_log = self.get('error_log', '')
		
		# Location
		self.root_dir = trimdir(os.path.abspath(self.get('root_dir', '.')))

		# self.get('trash_dir', self.root_dir + '/.trash')
		self.trash_dir = self.get('trash_dir', '')
		if self.trash_dir:
			self.trash_dir = trimdir(os.path.abspath(self.trash_dir))

		# user webbrowser
		self.webbrowser = True if self.get('webbrowser', 'true') == 'true' else False 

		# max_file_size (100MB)
		self.max_file_size = int(self.get('max_file_size', '104857600'))

		# max retry
		self.max_retry = int(self.get('max_retry', '3'))
		
		# Threads
		self.max_threads = int(self.get('num_threads', '4'))

		# includes
		self.includes = json.loads(self.get('includes', '[]'))
		self.excludes = json.loads(self.get('excludes', '[]'))

		# GDrive API
		self.API_BASE_URL = "https://api.onedrive.com/v1.0/"
		self.OAUTH_SCOPE = ['wl.signin', 'wl.offline_access', 'onedrive.readwrite']
		self.REDIRECT_URI = 'http://localhost:8080'
		self.client_id = self.get('client_id', '19f839f9-69d9-4e6d-b841-bc39d0c241d8')
		self.client_secret = self.get('client_secret', '2U0NhMmsKo1iw1RW7fJpjgq')
		self.token_file = self.get('token_file', '.onedrivesync.token')

		if os.path.exists(self.token_file):
			self.last_sync = mtime(self.token_file)
		else:
			self.last_sync = DT1970

	def get(self, configparam, default=None):
		"""get the value from the ini file's default section."""
		defaults = self.dict.defaults()
		if configparam in defaults:
			return defaults[configparam]
		if not default is None:
			return default
		raise KeyError(configparam)


# global config
config = Config()

class OneDriveSession(onedrivesdk.session.SessionBase):
	def __init__(self,
				 token_type,
				 expires_in,
				 scope_string,
				 access_token,
				 client_id,
				 auth_server_url,
				 redirect_uri,
				 refresh_token=None,
				 client_secret=None):
		self.token_type = token_type
		self.expires_at = time.time() + int(expires_in)
		self.scope = scope_string.split(" ")
		self.access_token = access_token
		self.client_id = client_id
		self.auth_server_url = auth_server_url
		self.redirect_uri = redirect_uri
		self.refresh_token = refresh_token
		self.client_secret = client_secret

	def is_expired(self):
		"""Whether or not the session has expired
		Returns:
			bool: True if the session has expired, otherwise false
		"""
		# Add a 60 second buffer in case the token is just about to expire
		return self.expires_at < time.time() - 60

	def refresh_session(self, expires_in, scope_string, access_token, refresh_token):
		self.expires_at = time.time() + int(expires_in)
		self.scope = scope_string.split(" ")
		self.access_token = access_token
		self.refresh_token = refresh_token

	def save_session(self, **save_session_kwargs):
		path = save_session_kwargs["path"]
		
		with open(path, "w") as f:
			s = { "token_type": self.token_type,
					"expires_at": self.expires_at,
					"scope": ' '.join(self.scope),
					"access_token": self.access_token,
					"client_id": self.client_id,
					"auth_server_url": self.auth_server_url,
					"redirect_uri": self.redirect_uri,
					"refresh_token": self.refresh_token,
					"client_secret": self.client_secret }
			f.write(json.dumps(s))

	@staticmethod
	def load_session(**load_session_kwargs):
		path = load_session_kwargs["path"]
		
		with open(path) as f:
			c = json.loads(f.read())
			s = OneDriveSession(c["token_type"],
								0,
								c["scope"],
								c["access_token"],
								c["client_id"],
								c["auth_server_url"],
								c["redirect_uri"],
								c["refresh_token"],
								c["client_secret"])
			s.expires_at = c["expires_at"]
			return s


class OneDriveCredentials(object):
	def __init__(self):
		self.path = os.path.abspath(config.token_file)
		self.lock = None

	def _load_credentials(self, client):
		if os.path.exists(self.path):
			client.auth_provider.load_session(path=self.path)
			client.item(drive="me", id="root").get()
			return
		raise Exception('Token file %s not found' % self.path)

	def _save_credentials(self, client):
		client.auth_provider.save_session(path=self.path)
		touch(self.path, config.last_sync)

	def _lock_credentials(self):
		FileLock.lock(open(self.path))

	def _authenticate(self, client):
		auth_url = client.auth_provider.get_auth_url(config.REDIRECT_URI)

		# Ask for the code
		uprint('Paste this URL into your browser, approve the app\'s access.')
		uprint('Copy everything in the address bar after "code=", and paste it below.')
		uprint(auth_url)
		if config.webbrowser:
			webbrowser.open(auth_url)
		code = raw_input('Paste code here: ')
		
		client.auth_provider.authenticate(code, config.REDIRECT_URI, config.client_secret)

	def get_service(self):
		http_provider = onedrivesdk.HttpProvider()
		auth_provider = onedrivesdk.AuthProvider(
			http_provider=http_provider,
			session_type=OneDriveSession,
			client_id=config.client_id,
			scopes=config.OAUTH_SCOPE)
		
		client = onedrivesdk.OneDriveClient(config.API_BASE_URL, auth_provider, http_provider)

		try:
			self._load_credentials(client)
		except Exception as e:
			uinfo("Failed to load credentials, begin the OAuth process.")
			self._authenticate(client)
			self._save_credentials(client)

		try:
			self._lock_credentials()
		except Exception as e:
			uerror(str(e))
			raise Exception('Failed to lock %s' % self.path)

		return client

class OFile:
	def __init__(self, r = None, root = False):
		self.path = None
		self.parent = None
		self.action = None
		self.reason = ''

		if r:
			self.id = r.id
			self.mdate = self.to_date(r.file_system_info._prop_dict)

			self.name = r.name
			self.folder = r.folder

			if self.folder:
				self.size = 0
				self.url = None
			else:
				self.folder = False
				self.size = r.size
				self.url = r.web_url
				
			if r.parent_reference:
				if not root:
					self.parent = r.parent_reference.id
			else:
				self.parent = 'UNKNOWN'

	def to_date(self, d):
		if "lastModifiedDateTime" in d:
			t = d["lastModifiedDateTime"].replace("Z", "")
			s = t.find('.')
			if s > 0:
				t = t[0:s]
			md = datetime.datetime.strptime(t, "%Y-%m-%dT%H:%M:%S")
			return md.replace(tzinfo=pytz.utc).astimezone(LTZ).replace(tzinfo=None)
		else:
			return None

class Obj:
	pass

class OneDriveSync:
	def __init__(self, service):
		'''
		:param service: The service of get_service by OneDriveCredentials.
		:param target: The target folder to sync.
		'''
		self.service = service
		self.rfiles = {}
		self.rpaths = {}
		self.skips = []

	def exea(self, api, msg):
		auth = False
		cnt = 0
		while True:
			try:
				cnt += 1
				if auth:
					self.service.auth_provider.refresh_token()
					auth = True
				return api.execute()
			except Exception as e:
				if cnt <= config.max_retry:
					err = str(e)
					if "unauthenticated" in err:
						auth = True
					uwarn(err)
					uwarn("Failed to %s, retry %d" % (msg, cnt))
					time.sleep(3)
				else:
					uerror("Failed to %s" % msg)
					uexception(e)
					raise

	def print_files(self, paths):
		uprint("--------------------------------------------------------------------------------")

		tz = 0
		lp = ''
		ks = list(paths.keys())
		ks.sort()
		for n in ks:
			f = paths[n]
			tp = os.path.dirname(f.path)
			if tp != lp:
				lp = tp

			tz += f.size
			if f.folder:
				uprint(u"== %s ==" % (f.path))
			elif f.parent and f.parent != '/' and f.path[0] != '?':
				uprint(u"    %-40s [%11s] (%s)" % (f.name, szstr(f.size), tmstr(f.mdate)))
			else:
				uprint(u"%-44s [%11s] (%s)" % (f.path, szstr(f.size), tmstr(f.mdate)))

		uprint("--------------------------------------------------------------------------------")
		uprint("Total %s items [%s]" % (szstr(len(paths)), szstr(tz)))
	
	def print_updates(self, files):
		if files:
			uprint("--------------------------------------------------------------------------------")
			uinfo("Files to be synchronized:")
			for f in files:
				uprint(u"%s: %s [%s] (%s) %s" % (f.action, f.path, szstr(f.size), tmstr(f.mdate), f.reason))

	def print_skips(self, files):
		if files:
			uprint("--------------------------------------------------------------------------------")
			uprint("Skipped files:")
			for f in files:
				uprint(u"%s: %s [%s] (%s) %s" % (f.action, f.path, szstr(f.size), tmstr(f.mdate), f.reason))

	def unknown_files(self, unknowns):
		uprint("--------------------------------------------------------------------------------")

		tz = 0
		for f in unknowns.values():
			tz += f.size
			uprint(u"%s %s [%s] (%s)" % ('=' if f.folder else ' ', f.name, szstr(f.size), tmstr(f.mdate)))

		uprint("--------------------------------------------------------------------------------")
		uprint("Unknown %s items [%s]" % (szstr(len(unknowns)), szstr(tz)))
	
	def get(self, fid):
		r = self.service.item(drive="me", id=fid)
		uprint(str(r))
		
	def tree(self, verb = False):
		uinfo('Get remote folders ...')
		return self._list(True, verb)

	def list(self, verb = False, unknown = False):
		uinfo('Get remote files ...')
		return self._list(False, verb, unknown)

	def _alist(self, fid):
		def exef(a):
			return self.service.item(drive="me", id=fid).children.request(top=1000).get()

		items = []
		a = Obj()
		a.execute = types.MethodType(exef, a)
		r = self.exea(a, "children.get");
		items.extend(r)
		
		self._anext(r, items)
		return items

	def _anext(self, c, items):
		if not hasattr(c, "_next_page_link"):
			return
		
		sys.stdout.write(" .")
		sys.stdout.flush()

		def exef(a):
			return onedrivesdk.ChildrenCollectionRequest.get_next_page_request(c, self.service).get();
		
		a = Obj()
		a.execute = types.MethodType(exef, a)
		r = self.exea(a, "children.next");
		if r:
			items.extend(r)
			self._anext(r, items)
		
	def _rlist(self, files, unknowns, fid, path, lvl):
		if not self.accept_path(path):
			return

		sys.stdout.write("\r> " + path.ljust(78))
		sys.stdout.flush()

		items = self._alist(fid)
		for r in items:
#			uprint("-------------")
#			uprint(str(r))
			f = OFile(r, True if lvl == 0 else False)
			
			# ignore unarchived SHARED files
			if f.parent == 'UNKNOWN':
				unknowns[f.id] = f
				continue
			
			# ignore online docs
			if not f.folder and not f.url:
				unknowns[f.id] = f
				continue

			files[f.id] = f
			
			if f.folder:
				self._rlist(files, unknowns, f.id, path + '/' + f.name, lvl+1)
		
		if lvl == 0:
			sys.stdout.write("\n")
		
	def _list(self, folder, verb, unknown = False):
		files = {}
		unknowns = {}

		self._rlist(files, unknowns, "root", "", 0)
#		for f in files.itervalues():
#			if verb:
#				uprint("%s %s  %s" % (f.id, f.name, f.parent))

		self.rfiles = {}
		self.rpaths = {}
		if files:
			for k,f in files.items():
				if folder and not f.folder:
					continue
				
				p = self.get_path(files, f)
				if p[0] == '?':
					unknowns[f.id] = f
					continue
			
				if not self.accept_path(p):
					continue
				
				self.rfiles[f.id] = f
				self.rpaths[p] = f

			if verb:
				self.print_files(self.rpaths)

		if verb and unknown and unknowns:
			self.unknown_files(unknowns)

	def get_path(self, files, f):
		p = u'/' + f.name
		i = f
		while i.parent:
			i = files.get(i.parent)
			if i is None:
				p = u'?' + p
				break
			p = u'/' + i.name + p
		f.path = p
		f.npath = os.path.abspath(config.root_dir + p)
		return p

	def accept_path(self, path):
		"""
		Return if name matches any of the ignore patterns.
		"""
		if not path:
			return True
		
		if config.excludes:
			for pat in config.excludes:
				if fnmatch.fnmatch(path, pat):
					return False
		
		if config.includes:
			for pat in config.includes:
				if fnmatch.fnmatch(path, pat):
					return True
			return False

		return True

	"""
	get all files in folders and subfolders
	"""
	def scan(self, verbose = False):
		rootdir = config.root_dir

		uinfo('Scan local files %s ...' % rootdir)
		
		lpaths = {}
		for dirpath, dirnames, filenames in os.walk(rootdir, topdown=True, followlinks=True):
			# do not walk into unacceptable directory
			dirnames[:] = [d for d in dirnames if not d[0] == '.' and self.accept_path(os.path.normpath(os.path.join(dirpath, d))[len(rootdir):].replace('\\', '/'))]

			for d in dirnames:
				np = os.path.normpath(os.path.join(dirpath, d))
				rp = np[len(rootdir):].replace('\\', '/')
				if not self.accept_path(rp):
					continue

				of = OFile()
				of.folder = True
				of.name = d
				of.parent = os.path.dirname(rp)
				of.npath = np
				of.path = normpath(rp)
				of.size = 0
				of.mdate = mtime(np)
				lpaths[of.path] = of

			for f in filenames:
				if f[0] == '.':
					continue

				np = os.path.normpath(os.path.join(dirpath, f))
				rp = np[len(rootdir):].replace('\\', '/')
				if not self.accept_path(rp):
					continue

				of = OFile()
				of.folder = False
				of.name = f
				of.parent = os.path.dirname(rp)
				of.npath = np
				of.path = normpath(rp)
				of.size = os.path.getsize(np)
				of.mdate = mtime(np)
				ext = os.path.splitext(f)[1]
				lpaths[of.path] = of

		self.lpaths = lpaths
		
		if verbose:
			self.print_files(lpaths)


	"""
	find remote patch files
	"""
	def find_remote_patches(self):
		lps = []
		for lp,lf in self.lpaths.items():
			if lf.folder:
				continue

			# check patchable
			rf = self.rpaths.get(lp)
			if rf and lf.size == rf.size and math.fabs(tseconds(lf.mdate - rf.mdate)) > 2:
				lf.action = '^~'
				lf.reason = '| <> R:' + tmstr(rf.mdate)
				lps.append(lp)

		lps.sort()
		ufiles = [ ]
		for lp in lps:
			ufiles.append(self.lpaths[lp])
		
		self.print_updates(ufiles)
		return ufiles

	"""
	find local touch files
	"""
	def find_local_touches(self):
		rps = []
		for rp,rf in self.rpaths.items():
			if rf.folder:
				continue

			# check touchable
			lf = self.lpaths.get(rp)
			if lf and lf.size == rf.size and math.fabs(tseconds(rf.mdate - lf.mdate)) > 2:
				rf.action = '>~'
				rf.reason = '| <> L:' + tmstr(lf.mdate)
				rps.append(rp)

		rps.sort()
		ufiles = [ ]
		for rp in rps:
			ufiles.append(self.rpaths[rp])
		
		self.print_updates(ufiles)
		return ufiles

	"""
	find local updated files
	"""
	def find_local_updates(self, lastsync = None, force = False):
		lps = []
		for lp,lf in self.lpaths.items():
			if lf.folder:
				# skip for SYNC
				if lastsync:
					continue
				
				# check remote dir exists
				rf = self.rpaths.get(lp)
				if rf:
					continue
				lf.action = '^/'
			else:
				# check updateable
				rf = self.rpaths.get(lp)
				if rf:
					if tseconds(lf.mdate - rf.mdate) <= 2:
						if not force or lf.size == rf.size:
							continue
					lf.action = '^*'
					lf.reason = '| > R:' + tmstr(rf.mdate)
				elif lastsync:
					if tseconds(lf.mdate - lastsync) > 2:
						lf.action = '^+'
					else:
						lf.action = '>-'
				else:
					lf.action = '^+'

			lps.append(lp)

		lps.sort()
		ufiles = [ ]
		for lp in lps:
			ufiles.append(self.lpaths[lp])
		
		# force to trash remote items that does not exist in local
		if force:
			# trash remote files
			for rp,rf in self.rpaths.items():
				if not rf.folder and not rp in self.lpaths:
					rf.action = '^-'
					ufiles.append(rf)

			# trash remote folders
			rps = []
			for rp,rf in self.rpaths.items():
				if rf.folder and not rp in self.lpaths:
					rf.action = '^-'
					rps.append(rp)

			rps.sort(reverse=True)
			for rp in rps:
				ufiles.append(self.rpaths[rp])
			
		self.print_updates(ufiles)
		return ufiles

	"""
	find remote updated files
	"""
	def find_remote_updates(self, lastsync = None, force = False):
		rps = []
		for rp,rf in self.rpaths.items():
			if rf.folder:
				# skip for SYNC
				if lastsync:
					continue
				
				# check local dir exists
				lf = self.lpaths.get(rp)
				if lf:
					continue
				rf.action = '>/'
			else:
				# check updateable
				lf = self.lpaths.get(rp)
				if lf:
					if tseconds(rf.mdate - lf.mdate) <= 2:
						if not force or lf.size == rf.size:
							continue
					rf.action = '>*'
					rf.reason = '| > L:' + tmstr(lf.mdate)
				elif lastsync:
					if tseconds(rf.mdate - lastsync) > 2:
						rf.action = '>+'
					else:
						rf.action = '^-'
				else:
					rf.action = '>+'

			rps.append(rp)

		rps.sort()
		ufiles = [ ]
		for rp in rps:
			ufiles.append(self.rpaths[rp])
		
		
		# force to trash local items that does not exist in remote
		if force:
			# trash local files
			for lp,lf in self.lpaths.items():
				if not lf.folder and not lp in self.rpaths:
					lf.action = '>-'
					ufiles.append(lf)

			# delete local folders
			lps = []
			for lp,lf in self.lpaths.items():
				if lf.folder and not lp in self.rpaths:
					lf.action = '>!'
					lps.append(lp)
			
			lps.sort(reverse=True)
			for lp in lps:
				ufiles.append(self.lpaths[lp])

		self.print_updates(ufiles)
		return ufiles

	"""
	find synchronizeable files
	"""
	def find_sync_files(self):
		lfiles = self.find_local_updates(config.last_sync)
		rfiles = self.find_remote_updates(config.last_sync)

		sfiles = lfiles + rfiles
		spaths = {}
		for sf in sfiles:
			if sf.path in spaths:
				raise Exception('Duplicated sync file: %s' % sf.path)
			spaths[sf.path] = sf
			
		return sfiles

	def sync_files(self, sfiles):
		i = 0
		t = len(sfiles)
		for sf in sfiles:
			i += 1
			self.prog = '[%d/%d]' % (i, t)
			if sf.action == '^-':
				self.trash_remote_file(sf)
			elif sf.action == '^*':
				rf = self.rpaths[sf.path]
				self.update_remote_file(rf, sf)
			elif sf.action == '^+':
				pf = self.make_remote_dirs(os.path.dirname(sf.path))
				self.insert_remote_file(pf, sf)
			elif sf.action == '^/':
				self.make_remote_dirs(sf.path)
			elif sf.action == '^~':
				rf = self.rpaths[sf.path]
				self.patch_remote_file(rf, sf.mdate)
			elif sf.action in ('>*', '>+'):
				self.download_remote_file(sf)
			elif sf.action == '>/':
				self.create_local_dirs(sf)
			elif sf.action == '>-':
				self.trash_local_file(sf)
			elif sf.action == '>!':
				self.remove_local_file(sf)
			elif sf.action == '>~':
				lf = self.lpaths[sf.path]
				self.touch_local_file(lf, sf.mdate)

		self.print_skips(self.skips)

	def upload_files(self, lfiles):
		self.sync_files(lfiles)

	def dnload_files(self, rfiles):
		self.sync_files(rfiles)

	def touch_files(self, pfiles):
		self.sync_files(pfiles)

	def patch_files(self, pfiles):
		self.sync_files(pfiles)

	def patch(self, noprompt):
		# get remote files
		self.list()
		
		# scan local files
		self.scan()

		pfiles = self.find_remote_patches()
		if pfiles:
			if not noprompt:
				ans = raw_input("Are you sure to patch %d remote files? (Y/N): " % (len(pfiles)))
				if ans.lower() != "y":
					return
			self.patch_files(pfiles)
			uprint("--------------------------------------------------------------------------------")
			uinfo("PATCH Completed!")
		else:
			uinfo('No files need to be patched.')

	def touch(self, noprompt):
		# get remote files
		self.list()
		
		# scan local files
		self.scan()

		pfiles = self.find_local_touches()
		if pfiles:
			if not noprompt:
				ans = raw_input("Are you sure to touch %d local files? (Y/N): " % (len(pfiles)))
				if ans.lower() != "y":
					return
			self.touch_files(pfiles)
			uprint("--------------------------------------------------------------------------------")
			uinfo("TOUCH Completed!")
		else:
			uinfo('No files need to be touched.')

	def push(self, force = False, noprompt = False):
		# get remote files
		self.list()
		
		# scan local files
		self.scan()
		
		# find files that are in folders and not in remote
		ufiles = self.find_local_updates(None, force)
		
		if ufiles:
			if not noprompt:
				ans = raw_input("Are you sure to push %d files to One Drive? (Y/N): " % len(ufiles))
				if ans.lower() != "y":
					return

			self.upload_files(ufiles)
			if force:
				self.up_to_date()
			uprint("--------------------------------------------------------------------------------")
			uinfo("PUSH %s Completed!" % ('(FORCE)' if force else ''))
		else:
			uprint("--------------------------------------------------------------------------------")
			uinfo('No files need to be uploaded to remote server.')

	def pull(self, force = False, noprompt = False):
		# get remote files
		self.list()
		
		# scan local files
		self.scan()
		
		# find files that are in folders and not in remote
		dfiles = self.find_remote_updates(None, force)
		
		if dfiles:
			if not noprompt:
				ans = raw_input("Are you sure to pull %d files to local? (Y/N): " % len(dfiles))
				if ans.lower() != "y":
					return

			self.dnload_files(dfiles)
			if force:
				self.up_to_date()
			uprint("--------------------------------------------------------------------------------")
			uinfo("PULL %s Completed!" % ('(FORCE)' if force else ''))
		else:
			uprint("--------------------------------------------------------------------------------")
			uinfo('No files need to be downloaded to local.')

	def sync(self, noprompt):
		# get remote files
		self.list()
		
		# scan local files
		self.scan()
		
		# find files that are need to be sync
		sfiles = self.find_sync_files()
		
		if sfiles:
			if not noprompt:
				ans = raw_input("Are you sure to sync %d files? (Y/N): " % len(sfiles))
				if ans.lower() != "y":
					return
			self.sync_files(sfiles)
			self.up_to_date()
			uprint("--------------------------------------------------------------------------------")
			uinfo("SYNC Completed!")
		else:
			self.up_to_date()
			uprint("--------------------------------------------------------------------------------")
			uinfo('No files need to be synchronized.')


	def up_to_date(self):
		self.service.auth_provider.save_session(path=config.token_file)
		touch(config.token_file)

	def to_ofile(self, r, root):
		f = OFile(r, root)
		
		self.rfiles[f.id] = f
		self.get_path(self.rfiles, f)
		self.rpaths[f.path] = f
		
		return f
		
	def create_remote_folder(self, path, title, pid = None):
		'''
		Create a folder with title under a parent folder with parent_id.
		'''
		uinfo("%s ^CREATE^ %s" % (self.prog, path))

		f = onedrivesdk.Folder()
		i = onedrivesdk.Item()
		i.name = title
		i.folder = f
		if pid is None:
			pid = "root"

		def exef(a):
			return self.service.item(drive="me", id=pid).children.add(i)
			
		a = Obj()
		a.execute = types.MethodType(exef, a)
		r = self.exea(a, "create")

		f = self.to_ofile(r, True if pid == "root" else False)
		return f

	def make_remote_dirs(self, path):
		rf = self.rpaths.get(path)
		if rf:
			return rf

		dirs = [i for i in path.strip().split('/') if i]
		p = ''
		f = None
		for d in dirs:
			p += '/' + d
			tf = self.rpaths.get(p)
			if tf:
				f = tf
			else:
				f = self.create_remote_folder(p, d, f.id if f else None)

		return f
	
	def trash_remote_file(self, file):
		"""
		Move a remote file to the trash.
		"""
		uinfo("%s ^TRASH^  %s [%s] (%s)" % (self.prog, file.path, szstr(file.size), tmstr(file.mdate)))

		def exef(a):
			return self.service.item(drive="me", id=file.id).delete()
			
		a = Obj()
		a.execute = types.MethodType(exef, a)
		self.exea(a, "trash")

		self.rfiles.pop(file.id, file)
		self.rpaths.pop(file.path, file)

	def insert_remote_file(self, pf, lf):
		if lf.size > config.max_file_size:
			self.skips.append(lf)
			uwarn("%s Unable to upload %s, File size [%s] exceed the limit" % (self.prog, lf.path, szstr(lf.size)))
			return

		'''
		Insert a file to onedrive.
		'''
		uinfo("%s ^UPLOAD^ %s [%s] (%s)" % (self.prog, lf.path, szstr(lf.size), tmstr(lf.mdate)))

		pid = "root" if pf is None else pf.id

		def exef(a):
			return self.service.item(drive="me", id=pid).children[quote(lf.name)].upload(lf.npath)
			
		a = Obj()
		a.execute = types.MethodType(exef, a)
		r = self.exea(a, "upload")

		rf = self.to_ofile(r, True if pf is None else False)
		
		self.patch_remote_file(rf, lf.mdate)
		return rf

	def update_remote_file(self, rf, lf):
		if lf.size > config.max_file_size:
			self.skips.append(lf)
			uwarn("%s Unable to update %s, File size [%s] exceed the limit" % (self.prog, lf.path, szstr(lf.size)))
			return

		'''
		Update a file to onedrive.
		'''
		uinfo("%s ^UPDATE^ %s [%s] (%s)" % (self.prog, rf.path, szstr(lf.size), tmstr(lf.mdate)))

		def exef(a):
			return self.service.item(drive="me", id=rf.id).upload(lf.npath)
			
		a = Obj()
		a.execute = types.MethodType(exef, a)
		self.exea(a, "update")

		rf.size = lf.size
		
		self.patch_remote_file(rf, lf.mdate)
		return rf

	def download_remote_file(self, rf):
		uinfo("%s >DNLOAD> %s [%s] (%s)" % (self.prog, rf.path, szstr(rf.size), tmstr(rf.mdate)))
		
		mkpdirs(rf.npath)

		if rf.size == 0:
			with open(rf.npath, "wb") as f:
				pass
		else:
			self.service.item(drive="me", id=rf.id).download(rf.npath)
		
		touch(rf.npath, rf.mdate)

	def patch_remote_file(self, rf, mt):
		'''
		Patch a remote file.
		'''
		uinfo("%s ^PATCH^  %s [%s] (%s)" % (self.prog, rf.path, szstr(rf.size), tmstr(mt)))

		i = { "id": rf.id, "fileSystemInfo": { "lastModifiedDateTime": mtstr(mt) } }

		def exef(a):
			self.service.item(drive="me", id=rf.id).update(i)

		a = Obj()
		a.execute = types.MethodType(exef, a)
		self.exea(a, 'patch')

		rf.mdate = mt
		return rf

	def touch_local_file(self, lf, mt):
		'''
		Touch a local file.
		'''
		uinfo("%s >TOUCH>  %s [%s] (%s)" % (self.prog, lf.path, szstr(lf.size), tmstr(mt)))

		touch(lf.npath, mt)

		lf.mdate = mt
		return lf

	def create_local_dirs(self, lf):
		if os.path.exists(lf.npath):
			return

		uinfo("%s >CREATE> %s" % (self.prog, lf.path))
		os.makedirs(lf.npath)

	def trash_local_file(self, lf):
		if config.trash_dir:
			uinfo("%s >TRASH>  %s" % (self.prog, lf.path))
	
			np = config.trash_dir + lf.path
			mkpdirs(np)
			
			if os.path.exists(np):
				os.remove(np)
			
			shutil.move(lf.npath, np)
		else:
			uinfo("%s >REMOVE> %s" % (self.prog, lf.path))
			os.remove(lf.npath)

	def remove_local_file(self, lf):
		uinfo("%s >REMOVE> %s" % (self.prog, lf.path))

		np = lf.npath
		if os.path.exists(np):
			os.rmdir(np)

def showUsage():
	print("OneDriveSync.py <command> ...")
	print("  <command>: ")
	print("    help                print command usage")
	print("    get <id>            print remote file info")
	print("    tree                list remote folders")
	print("    list [all]          list [all] remote files")
	print("    scan                scan local files")
	print("    pull [go] [force]   download remote files")
	print("      [force]           force to update file whose size is different")
	print("                        force to trash file that not exists in remote")
	print("      [go]              no confirm (always yes)")
	print("    push [go] [force]   upload local files")
	print("      [force]           force to update file whose size is different")
	print("                        force to trash file that not exists in local")
	print("    sync [go]           synchronize local <--> remote files")
	print("    touch [go]          set local file's modified date by remote")
	print("    patch [go]          set remote file's modified date by local")
	print("    drop                delete all remote files")
	print("")
	print("  <marks>: ")
	print("    ^-: trash remote file")
	print("    ^*: update remote file")
	print("    ^+: add remote file")
	print("    ^/: add remote folder")
	print("    ^~: patch remote file timestamp")
	print("    >*: update local file")
	print("    >+: add local file")
	print("    >/: add local folder")
	print("    >-: trash local file")
	print("    >!: remove local file")
	print("    >~: touch local file timestamp")

"""
Initial entry point for the uploads
"""
def main(args):
	global LOG

	LOG_FORMAT = '%(asctime)s %(levelname)s %(message)s'
	logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

	rlog = logging.getLogger('')
	rlog.handlers = [ logging.NullHandler() ]

	dbglog = config.debug_log
	if dbglog:
		debugs = logging.FileHandler(dbglog)
		debugs.setLevel(logging.DEBUG)
		debugs.setFormatter(logging.Formatter(LOG_FORMAT))
		rlog.addHandler(debugs)
		
	errlog = config.error_log
	if errlog:
		errors = logging.FileHandler(errlog)
		errors.setLevel(logging.ERROR)
		errors.setFormatter(logging.Formatter(LOG_FORMAT))
		rlog.addHandler(errors)

	LOG = logging.getLogger("onedrivesync")
	LOG.setLevel(logging.INFO)
#	logh = logging.StreamHandler()
#	logh.setFormatter(logging.Formatter(LOG_FORMAT))
#	LOG.addHandler(logh)

	cmd = ''
	if len(args) > 0:
		cmd = args[0]

	if cmd == 'help':
		showUsage()
		exit(0)

	uinfo('Start...')

	gc = OneDriveCredentials()
	service = gc.get_service()
	gs = OneDriveSync(service)

	opt1 = '' if len(args) < 2 else args[1]

	if cmd == 'get':
		gs.get(opt1)
	elif cmd == 'list':
		all = False
		idx = 1
		while (idx < len(args)):
			opt = args[idx]
			idx += 1
			if len(opt) < 1:
				continue
			if opt == 'all':
				all = True
				continue
			ch = opt[0]
			if ch == '+':
				config.includes = opt[1:].split()
			elif ch == '-':
				config.excludes = opt[1:].split()
		gs.list(True, all)
	elif cmd == 'tree':
		idx = 1
		while (idx < len(args)):
			opt = args[idx]
			idx += 1
			if len(opt) < 1:
				continue
			ch = opt[0]
			if ch == '+':
				config.includes = opt[1:].split()
			elif ch == '-':
				config.excludes = opt[1:].split()
		gs.tree(True)
	elif cmd == 'scan':
		gs.scan(True)
	elif cmd == 'drop':
		gs.drop(True if 'go' in args else False)
	elif cmd == 'push':
		gs.push(True if 'force' in args else False, True if 'go' in args else False)
	elif cmd == 'pull':
		gs.pull(True if 'force' in args else False, True if 'go' in args else False)
	elif cmd == 'sync':
		gs.sync(opt1)
	elif cmd == 'patch':
		gs.patch(True if 'go' in args else False)
	elif cmd == 'touch':
		gs.touch(True if 'go' in args else False)
	else:
		showUsage()


if __name__ == "__main__":
	main(sys.argv[1:])

