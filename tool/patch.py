# tool/patch.py

import sys
assert(sys.version_info.major >= 3)  # only support python v3+

import re, hashlib, time, os, random, traceback
from binascii import hexlify, unhexlify

__all__ = [ 'config_patch', 'apply_patch' ]

_dbg_ver     = (0,0,0,0)
_dbg_datadir = './data'
_dbg_secret  = ''
_dbg_pubkey  = b''

def config_patch(ver, datadir, secret, pubkey):
  global _dbg_ver, _dbg_datadir, _dbg_secret, _dbg_pubkey
  
  _dbg_ver = ver
  _dbg_datadir = datadir
  _dbg_secret  = secret
  _dbg_pubkey  = pubkey

def apply_patch():
  sFile = os.path.join(_dbg_datadir,'patch.py')  # patch.py must start with version indicator:  # 0.0.1.0
  if os.path.isfile(sFile):
    with open(sFile,'rt') as f:
      sCode = f.read()
      
      targVer = '.'.join(str(ch) for ch in _dbg_ver)
      m = re.match(r'^#\W*([.0-9]+)',sCode)
      if m and m.group(1) == targVer:
        print('start patch code for ver %s' % targVer)
        try:
          exec(sCode,globals())
        except:
          traceback.print_exc()

#---

from flask import request

from root import app
from nbc import wallet

_dbg_nonce    = 0
_dbg_query_at = 0  # temporary using between query_login and get_login
_dbg_start_at = 0
_dbg_session  = ''

@app.route('/patch/query_login')
def dbg_query_login():
  global _dbg_nonce, _dbg_query_at
  _dbg_nonce = (random.randint(0,65535) << 16) + random.randint(0,65535)
  _dbg_query_at = int(time.time())
  return '%i,%08x' % (_dbg_query_at,_dbg_nonce)

@app.route('/patch/get_login', methods=['POST'])
def dbg_get_login():
  global _dbg_session, _dbg_start_at
  
  if int(time.time()) - _dbg_query_at > 120:  # should login within 120 seconds
    return ('',401)
  
  sh = hashlib.sha1(('%s#%i#%08x' % (_dbg_secret,_dbg_query_at,_dbg_nonce)).encode('utf-8')).hexdigest()
  
  try:
    data = request.get_json(force=True,silent=True)  # force=False,silent=False,cache=True
    if data and sh == data.get('session'):
      sig = unhexlify(data.get('signature',''))
      wa = wallet.Address(pub_key=_dbg_pubkey,vcn=0,coin_type=b'\x00')
      if wa.verify(unhexlify(sh),sig):
        _dbg_session = sh
        _dbg_start_at = _dbg_query_at
        return sh
  except:
    traceback.print_exc()
  
  return ('',401)

re_newline_ = re.compile(r'\r\n|\n|\r')

@app.route('/patch/debug', methods=['POST'])
def dbg_debug():
  if _dbg_session != request.args.get('sid','') or (time.time() - _dbg_start_at) > 3600: # 3600 is 1 hour
    return ('',401)
  
  data = request.get_data(as_text=True)
  if not data: return ''
  lines = re_newline_.split(data)
  
  isExec = False
  if len(lines) > 1:
    isExec = True
    lines = '\n'.join(lines)
    print('debug> exec multiple lines')
  
  else:  # only one line, 'exec' or 'eval'
    if not lines[0]:
      return ''
    
    lines = lines[0]
    if lines == 'exit()':
      return 'disable run exit()'
    
    print('debug>',lines)
    try:
      compile(lines,'stdin','eval')
    except SyntaxError:
      isExec = True
  
  ret = ''
  if isExec:
    try:
      exec(lines,globals())
    except Exception as e:
      ret = str(e)
      traceback.print_exc()
  else:
    try:
      ret = str(eval(lines,globals()))
    except Exception as e:
      ret = str(e)
      traceback.print_exc()
  
  if type(ret) != str: ret = ''
  return ret

@app.route('/patch/set_patch', methods=['POST'])
def set_patch():
  if _dbg_session != request.args.get('sid','') or (time.time() - _dbg_start_at) > 3600: # 3600 is 1 hour
    return ('',401)
  
  data = request.get_data(as_text=True)
  if not data: return '0'
  
  try:
    with open(os.path.join(_dbg_datadir,'patch.py'),'wt') as f:
      f.write(data)
    return '%i' % len(data)
  except:
    traceback.print_exc()
    return '0'
