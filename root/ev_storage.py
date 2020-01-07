# -*- coding: utf-8 -*-
# filename: ev_storage.py

import sys, os, time, re, base64, hashlib, json, traceback
import shutil

from threading import Thread
from binascii import hexlify, unhexlify

__all__ = ['serial_msg', 'unserial_msg', 'ev_storage']

_admin_account = None

_csv_data_dir = os.path.join(os.environ.get('LOCAL_DIR','./data'),'csv')

def ensure_dir_(a_dir):
  if not a_dir or os.path.exists(a_dir): return
  
  ensure_dir_(os.path.split(a_dir)[0])
  os.mkdir(a_dir)

dict_schema_ = '@DICT'
byte_schema_ = '@BYTE'

if sys.version_info.major >= 3:
  def bytes2list(b):
    return [ch for ch in b]
else:
  def bytes2list(b):
    return [ord(ch) for ch in b]

# dict --> ['@DICT',[key,value], ...]  # each item is ordered by key name
# bytes --> ['@BYTE',n, ...]           # n should be 0 ~ 255
def serial_msg(msg):
  tp = type(msg)
  if tp == dict:
    names = list(msg.keys())
    names.sort()
    
    bRet = [dict_schema_]
    for name in names:
      bRet.append([name,serial_msg(msg[name])])
    return bRet
  elif tp == bytes:
    bRet = bytes2list(msg)
    bRet.insert(0,byte_schema_)
    return bRet
  else: return msg    # no changing

def unserial_msg(msg):
  if type(msg) == list and msg:
    schema = msg[0]
    if schema == dict_schema_:
      dRet = {}
      for i in range(1,len(msg),1):
        name,value = msg[i]
        dRet[name] = unserial_msg(value)
      return dRet
    elif schema == byte_schema_:
      return bytes(msg[1:])
  return msg

#----- testing -----
# b1 = serial_msg({'time':1561970020,'message':'geography info','location':{'xy':[50,50],'desc':'somewhere'}})
# b2 = serial_msg({'location':{'desc':'somewhere','xy':[50,50]},'message':'geography info','time':1561970020})
# assert(json.dumps(b1) == json.dumps(b2))
# unserial_msg(['@DICT',['location',['@DICT',['desc','somewhere'],['xy',[50,50]]]],['message','geography info'],['time',1561970020]])
# unserial_msg(b1)

#-----

def make_pos_id(ownerId, blockId, idx):
  b = ('%x-%x-%x' % (ownerId,blockId,idx)).split('-')
  for (i,s) in enumerate(b):
    if (len(s) & 0x01) != 0:
      b[i] = '0' + s    # avoid odd length hex-string
  return '-'.join(b)

re_newline_ = re.compile(rb'\r\n|\n|\r')

def read_cvs_rec(sFile, idx):
  # read content (last field) of row {idx} from cvs file {sFile}
  
  targ = b''
  
  try:
    with open(sFile,'rb') as f:
      lines = re_newline_.split(f.read())
      if lines: del lines[0]    # remove csv header
      
      sIdx = b'%i,' % (idx,)
      for line in lines:
        if line.find(sIdx) == 0:
          targ = line
          break
  except:
    traceback.print_exc()
    return b''
  
  if targ:
    b = targ.split(b',')
    return base64.b64decode(b[-1])
  else: return b''

re_hex_pubkey_ = re.compile('^[0-9a-fA-F]{66}$')

class EvStorage(Thread):
  MAX_CACHE_DAYS  = 7
  MAX_CACHE_NUMB  = 30000
  
  SUBMIT_ON_SECONDS = 1800
  MAX_REC_IN_FILE   = 5000
  
  def __init__(self):
    self._recent_dir = os.path.join(_csv_data_dir,'recent')
    ensure_dir_(self._recent_dir)
    
    Thread.__init__(self)
    self.daemon = True
    self._active = False
    
    self._cache = {}   # { hash:[fileName,index,pubKey,time] }
    
    self._wait_from = int(time.time())
    self._curr_file = ''
    self._writing_f = None
    self._rec_index = 0
    self._owner_id  = [self.get_ownerid(),self.load_cache()+1]  # [owner_id4, file_id4]
    
    # callback
    self.on_save_item  = None  # on_save_item(pubKey,time,hash2,(ownerId,blockId,recordId),evData,inData)
    self.on_query_item = None  # on_query_item(urlParam)
    self.on_list_item  = None  # on_list_item(urlParam)
  
  def get_ownerid(self):       # waiting override, provide unique number for multiple machine
    evId = os.environ.get('EV_MACHINE_ID')
    if evId:
      try:
        if evId[0:2].upper() == '0X':
          evId = int(evId,16)
        else: evId = int(evId)
      except: evId = 0
    
    return evId or int(time.time() * 1000)
  
  def exit(self):
    self._active = False
    self.join()
  
  def load_cache(self):
    maxIdx = 0
    
    b = os.listdir(self._recent_dir)
    for item in b:
      if item[0] == '.': continue
      bTmp = item.split('.')
      if len(bTmp) != 2 or bTmp[1] != 'csv': continue
      
      sFile = bTmp[0]  # yy-mm-dd-index
      ii = int(sFile.split('-')[-1])
      if ii > maxIdx: maxIdx = ii  # get max value of index
      
      with open(os.path.join(self._recent_dir,item),'rb') as f:
        lines = re_newline_.split(f.read())
        if lines: del lines[0]     # remove csv header
        
        try:
          for line in lines:           # index, hash, account, time, base64_json
            b2 = line.split(b',')
            if len(b2) != 5: continue  # maybe meet empty line
            # msg = unserial_msg(json.loads(base64.b64decode(b2[4]).decode('utf-8')))
            
            hash2 = b2[1].decode('utf-8')  # convert to utf-8 hex hash
            self._cache[hash2] = [sFile,int(b2[0]),b2[2],int(b2[3])]  # hex pubKey is bytes
        except:
          traceback.print_exc()
    
    return maxIdx
  
  def reset_cache(self, now, max_num=0):
    wait_bak = {}
    
    if max_num:
      dayCount = {}
      for (k,v) in self._cache.items():
        sFileId = v[0]
        dayCount[sFileId] = dayCount.get(sFileId,0) + 1
      
      bFiles = dayCount.keys()
      bFiles.sort()
      
      iWaitRmv = 0
      rmv_num = len(self._cache) - (max_num // 2)
      for i in range(len(bFiles)):
        sFileId = bFiles[0]
        wait_bak[sFileId] = True
        
        iWaitRmv += dayCount[sFileId]
        if iWaitRmv > rmv_num:
          break
      
      for (k,v) in self._cache.items():
        if v[0] in wait_bak:
          del self._cache[k]
      return wait_bak
    
    else:
      expiredTill = now - self.MAX_CACHE_DAYS * 86400
      st = time.gmtime(expiredTill)
      prefix = '%02i-%02i-%02i' % (st.tm_year % 100,st.tm_mon,st.tm_mday)
      
      for (k,v) in self._cache.items():
        sFileId = v[0]
        if sFileId.find(prefix) == 0:
          del self._cache[k]
          wait_bak[sFileId] = True
        elif v[3] < expiredTill:  # v[4] is record time
          del self._cache[k]
          wait_bak[sFileId] = True
      return wait_bak
  
  def backup_file(self, wait_bak):
    for sFile in wait_bak.keys():
      try:
        idx = int(sFile.split('-')[-1])
        ss = '%x' % idx
        if (len(ss) & 0x01) != 0:
          ss = '0' + ss
        
        sDir = os.path.join(_csv_data_dir,'%02x' % ((idx >> 8) & 0xff,))
        ensure_dir_(sDir)  # every 256 continuous files in same folder
        
        sSour = os.path.join(self._recent_dir,sFile+'.csv')  # data/csv/recent/yy-mm-dd-BlockId.csv
        sTarg = os.path.join(sDir,str(idx)+'.csv')  # data/csv/ff/BlockId.csv
        try:
          shutil.move(sSour,sTarg)
        except IOError as e:
          print('warning: backup file (%s) failed' % (sSour,))
      except:
        traceback.print_exc()
  
  def run(self):
    self._active = True
    last_tm = int(time.time())
    counter = 0
    
    while self.is_alive() and self._active:
      now = int(time.time())
      if now - last_tm >= 86400:  # 86400 = 24 * 3600
        last_tm = now
        self.backup_file(self.reset_cache(now,0)) # remove old record and make backup
      
      time.sleep(10)
      counter += 1
      
      if (counter % 60) == 59:    # check every 10 minutes
        if self._writing_f:
          try:  # avoid _writing_f re-assign to None
            self._writing_f.flush()
          except: pass
        
        if len(self._cache) > self.MAX_CACHE_NUMB:
          self.backup_file(self.reset_cache(now,self.MAX_CACHE_NUMB))
    
    self._active = False
    self.try_submit_csv()  # safe close and set _writing_f = None
    print('EvStorage thread exited.')
  
  def try_submit_csv(self):
    if self._writing_f:
      self._writing_f.flush()
      self._writing_f.seek(0,0)
      txt = self._writing_f.read()
      self._writing_f = None
      
      if txt:  # txt is bytes
        hash2 = hashlib.sha256(hashlib.sha256(txt).digest()).digest()
        # machine_id = self._owner_id[0]
        # block_idx  = self._owner_id[1] - 1
        # print('waiting record:',machine_id,block_idx,hash2)
        # blockchain_submit(client_id,file_id,hash2)
  
  def init(self, account):
    global _admin_account
    _admin_account = account
  
  def save_evidence(self, pub_key, ev_data, in_data, hash2, sig):
    account = ev_data['account']  # fixed field: account
    tm = ev_data['time']          # fixed field: time
    
    succ = False; sRet = ''
    now = int(time.time())
    
    try:
      if self._writing_f is None:
        st = time.gmtime(now)
        block_idx = self._owner_id[1]
        sFile = '%02i-%02i-%02i-%i' % (st.tm_year%100,st.tm_mon,st.tm_mday,block_idx)
        self._curr_file = sFile
        sFile += '.csv'
        self._owner_id[1] = block_idx + 1
        
        self._writing_f = open(os.path.join(self._recent_dir,sFile),'w+b')
        self._writing_f.write(b'index,hash,account,time,content\r\n')  # header line
        self._rec_index = 0
      else: block_idx = self._owner_id[1] - 1
      
      try:
        hex_hash = hexlify(hash2)
        hex_pub  = hexlify(pub_key)
        line = b'%i,%s,%s,%i,%s\r\n' % (self._rec_index,hex_hash,hex_pub,tm,base64.b64encode(in_data))
        self._writing_f.write(line)  # index, hash, account, time, base64_json
        self._rec_index += 1
        
        if now - self._wait_from > self.SUBMIT_ON_SECONDS or self._rec_index >= self.MAX_REC_IN_FILE: # more than half hour or too many records
          self.try_submit_csv()      # auto close and set _writing_f = None
          self._wait_from = now
        
        succ = True
        info = (self._owner_id[0],block_idx,self._rec_index-1)  # position info
        if self.on_save_item:        # plugin callback
          self.on_save_item(pub_key,tm,hash2,info,ev_data,in_data)
        
        self._cache[hex_hash.decode('utf-8')] = [self._curr_file,info[2],hex_pub,tm] # hex_pub is bytes
        
        sRet = make_pos_id(*info)
        sig  = _admin_account.sign_noder(sRet.encode('utf-8') + b':' + hex_hash)
        sRet = sRet + ':' + hexlify(sig).decode('utf-8')
      except:
        traceback.print_exc()
        sRet = 'SAVE_FAILED'
    
    except:
      traceback.print_exc()
      sRet = 'SYSTEM_ERROR'
      
      if now - self._wait_from > 3600:  # meet some unexpected error
        self.try_submit_csv()  # auto close and set _writing_f = None
        self._wait_from = now
    
    return (succ,sRet)
  
  def read_ev_data(self, sFile, sHash, rec_idx=None):
    if self._curr_file == sFile:   # still in writing, flush it first
      if self._writing_f:
        self._writing_f.flush()
    
    fileFull = os.path.join(self._recent_dir,sFile+'.csv')
    with open(fileFull,'rt') as f:
      b = f.readlines()
      if b: del b[0]               # remove header line
      
      if type(rec_idx) == int:
        if 0 <= rec_idx < len(b):
          item = b[rec_idx].rstrip().split(',')
          if len(item) >= 5 and item[1] == sHash:
            return item[-1]        # in base64 format
      
      hash2 = ',' + sHash + ','  # sHash should be utf-8
      for line in b:
        i2 = line.find(hash2)
        if i2 > 0:
          item = line.rstrip().split(',')
          if len(item) >= 5:
            return item[-1]      # in base64 format
          break
    
    return None
  
  def query_content(self, sHash):
    item = self._cache.get(sHash)
    if item:
      return self.read_ev_data(item[0],sHash,item[1])
    else: return None
  
  def query_evidence(self, param):
    if self.on_query_item:
      return self.on_query_item(param)
    
    succ = False; sRet = 'NOT_FOUND'
    sHash = param.get('hash')
    sPos  = param.get('pos')
    
    try:
      if sHash:  # sHash should be utf-8 hex_hash
        item = self._cache.get(sHash)
        if item: # [fileName,index,pubKey,time]
          sTmp = read_cvs_rec(os.path.join(self._recent_dir,item[0]+'.csv'),item[1])
          if sTmp:
            sRet = sTmp
            succ = True
      
      elif sPos:
        b = sPos.split('-')  # sPos like 'hex_owner-hex_block-hex_index'
        if len(b) == 3:
          blockIdx = str(int(b[1],16))
          idx = int(b[2],16) 
          
          fileName = ''
          for (k,v) in self._cache.items():
            if v[1] == idx and blockIdx == v[0].split('-')[-1]:
              fileName = v[0]
              break
          
          if fileName:
            sTmp = read_cvs_rec(os.path.join(self._recent_dir,fileName+'.csv'),idx)
            if sTmp:
              sRet = sTmp
              succ = True
    
    except:
      traceback.print_exc()
      sRet = 'SYSTEM_ERROR'
    
    return succ,sRet
  
  def list_evidence(self, param):
    if self.on_list_item:
      return self.on_list_item(param)
    
    succ = False; sRet = '[]'
    sPub  = param.get('addr')
    sHash = param.get('hash')
    sPos  = param.get('pos')
    
    try:
      bRet = []
      
      if sPub and re_hex_pubkey_.search(sPub): # should be hexlify public key
        sPub = sPub.lower().encode('utf-8')
        ownerId = self._owner_id[0]
        
        for (k,v) in self._cache.items():
          if v[2] == sPub:
            blockIdx = int(v[0].split('-')[-1])  # v[0] like 'yy-mm-dd-128'
            bRet.append([make_pos_id(ownerId,blockIdx,v[1]),v[3],k])
      
      elif sHash:
        item = self._cache.get(sHash)
        if item: # [fileName,index,pubKey,time]
          blockIdx = int(item[0].split('-')[-1])
          bRet.append([make_pos_id(self._owner_id[0],blockIdx,item[1]),item[3],sHash])
      
      elif sPos:
        b = sPos.split('-')
        if len(b) == 3:
          blockIdx = int(b[1],16)
          sBlockId = str(blockIdx)
          idx = int(b[2],16)
          
          for (k,v) in self._cache.items():
            if v[1] == idx and sBlockId == v[0].split('-')[-1]:
              bRet.append([make_pos_id(self._owner_id[0],blockIdx,idx),v[3],k])
              break
      
      sRet = json.dumps(bRet)
      succ = True
    
    except:
      traceback.print_exc()
      sRet = 'SYSTEM_ERROR'
    return succ,sRet

ev_storage = EvStorage()
