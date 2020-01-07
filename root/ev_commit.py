# -*- coding: utf-8 -*-
# filename: ev_commit.py

import sys, os, time, struct, traceback
import requests

from binascii import hexlify, unhexlify
from threading import Thread

from nbc import util
from nbc import coins
from nbc import wallet
from nbc import protocol
from nbc import script

curr_coin = coins.Newborntoken
# curr_coin.WEB_SERVER_ADDR = 'http://user1-node.nb-chain.net'

def ORD(ch):   # compatible to python3
  return ch if type(ch) == int else ord(ch)

def CHR(i):    # compatible to python3
  return bytes(bytearray((i,)))

class WalletApp(Thread):
  SHEET_CACHE_SIZE = 16
  
  WEB_SERVER_ADDR  = ''
  
  def __init__(self, wallet, vcn=0, coin=curr_coin):
    Thread.__init__(self)
    self.daemon = True
    self._active = False
    
    self._wallet = wallet
    self._vcn = vcn
    self._coin = coin
    
    self._sequence = 0
    self._last_uock = 0
    self._wait_submit = []
    self._wait_retry = []
  
  def exit(self):
    self._active = False
    self.join()
  
  def failed_desc(self, r):
    return 'Error: request failed, code=' + str(r.status_code)
  
  def get_reject_msg_(self, msg):
    sErr = msg.message
    if type(sErr) != str:
      sErr = sErr.decode('latin-1')
    return sErr or 'Meet unknown error'
  
  def prepare_txn2_(self, protocol_id, str_list, scan_count, min_utxo, max_utxo, sort_flag, from_uock):
    if not self.WEB_SERVER_ADDR: return None
    
    str_list2 = []
    ii = 0               # 0x00000010 PUSH <MSG> PUSH <locate> PUSH <utf8-message>
    for s in str_list:   # 0x00000010 PUSH <PROOF> PUSH <locate> PUSH <hash32>
      if type(s) != bytes:
        s = s.encode('utf-8')
      if len(s) > 75:    # msg length must < 76 (OP_PUSHDATA1)
        print('Error: item of RETURN list should be short than 75 bytes')
        return None
      ii += len(s) + 2   # 2 is OP_PUSH(1) + LEN(1)
      if ii > 84:        # RETURN(1) + B(1) + ID(4) + 84 = 90
        print('Error: RETURN list exceed max byte length')
        return None
      str_list2.append(s)
    
    self._sequence = self._sequence + 1
    pay_from = [ protocol.format.PayFrom(0,self._wallet.address()) ]
    
    ex_args = []; ex_format = ''
    for s in str_list2:
      ex_format += 'BB%is' % len(s)
      ex_args.extend([76,len(s),s])    # 0x4c=76 is OP_PUSHDATA1
    ex_msg = struct.pack('<BBI'+ex_format,106,4,protocol_id,*ex_args) # 0x6a=106 is OP_RETURN
    pay_to = [protocol.format.PayTo(0,ex_msg)]  # value=0 means using RETURN script 
    
    return protocol.MakeSheet(self._vcn,self._sequence,pay_from,pay_to,scan_count,min_utxo,max_utxo,sort_flag,[from_uock])
  
  def submit_txn_(self, msg, submit):
    headers = {'Content-Type': 'application/octet-stream'}
    r = requests.post(self.WEB_SERVER_ADDR + '/txn/sheets/sheet',data=msg.binary(self._coin.magic),headers=headers,timeout=30)
    
    if r.status_code == 200:
      msg2 = protocol.Message.parse(r.content,self._coin.magic)
      if msg2.command == protocol.UdpReject.command:
        print('Error: ' + self.get_reject_msg_(msg2))
        return 0
      
      if msg2.command == protocol.OrgSheet.command:
        # assert(msg2.sequence == self._sequence)
        self._last_uock = msg2.last_uocks[0]
        
        # step 1: check message is not imitation
        # wait to do: verify msg.signature ...
        
        # check pay_to balance
        coin_hash = self._wallet.publicHash() + self._wallet.coin_type
        d = {}
        for p in msg.pay_to:
          if p.value != 0 or p.address[0:1] != b'\x6a':  # not OP_RETURN
            d[util.base58.decode_check(p.address)[1:]] = p.value
        for idx in range(len(msg2.tx_out)):
          item = msg2.tx_out[idx]
          if item.value == 0 and item.pk_script[0:1] == b'\x6a':   # OP_RETURN
            continue  # ignore
          
          addr = script.get_script_address(item.pk_script,None)
          if not addr:
            print('Error: invalid output address (idx=%i)' % (idx,))
            return 0
          else:
            value_ = d.pop(addr,None)
            if item.value != value_:
              if (value_ is None) and addr[2:] == coin_hash:
                pass
              else:
                print('Error: invalid output value (idx=%i)' % (idx,))
                return 0
        
        for addr in d.keys():
          if coin_hash != addr[2:]:   # the left address should be pay-to-self
            print('Error: unknown output address (%s)' % (hexlify(addr),))
            return 0                  # be ensure not pay to unexpected person
        
        # step 2: sign first pks_out (numbers of tx_in)
        pks_out0 = msg2.pks_out[0].items; pks_num = len(pks_out0)
        tx_ins2 = []
        pub_key = self._wallet.publicKey()
        for (idx,tx_in) in enumerate(msg2.tx_in):   # sign every inputs
          if idx < pks_num:
            hash_type = 1
            payload = script.make_payload(pks_out0[idx],msg2.version,msg2.tx_in,msg2.tx_out,0,idx,hash_type)  # lock_time=0
            sig = self._wallet.sign(payload) + CHR(hash_type)
            sig_script = CHR(len(sig)) + sig + CHR(len(pub_key)) + pub_key
            tx_ins2.append(protocol.TxnIn(tx_in.prev_output,sig_script,tx_in.sequence))
          else: tx_ins2.append(tx_in)
        
        # step 3: make payload and submit
        txn = protocol.Transaction(msg2.version,tx_ins2,msg2.tx_out,msg2.lock_time,b'') # sig_raw = b''
        payload = txn.binary(self._coin.magic)
        hash_ = util.sha256d(payload[24:-1])   # exclude sig_raw
        
        state_info = [msg2.sequence,txn,'requested',hash_,msg2.last_uocks,int(time.time())]
        self._wait_submit.append(state_info)
        while len(self._wait_submit) > self.SHEET_CACHE_SIZE:
          print('warning: tracing transaction out of range')
          del self._wait_submit[0]
        
        if submit:
          unsign_num = len(msg2.tx_in) - pks_num
          if unsign_num != 0:  # leaving to sign
            print('Warning: some input not signed: %i' % (unsign_num,))
            # return 0
          else:
            r2 = requests.post(self.WEB_SERVER_ADDR + '/txn/sheets/txn',data=txn.binary(self._coin.magic),headers=headers,timeout=30)
            if r2.status_code == 200:
              msg3 = protocol.Message.parse(r2.content,self._coin.magic)
              if msg3.command == protocol.UdpReject.command:
                print('Error: ' + self.get_reject_msg_(msg3))
                # return 0
              elif msg3.command == protocol.UdpConfirm.command and msg3.hash == hash_:
                state_info[2] = 'submited'
                state_info[5] = int(time.time())
                return msg2.sequence
              # else: return 0     # meet unexpected error
            else:
              print(self.failed_desc(r2))
              # return 0
        else: return msg2.sequence
    
    else:
      print(self.failed_desc(r))
    
    return 0
  
  def query_sheet_ex(self, protocol_id, str_list, submit=True, scan_count=0, min_utxo=0, max_utxo=0, sort_flag=0):
    msg = self.prepare_txn2_(protocol_id,str_list,scan_count,min_utxo,max_utxo,sort_flag,self._last_uock)
    if not msg: return 0
    return self.submit_txn_(msg,submit)
  
  def submit_again(self, sn):
    for state_info in self._wait_submit:
      if state_info[0] == sn:
        txn, old_state, hash_ = state_info[1:4]
        
        headers = {'Content-Type': 'application/octet-stream'}
        r2 = requests.post(self.WEB_SERVER_ADDR + '/txn/sheets/txn',data=txn.binary(self._coin.magic),headers=headers,timeout=30)
        if r2.status_code == 200:
          msg3 = protocol.Message.parse(r2.content,self._coin.magic)
          if msg3.command == protocol.UdpReject.command:
            print('Error: ' + self.get_reject_msg_(msg3))
          
          elif msg3.command == protocol.UdpConfirm.command and msg3.hash == hash_:
            state_info[2] = state = 'submited'
            state_info[5] = int(time.time())
            return state
        else:
          print(self.failed_desc(r2))
        break
    
    return 'unknown'
  
  def submit_info(self, sn):
    for (sn2,txn,state,hash2,uocks,tm) in self._wait_submit:
      if sn2 == sn:
        return (txn,state,hash2,uocks,tm)
    return (None,'unknown',None,None,0)
  
  def confirm_state(self, hash_):  # try update confirm state
    if type(hash_) != bytes:
      hash_ = hash_.encode('latin-1')
    hash2 = hexlify(hash_).decode('latin-1')
    
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    r = requests.get(self.WEB_SERVER_ADDR + '/txn/sheets/state',params={'hash':hash2},headers=headers,timeout=30)
    if r.status_code == 200:
      msg3 = protocol.Message.parse(r.content,self._coin.magic)
      if msg3.command == protocol.UdpReject.command:
        sErr = self.get_reject_msg_(msg3)
        if sErr == 'in pending state':
          return 'pending'   # peer has received it but still in waiting publish
        else: print('Error: ' + sErr)
      
      elif msg3.command == protocol.UdpConfirm.command and msg3.hash == hash_:
        hi  = msg3.arg & 0xffffffff
        num = (msg3.arg >> 32) & 0xffff
        idx = (msg3.arg >> 48) & 0xffff
        state = 'confirm=%i, height=%i, index=%i' % (num,hi,idx)
        return state
    else:
      print(self.failed_desc(r))
      return 'unreach'
    
    return 'unknown'
  
  def run(self):
    self._active = True
    counter = 0
    
    while self.is_alive() and self._active:
      time.sleep(10)
      counter += 1
      
      if counter % 48 == 47:    # every 8 minutes, 48 * 10 = 480 seconds
        try:
          # step 1: try re-query and re-sumbit transaction
          ii = len(self._wait_retry) - 1
          while ii >= 0:
            item = self._wait_retry[ii]
            ii -= 1
            
            sn = self.query_sheet_ex(1,item[0])
            if not sn:
              if item[1] >= 10:
                print('warning: too many retry for recording',item[0])
                self._wait_retry.remove(item)
              else: item[1] = item[1] + 1
            else:  # successful
              try:
                self._wait_retry.remove(item)
              except: pass
          
          # step 2: scan txn state when it already requested
          waitRmv = []; now = int(time.time())
          for item in self._wait_submit:   # [sn,txn,state,hash,last_uocks,tm]
            passed = now - item[5]
            if passed > 10800:       # more than 3 hours
              print('warning: waiting transaction (hash=%s) confirm timeout' % (item[3],))
              waitRmv.append(item)
            elif passed > 7200:      # more than 2 hours, maybe re-submit some times before 3 hours
              self.submit_again(item[0])   # if successful, time in item[5] will be changed
              continue
            
            state2 = self.confirm_state(item[3])
            if state2 == 'unknown':  # meet unexpeted error
              print('warning: query transaction (hash=%s) failed' % (item[3],))
              waitRmv.append(item)
            elif state2.find('confirm=') == 0:  # success
              waitRmv.append(item)
          
          for item in waitRmv:
            try:
              self._wait_submit.remove(item)
            except: pass
        
        except:
          traceback.print_exc()
      
      # step 3: try reset last uock every 8 hours
      if counter % 2880 == 2879:    # 8*3600/10 = 2880
        if len(self._wait_submit) == 0:
          self._last_uock = 0
    
    self._active = False
    print('WalletApp thread exited.')
  
  def record(self, client_id, file_id, content, where=b'0'):
    rec_info = [client_id,file_id,b'HASH',where,content]
    sn = self.query_sheet_ex(1,rec_info)
    
    if not sn:  # failed
      self._wait_retry.append([rec_info,1])  # request couter = 1
    else:       # request sheet successful
      info = self.submit_info(sn)
      state = info[1]; txn_hash = info[2]; last_uocks = info[3]; request_tm = info[4]
      if state == 'submited' and txn_hash:
        sDesc = 'request transaction at %s, state: %s' % (time.strftime('%y-%m-%d %H:%M:%S',time.localtime(request_tm)),state)
        if last_uocks: sDesc += ', last uock: %016x' % (last_uocks[0],)
        print(sDesc)
        print('hash: %s' % (hexlify(txn_hash).decode('latin-1'),))
      
      # if txn_hash: state = self.confirm_state(txn_hash)
      # print('transaction state:',state)

#=============================

WalletApp.WEB_SERVER_ADDR = curr_coin.WEB_SERVER_ADDR

# import hashlib
# 
# account = wallet.loadFrom('data/account.cfg',password)
# app = WalletApp(account,vcn=0)
# app.start()
# 
# content = hashlib.sha256(b'example').digest()
# content = hashlib.sha256(content).digest()  # double hash256
# app.record(client_id,file_id,content)
# 
# txn_hash = unhexlify('4a1860b584de5797524d58e7a2f6c55040fec7369cd872b0eb06867b1d29aca9')
# app.confirm_state(txn_hash)
