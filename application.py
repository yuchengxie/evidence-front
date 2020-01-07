# application.py

import traceback
import os
from root import app, serial_msg, unserial_msg, ev_storage
from nbc import wallet
from flask import request
from binascii import unhexlify
import json
from tool import patch
import logging
import sys
if sys.version_info.major < 3:
    raise Exception('only support python v3+')


__local_dbg__ = True
_data_dir = os.environ.get('LOCAL_DIR', './data')

_default_privkey = ''


# ---- config logger


_log_fmt = '%(asctime)s [%(name)s %(levelname)s] %(message)s'
logging.basicConfig(
    level=logging.DEBUG if __local_dbg__ else logging.INFO, format=_log_fmt)

logger = logging.getLogger(__name__)

# True/False for logging to file or not
if False:  # max rotate 20 files, every file upto 4M
    from logging.handlers import RotatingFileHandler

    _log_file = RotatingFileHandler(os.path.join(
        _data_dir, 'log.txt'), maxBytes=4096*1024, backupCount=20)
    _log_file.setFormatter(logging.Formatter(_log_fmt))
    _log_file.setLevel(logging.INFO)
    logger.addHandler(_log_file)


# ---- prepare AWS security group and patch system


_dbg_ver = (0, 0, 1, 0)  # v0.0.1.0

_dbg_secret = os.environ.get('DBG_SECRET', '')
_dbg_pubkey = b'\x03\xbd\xfaa\x92\x9d\xf7\x1bj\xed\xb7\x88\x8f.\xe7\xd3c\xbb\xc7\x97\xe4\xe0i\x13[\x94\x80\t\x90\xd6I\x9a\xac'

patch.config_patch(_dbg_ver, _data_dir, _dbg_secret, _dbg_pubkey)
patch.apply_patch()


# ---- start flask app


_owner_privkey = os.environ.get(
    'OWNER_KEY', _default_privkey)   # private key in WIF format
if _owner_privkey:
    _owner_account = wallet.Address(priv_key=_owner_privkey.encode('utf-8'))
else:
    print('!! warning: owner account not defined, create one instead.')
    _owner_account = wallet.Address.generate()

ev_storage.init(_owner_account)
ev_storage.start()
# ev_storage.exit()


@app.route('/favicon.ico')
def favicon():
    return app.send_static_file('favicon.ico')


@app.route('/')
@app.route('/index.html')
def index_page():
    return ('', 302, {'Location': '/static/index.html'})

# ----


def isCompPubKey_(pubKey):
    ch = ord(pubKey[:1])
    return ch == 2 or ch == 3  # 2 or 3 means compressed, 4 for uncompressed


@app.route('/ev/item', methods=['GET', 'POST'])
def ev_item():
    if request.method == 'POST':
        print('hello /ev/item')
        sig = request.args.get('sig', '')
        print('sig:', sig)
        if not sig:
            return ('PARAMETER_ERROR', 400)

        try:
            sig = unhexlify(sig)
            print('sig2:', sig, len(sig))

            if len(sig) != 64:
                raise Exception('invalid')
        except:
            traceback.print_exc()
            return ('WRONG_SIGNATURE', 400)

        inData = request.get_data()      # as_text = False, inData is bytes
        try:
            evData = json.loads(inData.decode('utf-8'))
            print('evData:', evData)
            evData = unserial_msg(evData)  # get unserial evidence data

            pubKey = evData.get('account')
            print('pubKey:', pubKey)

            if type(pubKey) != bytes or len(pubKey) != 33 or not isCompPubKey_(pubKey):
                return ('INVALID_ACCOUNT', 400)
            if type(evData.get('time')) != int:
                return ('INVALID_TIME', 400)

            account = wallet.Address(pub_key=pubKey)
            hash2 = account.verify_noder(inData, sig)
            if not hash2:
                return ('WRONG_SIGNATURE', 400)

            succ, desc = ev_storage.save_evidence(
                pubKey, evData, inData, hash2, sig)
            print('保存数据:', succ, desc)
            return (desc, 200) if succ else (desc, 400)
        except:
            logger.warning(traceback.format_exc())
            return ('SYSTEM_ERROR', 400)

    elif request.method == 'GET':
        try:
            succ, desc = ev_storage.query_evidence(request.args)
            return (desc, 200) if succ else (desc, 400)
        except:
            logger.warning(traceback.format_exc())
            return ('SYSTEM_ERROR', 400)


@app.route('/ev/content')
def ev_content():
    sHash = request.args.get('hash')
    if sHash:
        desc = ev_storage.query_content(sHash)
        if desc:
            return (desc, 200)
        else:
            return ('NOT_FOUND', 400)
    else:
        return ('SYSTEM_ERROR', 400)


@app.route('/ev/list')
def ev_list():
    try:
        print('request.args:', request.args)
        succ, desc = ev_storage.list_evidence(request.args)
        return (desc, 200) if succ else (desc, 400)
    except:
        logger.warning(traceback.format_exc())
        return ('SYSTEM_ERROR', 400)


application = app  # avoid print warning: WSGI not contain 'application'

if __name__ == '__main__':
    application.run(host='0.0.0.0', port=5001, debug=__local_dbg__)
