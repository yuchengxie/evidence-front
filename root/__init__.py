# root/__init__.py

import flask
from flask_cors import *

app = flask.Flask(__name__,static_folder='../static',static_url_path='/static')

CORS(app, supports_credentials=True)

from .ev_storage import *
