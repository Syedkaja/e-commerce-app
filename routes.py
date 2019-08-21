import json
import time
import uuid
from datetime import datetime, timedelta
from functools import wraps
from tzlocal import get_localzone

from flask import Flask, jsonify, request, session
from flask_cors import CORS
from pony.orm import commit, db_session, select, desc

app = Flask(__name__, static_url_path="", static_folder="./static/dist/e-commerce")
CORS(
    app,
    allow_headers=["Content-Type", "Authorization", "Access-Control-Allow-Credentials"],
    supports_credentials=True,
)

app.secret_key = (
    ";\x82\xe1\x0c\xaf\x1f\x9fM\xb1\x17\xedET\xef\x13l\xf2\x90\xcf\x85\xee\x01\xe2z"
)

LOCAL_TZ = get_localzone()



