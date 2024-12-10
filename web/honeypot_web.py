from flask import Flask, render_template, request, redirect, url_for
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import os

base_dir = Path(__file__).parent.parent
log_dir = 'log'
if not os.path.exists(f'{base_dir}/{log_dir}'):
    os.makedirs(f'{base_dir}/{log_dir}')

log_formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

log = logging.getLogger('FunnelLogger')
log.setLevel(logging.INFO)
audit_handler = RotatingFileHandler(f'{base_dir}/{log_dir}/web_audit.log', maxBytes=2000, backupCount=5)
audit_handler.setFormatter(log_formatter)
log.addHandler(audit_handler)

def baseline_web_honeypot(input_username="admin", input_password="deeboodah"):

    app = Flask(__name__)

    @app.route('/')
    def index():
        return render_template('template.html')

    @app.route('/login', methods=['POST'])
    def login():
        username = request.form['username']
        password = request.form['password']

        ip_address = request.remote_addr

        log.info(f'Client with IP Address: {ip_address} entered\n Username: {username}, Password: {password}')

        if username == input_username and password == input_password:
            return 'Congrats, you are in'
        else:
            return "Invalid username or password, please try again."
        
    return app

def run(port=2222, input_username="admin", input_password="admin"):
     app = baseline_web_honeypot(input_username, input_password)
     app.run(debug=True, port=port, host="0.0.0.0")

     return app