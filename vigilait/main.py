import os
import urllib.request
import tarfile
import zipfile
import hashlib
import json
import logging
import pickle
import time
import yaml
import requests
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder
from sklearn.metrics import classification_report
from sklearn.cluster import DBSCAN  # For anomaly detection
import argparse
from logging.handlers import RotatingFileHandler
from scapy.all import sniff, IP, TCP, UDP, Raw  # Added UDP protocol support
from flask import Flask, jsonify, request, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# ======= Configuration =======
CONFIG_FILE = "./config/config.yaml"
API_KEYS_FILE = "./config/api_keys.json"

# Load configuration settings
def load_config():
    with open(CONFIG_FILE, 'r') as f:
        return yaml.safe_load(f)

# ======= Logging Setup =======
def setup_logging(log_file):
    handler = RotatingFileHandler(log_file, maxBytes=10**6, backupCount=5)
    logging.basicConfig(
        handlers=[handler],
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

# ======= Database Setup =======
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vigilait.db'
app.config['SECRET_KEY'] = os.urandom(24)
db = SQLAlchemy(app)

# ======= User Model =======
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Create the database tables
with app.app_context():
    db.create_all()

# ======= Authentication Decorator =======
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ======= User Authentication Routes =======
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['username'] = username
            return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/events', methods=['GET'])
@login_required
def get_events():
    return jsonify(siem.events)

@app.route('/execute_playbook', methods=['POST'])
@login_required
def api_execute_playbook():
    playbook_file = request.json.get('playbook_file')
    if not playbook_file:
        return jsonify({"error": "Playbook file is required"}), 400
    execute_playbook(playbook_file)
    return jsonify({"status": "Playbook executed successfully"})

# ======= Utility Functions =======
def hash_file(file_path, hash_type="md5"):
    hasher = hashlib.new(hash_type)
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def download_file(url, dest):
    try:
        logging.info(f"Downloading {url}...")
        urllib.request.urlretrieve(url, dest)
        logging.info(f"Downloaded to {dest}")
    except Exception as e:
        logging.error(f"Error downloading {url}: {e}")

def extract_archive(archive_path, extract_to):
    if archive_path.endswith(".gz"):
        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(path=extract_to)
    elif archive_path.endswith(".zip"):
        with zipfile.ZipFile(archive_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)

def verify_or_fetch_files(required_files):
    for category, files in required_files.items():
        logging.info(f"Checking {category}...")
        for name, info in files.items():
            local_path = info["local_path"]
            if os.path.exists(local_path):
                if "hash" in info and hash_file(local_path) != info["hash"]:
                    logging.warning(f"Hash mismatch for {name}. Re-downloading...")
                    download_file(info["url"], local_path)
            else:
                download_file(info["url"], local_path)
                if local_path.endswith((".gz", ".zip")):
                    extract_archive(local_path, os.path.dirname(local_path))

# ======= API Handling =======
def load_api_keys(api_keys_file):
    if not os.path.exists(api_keys_file):
        logging.error("API keys not found. Please create api_keys.json.")
        exit(1)
    with open(api_keys_file) as f:
        return json.load(f)

def query_virustotal(api_key, hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    return response.json() if response.status_code == 200 else {}

# ======= AI-Based Threat Detection =======
def load_dataset(file_path):
    data = []
    with open(file_path, 'rt') as f:
        for line in f:
            data.append(line.strip().split(','))
    return data

def train_model(data):
    encoder = OneHotEncoder()
    X = encoder.fit_transform([row[:-1] for row in data]).toarray()
    y = [row[-1] for row in data]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3)

    model = RandomForestClassifier()
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    logging.info(classification_report(y_test, y_pred))

    return model, encoder

def detect_threat(sample, model, encoder):
    sample_encoded = encoder.transform([sample]).toarray()
    prediction = model.predict(sample_encoded)
    return prediction[0]

def detect_anomalies(data):
    # Using DBSCAN for anomaly detection
    clustering = DBSCAN(eps=0.5, min_samples=5).fit(data)
    return clustering.labels_

# ======= SIEM Implementation =======
class SIEM:
    def __init__(self):
        self.events = []

    def log_event(self, event):
        self.events.append(event)
        logging.info(f"SIEM Event: {event}")

    def send_alert(self, message):
        # Placeholder for alerting mechanism (e.g., email, SMS)
        logging.warning(f"Alert: {message}")

# ======= Playbook Execution =======
def execute_playbook(playbook_file):
    with open(playbook_file) as f:
        playbook = yaml.safe_load(f)

    for task in playbook['tasks']:
        logging.info(f"Executing task: {task['name']}")
        if task['type'] == 'command':
            os.system(task['command'])
        elif task['type'] == 'script':
            exec(open(task['script']).read())  # Executing an external script
        elif task['type'] == 'http_request':
            response = requests.get(task['url'])
            logging.info(f"HTTP Request to {task['url']} returned status {response.status_code}")
            if 'alert' in task and response.status_code != 200:
                siem.send_alert(task['alert'])

# ======= Real-Time Network Monitoring =======
def packet_callback(packet):
    if IP in packet and (TCP in packet or UDP in packet):  # Extended to handle UDP
        payload = bytes(packet[TCP].payload) if TCP in packet else bytes(packet[UDP].payload)
        hash_value = hashlib.md5(payload).hexdigest()
        logging.info(f"Captured packet: {packet[IP].src} -> {packet[IP].dst} with hash {hash_value}")

        # Check packet payload with VirusTotal
        result = query_virustotal(api_key, hash_value)
        if result and 'data' in result:
            # Example response handling
            malicious = result['data'].get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
            if malicious > 0:
                siem.send_alert(f"Malicious activity detected from {packet[IP].src}.")

# ======= Main Function =======
if __name__ == "__main__":
    # Load configurations and API keys
    config = load_config()
    api_keys = load_api_keys(API_KEYS_FILE)
    api_key = api_keys.get("virustotal")

    # Setup logging
    log_file = config["logging"]["log_file"]
    setup_logging(log_file)

    # Verify or fetch required files
    verify_or_fetch_files(config["files"])

    # Load machine learning model
    model, encoder = train_model(config["model_data"])

    # Initialize SIEM
    siem = SIEM()

    # Start the web interface in a separate thread
    from threading import Thread

    def run_flask():
        app.run(host='0.0.0.0', port=5000)

    # Start Flask app in a new thread
    thread = Thread(target=run_flask)
    thread.start()

    # Start packet sniffing
    sniff(prn=packet_callback, store=0)  # Adjust according to your needs
