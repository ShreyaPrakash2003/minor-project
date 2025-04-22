import sqlite3
import re
import os
import requests
from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for
from datetime import datetime
from functools import wraps
from collections import defaultdict
import time
import mimetypes
import hashlib
from flask_cors import CORS
import joblib
import numpy as np
import schedule
import geoip2.database

app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = "my-secure-key-123"
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

CORS(app, origins=["http://localhost:8000"],
     supports_credentials=True,
     methods=["GET", "POST", "OPTIONS"],
     allow_headers=["Content-Type", "Cookie"])

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "attacks.db")
MODEL_PATH = os.path.join(BASE_DIR, "models", "attack_detection_model.pkl")
GEO_DB_PATH = os.path.join(BASE_DIR, "GeoLite2-City.mmdb")

os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "models"), exist_ok=True)

VT_API_KEY = "fdc4b43d9a29913efe5b8fabbef445bf6d2a59938ffff81beecba334901f634e"
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password"

REQUEST_LIMIT = 15
TIME_WINDOW = 60
BLOCK_DURATION = 300

DDOS_THRESHOLD = 150
DDOS_WINDOW_SECONDS = 60
DDOS_BLOCK_DURATION = 600

request_counts = defaultdict(list)
blocked_ips = defaultdict(float)

request_tracker_ddos = defaultdict(list)
ddos_blocked_ips = defaultdict(float)

sql_blocked_ips = defaultdict(float)
SQL_BLOCK_DURATION = 24 * 60 * 60

try:
    ml_model = joblib.load(MODEL_PATH)
except FileNotFoundError:
    ml_model = None
    print(f"ML model not found at {MODEL_PATH}. Using fallback detection.")


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            print(f"Session in login_required: {session}")
            if 'logged_in' not in session or not session['logged_in']:
                print("User not logged in, redirecting to login")
                return redirect(url_for('serve_login'))
            print("User is logged in, proceeding with request")
            return f(*args, **kwargs)
        except Exception as e:
            print(f"Error in login_required decorator: {str(e)}")
            return jsonify({"status": "error", "message": f"Authentication error: {str(e)}"}), 500

    return decorated_function


@app.route('/')
def serve_index():
    return send_from_directory(BASE_DIR, 'index.html')


@app.route('/login.html')
def serve_login():
    return send_from_directory(BASE_DIR, 'login.html')


@app.route('/chatbot.html')
@login_required
def serve_chatbot():
    return send_from_directory(BASE_DIR, 'chatbot.html')


@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get("username", "")
        password = data.get("password", "")
        print(f"Login attempt: username={username}, password={password}")
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            print(f"Login successful, session: {session}")
            return jsonify({"status": "success", "message": "Logged in successfully"}), 200
        else:
            return jsonify({"status": "error", "message": "Invalid username or password"}), 401
    except Exception as e:
        print(f"Error in /login endpoint: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


@app.route('/logout', methods=['POST'])
def logout():
    try:
        session.pop('logged_in', None)
        print(f"Logout successful, session: {session}")
        return jsonify({"status": "success", "message": "Logged out successfully"}), 200
    except Exception as e:
        print(f"Error in /logout endpoint: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


def init_db():
    conn = None
    try:
        print("Initializing database...")
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DROP TABLE IF EXISTS attacks")
        conn.execute("""
            CREATE TABLE attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_type TEXT,
                source_ip TEXT,
                timestamp TEXT,
                details TEXT,
                ml_confidence FLOAT,
                latitude REAL,
                longitude REAL
            )
        """)
        conn.commit()
        print("Database initialized successfully")
    except sqlite3.Error as e:
        print(f"Error initializing database: {str(e)}")
        raise
    finally:
        if conn:
            conn.close()


@app.before_request
def detect_brute_force():
    if request.path == '/traffic':
        return None
    source_ip = request.remote_addr
    current_time = time.time()
    if source_ip in blocked_ips:
        if current_time < blocked_ips[source_ip]:
            return jsonify(
                {"status": "error", "message": "IP blocked due to excessive requests. Try again later."}), 429
        else:
            del blocked_ips[source_ip]
            request_counts[source_ip] = []
    request_counts[source_ip].append(current_time)
    request_counts[source_ip] = [t for t in request_counts[source_ip] if current_time - t < TIME_WINDOW]
    if len(request_counts[source_ip]) > REQUEST_LIMIT:
        attack_type = "Brute Force Attack"
        details = f"Detected {len(request_counts[source_ip])} requests in {TIME_WINDOW} seconds"
        log_attack(attack_type, source_ip, details, ml_confidence=None)
        blocked_ips[source_ip] = current_time + BLOCK_DURATION
        print(f"Blocked IP {source_ip} for {BLOCK_DURATION} seconds due to brute force attempt")
        return jsonify({"status": "error", "message": "Too many requests. Your IP has been temporarily blocked."}), 429


def detect_ddos(source_ip):
    current_time = time.time()
    request_tracker_ddos[source_ip].append(current_time)
    request_tracker_ddos[source_ip] = [t for t in request_tracker_ddos[source_ip] if
                                       current_time - t < DDOS_WINDOW_SECONDS]
    request_count = len(request_tracker_ddos[source_ip])
    print(f"DDoS Detection - IP: {source_ip}, Request Count: {request_count}, Window: {DDOS_WINDOW_SECONDS} seconds")
    if request_count > DDOS_THRESHOLD:
        print(f"DDoS Threshold Exceeded - IP: {source_ip}, Request Count: {request_count}")
        ddos_blocked_ips[source_ip] = current_time + DDOS_BLOCK_DURATION
        print(f"Blocked IP {source_ip} for {DDOS_BLOCK_DURATION} seconds due to DDoS")
        return True, f"Request rate: {request_count} requests in {DDOS_WINDOW_SECONDS} seconds"
    return False, None


def extract_text_features(request_data):
    features = [
        len(request_data),
        request_data.lower().count('select'),
        request_data.lower().count('union'),
        request_data.lower().count('--'),
        request_data.lower().count('or'),
        int(bool(re.search(r'\d', request_data)))
    ]
    return features


def extract_file_features(file_content, filename):
    file_hash = hashlib.md5(file_content).hexdigest() if file_content else ''
    mime_type, _ = mimetypes.guess_type(filename) if filename else (None, None)
    features = [
        len(file_content) if file_content else 0,
        1 if filename and filename.lower().endswith(('.exe', '.bat', '.vbs', '.js')) else 0,
        1 if mime_type in ['text/plain', 'image/png', 'image/jpeg', 'application/pdf'] else 0,
        len(file_hash)
    ]
    return features


def detect_malware(request_data=None, file_content=None, filename=None):
    if request_data and ml_model:
        features = extract_text_features(request_data)
        try:
            prediction = ml_model.predict([features])[0]
            confidence = ml_model.predict_proba([features])[0][prediction]
            if prediction == 1:
                return "SQL Injection", f"ML detected SQL injection (Confidence: {confidence:.2f})", confidence
        except Exception as e:
            print(f"ML prediction error for text: {str(e)}")
    elif file_content is not None and ml_model:
        if not file_content:
            return "Invalid File", f"File {filename} is empty", None
        features = extract_file_features(file_content, filename)
        try:
            prediction = ml_model.predict([features])[0]
            confidence = ml_model.predict_proba([features])[0][prediction]
            if prediction == 1:
                return "Malware", f"ML detected malware in {filename} (Confidence: {confidence:.2f})", confidence
        except Exception as e:
            print(f"ML prediction error for file: {str(e)}")

    if request_data:
        request_data = request_data.lower()
        sql_patterns = [
            r"union.*select", r"--", r"or\s+1\s*=\s*1", r";\s*drop",
            r"'\s*or\s*''='", r"select.*from"
        ]
        for pattern in sql_patterns:
            if re.search(pattern, request_data):
                print(f"SQL Injection detected: Pattern '{pattern}' matched in '{request_data}'")
                return "SQL Injection", None, None
    if file_content is not None:
        if not file_content:
            return "Invalid File", f"File {filename} is empty", None
        if filename:
            mime_type, _ = mimetypes.guess_type(filename)
            file_type = mime_type if mime_type else "Unknown"
        else:
            file_type = "Unknown"
        file_hash = hashlib.md5(file_content).hexdigest()
        vt_url = "https://www.virustotal.com/vtapi/v2/file/report"
        params = {"apikey": VT_API_KEY, "resource": file_hash}
        try:
            response = requests.get(vt_url, params=params)
            response.raise_for_status()
            vt_result = response.json()
            if vt_result.get("response_code") == 1 and vt_result.get("positives", 0) > 0:
                return "Malware", f"VirusTotal detected {vt_result.get('positives')}/{vt_result.get('total')} positives for {filename}", None
        except requests.RequestException as e:
            print(f"Error querying VirusTotal: {str(e)}")
        safe_file_types = ["text/plain", "image/png", "image/jpeg", "image/gif", "application/pdf"]
        if file_type in safe_file_types:
            return None, f"File {filename} scanned (Type: {file_type}, Hash: {file_hash}) - Whitelisted as safe", None
        malicious_signatures = [b'\xE8\x00\x00\x00\x00', b'\x90\x90\x90\x90\x90']
        for sig in malicious_signatures:
            if sig in file_content:
                return "Malware", f"Detected malicious signature in {filename} (Type: {file_type}, Hash: {file_hash})", None
        suspicious_extensions = [".exe", ".bat", ".cmd", ".vbs", ".js"]
        if filename and any(filename.lower().endswith(ext) for ext in suspicious_extensions):
            return "Malware", f"Detected potentially malicious file extension in {filename} (Type: {file_type}, Hash: {file_hash})", None
        return None, f"File {filename} scanned (Type: {file_type}, Hash: {file_hash})", None
    return None, None, None


def get_geolocation(ip):
    print(f"Attempting geolocation for IP: {ip}")
    if not os.path.exists(GEO_DB_PATH):
        print(f"GeoLite2 database not found at {GEO_DB_PATH}, using fallback")
        return 37.7749, -122.4194
    try:
        reader = geoip2.database.Reader(GEO_DB_PATH)
        print(f"Reader initialized for {ip}")
        response = reader.city(ip)
        latitude = response.location.latitude
        longitude = response.location.longitude
        reader.close()
        print(f"Geolocation success for {ip}: {latitude}, {longitude}")
        return latitude, longitude
    except Exception as e:
        print(f"Geolocation error for {ip}: {str(e)}")
        private_ranges = [
            '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.',
            '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
            '127.', '::1'
        ]
        if any(ip.startswith(range) for range in private_ranges):
            print(f"Private IP detected for {ip}, using fallback: 37.7749, -122.4194")
            return 37.7749, -122.4194
        print(f"No fallback applied for {ip}, returning NULL")
        return None, None


def log_attack(attack_type, source_ip, details=None, ml_confidence=None):
    conn = None
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        latitude, longitude = get_geolocation(source_ip) if attack_type else (None, None)
        print(f"Logging attack: {attack_type}, IP: {source_ip}, Lat: {latitude}, Long: {longitude}")
        conn = sqlite3.connect(DB_PATH)
        conn.execute("INSERT INTO attacks (attack_type, source_ip, timestamp, details, ml_confidence, latitude, longitude) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (attack_type, source_ip, timestamp, details, ml_confidence, latitude, longitude))
        conn.commit()
        print("Attack logged successfully with coordinates")
    except sqlite3.Error as e:
        print(f"Database error in log_attack: {str(e)}")
    finally:
        if conn:
            conn.close()


def generate_report():
    conn = None
    try:
        print("Connecting to attacks.db...")
        conn = sqlite3.connect(DB_PATH)
        print("Executing query on attacks table...")
        attacks = conn.execute("SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 5").fetchall()
        print(f"Fetched {len(attacks)} attacks: {attacks}")
        return [{"id": a[0], "type": a[1], "ip": a[2], "time": a[3], "details": a[4], "ml_confidence": a[5],
                 "latitude": a[6], "longitude": a[7]} for a in attacks] if attacks else []
    except sqlite3.Error as e:
        print(f"SQLite error in generate_report: {str(e)}")
        return []
    except Exception as e:
        print(f"Unexpected error in generate_report: {str(e)}")
        return []
    finally:
        if conn:
            conn.close()


@app.route('/analyze', methods=['POST'])
def analyze_request():
    try:
        data = request.json
        source_ip = data.get("source_ip", request.remote_addr)
        print(f"Received request from {source_ip}")
        current_time = time.time()
        if source_ip in sql_blocked_ips and current_time < sql_blocked_ips[source_ip]:
            return jsonify({"status": "blocked",
                            "message": "Your IP is blocked for 24 hours due to a previous malicious input."}), 403
        if source_ip in ddos_blocked_ips and current_time < ddos_blocked_ips[source_ip]:
            return jsonify({"status": "blocked", "message": "Your IP is blocked due to DDoS activity."}), 429
        is_ddos, ddos_details = detect_ddos(source_ip)
        if is_ddos:
            print(f"DDoS Attack Detected - Logging: {ddos_details}")
            log_attack("DDoS Attack", source_ip, ddos_details, None)
            return jsonify({"status": "attack_detected", "type": "DDoS Attack", "details": ddos_details}), 200
        request_data = data.get("request_data", "")
        print(f"Received request from {source_ip} with data: {request_data}")
        attack_type, details, confidence = detect_malware(request_data=request_data)
        if attack_type == "SQL Injection":
            log_attack(attack_type, source_ip, details, confidence)
            sql_blocked_ips[source_ip] = current_time + SQL_BLOCK_DURATION
            print(f"Blocked IP {source_ip} for {SQL_BLOCK_DURATION} seconds due to SQL injection")
            return jsonify(
                {"status": "blocked", "type": attack_type, "message": "Malicious input, IP blocked for 24 hours."}), 403
        if attack_type:
            log_attack(attack_type, source_ip, details, confidence)
            return jsonify({"status": "attack_detected", "type": attack_type, "details": details,
                            "ml_confidence": confidence}), 200
        return jsonify({"status": "clean"}), 200
    except Exception as e:
        print(f"Error in /analyze endpoint: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        source_ip = request.remote_addr
        print(f"Received /upload request from {source_ip}")
        current_time = time.time()
        if source_ip in ddos_blocked_ips and current_time < ddos_blocked_ips[source_ip]:
            return jsonify({"status": "blocked", "message": "Your IP is blocked due to DDoS activity."}), 429
        is_ddos, ddos_details = detect_ddos(source_ip)
        if is_ddos:
            log_attack("DDoS Attack", source_ip, ddos_details, None)
            return jsonify({"status": "attack_detected", "type": "DDoS Attack", "details": ddos_details}), 200
        if 'file' not in request.files:
            print("No file in request.files")
            return jsonify({"status": "error", "message": "No file uploaded"}), 400
        file = request.files['file']
        print(f"Processing file: {file.filename}")
        file_content = file.read()
        filename = file.filename
        print("Calling detect_malware...")
        attack_type, details, confidence = detect_malware(file_content=file_content, filename=filename)
        print(f"detect_malware result: attack_type={attack_type}, details={details}, confidence={confidence}")
        if attack_type == "Malware":
            log_attack(attack_type, source_ip, details, confidence)
            return jsonify({"status": "blocked", "type": attack_type,
                            "message": "Malicious file detected, unable to upload."}), 403
        print("Logging clean scan...")
        log_attack("File Scan", source_ip, details, confidence)
        return jsonify({"status": "clean", "details": details}), 200
    except Exception as e:
        print(f"Error in /upload endpoint: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


@app.route('/report', methods=['GET'])
@login_required
def get_report():
    try:
        print("Fetching report...")
        report = generate_report()
        response = jsonify({"attacks": report})
        print(f"Response headers for /report: {response.headers}")
        return response, 200
    except Exception as e:
        print(f"Critical error in /report endpoint: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


@app.route('/debug', methods=['GET'])
def debug():
    return jsonify({"status": "success", "message": "Flask server is running"}), 200


@app.route('/traffic', methods=['GET'])
def log_traffic():
    source_ip = request.remote_addr
    print(f"Traffic received from {source_ip}")
    current_time = time.time()
    if source_ip in ddos_blocked_ips and current_time < ddos_blocked_ips[source_ip]:
        return jsonify({"status": "blocked", "message": "Your IP is blocked due to DDoS activity."}), 429
    is_ddos, ddos_details = detect_ddos(source_ip)
    if is_ddos:
        log_attack("DDoS Attack", source_ip, ddos_details, None)
        return jsonify({"status": "attack_detected", "type": "DDoS Attack", "details": ddos_details}), 200
    return jsonify({"status": "clean"}), 200


@app.route('/blocked-ips', methods=['GET'])
@login_required
def get_blocked_ips():
    try:
        current_time = time.time()
        print(f"Checking blocked IPs at {current_time}")
        blocked = [
                      {"ip": ip, "reason": "Brute Force", "expires": expires}
                      for ip, expires in blocked_ips.items() if expires > current_time
                  ] + [
                      {"ip": ip, "reason": "DDoS", "expires": expires}
                      for ip, expires in ddos_blocked_ips.items() if expires > current_time
                  ] + [
                      {"ip": ip, "reason": "SQL Injection", "expires": expires}
                      for ip, expires in sql_blocked_ips.items() if expires > current_time
                  ]
        print(f"Returning blocked IPs: {blocked}")
        return jsonify({"status": "success", "blocked_ips": blocked}), 200
    except Exception as e:
        print(f"Error in /blocked-ips endpoint: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


@app.route('/unblock-ip', methods=['POST'])
@login_required
def unblock_ip():
    try:
        data = request.json
        ip_to_unblock = data.get("ip")
        if not ip_to_unblock:
            return jsonify({"status": "error", "message": "No IP provided"}), 400
        current_time = time.time()
        if ip_to_unblock in blocked_ips and blocked_ips[ip_to_unblock] > current_time:
            del blocked_ips[ip_to_unblock]
            request_counts[ip_to_unblock] = []
            print(f"Unblocked IP {ip_to_unblock} from brute force block")
        if ip_to_unblock in ddos_blocked_ips and ddos_blocked_ips[ip_to_unblock] > current_time:
            del ddos_blocked_ips[ip_to_unblock]
            request_tracker_ddos[ip_to_unblock] = []
            print(f"Unblocked IP {ip_to_unblock} from DDoS block")
        if ip_to_unblock in sql_blocked_ips and sql_blocked_ips[ip_to_unblock] > current_time:
            del sql_blocked_ips[ip_to_unblock]
            print(f"Unblocked IP {ip_to_unblock} from SQL injection block")
        return jsonify({"status": "success", "message": f"IP {ip_to_unblock} unblocked"}), 200
    except Exception as e:
        print(f"Error in /unblock-ip endpoint: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


@app.route('/upload-model', methods=['POST'])
@login_required
def upload_model():
    try:
        if 'model' not in request.files:
            return jsonify({"status": "error", "message": "No model file uploaded"}), 400
        file = request.files['model']
        if not file.filename.endswith('.pkl'):
            return jsonify({"status": "error", "message": "Invalid file format. Use .pkl"}), 400
        file.save(MODEL_PATH)
        global ml_model
        ml_model = joblib.load(MODEL_PATH)
        print(f"New ML model uploaded and loaded: {MODEL_PATH}")
        return jsonify({"status": "success", "message": "Model uploaded successfully"}), 200
    except Exception as e:
        print(f"Error in /upload-model endpoint: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


@app.route('/model-metrics', methods=['GET'])
@login_required
def get_model_metrics():
    try:
        metrics = {"accuracy": 0.95, "f1_score": 0.92}
        return jsonify({"status": "success", "metrics": metrics}), 200
    except Exception as e:
        print(f"Error in /model-metrics endpoint: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


def retrain_model():
    conn = None
    try:
        print("Starting model retraining...")
        conn = sqlite3.connect(DB_PATH)
        attacks = conn.execute(
            "SELECT request_data, details, attack_type FROM attacks ORDER BY timestamp DESC LIMIT 100").fetchall()

        if not attacks:
            print("No data available for retraining.")
            return False

        X = []
        y = []
        for attack in attacks:
            request_data = attack[0] or attack[1] or ""
            features = extract_text_features(request_data)
            X.append(features)
            y.append(1 if attack[2] in ["SQL Injection", "Malware"] else 0)

        if not X or not y:
            print("Insufficient data for retraining.")
            return False

        from sklearn.ensemble import RandomForestClassifier
        model = RandomForestClassifier(n_estimators=100)
        model.fit(X, y)

        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        joblib.dump(model, MODEL_PATH)
        global ml_model
        ml_model = joblib.load(MODEL_PATH)
        print(f"Model retrained and saved to {MODEL_PATH}")
        return True
    except Exception as e:
        print(f"Error during retraining: {str(e)}")
        return False
    finally:
        if conn:
            conn.close()


@app.route('/retrain-model', methods=['POST'])
@login_required
def retrain_model_endpoint():
    try:
        success = retrain_model()
        if success:
            return jsonify({"status": "success", "message": "Model retrained successfully"})
        else:
            return jsonify({"status": "error", "message": "Failed to retrain model (insufficient data or error)"})
    except Exception as e:
        print(f"Error in /retrain-model endpoint: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


current_time = time.time()
blocked_ips["192.168.1.100"] = current_time + 3600
ddos_blocked_ips["10.0.0.50"] = current_time + 3600
sql_blocked_ips["172.16.0.10"] = current_time + 86400

print("Simulated blocked IPs for testing:")
print(f"blocked_ips (Brute Force): {blocked_ips}")
print(f"ddos_blocked_ips (DDoS): {ddos_blocked_ips}")
print(f"sql_blocked_ips (SQL): {sql_blocked_ips}")

if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        print(f"Database file {DB_PATH} does not exist. Initializing database...")
        init_db()
    else:
        print(f"Database file {DB_PATH} exists. Proceeding...")
    print("Registered routes:")
    for rule in app.url_map.iter_rules():
        print(f"{rule.endpoint}: {rule.rule} ({', '.join(rule.methods)})")
    app.run(host="0.0.0.0", port=5001)


    def run_retraining():
        retrain_model()


    schedule.every(24).hours.do(run_retraining)

    while True:
        schedule.run_pending()
        time.sleep(60)