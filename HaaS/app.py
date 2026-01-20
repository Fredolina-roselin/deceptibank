# ---------------- Imports ---------------- #
import os
import json
import secrets
import random
import logging
import re
from logging.handlers import RotatingFileHandler
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ---------------- Flask Setup ---------------- #
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(16))
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL', 'mysql+pymysql://root:%40Roserose123@localhost/bankdatabase'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ---------------- Logging Setup ---------------- #
LOG_DIR = Path("logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)
app_log_path = LOG_DIR / "app.log"
handler = RotatingFileHandler(app_log_path, maxBytes=5 * 1024 * 1024, backupCount=3)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
handler.setLevel(logging.INFO)
app.logger.setLevel(logging.INFO)
app.logger.addHandler(handler)

# Honeypot log file (json-lines)
HONEYPOT_LOG_FILE = Path("honeypot.log")
if not HONEYPOT_LOG_FILE.exists():
    HONEYPOT_LOG_FILE.touch()

# ---------------- Database Models ---------------- #
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    verification_code = db.Column(db.String(6))
    is_verified = db.Column(db.Boolean, default=False)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    transaction_type = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    recipient = db.Column(db.String(100))
    description = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_fake = db.Column(db.Boolean, default=True)

class HoneypotLog(db.Model):
    __tablename__ = 'honeypot_log'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    attack_type = db.Column(db.String(200))
    threat_level = db.Column(db.String(10))
    request_path = db.Column(db.String(200))
    request_data = db.Column(db.Text)
    user_agent = db.Column(db.String(255))
    is_suspicious = db.Column(db.Boolean, default=False)

class AttackSession(db.Model):
    __tablename__ = 'attack_sessions'
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(255), unique=True, index=True)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    first_seen = db.Column(db.DateTime)
    last_seen = db.Column(db.DateTime)
    total_requests = db.Column(db.Integer, default=0)
    threat_score = db.Column(db.Integer, default=0)
    attack_types = db.Column(db.Text)
    geolocation = db.Column(db.Text)
    is_blocked = db.Column(db.Boolean, default=False)
    notes = db.Column(db.Text)

    def to_dict(self):
        return {
            "id": self.id,
            "session_id": self.session_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "total_requests": self.total_requests,
            "threat_score": self.threat_score,
            "attack_types": self.attack_types,
            "geolocation": self.geolocation,
            "is_blocked": self.is_blocked,
            "notes": self.notes
        }

# ---------------- Advanced AI Deception Engine ---------------- #
class AdvancedAIDeceptionEngine:
    def __init__(self):
        self.attack_memory = []

    def analyze_threat(self, request_data, ip, user_agent):
        attack_types = []
        threat_level = "low"
        data_str = str(request_data).lower()
        ua = (user_agent or "").lower()

        if any(x in data_str for x in ["drop", "delete", "union select", "or '1'='1", "insert", "update", "into outfile", "load_file("]):
            attack_types.append("sql_injection")
            threat_level = "high"
        elif "admin" in data_str:
            attack_types.append("brute_force")
            threat_level = "high"
        elif any(x in ua for x in ["curl", "python-requests", "sqlmap", "nikto", "acunetix", "wpscan"]):
            attack_types.append("automated_probe")
            if threat_level != "high":
                threat_level = "medium"
        elif any(x in data_str for x in ["wget", "rce", "exec(", "system("]):
            attack_types.append("brute_force_attempt")
            threat_level = "critical"
        else:
            attack_types.append("normal_activity")

        self.attack_memory.append({"ip": ip, "user_agent": user_agent, "attack_types": attack_types, "threat_level": threat_level, "timestamp": datetime.utcnow().isoformat()})
        return {"threat_level": threat_level, "attack_types": attack_types}

    def get_attacker_statistics(self):
        total = len(self.attack_memory)
        high = len([a for a in self.attack_memory if a["threat_level"] == "high"])
        med = len([a for a in self.attack_memory if a["threat_level"] == "medium"])
        low = len([a for a in self.attack_memory if a["threat_level"] == "low"])
        return {"total": total, "high": high, "medium": med, "low": low}

ai_engine = AdvancedAIDeceptionEngine()

# ---------------- Honeypot Logger ---------------- #
class HoneypotLogger:
    def __init__(self, db_session, log_file: Path):
        self.db_session = db_session
        self.log_file = log_file


    def trigger_attack(self, event: dict):
        event.setdefault('timestamp', datetime.utcnow().isoformat())
        event.setdefault('attack_types', [])
        event.setdefault('threat_level', 'medium')

        # write json-line file
        try:
            with self.log_file.open('a', encoding='utf-8') as f:
                f.write(json.dumps(event, default=str) + "\n")
        except Exception as e:
            app.logger.error(f"Failed to write to honeypot.log: {e}")

        # update/create attack session
        try:
            session_id = event.get('session_id')
            ip = event.get('ip_address')
            ua = event.get('user_agent', '')
            attack_types = event.get('attack_types') or []
            attack_types_str = ','.join(attack_types) if isinstance(attack_types, (list, tuple)) else (attack_types or '')
            now = datetime.utcnow()
            existing = AttackSession.query.filter_by(session_id=session_id).first() if session_id else None

            if existing:
                existing.last_seen = now
                existing.total_requests = (existing.total_requests or 0) + 1
                existing.threat_score = max(existing.threat_score or 0, int(event.get('risk_score', existing.threat_score or 0)))
                existing_types = set(existing.attack_types.split(',') if existing.attack_types else [])
                new_types = set(attack_types_str.split(',') if attack_types_str else [])
                combined = ','.join(sorted(t for t in (existing_types.union(new_types)) if t))
                existing.attack_types = combined
                if event.get('geolocation'):
                    existing.geolocation = json.dumps(event.get('geolocation'))
                self.db_session.commit()
            else:
                new_sess = AttackSession(
                    session_id=session_id or f"sess_{ip}_{int(datetime.utcnow().timestamp())}",
                    ip_address=ip,
                    user_agent=ua,
                    first_seen=now,
                    last_seen=now,
                    total_requests=1,
                    threat_score=int(event.get('risk_score', 0)),
                    attack_types=attack_types_str,
                    geolocation=json.dumps(event.get('geolocation') or {}),
                    is_blocked=False,
                    notes=None
                )
                self.db_session.add(new_sess)
                self.db_session.commit()
        except Exception as e:
            app.logger.error(f"Failed to insert/update attack_sessions: {e}")
            self.db_session.rollback()

honeypot_logger = HoneypotLogger(db.session, HONEYPOT_LOG_FILE)

# ---------------- Helper Functions ---------------- #
def send_otp_email(receiver_email, otp):
    sender_email = os.getenv('OTP_SENDER_EMAIL', 'deceptibank@gmail.com')
    sender_password = os.getenv('GMAIL_APP_PASSWORD') or "vpby oqyw nozm hdmi"
    subject = "Your DeceptiBank OTP Verification Code"
    body = f"Your OTP code is: {otp}"
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, sender_password)
            server.send_message(msg)
        app.logger.info(f"OTP sent to {receiver_email}")
        return True
    except Exception as e:
        app.logger.error(f"Error sending OTP: {e}")
        return False

def is_suspicious_input(payload, user_agent=''):
    s = str(payload).lower()
    suspicious_keywords = [
        "select", "union", "drop", "delete", "insert", "update", "or '1'='1",
        "--", ";--", "sleep(", "benchmark(", "admin", "into outfile", "load_file("
    ]
    for kw in suspicious_keywords:
        if kw in s:
            return True
    if "curl" in (user_agent or "").lower() or "python-requests" in (user_agent or "").lower():
        return True
    return False

def get_client_ip():
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or request.environ.get('REMOTE_ADDR') or '0.0.0.0'

def trigger_honeypot_attack(request_data, attack_type='suspicious_activity'):
    ip = get_client_ip()
    ua = request.headers.get('User-Agent', '')
    now = datetime.utcnow()
    session_id = f"sess_{ip}_{int(now.timestamp())}"
    analysis = ai_engine.analyze_threat(request_data, ip, ua)
    risk_map = {'low': 10, 'medium': 50, 'high': 80, 'critical': 100}
    risk_score = risk_map.get(analysis.get('threat_level', 'medium'), 50)
    event = {
        'session_id': session_id,
        'timestamp': now.isoformat(),
        'ip_address': ip,
        'user_agent': ua,
        'attack_types': analysis.get('attack_types', [attack_type]),
        'indicators': [str(request_data)],
        'threat_level': analysis.get('threat_level', 'medium'),
        'request_path': request.path,
        'request_data': str(request_data),
        'risk_score': risk_score,
        'geolocation': {'country': 'Unknown', 'city': 'Unknown'}
    }
    try:
        honeypot_logger.trigger_attack(event)
    except Exception as e:
        app.logger.error(f"Honeypot trigger failed: {e}")
    try:
        hp_log = HoneypotLog(
            timestamp=now,
            ip_address=ip,
            attack_type=', '.join(event['attack_types']) if event['attack_types'] else attack_type,
            threat_level=event['threat_level'],
            request_path=event['request_path'],
            request_data=event['request_data'][:4000],
            user_agent=ua,
            is_suspicious=True
        )
        db.session.add(hp_log)
        db.session.commit()
    except Exception as e:
        app.logger.error(f"Failed saving HoneypotLog row: {e}")
        db.session.rollback()

# ---------------- Routes ---------------- #
@app.route('/')
def home():
    return render_template('index.html')

# ---------------- User Registration ---------------- #
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not name or not email or not username or not password:
            flash("⚠️ Please fill all fields.")
            return redirect(url_for('register'))
        if User.query.filter((User.email == email) | (User.username == username)).first():
            flash("⚠️ Email or username already exists!")
            return redirect(url_for('register'))
        combined_payload = {"name": name, "email": email, "username": username}
        if is_suspicious_input(combined_payload, request.headers.get('User-Agent', '')):
            trigger_honeypot_attack(combined_payload, attack_type='suspicious_registration')
        otp = str(random.randint(100000, 999999))
        if send_otp_email(email, otp):
            user = User(
                name=name, email=email, username=username,
                password_hash=generate_password_hash(password),
                verification_code=otp, is_verified=False
            )
            db.session.add(user)
            db.session.commit()
            session['temp_user_id'] = user.id
            flash("✅ OTP sent to your email. Enter it below to verify.")
            return redirect(url_for('verify'))
        else:
            flash("❌ Failed to send OTP. Try again later.")
            return redirect(url_for('register'))
    return render_template('register.html')

# ---------------- OTP Verification ---------------- #
@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if 'temp_user_id' not in session:
        return redirect(url_for('register'))
    user = User.query.get(session['temp_user_id'])
    if not user:
        flash("⚠️ User not found. Please register again.")
        return redirect(url_for('register'))
    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        if otp == user.verification_code:
            user.is_verified = True
            user.verification_code = None
            db.session.commit()
            session['user_id'] = user.id
            session['role'] = user.role
            session.pop('temp_user_id', None)
            flash("✅ Verification successful!")
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash("❌ Invalid OTP. Try again.")
    return render_template('verify.html')

# ---------------- Login ---------------- #
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            if not user.is_verified and user.role != 'admin':
                session['temp_user_id'] = user.id
                flash("⚠️ Please verify your email first.")
                return redirect(url_for('verify'))
            session['user_id'] = user.id
            session['role'] = user.role
            flash("✅ Login successful!")
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            trigger_honeypot_attack({'username': username}, attack_type='failed_login')
            if is_suspicious_input({'username': username, 'password': password}, request.headers.get('User-Agent', '')):
                trigger_honeypot_attack({'username': username, 'password': password}, attack_type='suspicious_login_payload')
            flash("❌ Invalid credentials.")
    return render_template('login.html')

# ---------------- User Dashboard ---------------- #
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user or user.role == 'admin':
        flash("🚫 Unauthorized access!")
        return redirect(url_for('login'))
    transactions = Transaction.query.filter_by(user_id=user.id).order_by(Transaction.timestamp.desc()).all()
    balance = sum((t.amount if t.transaction_type == 'credit' else -t.amount) for t in transactions) if transactions else 0.0
    accounts = [{"type": "Checking", "account_no": "1234567890", "balance": balance}]
    return render_template('dashboard.html', user=user, transactions=transactions, balance=balance, accounts=accounts)

# ---------------- Admin Dashboard ---------------- #
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session:
        flash("⚠️ Please login first.")
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user or user.role != 'admin':
        flash("🚫 Unauthorized access!")
        return redirect(url_for('login'))

    # Fetch all sessions and honeypot logs
    sessions = AttackSession.query.order_by(AttackSession.last_seen.desc()).all()
    honeypot_logs = HoneypotLog.query.order_by(HoneypotLog.timestamp.desc()).all()

    all_logs = []

    # Process AttackSessions
    for s in sessions:
        try:
            geo_data = json.loads(s.geolocation) if s.geolocation else {}
        except Exception:
            geo_data = {}
        all_logs.append({
            "source": "AttackSession",
            "session_id": s.session_id,
            "ip_address": s.ip_address,
            "first_seen": s.first_seen,
            "last_seen": s.last_seen,
            "total_requests": s.total_requests,
            "threat_score": s.threat_score,
            "attack_types": s.attack_types,
            "geolocation": geo_data or {"country": "Unknown", "city": "Unknown"},
            "is_blocked": s.is_blocked,
            "notes": s.notes,
            "timestamp": s.last_seen or s.first_seen,
            "attack_type": s.attack_types,
            "threat_level": s.threat_score,
        })

    # Process HoneypotLogs
    for h in honeypot_logs:
        all_logs.append({
            "source": "HoneypotLog",
            "session_id": "-",
            "ip_address": h.ip_address,
            "first_seen": h.timestamp,
            "last_seen": h.timestamp,
            "total_requests": "-",
            "threat_score": h.threat_level,
            "attack_types": h.attack_type,
            "geolocation": {"country": "-", "city": "-"},
            "is_blocked": "-",
            "notes": "-",
            "timestamp": h.timestamp,
            "attack_type": h.attack_type,
            "threat_level": h.threat_level,
        })

    # Sort logs by newest first
    all_logs = sorted(all_logs, key=lambda x: x["timestamp"], reverse=True)

    # Stats for dashboard
    display_stats = {
        "high_threat_attempts": AttackSession.query.filter(AttackSession.threat_score >= 75).count(),
        "total_attempts": AttackSession.query.count(),
        "suspicious_attempts": AttackSession.query.filter(AttackSession.threat_score >= 50).count(),
        "unique_ips": db.session.query(AttackSession.ip_address).distinct().count(),
        "suspicious_ips": AttackSession.query.filter(AttackSession.threat_score >= 50).count()
    }

    return render_template(
        'admin_dashboard.html',
        logs=all_logs,
        ai_stats=ai_engine.get_attacker_statistics(),
        stats=display_stats
    )


# ---------------- Honeypot Listener ---------------- #
@app.route('/honeypot', methods=['POST'])
def honeypot_listener():
    data = request.get_json(silent=True) or {}
    ip = get_client_ip()
    ua = request.headers.get('User-Agent', '')
    analysis = ai_engine.analyze_threat(data, ip, ua)
    if analysis['threat_level'] in ['medium', 'high', 'critical']:
        trigger_honeypot_attack(data, attack_type=', '.join(analysis['attack_types']))
    return jsonify({"status": "logged", "analysis": analysis})

# ---------------- API: Attack Sessions ---------------- #
@app.route('/api/attack-sessions')
def api_attack_sessions():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({"error": "unauthorized"}), 403
    sessions = AttackSession.query.order_by(AttackSession.last_seen.desc()).all()
    return jsonify([s.to_dict() for s in sessions])

# ---------------- Raw Honeypot Log View ---------------- #
@app.route('/admin/honeypot/raw')
def view_raw_honeypot():
    if 'user_id' not in session:
        flash("⚠️ Please login first.")
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user or user.role != 'admin':
        flash("🚫 Unauthorized access!")
        return redirect(url_for('login'))
    try:
        with HONEYPOT_LOG_FILE.open('r', encoding='utf-8') as f:
            lines = f.readlines()[-1000:]
        return render_template('admin/honeypot_raw.html', lines=[l.strip() for l in lines])
    except Exception as e:
        app.logger.error(f"Failed to read honeypot log: {e}")
        flash("Failed to read honeypot log.")
        return redirect(url_for('admin_dashboard'))

# ---------------- Export Attack Sessions CSV ---------------- #
@app.route('/admin/attack-sessions/export')
def export_attack_sessions():
    if 'user_id' not in session:
        flash("⚠️ Please login first.")
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user or user.role != 'admin':
        flash("🚫 Unauthorized access!")
        return redirect(url_for('login'))
    sessions = AttackSession.query.order_by(AttackSession.last_seen.desc()).all()
    def generate():
        header = "id,session_id,ip_address,first_seen,last_seen,total_requests,threat_score,attack_types,geolocation,is_blocked,notes\n"
        yield header
        for s in sessions:
            row = [
                str(s.id or ''),
                (s.session_id or '').replace(',', ' '),
                (s.ip_address or ''),
                (s.first_seen.isoformat() if s.first_seen else ''),
                (s.last_seen.isoformat() if s.last_seen else ''),
                str(s.total_requests or 0),
                str(s.threat_score or 0),
                '"' + (s.attack_types or '').replace('"','""') + '"',
                '"' + (s.geolocation or '').replace('"','""') + '"',
                str(int(bool(s.is_blocked))),
                '"' + (s.notes or '').replace('"','""') + '"'
            ]
            yield ",".join(row) + "\n"
    return Response(generate(), mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=attack_sessions.csv'})


# ---------------- Logout ---------------- #
@app.route('/logout')
def logout():
    session.clear()
    flash("✅ Logged out successfully.")
    return redirect(url_for('login'))

# ---------------- Run App ---------------- #
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=int(os.getenv('PORT', 5000)))