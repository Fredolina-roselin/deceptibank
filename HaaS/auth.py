"""
Enhanced Authentication System for DeceptiBank Honeypot
Includes security features, session management, and attack detection
"""

from flask import session, request, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import re
import json
import logging
from functools import wraps
import hashlib
import time

class AuthenticationManager:
    def __init__(self, app, db):
        self.app = app
        self.db = db
        self.failed_attempts = {}  # Track failed login attempts
        self.suspicious_ips = set()  # Track suspicious IP addresses
        self.session_tokens = {}  # Track active sessions
        
        # Configure authentication logging
        self.auth_logger = logging.getLogger('auth')
        handler = logging.FileHandler('auth.log')
        formatter = logging.Formatter('%(asctime)s - AUTH - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.auth_logger.addHandler(handler)
        self.auth_logger.setLevel(logging.INFO)
    
    def get_client_ip(self):
        """Get the real client IP address"""
        if request.environ.get('HTTP_X_FORWARDED_FOR'):
            return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()
        elif request.environ.get('HTTP_X_REAL_IP'):
            return request.environ['HTTP_X_REAL_IP']
        else:
            return request.remote_addr
    
    def is_suspicious_login_attempt(self, username, password, ip_address):
        """Analyze login attempt for suspicious patterns"""
        suspicious_indicators = []
        
        # Check for common attack patterns in username
        sql_patterns = [
            r"'.*or.*'.*=.*'",
            r"union\s+select",
            r"drop\s+table",
            r"insert\s+into",
            r"delete\s+from",
            r"1=1",
            r"admin'--",
            r"' or 1=1--"
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, username, re.IGNORECASE):
                suspicious_indicators.append(f"SQL injection pattern in username: {pattern}")
        
        # Check for common attack patterns in password
        for pattern in sql_patterns:
            if re.search(pattern, password, re.IGNORECASE):
                suspicious_indicators.append(f"SQL injection pattern in password: {pattern}")
        
        # Check for XSS patterns
        xss_patterns = [
            r"<script.*?>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"eval\s*\(",
            r"document\.cookie"
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, username + password, re.IGNORECASE):
                suspicious_indicators.append(f"XSS pattern detected: {pattern}")
        
        # Check for common default credentials
        common_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('root', 'root'),
            ('root', 'password'),
            ('administrator', 'administrator'),
            ('test', 'test'),
            ('guest', 'guest'),
            ('user', 'user'),
            ('demo', 'demo')
        ]
        
        if (username.lower(), password.lower()) in common_creds:
            suspicious_indicators.append("Common default credentials attempted")
        
        # Check for brute force patterns
        if ip_address in self.failed_attempts:
            attempts = self.failed_attempts[ip_address]
            recent_attempts = [a for a in attempts if a['timestamp'] > datetime.now() - timedelta(minutes=15)]
            
            if len(recent_attempts) > 5:
                suspicious_indicators.append(f"Brute force detected: {len(recent_attempts)} attempts in 15 minutes")
        
        # Check for unusual characters or encoding
        if any(ord(char) > 127 for char in username + password):
            suspicious_indicators.append("Non-ASCII characters detected")
        
        # Check for extremely long inputs (potential buffer overflow attempts)
        if len(username) > 100 or len(password) > 100:
            suspicious_indicators.append("Unusually long input detected")
        
        return suspicious_indicators
    
    def log_failed_attempt(self, username, password, ip_address, suspicious_indicators):
        """Log failed authentication attempt"""
        if ip_address not in self.failed_attempts:
            self.failed_attempts[ip_address] = []
        
        attempt_data = {
            'username': username,
            'password_hash': hashlib.sha256(password.encode()).hexdigest()[:10],  # Partial hash for analysis
            'timestamp': datetime.now(),
            'user_agent': request.headers.get('User-Agent', ''),
            'suspicious_indicators': suspicious_indicators
        }
        
        self.failed_attempts[ip_address].append(attempt_data)
        
        # Mark IP as suspicious if multiple indicators
        if len(suspicious_indicators) > 2:
            self.suspicious_ips.add(ip_address)
        
        # Log to file
        self.auth_logger.warning(f"Failed login attempt - IP: {ip_address}, Username: {username}, "
                               f"Indicators: {len(suspicious_indicators)}")
        
        # Log to database
        from app import HoneypotLog
        log_entry = HoneypotLog(
            ip_address=ip_address,
            user_agent=request.headers.get('User-Agent', ''),
            request_method='POST',
            request_path='/login',
            request_data=json.dumps({
                'username': username,
                'password_length': len(password),
                'suspicious_indicators': suspicious_indicators
            }),
            session_id=session.get('session_id', 'anonymous'),
            threat_level='high' if len(suspicious_indicators) > 2 else 'medium',
            attack_type='authentication_attack',
            geolocation=f"IP: {ip_address}",
            is_suspicious=True
        )
        
        self.db.session.add(log_entry)
        self.db.session.commit()
    
    def authenticate_user(self, username, password):
        """Authenticate user with enhanced security monitoring"""
        from app import User
        
        ip_address = self.get_client_ip()
        
        # Check for suspicious patterns
        suspicious_indicators = self.is_suspicious_login_attempt(username, password, ip_address)
        
        # Find user
        user = User.query.filter(
            (User.username == username) | (User.email == username)
        ).first()
        
        if user and check_password_hash(user.password_hash, password):
            # Successful authentication
            self.auth_logger.info(f"Successful login - User: {user.username}, IP: {ip_address}")
            
            # Generate session token
            session_token = secrets.token_hex(32)
            session['session_token'] = session_token
            session['user_id'] = user.id
            session['user_role'] = user.role
            session['login_time'] = datetime.now().isoformat()
            session['ip_address'] = ip_address
            
            # Store session info
            self.session_tokens[session_token] = {
                'user_id': user.id,
                'ip_address': ip_address,
                'login_time': datetime.now(),
                'last_activity': datetime.now()
            }
            
            # Generate verification code
            verification_code = str(secrets.randbelow(900000) + 100000)  # 6-digit code
            user.verification_code = verification_code
            user.is_verified = False
            self.db.session.commit()
            
            # Log successful authentication
            from app import HoneypotLog
            log_entry = HoneypotLog(
                ip_address=ip_address,
                user_agent=request.headers.get('User-Agent', ''),
                request_method='POST',
                request_path='/login',
                request_data=json.dumps({
                    'username': username,
                    'success': True,
                    'user_role': user.role
                }),
                session_id=session_token,
                threat_level='low',
                attack_type='normal_login',
                geolocation=f"IP: {ip_address}",
                is_suspicious=False
            )
            
            self.db.session.add(log_entry)
            self.db.session.commit()
            
            return {'success': True, 'user': user, 'verification_code': verification_code}
        
        else:
            # Failed authentication
            self.log_failed_attempt(username, password, ip_address, suspicious_indicators)
            
            # Add delay for suspicious IPs
            if ip_address in self.suspicious_ips:
                time.sleep(2)  # Add delay to slow down attacks
            
            return {'success': False, 'suspicious_indicators': suspicious_indicators}
    
    def verify_user(self, user_id, verification_code):
        """Verify user with 2FA code"""
        from app import User
        
        user = User.query.get(user_id)
        ip_address = self.get_client_ip()
        
        if user and user.verification_code == verification_code:
            user.is_verified = True
            user.verification_code = None  # Clear the code
            self.db.session.commit()
            
            self.auth_logger.info(f"Successful verification - User: {user.username}, IP: {ip_address}")
            
            # Update session
            if 'session_token' in session:
                token = session['session_token']
                if token in self.session_tokens:
                    self.session_tokens[token]['verified'] = True
                    self.session_tokens[token]['verification_time'] = datetime.now()
            
            return {'success': True, 'user': user}
        
        else:
            # Failed verification
            self.auth_logger.warning(f"Failed verification - User ID: {user_id}, IP: {ip_address}")
            
            # Log failed verification attempt
            from app import HoneypotLog
            log_entry = HoneypotLog(
                ip_address=ip_address,
                user_agent=request.headers.get('User-Agent', ''),
                request_method='POST',
                request_path='/verify',
                request_data=json.dumps({
                    'user_id': user_id,
                    'code_provided': verification_code,
                    'success': False
                }),
                session_id=session.get('session_token', 'anonymous'),
                threat_level='medium',
                attack_type='verification_bypass',
                geolocation=f"IP: {ip_address}",
                is_suspicious=True
            )
            
            self.db.session.add(log_entry)
            self.db.session.commit()
            
            return {'success': False}
    
    def register_user(self, name, email, username, password, role='user'):
        """Register new user with validation"""
        from app import User
        
        ip_address = self.get_client_ip()
        
        # Validate input
        if not all([name, email, username, password]):
            return {'success': False, 'error': 'All fields are required'}
        
        # Check for existing users
        if User.query.filter_by(username=username).first():
            return {'success': False, 'error': 'Username already exists'}
        
        if User.query.filter_by(email=email).first():
            return {'success': False, 'error': 'Email already exists'}
        
        # Check for suspicious registration patterns
        suspicious_indicators = []
        
        # Check for SQL injection in registration data
        sql_patterns = [r"'.*or.*'.*=.*'", r"union\s+select", r"drop\s+table"]
        for field, value in [('name', name), ('email', email), ('username', username)]:
            for pattern in sql_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    suspicious_indicators.append(f"SQL injection in {field}")
        
        # Check for XSS patterns
        xss_patterns = [r"<script.*?>", r"javascript:", r"on\w+\s*="]
        for field, value in [('name', name), ('email', email), ('username', username)]:
            for pattern in xss_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    suspicious_indicators.append(f"XSS pattern in {field}")
        
        # Log suspicious registration
        if suspicious_indicators:
            self.auth_logger.warning(f"Suspicious registration - IP: {ip_address}, "
                                   f"Username: {username}, Indicators: {suspicious_indicators}")
            
            from app import HoneypotLog
            log_entry = HoneypotLog(
                ip_address=ip_address,
                user_agent=request.headers.get('User-Agent', ''),
                request_method='POST',
                request_path='/register',
                request_data=json.dumps({
                    'username': username,
                    'email': email,
                    'suspicious_indicators': suspicious_indicators
                }),
                session_id=session.get('session_id', 'anonymous'),
                threat_level='high',
                attack_type='registration_attack',
                geolocation=f"IP: {ip_address}",
                is_suspicious=True
            )
            
            self.db.session.add(log_entry)
            self.db.session.commit()
        
        # Create user
        try:
            user = User(
                name=name,
                email=email,
                username=username,
                password_hash=generate_password_hash(password),
                role=role,
                created_at=datetime.utcnow()
            )
            
            self.db.session.add(user)
            self.db.session.commit()
            
            self.auth_logger.info(f"User registered - Username: {username}, IP: {ip_address}")
            
            return {'success': True, 'user': user}
            
        except Exception as e:
            self.db.session.rollback()
            self.auth_logger.error(f"Registration error - {str(e)}")
            return {'success': False, 'error': 'Registration failed'}
    
    def is_session_valid(self, session_token):
        """Check if session is valid and not expired"""
        if session_token not in self.session_tokens:
            return False
        
        session_data = self.session_tokens[session_token]
        
        # Check if session is expired (24 hours)
        if datetime.now() - session_data['login_time'] > timedelta(hours=24):
            del self.session_tokens[session_token]
            return False
        
        # Update last activity
        session_data['last_activity'] = datetime.now()
        return True
    
    def logout_user(self, session_token=None):
        """Logout user and clean up session"""
        if not session_token:
            session_token = session.get('session_token')
        
        if session_token and session_token in self.session_tokens:
            user_id = self.session_tokens[session_token]['user_id']
            del self.session_tokens[session_token]
            
            self.auth_logger.info(f"User logged out - User ID: {user_id}")
        
        # Clear Flask session
        session.clear()
    
    def get_failed_attempts_stats(self):
        """Get statistics about failed authentication attempts"""
        total_attempts = sum(len(attempts) for attempts in self.failed_attempts.values())
        unique_ips = len(self.failed_attempts)
        suspicious_ips = len(self.suspicious_ips)
        
        # Get recent attempts (last 24 hours)
        recent_attempts = []
        for ip, attempts in self.failed_attempts.items():
            recent = [a for a in attempts if a['timestamp'] > datetime.now() - timedelta(hours=24)]
            recent_attempts.extend(recent)
        
        return {
            'total_attempts': total_attempts,
            'unique_ips': unique_ips,
            'suspicious_ips': suspicious_ips,
            'recent_attempts': len(recent_attempts),
            'top_attacking_ips': sorted(
                [(ip, len(attempts)) for ip, attempts in self.failed_attempts.items()],
                key=lambda x: x[1],
                reverse=True
            )[:10]
        }

# Authentication decorators
def login_required(f):
    """Decorator to require user login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        
        # Check session validity
        session_token = session.get('session_token')
        if session_token:
            from app import auth_manager
            if not auth_manager.is_session_valid(session_token):
                session.clear()
                flash('Your session has expired. Please log in again.')
                return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        
        from app import User
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            flash('Admin privileges required.')
            return redirect(url_for('dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function

def verified_required(f):
    """Decorator to require verified user"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        from app import User
        user = User.query.get(session['user_id'])
        if not user or not user.is_verified:
            if user and user.role == 'admin':
                return redirect(url_for('admin_verify'))
            else:
                return redirect(url_for('verify'))
        
        return f(*args, **kwargs)
    return decorated_function

# Rate limiting decorator
def rate_limit(max_requests=5, window=60):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from app import auth_manager
            
            ip_address = auth_manager.get_client_ip()
            current_time = time.time()
            
            # Initialize rate limit tracking
            if not hasattr(auth_manager, 'rate_limits'):
                auth_manager.rate_limits = {}
            
            if ip_address not in auth_manager.rate_limits:
                auth_manager.rate_limits[ip_address] = []
            
            # Clean old requests
            auth_manager.rate_limits[ip_address] = [
                req_time for req_time in auth_manager.rate_limits[ip_address]
                if current_time - req_time < window
            ]
            
            # Check rate limit
            if len(auth_manager.rate_limits[ip_address]) >= max_requests:
                # Log rate limit violation
                from app import HoneypotLog
                log_entry = HoneypotLog(
                    ip_address=ip_address,
                    user_agent=request.headers.get('User-Agent', ''),
                    request_method=request.method,
                    request_path=request.path,
                    request_data=json.dumps({'rate_limit_exceeded': True}),
                    session_id=session.get('session_token', 'anonymous'),
                    threat_level='high',
                    attack_type='rate_limit_exceeded',
                    geolocation=f"IP: {ip_address}",
                    is_suspicious=True
                )
                
                from app import db
                db.session.add(log_entry)
                db.session.commit()
                
                flash('Too many requests. Please try again later.')
                return redirect(url_for('home'))
            
            # Add current request
            auth_manager.rate_limits[ip_address].append(current_time)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator
