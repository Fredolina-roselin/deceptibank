"""
Advanced Session Management for DeceptiBank Honeypot
Handles session security, tracking, and suspicious activity detection
"""

import secrets
import json
from datetime import datetime, timedelta
from flask import session, request
import logging

class SessionManager:
    def __init__(self, app, db):
        self.app = app
        self.db = db
        self.active_sessions = {}
        self.suspicious_sessions = set()
        
        # Configure session logging
        self.session_logger = logging.getLogger('session')
        handler = logging.FileHandler('session.log')
        formatter = logging.Formatter('%(asctime)s - SESSION - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.session_logger.addHandler(handler)
        self.session_logger.setLevel(logging.INFO)
    
    def create_session(self, user_id, ip_address, user_agent):
        """Create a new secure session"""
        session_id = secrets.token_hex(32)
        
        session_data = {
            'session_id': session_id,
            'user_id': user_id,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'created_at': datetime.now(),
            'last_activity': datetime.now(),
            'page_views': [],
            'suspicious_activities': [],
            'is_verified': False
        }
        
        self.active_sessions[session_id] = session_data
        
        # Set Flask session
        session['session_id'] = session_id
        session['user_id'] = user_id
        session['created_at'] = datetime.now().isoformat()
        
        self.session_logger.info(f"Session created - ID: {session_id[:8]}..., User: {user_id}, IP: {ip_address}")
        
        return session_id
    
    def update_session_activity(self, session_id, activity_data):
        """Update session with new activity"""
        if session_id not in self.active_sessions:
            return False
        
        session_data = self.active_sessions[session_id]
        session_data['last_activity'] = datetime.now()
        
        # Track page views
        if 'page' in activity_data:
            session_data['page_views'].append({
                'page': activity_data['page'],
                'timestamp': datetime.now(),
                'method': activity_data.get('method', 'GET')
            })
        
        # Detect suspicious patterns
        suspicious_indicators = self.detect_suspicious_session_activity(session_data, activity_data)
        
        if suspicious_indicators:
            session_data['suspicious_activities'].extend(suspicious_indicators)
            self.suspicious_sessions.add(session_id)
            
            self.session_logger.warning(f"Suspicious activity - Session: {session_id[:8]}..., "
                                      f"Indicators: {suspicious_indicators}")
        
        return True
    
    def detect_suspicious_session_activity(self, session_data, activity_data):
        """Detect suspicious patterns in session activity"""
        suspicious_indicators = []
        
        # Check for rapid page navigation (bot-like behavior)
        recent_views = [v for v in session_data['page_views'] 
                       if datetime.now() - v['timestamp'] < timedelta(seconds=30)]
        
        if len(recent_views) > 10:
            suspicious_indicators.append("Rapid page navigation detected")
        
        # Check for unusual user agent changes
        current_ua = request.headers.get('User-Agent', '')
        if current_ua != session_data['user_agent']:
            suspicious_indicators.append("User agent changed during session")
        
        # Check for IP address changes
        current_ip = self.get_client_ip()
        if current_ip != session_data['ip_address']:
            suspicious_indicators.append("IP address changed during session")
        
        # Check for direct access to admin pages without proper navigation
        if activity_data.get('page') == 'admin_dashboard':
            admin_navigation = any(v['page'] in ['login', 'admin_verify'] 
                                 for v in session_data['page_views'][-5:])
            if not admin_navigation:
                suspicious_indicators.append("Direct admin access without proper authentication flow")
        
        # Check for automated tool signatures
        automated_patterns = [
            'python-requests',
            'curl/',
            'wget/',
            'sqlmap',
            'nikto',
            'nmap',
            'burp',
            'zap'
        ]
        
        user_agent = request.headers.get('User-Agent', '').lower()
        for pattern in automated_patterns:
            if pattern in user_agent:
                suspicious_indicators.append(f"Automated tool detected: {pattern}")
        
        # Check for session hijacking attempts
        if len(session_data['suspicious_activities']) > 5:
            suspicious_indicators.append("Multiple suspicious activities in session")
        
        return suspicious_indicators
    
    def get_client_ip(self):
        """Get the real client IP address"""
        if request.environ.get('HTTP_X_FORWARDED_FOR'):
            return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[0].strip()
        elif request.environ.get('HTTP_X_REAL_IP'):
            return request.environ['HTTP_X_REAL_IP']
        else:
            return request.remote_addr
    
    def is_session_valid(self, session_id):
        """Check if session is valid and not expired"""
        if session_id not in self.active_sessions:
            return False
        
        session_data = self.active_sessions[session_id]
        
        # Check for session timeout (24 hours)
        if datetime.now() - session_data['created_at'] > timedelta(hours=24):
            self.destroy_session(session_id)
            return False
        
        # Check for inactivity timeout (2 hours)
        if datetime.now() - session_data['last_activity'] > timedelta(hours=2):
            self.destroy_session(session_id)
            return False
        
        return True
    
    def destroy_session(self, session_id):
        """Destroy session and clean up"""
        if session_id in self.active_sessions:
            session_data = self.active_sessions[session_id]
            
            # Log session destruction
            self.session_logger.info(f"Session destroyed - ID: {session_id[:8]}..., "
                                   f"Duration: {datetime.now() - session_data['created_at']}, "
                                   f"Pages viewed: {len(session_data['page_views'])}")
            
            # Log to database if suspicious
            if session_id in self.suspicious_sessions:
                self.log_suspicious_session(session_data)
            
            del self.active_sessions[session_id]
            self.suspicious_sessions.discard(session_id)
        
        # Clear Flask session
        session.clear()
    
    def log_suspicious_session(self, session_data):
        """Log suspicious session to database"""
        from app import HoneypotLog
        
        log_entry = HoneypotLog(
            ip_address=session_data['ip_address'],
            user_agent=session_data['user_agent'],
            request_method='SESSION',
            request_path='/session_analysis',
            request_data=json.dumps({
                'session_duration': str(datetime.now() - session_data['created_at']),
                'pages_viewed': len(session_data['page_views']),
                'suspicious_activities': session_data['suspicious_activities'],
                'page_sequence': [v['page'] for v in session_data['page_views'][-10:]]
            }),
            session_id=session_data['session_id'],
            threat_level='high',
            attack_type='suspicious_session',
            geolocation=f"IP: {session_data['ip_address']}",
            is_suspicious=True
        )
        
        self.db.session.add(log_entry)
        self.db.session.commit()
    
    def get_session_stats(self):
        """Get session statistics"""
        total_sessions = len(self.active_sessions)
        suspicious_sessions = len(self.suspicious_sessions)
        
        # Calculate average session duration
        if self.active_sessions:
            durations = [
                (datetime.now() - s['created_at']).total_seconds()
                for s in self.active_sessions.values()
            ]
            avg_duration = sum(durations) / len(durations)
        else:
            avg_duration = 0
        
        # Get most viewed pages
        all_page_views = []
        for session_data in self.active_sessions.values():
            all_page_views.extend([v['page'] for v in session_data['page_views']])
        
        page_counts = {}
        for page in all_page_views:
            page_counts[page] = page_counts.get(page, 0) + 1
        
        top_pages = sorted(page_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'total_sessions': total_sessions,
            'suspicious_sessions': suspicious_sessions,
            'avg_duration_minutes': round(avg_duration / 60, 2),
            'top_pages': top_pages
        }
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions (run periodically)"""
        expired_sessions = []
        
        for session_id, session_data in self.active_sessions.items():
            if datetime.now() - session_data['created_at'] > timedelta(hours=24):
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            self.destroy_session(session_id)
        
        self.session_logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
        
        return len(expired_sessions)