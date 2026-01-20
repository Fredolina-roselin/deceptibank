import random
import json
import re
import time
from datetime import datetime, timedelta
from collections import defaultdict
import hashlib
import logging

class AdvancedAIDeceptionEngine:
    def __init__(self, db_session):
        self.db = db_session
        self.threat_patterns = {
            'sql_injection': [
                r'union\s+select', r'drop\s+table', r'insert\s+into', r'delete\s+from',
                r'1\s*=\s*1', r'or\s+1\s*=\s*1', r'admin\'\s*--', r'\';\s*drop',
                r'information_schema', r'sysobjects', r'msysobjects'
            ],
            'xss': [
                r'<script[^>]*>', r'javascript:', r'eval\s*\(', r'document\.cookie',
                r'alert\s*\(', r'onload\s*=', r'onerror\s*=', r'<iframe[^>]*>',
                r'vbscript:', r'expression\s*\('
            ],
            'directory_traversal': [
                r'\.\./', r'\.\.\\', r'%2e%2e%2f', r'%2e%2e%5c',
                r'/etc/passwd', r'/windows/system32', r'boot\.ini'
            ],
            'command_injection': [
                r';\s*cat\s+', r';\s*ls\s+', r';\s*dir\s+', r';\s*whoami',
                r'`.*`', r'\$$$.*$$', r'&&\s*', r'\|\|\s*'
            ],
            'brute_force': [
                r'admin', r'administrator', r'root', r'password', r'123456',
                r'qwerty', r'letmein', r'welcome', r'monkey'
            ]
        }
        
        self.deception_strategies = {
            'delay_response': self._delay_response,
            'fake_error': self._generate_fake_error,
            'honeytrap_data': self._generate_honeytrap_data,
            'fake_success': self._generate_fake_success,
            'redirect_trap': self._generate_redirect_trap
        }
        
        self.attacker_profiles = defaultdict(lambda: {
            'first_seen': datetime.utcnow(),
            'attack_count': 0,
            'attack_types': set(),
            'sophistication_level': 'low',
            'behavioral_patterns': [],
            'deception_history': []
        })
        
        self.fake_data_generators = {
            'banking_accounts': self._generate_fake_banking_data,
            'user_credentials': self._generate_fake_credentials,
            'transaction_history': self._generate_fake_transactions,
            'system_info': self._generate_fake_system_info,
            'database_schema': self._generate_fake_db_schema
        }

    def analyze_threat(self, request_data, ip_address, user_agent, session_data=None):
        """Advanced threat analysis with behavioral profiling"""
        threat_analysis = {
            'threat_level': 'low',
            'attack_types': [],
            'confidence_score': 0.0,
            'sophistication_level': 'low',
            'recommended_deception': 'standard',
            'behavioral_indicators': [],
            'is_suspicious': False
        }
        
        # Convert request data to analyzable string
        request_str = self._serialize_request_data(request_data)
        
        # Pattern matching analysis
        detected_attacks = self._detect_attack_patterns(request_str)
        threat_analysis['attack_types'] = detected_attacks
        
        # Behavioral analysis
        behavioral_score = self._analyze_behavior(ip_address, user_agent, detected_attacks)
        threat_analysis['behavioral_indicators'] = behavioral_score['indicators']
        
        # Calculate overall threat level
        pattern_score = len(detected_attacks) * 0.3
        behavior_score = behavioral_score['score']
        
        total_score = pattern_score + behavior_score
        threat_analysis['confidence_score'] = min(total_score, 1.0)
        
        # Determine threat level
        if total_score >= 0.8:
            threat_analysis['threat_level'] = 'critical'
            threat_analysis['sophistication_level'] = 'high'
        elif total_score >= 0.6:
            threat_analysis['threat_level'] = 'high'
            threat_analysis['sophistication_level'] = 'medium'
        elif total_score >= 0.3:
            threat_analysis['threat_level'] = 'medium'
            threat_analysis['sophistication_level'] = 'low'
        
        threat_analysis['is_suspicious'] = total_score >= 0.3
        
        # Update attacker profile
        self._update_attacker_profile(ip_address, threat_analysis)
        
        # Recommend deception strategy
        threat_analysis['recommended_deception'] = self._recommend_deception_strategy(
            ip_address, threat_analysis
        )
        
        return threat_analysis

    def _serialize_request_data(self, request_data):
        """Convert request data to analyzable string"""
        if isinstance(request_data, dict):
            return json.dumps(request_data, default=str).lower()
        return str(request_data).lower()

    def _detect_attack_patterns(self, request_str):
        """Detect attack patterns using regex matching"""
        detected_attacks = []
        
        for attack_type, patterns in self.threat_patterns.items():
            for pattern in patterns:
                if re.search(pattern, request_str, re.IGNORECASE):
                    detected_attacks.append(attack_type)
                    break
        
        return list(set(detected_attacks))  # Remove duplicates

    def _analyze_behavior(self, ip_address, user_agent, detected_attacks):
        """Analyze behavioral patterns for sophistication assessment"""
        profile = self.attacker_profiles[ip_address]
        indicators = []
        score = 0.0
        
        # Update profile
        profile['attack_count'] += 1
        profile['attack_types'].update(detected_attacks)
        
        # Frequency analysis
        time_window = datetime.utcnow() - timedelta(minutes=10)
        recent_attacks = sum(1 for timestamp in profile['behavioral_patterns'] 
                           if timestamp > time_window)
        
        if recent_attacks > 5:
            indicators.append('high_frequency_attacks')
            score += 0.3
        
        # Diversity of attack types
        if len(profile['attack_types']) > 3:
            indicators.append('diverse_attack_methods')
            score += 0.2
        
        # User agent analysis
        if self._is_suspicious_user_agent(user_agent):
            indicators.append('suspicious_user_agent')
            score += 0.1
        
        # Persistence analysis
        if profile['attack_count'] > 10:
            indicators.append('persistent_attacker')
            score += 0.2
        
        # Add current timestamp to behavioral patterns
        profile['behavioral_patterns'].append(datetime.utcnow())
        
        # Keep only recent patterns (last hour)
        cutoff_time = datetime.utcnow() - timedelta(hours=1)
        profile['behavioral_patterns'] = [
            timestamp for timestamp in profile['behavioral_patterns']
            if timestamp > cutoff_time
        ]
        
        return {'score': score, 'indicators': indicators}

    def _is_suspicious_user_agent(self, user_agent):
        """Check if user agent is suspicious"""
        suspicious_patterns = [
            'sqlmap', 'nikto', 'nmap', 'burp', 'zap', 'curl', 'wget',
            'python-requests', 'bot', 'crawler', 'scanner'
        ]
        
        if not user_agent:
            return True
        
        user_agent_lower = user_agent.lower()
        return any(pattern in user_agent_lower for pattern in suspicious_patterns)

    def _update_attacker_profile(self, ip_address, threat_analysis):
        """Update attacker profile with new analysis"""
        profile = self.attacker_profiles[ip_address]
        
        # Update sophistication level
        if threat_analysis['confidence_score'] > 0.7:
            profile['sophistication_level'] = 'high'
        elif threat_analysis['confidence_score'] > 0.4:
            profile['sophistication_level'] = 'medium'

    def _recommend_deception_strategy(self, ip_address, threat_analysis):
        """Recommend appropriate deception strategy"""
        profile = self.attacker_profiles[ip_address]
        
        # High sophistication attackers get more elaborate deception
        if profile['sophistication_level'] == 'high':
            return random.choice(['honeytrap_data', 'fake_success', 'delay_response'])
        elif threat_analysis['threat_level'] in ['high', 'critical']:
            return random.choice(['fake_error', 'redirect_trap', 'delay_response'])
        else:
            return 'standard'

    def execute_deception(self, strategy, context=None):
        """Execute the recommended deception strategy"""
        if strategy in self.deception_strategies:
            return self.deception_strategies[strategy](context)
        return None

    def _delay_response(self, context=None):
        """Introduce artificial delay to slow down attackers"""
        delay = random.uniform(2, 8)  # 2-8 second delay
        time.sleep(delay)
        return {'type': 'delay', 'duration': delay}

    def _generate_fake_error(self, context=None):
        """Generate convincing fake error messages"""
        fake_errors = [
            "Database connection timeout. Please try again later.",
            "Internal server error. Contact system administrator.",
            "Access denied. Insufficient privileges.",
            "Session expired. Please login again.",
            "Invalid request format. Please check your input.",
            "Service temporarily unavailable. Maintenance in progress."
        ]
        
        error = random.choice(fake_errors)
        return {'type': 'fake_error', 'message': error, 'status_code': 500}

    def _generate_honeytrap_data(self, context=None):
        """Generate fake sensitive data to trap attackers"""
        data_type = context.get('data_type', 'general') if context else 'general'
        
        if data_type in self.fake_data_generators:
            return self.fake_data_generators[data_type]()
        
        # Default honeytrap data
        return {
            'type': 'honeytrap_data',
            'data': {
                'admin_password': 'temp_admin_2024!',
                'database_host': '192.168.1.100',
                'api_key': 'sk-fake-key-' + ''.join(random.choices('abcdef0123456789', k=32)),
                'backup_location': '/var/backups/sensitive/',
                'encryption_key': hashlib.md5(str(random.random()).encode()).hexdigest()
            }
        }

    def _generate_fake_success(self, context=None):
        """Generate fake success responses to keep attackers engaged"""
        success_messages = [
            "Login successful. Redirecting to dashboard...",
            "Data retrieved successfully.",
            "Transaction completed. Reference ID: " + str(random.randint(100000, 999999)),
            "File uploaded successfully.",
            "Configuration updated.",
            "Backup created successfully."
        ]
        
        message = random.choice(success_messages)
        return {'type': 'fake_success', 'message': message, 'status_code': 200}

    def _generate_redirect_trap(self, context=None):
        """Generate fake redirects to waste attacker time"""
        fake_urls = [
            '/admin/login.php',
            '/administrator/index.php',
            '/wp-admin/',
            '/phpmyadmin/',
            '/admin/dashboard.html',
            '/management/console.jsp'
        ]
        
        url = random.choice(fake_urls)
        return {'type': 'redirect_trap', 'url': url, 'status_code': 302}

    def _generate_fake_banking_data(self):
        """Generate fake banking account data"""
        accounts = []
        for i in range(random.randint(2, 5)):
            account = {
                'account_number': f"****{random.randint(1000, 9999)}",
                'account_type': random.choice(['Savings', 'Current', 'Fixed Deposit']),
                'balance': round(random.uniform(1000, 100000), 2),
                'currency': 'USD',
                'status': 'Active'
            }
            accounts.append(account)
        
        return {'type': 'banking_data', 'accounts': accounts}

    def _generate_fake_credentials(self):
        """Generate fake user credentials"""
        usernames = ['admin', 'administrator', 'root', 'manager', 'supervisor']
        passwords = ['admin123', 'password', 'welcome', 'manager2024', 'temp123']
        
        credentials = []
        for i in range(random.randint(3, 7)):
            cred = {
                'username': random.choice(usernames) + str(random.randint(1, 99)),
                'password': random.choice(passwords),
                'role': random.choice(['admin', 'user', 'manager']),
                'last_login': (datetime.utcnow() - timedelta(days=random.randint(1, 30))).isoformat()
            }
            credentials.append(cred)
        
        return {'type': 'credentials', 'users': credentials}

    def _generate_fake_transactions(self):
        """Generate fake transaction history"""
        transactions = []
        for i in range(random.randint(10, 25)):
            transaction = {
                'id': random.randint(100000, 999999),
                'date': (datetime.utcnow() - timedelta(days=random.randint(1, 90))).strftime('%Y-%m-%d'),
                'amount': round(random.uniform(-5000, 10000), 2),
                'description': random.choice([
                    'Salary Credit', 'ATM Withdrawal', 'Online Transfer',
                    'Bill Payment', 'Interest Credit', 'Maintenance Fee'
                ]),
                'balance': round(random.uniform(5000, 50000), 2)
            }
            transactions.append(transaction)
        
        return {'type': 'transactions', 'data': transactions}

    def _generate_fake_system_info(self):
        """Generate fake system information"""
        return {
            'type': 'system_info',
            'data': {
                'server_version': 'Apache/2.4.41 (Ubuntu)',
                'php_version': '7.4.3',
                'mysql_version': '8.0.25',
                'os': 'Ubuntu 20.04.3 LTS',
                'server_ip': '192.168.1.100',
                'document_root': '/var/www/html',
                'upload_max_filesize': '2M',
                'memory_limit': '128M'
            }
        }

    def _generate_fake_db_schema(self):
        """Generate fake database schema information"""
        tables = [
            {'name': 'users', 'columns': ['id', 'username', 'password', 'email', 'role']},
            {'name': 'accounts', 'columns': ['id', 'user_id', 'account_number', 'balance', 'type']},
            {'name': 'transactions', 'columns': ['id', 'account_id', 'amount', 'description', 'timestamp']},
            {'name': 'admin_logs', 'columns': ['id', 'admin_id', 'action', 'timestamp', 'ip_address']},
            {'name': 'config', 'columns': ['id', 'key', 'value', 'updated_at']}
        ]
        
        return {'type': 'database_schema', 'tables': tables}

    def get_attacker_statistics(self):
        """Get statistics about tracked attackers"""
        stats = {
            'total_attackers': len(self.attacker_profiles),
            'high_sophistication': 0,
            'medium_sophistication': 0,
            'low_sophistication': 0,
            'most_common_attacks': defaultdict(int),
            'top_attackers': []
        }
        
        for ip, profile in self.attacker_profiles.items():
            # Count sophistication levels
            if profile['sophistication_level'] == 'high':
                stats['high_sophistication'] += 1
            elif profile['sophistication_level'] == 'medium':
                stats['medium_sophistication'] += 1
            else:
                stats['low_sophistication'] += 1
            
            # Count attack types
            for attack_type in profile['attack_types']:
                stats['most_common_attacks'][attack_type] += 1
            
            # Track top attackers
            stats['top_attackers'].append({
                'ip': ip,
                'attack_count': profile['attack_count'],
                'sophistication': profile['sophistication_level'],
                'first_seen': profile['first_seen'].isoformat()
            })
        
        # Sort top attackers by attack count
        stats['top_attackers'].sort(key=lambda x: x['attack_count'], reverse=True)
        stats['top_attackers'] = stats['top_attackers'][:10]
        
        return stats

    def generate_threat_report(self, time_period_hours=24):
        """Generate comprehensive threat analysis report"""
        cutoff_time = datetime.utcnow() - timedelta(hours=time_period_hours)
        
        recent_attackers = {
            ip: profile for ip, profile in self.attacker_profiles.items()
            if profile['first_seen'] > cutoff_time or 
               any(timestamp > cutoff_time for timestamp in profile['behavioral_patterns'])
        }
        
        report = {
            'report_generated': datetime.utcnow().isoformat(),
            'time_period_hours': time_period_hours,
            'summary': {
                'total_recent_attackers': len(recent_attackers),
                'total_attacks': sum(profile['attack_count'] for profile in recent_attackers.values()),
                'unique_attack_types': len(set().union(*(profile['attack_types'] for profile in recent_attackers.values()))),
                'high_threat_attackers': sum(1 for profile in recent_attackers.values() if profile['sophistication_level'] == 'high')
            },
            'attack_patterns': defaultdict(int),
            'geographic_distribution': {},  # Would be populated with real geolocation data
            'recommendations': []
        }
        
        # Analyze attack patterns
        for profile in recent_attackers.values():
            for attack_type in profile['attack_types']:
                report['attack_patterns'][attack_type] += 1
        
        # Generate recommendations
        if report['summary']['high_threat_attackers'] > 5:
            report['recommendations'].append("High number of sophisticated attackers detected. Consider implementing additional security measures.")
        
        if report['attack_patterns'].get('sql_injection', 0) > 10:
            report['recommendations'].append("Multiple SQL injection attempts detected. Review input validation and parameterized queries.")
        
        if report['attack_patterns'].get('brute_force', 0) > 20:
            report['recommendations'].append("Significant brute force activity detected. Consider implementing account lockout policies.")
        
        return report
