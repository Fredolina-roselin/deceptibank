import json
import logging
from datetime import datetime
import pymysql

class HoneypotLoggingSystem:
    def __init__(self, host='localhost', user='newuser1', password='StrongPassword123!', database='deceptibank'):
        self.db_config = {
            'host': host,
            'user': user,
            'password': password,
            'database': database,
            'charset': 'utf8mb4',
            'cursorclass': pymysql.cursors.DictCursor
        }

        self.logger = self._setup_logger()
        self.attack_logger = logging.getLogger('attack_logger')
        self.attack_logger.setLevel(logging.CRITICAL)
        if not self.attack_logger.handlers:
            ah = logging.StreamHandler()
            ah.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            self.attack_logger.addHandler(ah)

        self.alert_manager = self._setup_alert_manager()
        self._ensure_database()

    # ---------------- Logger & Alert ----------------
    def _setup_logger(self):
        logger = logging.getLogger('honeypot_logger')
        logger.setLevel(logging.DEBUG)
        if not logger.handlers:
            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            ch.setFormatter(formatter)
            logger.addHandler(ch)
        return logger

    def _setup_alert_manager(self):
        class DummyAlertManager:
            def check_alert_conditions(self, attack_data):
                # Implement real alerts if needed
                pass
        return DummyAlertManager()

    # ---------------- Public method to trigger attack ----------------
    def trigger_attack(self, attack_data):
        """
        Call this whenever a real attack occurs.
        attack_data should include:
            - session_id
            - ip_address
            - user_agent
            - attack_types (list)
            - indicators (list)
        """
        self.log_attack(attack_data)

    # ---------------- Attack handling ----------------
    def log_attack(self, attack_data):
        try:
            enriched_data = self._enrich_attack_data(attack_data)
            self.attack_logger.critical(json.dumps(enriched_data, default=str))
            self._update_attack_session(enriched_data)
            self._update_threat_intelligence(enriched_data)
            self.alert_manager.check_alert_conditions(enriched_data)
            self._log_system_event("attack_detected", enriched_data, severity=self._get_severity(enriched_data))
        except Exception as e:
            self.logger.error(f"Error logging attack: {str(e)}")

    def _enrich_attack_data(self, attack_data):
        enriched = attack_data.copy()
        try: enriched['geolocation'] = self._get_geolocation(attack_data.get('ip_address'))
        except: enriched['geolocation'] = {'country':'Unknown','city':'Unknown'}

        try: enriched['threat_intel'] = self._get_threat_intelligence(attack_data.get('ip_address'))
        except: enriched['threat_intel'] = []

        try: enriched['session_context'] = self._get_session_context(attack_data.get('session_id'))
        except: enriched['session_context'] = {}

        try: enriched['risk_score'] = self._calculate_risk_score(enriched)
        except: enriched['risk_score'] = 0

        if 'timestamp' not in enriched:
            enriched['timestamp'] = datetime.now().isoformat()
        return enriched

    def _get_severity(self, enriched_data):
        """Determine severity based on risk score."""
        score = enriched_data.get('risk_score',0)
        if score >= 75: return "high"
        elif score >= 50: return "medium"
        else: return "low"

    # ----------------- MySQL helper -----------------
    def _get_connection(self):
        return pymysql.connect(**self.db_config)

    def _ensure_database(self):
        """Create tables if they don't exist."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS attack_sessions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    session_id VARCHAR(255) UNIQUE,
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    first_seen DATETIME,
                    last_seen DATETIME,
                    total_requests INT DEFAULT 0,
                    threat_score FLOAT DEFAULT 0,
                    attack_types TEXT,
                    geolocation TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    ip_address VARCHAR(45),
                    threat_type VARCHAR(255),
                    confidence_score FLOAT,
                    detection_count INT DEFAULT 1,
                    first_detected DATETIME,
                    last_detected DATETIME,
                    source VARCHAR(255),
                    indicators TEXT
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_events (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    event_type VARCHAR(255),
                    event_data TEXT,
                    severity VARCHAR(50),
                    component VARCHAR(100),
                    timestamp DATETIME
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error(f"Error creating tables: {e}")

    # ----------------- Database operations -----------------
    def _update_attack_session(self, attack_data):
        try:
            session_id = attack_data.get('session_id')
            if not session_id: return
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id, total_requests, attack_types FROM attack_sessions WHERE session_id=%s", (session_id,))
            existing = cursor.fetchone()

            attack_types = attack_data.get('attack_types', [])
            if isinstance(attack_types, list): attack_types = ','.join(attack_types)
            elif attack_types is None: attack_types = ''

            now = datetime.now()

            if existing:
                existing_types = set(existing['attack_types'].split(',') if existing['attack_types'] else [])
                new_types = set(attack_types.split(',') if attack_types else [])
                combined_types = ','.join(sorted(existing_types.union(new_types)))
                total_requests = (existing['total_requests'] or 0) + 1
                cursor.execute("""
                    UPDATE attack_sessions
                    SET last_seen=%s, total_requests=%s, threat_score=%s, attack_types=%s
                    WHERE session_id=%s
                """, (now, total_requests, attack_data.get('risk_score',0), combined_types, session_id))
            else:
                cursor.execute("""
                    INSERT INTO attack_sessions
                    (session_id, ip_address, user_agent, first_seen, last_seen, total_requests, threat_score, attack_types, geolocation)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (
                    session_id,
                    attack_data.get('ip_address'),
                    attack_data.get('user_agent'),
                    now,
                    now,
                    1,
                    attack_data.get('risk_score',0),
                    attack_types,
                    json.dumps(attack_data.get('geolocation',{}))
                ))
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error(f"Error updating attack session: {e}")

    def _update_threat_intelligence(self, attack_data):
        try:
            ip_address = attack_data.get('ip_address')
            attack_types = attack_data.get('attack_types', [])
            if not ip_address or not attack_types: return
            if isinstance(attack_types,str): attack_types = attack_types.split(',')

            conn = self._get_connection()
            cursor = conn.cursor()
            now = datetime.now()
            for atype in attack_types:
                atype = atype.strip()
                if not atype: continue
                cursor.execute("SELECT id, detection_count FROM threat_intelligence WHERE ip_address=%s AND threat_type=%s", (ip_address, atype))
                existing = cursor.fetchone()
                confidence = min(float(attack_data.get('risk_score',0))/100.0,1.0)
                if existing:
                    detection_count = (existing['detection_count'] or 0) + 1
                    cursor.execute("""
                        UPDATE threat_intelligence
                        SET detection_count=%s, last_detected=%s, confidence_score=%s
                        WHERE id=%s
                    """,(detection_count, now, confidence, existing['id']))
                else:
                    cursor.execute("""
                        INSERT INTO threat_intelligence
                        (ip_address, threat_type, confidence_score, first_detected, last_detected, source, indicators)
                        VALUES (%s,%s,%s,%s,%s,%s,%s)
                    """,(ip_address, atype, confidence, now, now, 'honeypot_detection', json.dumps(attack_data.get('indicators',[]))))
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error(f"Error updating threat intelligence: {e}")

    def _log_system_event(self, event_type, event_data, severity='info'):
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO system_events (event_type, event_data, severity, component, timestamp)
                VALUES (%s,%s,%s,%s,%s)
            """,(event_type, json.dumps(event_data, default=str), severity, 'honeypot_logger', datetime.now()))
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error(f"Error logging system event: {e}")

    # ----------------- Placeholder helpers -----------------
    def _get_geolocation(self, ip): return {'country':'Reserved','city':'Local'}
    def _get_threat_intelligence(self, ip): return []
    def _get_session_context(self, session_id): return {}
    def _calculate_risk_score(self, enriched_data):
        score = 50
        indicators = enriched_data.get('indicators',[])
        if any('sqli' in str(i).lower() for i in indicators):
            score += 25
        return min(score,100)
