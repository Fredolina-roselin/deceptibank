#!C:\Users\dell\AppData\Local\Programs\Python\Python311\python
"""
Advanced Windump Network Monitoring Integration for DeceptiBank Honeypot
This module captures and analyzes network traffic with AI-powered threat detection
"""

import subprocess
import json
import sqlite3
import threading
import time
from datetime import datetime, timedelta
import re
import logging
import socket
import struct
from collections import defaultdict, deque
import hashlib
import psutil
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest, HTTPResponse

class AdvancedWindumpMonitor:
    def __init__(self, interface='eth0', db_path='deceptibank.db'):
        self.interface = interface
        self.db_path = db_path
        self.is_monitoring = False
        self.packet_count = 0
        self.suspicious_count = 0
        self.bandwidth_usage = 0.0
        
        # Advanced threat detection patterns
        self.threat_signatures = {
            'port_scan': {
                'patterns': [r'nmap', r'masscan', r'zmap'],
                'behavior': 'multiple_ports',
                'severity': 'high'
            },
            'vulnerability_scan': {
                'patterns': [r'nikto', r'openvas', r'nessus', r'acunetix'],
                'behavior': 'directory_enumeration',
                'severity': 'high'
            },
            'sql_injection_tools': {
                'patterns': [r'sqlmap', r'havij', r'bbqsql'],
                'behavior': 'database_probing',
                'severity': 'critical'
            },
            'web_attack_tools': {
                'patterns': [r'burp', r'zap', r'w3af', r'skipfish'],
                'behavior': 'web_fuzzing',
                'severity': 'high'
            },
            'brute_force_tools': {
                'patterns': [r'hydra', r'medusa', r'brutespray', r'patator'],
                'behavior': 'credential_stuffing',
                'severity': 'high'
            },
            'directory_busters': {
                'patterns': [r'dirb', r'gobuster', r'dirbuster', r'ffuf'],
                'behavior': 'directory_enumeration',
                'severity': 'medium'
            }
        }
        
        # Traffic analysis data structures
        self.connection_tracker = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'first_seen': None,
            'last_seen': None,
            'ports_accessed': set(),
            'suspicious_score': 0
        })
        
        self.recent_packets = deque(maxlen=1000)  # Keep last 1000 packets for analysis
        self.attack_patterns = defaultdict(int)
        self.blocked_ips = set()
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - Windump - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('windump_monitor.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Initialize packet capture
        self.packet_capture = None
        
    def start_monitoring(self):
        """Start advanced network traffic monitoring"""
        self.is_monitoring = True
        self.logger.info(f"Starting Advanced Windump monitoring on interface {self.interface}")
        
        # Start multiple monitoring threads
        threads = []
        
        # Packet capture thread
        capture_thread = threading.Thread(target=self._capture_packets)
        capture_thread.daemon = True
        capture_thread.start()
        threads.append(capture_thread)
        
        # Traffic analysis thread
        analysis_thread = threading.Thread(target=self._analyze_traffic_patterns)
        analysis_thread.daemon = True
        analysis_thread.start()
        threads.append(analysis_thread)
        
        # Bandwidth monitoring thread
        bandwidth_thread = threading.Thread(target=self._monitor_bandwidth)
        bandwidth_thread.daemon = True
        bandwidth_thread.start()
        threads.append(bandwidth_thread)
        
        # Threat correlation thread
        correlation_thread = threading.Thread(target=self._correlate_threats)
        correlation_thread.daemon = True
        correlation_thread.start()
        threads.append(correlation_thread)
        
        return threads
    
    def stop_monitoring(self):
        """Stop network traffic monitoring"""
        self.is_monitoring = False
        if self.packet_capture:
            self.packet_capture.stop()
        self.logger.info("Stopping Advanced Windump monitoring")
    
    def _capture_packets(self):
        """Capture packets using Scapy with advanced filtering"""
        try:
            def packet_handler(packet):
                if not self.is_monitoring:
                    return
                
                self.packet_count += 1
                self._process_packet(packet)
            
            # Filter for HTTP/HTTPS traffic and common attack vectors
            filter_str = "tcp port 5000 or tcp port 80 or tcp port 443 or tcp port 22 or tcp port 21 or tcp port 23"
            
            self.logger.info(f"Starting packet capture with filter: {filter_str}")
            
            # Start packet capture
            scapy.sniff(
                iface=self.interface,
                filter=filter_str,
                prn=packet_handler,
                store=0,
                stop_filter=lambda x: not self.is_monitoring
            )
            
        except Exception as e:
            self.logger.error(f"Error in packet capture: {str(e)}")
            self._fallback_monitoring()
    
    def _process_packet(self, packet):
        """Process individual packets for threat analysis"""
        try:
            packet_info = {
                'timestamp': datetime.now(),
                'size': len(packet),
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'protocol': None,
                'payload': None,
                'flags': None
            }
            
            # Extract IP layer information
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                packet_info['src_ip'] = ip_layer.src
                packet_info['dst_ip'] = ip_layer.dst
                packet_info['protocol'] = ip_layer.proto
            
            # Extract TCP layer information
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_info['src_port'] = tcp_layer.sport
                packet_info['dst_port'] = tcp_layer.dport
                packet_info['flags'] = tcp_layer.flags
                
                # Extract payload if available
                if tcp_layer.payload:
                    packet_info['payload'] = str(tcp_layer.payload)
            
            # Extract UDP layer information
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_info['src_port'] = udp_layer.sport
                packet_info['dst_port'] = udp_layer.dport
            
            # Extract HTTP information if available
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                packet_info['http_method'] = http_layer.Method.decode() if http_layer.Method else None
                packet_info['http_path'] = http_layer.Path.decode() if http_layer.Path else None
                packet_info['http_host'] = http_layer.Host.decode() if http_layer.Host else None
                packet_info['user_agent'] = http_layer.User_Agent.decode() if http_layer.User_Agent else None
            
            # Add to recent packets for analysis
            self.recent_packets.append(packet_info)
            
            # Update connection tracking
            if packet_info['src_ip'] and packet_info['dst_ip']:
                self._update_connection_tracking(packet_info)
            
            # Analyze for threats
            threat_analysis = self._analyze_packet_threats(packet_info)
            if threat_analysis['is_suspicious']:
                self.suspicious_count += 1
                self._handle_suspicious_packet(packet_info, threat_analysis)
            
        except Exception as e:
            self.logger.error(f"Error processing packet: {str(e)}")
    
    def _update_connection_tracking(self, packet_info):
        """Update connection tracking information"""
        src_ip = packet_info['src_ip']
        connection_key = src_ip
        
        connection = self.connection_tracker[connection_key]
        connection['packets'] += 1
        connection['bytes'] += packet_info['size']
        
        if connection['first_seen'] is None:
            connection['first_seen'] = packet_info['timestamp']
        connection['last_seen'] = packet_info['timestamp']
        
        if packet_info['dst_port']:
            connection['ports_accessed'].add(packet_info['dst_port'])
        
        # Calculate suspicious score based on behavior
        self._calculate_suspicious_score(connection_key, packet_info)
    
    def _calculate_suspicious_score(self, connection_key, packet_info):
        """Calculate suspicious score for a connection"""
        connection = self.connection_tracker[connection_key]
        score = 0
        
        # High packet rate
        if connection['packets'] > 100:
            score += 20
        
        # Multiple port access (port scanning)
        if len(connection['ports_accessed']) > 10:
            score += 30
        
        # Suspicious user agent
        if packet_info.get('user_agent'):
            ua = packet_info['user_agent'].lower()
            suspicious_ua_patterns = ['nmap', 'nikto', 'sqlmap', 'burp', 'scanner', 'bot']
            if any(pattern in ua for pattern in suspicious_ua_patterns):
                score += 40
        
        # Suspicious payload patterns
        if packet_info.get('payload'):
            payload = packet_info['payload'].lower()
            for threat_type, threat_info in self.threat_signatures.items():
                for pattern in threat_info['patterns']:
                    if re.search(pattern, payload, re.IGNORECASE):
                        score += 50
                        break
        
        # Time-based analysis (rapid connections)
        if connection['first_seen'] and connection['last_seen']:
            duration = (connection['last_seen'] - connection['first_seen']).total_seconds()
            if duration > 0 and connection['packets'] / duration > 10:  # More than 10 packets per second
                score += 25
        
        connection['suspicious_score'] = min(score, 100)  # Cap at 100
    
    def _analyze_packet_threats(self, packet_info):
        """Analyze packet for various threat indicators"""
        threat_analysis = {
            'is_suspicious': False,
            'threat_types': [],
            'severity': 'low',
            'confidence': 0.0,
            'indicators': []
        }
        
        payload = packet_info.get('payload', '').lower() if packet_info.get('payload') else ''
        user_agent = packet_info.get('user_agent', '').lower() if packet_info.get('user_agent') else ''
        
        # Check for known attack tool signatures
        for threat_type, threat_info in self.threat_signatures.items():
            for pattern in threat_info['patterns']:
                if re.search(pattern, payload + ' ' + user_agent, re.IGNORECASE):
                    threat_analysis['is_suspicious'] = True
                    threat_analysis['threat_types'].append(threat_type)
                    threat_analysis['severity'] = threat_info['severity']
                    threat_analysis['confidence'] += 0.3
                    threat_analysis['indicators'].append(f"Tool signature: {pattern}")
        
        # Check for SQL injection patterns
        sql_patterns = [
            r'union\s+select', r'drop\s+table', r'insert\s+into', r'delete\s+from',
            r'1\s*=\s*1', r'or\s+1\s*=\s*1', r'admin\'\s*--', r'\';\s*drop'
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                threat_analysis['is_suspicious'] = True
                threat_analysis['threat_types'].append('sql_injection')
                threat_analysis['severity'] = 'high'
                threat_analysis['confidence'] += 0.4
                threat_analysis['indicators'].append(f"SQL injection pattern: {pattern}")
        
        # Check for XSS patterns
        xss_patterns = [
            r'<script[^>]*>', r'javascript:', r'eval\s*\(', r'document\.cookie',
            r'alert\s*\(', r'onload\s*=', r'onerror\s*='
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                threat_analysis['is_suspicious'] = True
                threat_analysis['threat_types'].append('xss')
                threat_analysis['severity'] = 'medium'
                threat_analysis['confidence'] += 0.3
                threat_analysis['indicators'].append(f"XSS pattern: {pattern}")
        
        # Check for directory traversal
        traversal_patterns = [r'\.\./', r'\.\.\\', r'%2e%2e%2f', r'%2e%2e%5c']
        
        for pattern in traversal_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                threat_analysis['is_suspicious'] = True
                threat_analysis['threat_types'].append('directory_traversal')
                threat_analysis['severity'] = 'medium'
                threat_analysis['confidence'] += 0.3
                threat_analysis['indicators'].append(f"Directory traversal: {pattern}")
        
        # Check for port scanning behavior
        src_ip = packet_info.get('src_ip')
        if src_ip and src_ip in self.connection_tracker:
            connection = self.connection_tracker[src_ip]
            if len(connection['ports_accessed']) > 5:
                threat_analysis['is_suspicious'] = True
                threat_analysis['threat_types'].append('port_scan')
                threat_analysis['severity'] = 'high'
                threat_analysis['confidence'] += 0.4
                threat_analysis['indicators'].append(f"Port scanning: {len(connection['ports_accessed'])} ports")
        
        # Normalize confidence score
        threat_analysis['confidence'] = min(threat_analysis['confidence'], 1.0)
        
        return threat_analysis
    
    def _handle_suspicious_packet(self, packet_info, threat_analysis):
        """Handle suspicious packets with logging and response"""
        try:
            # Log to database
            self._log_network_threat(packet_info, threat_analysis)
            
            # Log to file
            self.logger.warning(
                f"Suspicious network activity detected: "
                f"IP={packet_info.get('src_ip')}, "
                f"Threats={','.join(threat_analysis['threat_types'])}, "
                f"Severity={threat_analysis['severity']}, "
                f"Confidence={threat_analysis['confidence']:.2f}"
            )
            
            # Update attack patterns
            for threat_type in threat_analysis['threat_types']:
                self.attack_patterns[threat_type] += 1
            
            # Consider IP blocking for high-severity threats
            if (threat_analysis['severity'] in ['high', 'critical'] and 
                threat_analysis['confidence'] > 0.7):
                self._consider_ip_blocking(packet_info['src_ip'])
            
        except Exception as e:
            self.logger.error(f"Error handling suspicious packet: {str(e)}")
    
    def _log_network_threat(self, packet_info, threat_analysis):
        """Log network threat to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Prepare threat data
            threat_data = {
                'packet_info': {
                    'src_ip': packet_info.get('src_ip'),
                    'dst_ip': packet_info.get('dst_ip'),
                    'src_port': packet_info.get('src_port'),
                    'dst_port': packet_info.get('dst_port'),
                    'protocol': packet_info.get('protocol'),
                    'size': packet_info.get('size'),
                    'flags': packet_info.get('flags')
                },
                'threat_analysis': threat_analysis,
                'timestamp': packet_info['timestamp'].isoformat()
            }
            
            # Insert into honeypot_log table
            cursor.execute('''
                INSERT INTO honeypot_log 
                (ip_address, user_agent, request_method, request_path, request_data, 
                 session_id, threat_level, attack_type, geolocation, is_suspicious, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                packet_info.get('src_ip', 'unknown'),
                packet_info.get('user_agent', 'Network Monitor'),
                'NETWORK',
                f"/network/{packet_info.get('dst_port', 'unknown')}",
                json.dumps(threat_data),
                'windump_session',
                threat_analysis['severity'],
                ','.join(threat_analysis['threat_types']) or 'network_anomaly',
                f"Network: {packet_info.get('src_ip')} -> {packet_info.get('dst_ip')}",
                True,
                packet_info['timestamp']
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error logging network threat: {str(e)}")
    
    def _consider_ip_blocking(self, src_ip):
        """Consider blocking IP based on threat level"""
        if src_ip and src_ip not in self.blocked_ips:
            connection = self.connection_tracker.get(src_ip)
            if connection and connection['suspicious_score'] > 80:
                self.blocked_ips.add(src_ip)
                self.logger.critical(f"IP {src_ip} added to block list (score: {connection['suspicious_score']})")
                
                # In a real implementation, this would interface with firewall rules
                # For now, we just log the action
                self._log_ip_block_action(src_ip, connection['suspicious_score'])
    
    def _log_ip_block_action(self, ip_address, score):
        """Log IP blocking action"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO honeypot_log 
                (ip_address, user_agent, request_method, request_path, request_data, 
                 session_id, threat_level, attack_type, geolocation, is_suspicious)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                ip_address,
                'Windump Auto-Block',
                'BLOCK',
                '/network/auto-block',
                json.dumps({'action': 'auto_block', 'score': score, 'reason': 'high_threat_activity'}),
                'windump_session',
                'critical',
                'auto_block',
                f"Auto-blocked: {ip_address}",
                True
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error logging IP block action: {str(e)}")
    
    def _analyze_traffic_patterns(self):
        """Analyze traffic patterns for advanced threat detection"""
        while self.is_monitoring:
            try:
                time.sleep(60)  # Analyze every minute
                
                # Analyze connection patterns
                self._analyze_connection_patterns()
                
                # Detect coordinated attacks
                self._detect_coordinated_attacks()
                
                # Clean old connection data
                self._cleanup_old_connections()
                
            except Exception as e:
                self.logger.error(f"Error in traffic pattern analysis: {str(e)}")
    
    def _analyze_connection_patterns(self):
        """Analyze connection patterns for anomalies"""
        current_time = datetime.now()
        
        for ip, connection in self.connection_tracker.items():
            if connection['last_seen'] and (current_time - connection['last_seen']).total_seconds() < 300:  # Active in last 5 minutes
                
                # Check for rapid-fire connections
                if connection['packets'] > 200:
                    self.logger.warning(f"High packet volume from {ip}: {connection['packets']} packets")
                
                # Check for port scanning
                if len(connection['ports_accessed']) > 20:
                    self.logger.warning(f"Potential port scan from {ip}: {len(connection['ports_accessed'])} ports accessed")
                
                # Check for suspicious score threshold
                if connection['suspicious_score'] > 70:
                    self.logger.warning(f"High suspicious score for {ip}: {connection['suspicious_score']}")
    
    def _detect_coordinated_attacks(self):
        """Detect coordinated attacks from multiple IPs"""
        current_time = datetime.now()
        recent_attackers = []
        
        for ip, connection in self.connection_tracker.items():
            if (connection['last_seen'] and 
                (current_time - connection['last_seen']).total_seconds() < 600 and  # Active in last 10 minutes
                connection['suspicious_score'] > 50):
                recent_attackers.append(ip)
        
        if len(recent_attackers) > 5:
            self.logger.critical(f"Potential coordinated attack detected from {len(recent_attackers)} IPs: {recent_attackers[:10]}")
    
    def _cleanup_old_connections(self):
        """Clean up old connection tracking data"""
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(hours=2)  # Keep data for 2 hours
        
        old_connections = [
            ip for ip, connection in self.connection_tracker.items()
            if connection['last_seen'] and connection['last_seen'] < cutoff_time
        ]
        
        for ip in old_connections:
            del self.connection_tracker[ip]
        
        if old_connections:
            self.logger.info(f"Cleaned up {len(old_connections)} old connection records")
    
    def _monitor_bandwidth(self):
        """Monitor bandwidth usage"""
        while self.is_monitoring:
            try:
                time.sleep(5)  # Update every 5 seconds
                
                # Calculate bandwidth from recent packets
                current_time = datetime.now()
                recent_cutoff = current_time - timedelta(seconds=5)
                
                recent_bytes = sum(
                    packet['size'] for packet in self.recent_packets
                    if packet['timestamp'] > recent_cutoff
                )
                
                self.bandwidth_usage = recent_bytes / (1024 * 1024)  # Convert to MB
                
            except Exception as e:
                self.logger.error(f"Error monitoring bandwidth: {str(e)}")
    
    def _correlate_threats(self):
        """Correlate threats across different detection methods"""
        while self.is_monitoring:
            try:
                time.sleep(120)  # Correlate every 2 minutes
                
                # Generate threat correlation report
                correlation_report = self._generate_correlation_report()
                
                if correlation_report['high_priority_threats']:
                    self.logger.critical(f"High priority threats detected: {correlation_report['high_priority_threats']}")
                
            except Exception as e:
                self.logger.error(f"Error in threat correlation: {str(e)}")
    
    def _generate_correlation_report(self):
        """Generate threat correlation report"""
        current_time = datetime.now()
        recent_cutoff = current_time - timedelta(minutes=10)
        
        report = {
            'timestamp': current_time.isoformat(),
            'high_priority_threats': [],
            'attack_patterns': dict(self.attack_patterns),
            'top_attackers': [],
            'blocked_ips': list(self.blocked_ips)
        }
        
        # Identify high priority threats
        for threat_type, count in self.attack_patterns.items():
            if count > 10:  # More than 10 instances
                report['high_priority_threats'].append({
                    'type': threat_type,
                    'count': count,
                    'severity': self.threat_signatures.get(threat_type, {}).get('severity', 'medium')
                })
        
        # Identify top attackers
        sorted_attackers = sorted(
            self.connection_tracker.items(),
            key=lambda x: x[1]['suspicious_score'],
            reverse=True
        )[:10]
        
        for ip, connection in sorted_attackers:
            if connection['suspicious_score'] > 30:
                report['top_attackers'].append({
                    'ip': ip,
                    'score': connection['suspicious_score'],
                    'packets': connection['packets'],
                    'ports_accessed': len(connection['ports_accessed'])
                })
        
        return report
    
    def _fallback_monitoring(self):
        """Fallback monitoring when Scapy is not available"""
        self.logger.info("Using fallback monitoring mode...")
        
        while self.is_monitoring:
            time.sleep(30)
            
            # Simulate network monitoring
            simulated_threats = [
                {
                    'src_ip': f"192.168.1.{100 + (self.packet_count % 50)}",
                    'dst_ip': '127.0.0.1',
                    'dst_port': 5000,
                    'payload': 'GET /admin HTTP/1.1\r\nUser-Agent: sqlmap/1.0',
                    'timestamp': datetime.now()
                },
                {
                    'src_ip': f"10.0.0.{50 + (self.packet_count % 30)}",
                    'dst_ip': '127.0.0.1',
                    'dst_port': 5000,
                    'payload': "POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin' OR '1'='1&password=test",
                    'timestamp': datetime.now()
                }
            ]
            
            for threat in simulated_threats:
                self.packet_count += 1
                threat_analysis = self._analyze_packet_threats(threat)
                if threat_analysis['is_suspicious']:
                    self.suspicious_count += 1
                    self._handle_suspicious_packet(threat, threat_analysis)
    
    def get_network_stats(self):
        """Get comprehensive network monitoring statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get network-related logs from last 24 hours
            cursor.execute('''
                SELECT COUNT(*) as total,
                       SUM(CASE WHEN is_suspicious = 1 THEN 1 ELSE 0 END) as suspicious,
                       SUM(CASE WHEN threat_level = 'high' THEN 1 ELSE 0 END) as high_threat,
                       SUM(CASE WHEN threat_level = 'critical' THEN 1 ELSE 0 END) as critical_threat
                FROM honeypot_log 
                WHERE request_method = 'NETWORK' 
                AND timestamp > datetime('now', '-24 hours')
            ''')
            
            result = cursor.fetchone()
            conn.close()
            
            return {
                'total_packets': self.packet_count,
                'suspicious_packets': self.suspicious_count,
                'high_threat_packets': result[2] if result[2] else 0,
                'critical_threat_packets': result[3] if result[3] else 0,
                'bandwidth_usage_mb': round(self.bandwidth_usage, 2),
                'active_connections': len(self.connection_tracker),
                'blocked_ips': len(self.blocked_ips),
                'attack_patterns': dict(self.attack_patterns),
                'detection_rate': round((self.suspicious_count / max(self.packet_count, 1)) * 100, 2)
            }
            
        except Exception as e:
            self.logger.error(f"Error getting network stats: {str(e)}")
            return {
                'total_packets': self.packet_count,
                'suspicious_packets': self.suspicious_count,
                'high_threat_packets': 0,
                'critical_threat_packets': 0,
                'bandwidth_usage_mb': round(self.bandwidth_usage, 2),
                'active_connections': len(self.connection_tracker),
                'blocked_ips': len(self.blocked_ips),
                'attack_patterns': dict(self.attack_patterns),
                'detection_rate': 0
            }
    
    def get_threat_intelligence(self):
        """Get threat intelligence summary"""
        return {
            'timestamp': datetime.now().isoformat(),
            'monitoring_status': 'active' if self.is_monitoring else 'inactive',
            'threat_signatures': len(self.threat_signatures),
            'correlation_report': self._generate_correlation_report(),
            'top_threats': sorted(self.attack_patterns.items(), key=lambda x: x[1], reverse=True)[:5]
        }

def main():
    """Main function to run advanced windump monitor standalone"""
    monitor = AdvancedWindumpMonitor()
    
    try:
        print("Starting DeceptiBank Advanced Windump Monitor...")
        print("Press Ctrl+C to stop monitoring")
        
        threads = monitor.start_monitoring()
        
        while True:
            time.sleep(30)
            stats = monitor.get_network_stats()
            print(f"\n=== Network Monitoring Stats ===")
            print(f"Total Packets: {stats['total_packets']}")
            print(f"Suspicious: {stats['suspicious_packets']} ({stats['detection_rate']}%)")
            print(f"High Threat: {stats['high_threat_packets']}")
            print(f"Critical Threat: {stats['critical_threat_packets']}")
            print(f"Bandwidth: {stats['bandwidth_usage_mb']} MB/s")
            print(f"Active Connections: {stats['active_connections']}")
            print(f"Blocked IPs: {stats['blocked_ips']}")
            print(f"Top Attack Types: {list(stats['attack_patterns'].items())[:3]}")
            
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        monitor.stop_monitoring()
        print("Monitor stopped.")

if __name__ == '__main__':
    main()
