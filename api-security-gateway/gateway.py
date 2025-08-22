#!/usr/bin/env python3
import sys
import json
import argparse
import time
import re
import hashlib
import hmac
import base64
import sqlite3
import threading
import logging
import smtplib
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import urllib.request
import urllib.error
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ssl
import socket

class ThreatDetector:
    def __init__(self):
        self.attack_patterns = {
            'sql_injection': [
                r'union.*select', r'drop.*table', r'insert.*into',
                r'delete.*from', r'update.*set', r'exec.*xp_',
                r'sp_executesql', r'xp_cmdshell'
            ],
            'xss': [
                r'<script.*?>.*?</script>', r'javascript:', r'onload=',
                r'onerror=', r'onclick=', r'onmouseover=', r'eval\(',
                r'document\.cookie', r'window\.location'
            ],
            'path_traversal': [
                r'\.\./', r'\.\.\\', r'%2e%2e%2f', r'%2e%2e\\',
                r'/etc/passwd', r'/proc/version', r'boot\.ini'
            ],
            'command_injection': [
                r';\s*cat\s+', r';\s*ls\s+', r';\s*id\s*;',
                r'`.*`', r'\$\(.*\)', r'&&\s*cat\s+',
                r'\|\s*nc\s+', r'wget\s+http'
            ],
            'ldap_injection': [
                r'\*\)\(.*=', r'\)\(\|', r'\)\(&',
                r'admin\)\(', r'\*\)\(uid='
            ]
        }
        
        self.suspicious_headers = [
            'x-forwarded-for', 'x-real-ip', 'x-originating-ip',
            'cf-connecting-ip', 'true-client-ip'
        ]
    
    def detect_threats(self, request_data, headers):
        threats = []
        combined_data = request_data + str(headers)
        
        for threat_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, combined_data, re.IGNORECASE):
                    threats.append({
                        'type': threat_type,
                        'pattern': pattern,
                        'severity': self.get_severity(threat_type)
                    })
        
        return threats
    
    def get_severity(self, threat_type):
        severity_map = {
            'sql_injection': 'HIGH',
            'xss': 'MEDIUM',
            'path_traversal': 'HIGH',
            'command_injection': 'CRITICAL',
            'ldap_injection': 'HIGH'
        }
        return severity_map.get(threat_type, 'LOW')

class DatabaseManager:
    def __init__(self, db_path='gateway.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Requests table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                client_ip TEXT,
                method TEXT,
                path TEXT,
                user_agent TEXT,
                status_code INTEGER,
                response_time REAL,
                threat_level TEXT,
                blocked BOOLEAN DEFAULT FALSE
            )
        ''')
        
        # Threats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                client_ip TEXT,
                threat_type TEXT,
                pattern TEXT,
                severity TEXT,
                request_data TEXT,
                blocked BOOLEAN DEFAULT FALSE
            )
        ''')
        
        # API keys table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash TEXT UNIQUE,
                name TEXT,
                rate_limit INTEGER DEFAULT 100,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used DATETIME,
                active BOOLEAN DEFAULT TRUE
            )
        ''')
        
        # Blocked IPs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE,
                reason TEXT,
                blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME,
                permanent BOOLEAN DEFAULT FALSE
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_request(self, client_ip, method, path, user_agent, status_code, response_time, threat_level, blocked):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO requests (client_ip, method, path, user_agent, status_code, response_time, threat_level, blocked)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (client_ip, method, path, user_agent, status_code, response_time, threat_level, blocked))
        conn.commit()
        conn.close()
    
    def log_threat(self, client_ip, threat_type, pattern, severity, request_data, blocked):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO threats (client_ip, threat_type, pattern, severity, request_data, blocked)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (client_ip, threat_type, pattern, severity, request_data, blocked))
        conn.commit()
        conn.close()
    
    def is_ip_blocked(self, ip_address):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT COUNT(*) FROM blocked_ips 
            WHERE ip_address = ? AND (expires_at > CURRENT_TIMESTAMP OR permanent = TRUE)
        ''', (ip_address,))
        result = cursor.fetchone()[0] > 0
        conn.close()
        return result
    
    def block_ip(self, ip_address, reason, duration_hours=24):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        expires_at = datetime.now() + timedelta(hours=duration_hours) if duration_hours else None
        cursor.execute('''
            INSERT OR REPLACE INTO blocked_ips (ip_address, reason, expires_at, permanent)
            VALUES (?, ?, ?, ?)
        ''', (ip_address, reason, expires_at, duration_hours is None))
        conn.commit()
        conn.close()

class AlertManager:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    def send_alert(self, alert_type, message, severity='MEDIUM'):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        alert_message = f"[{severity}] {alert_type} - {timestamp}\n{message}"
        
        # Log alert
        self.logger.warning(alert_message)
        
        # Send email if configured
        if self.config.get('alerts', {}).get('email'):
            self.send_email_alert(alert_type, alert_message, severity)
        
        # Send webhook if configured
        if self.config.get('alerts', {}).get('webhook_url'):
            self.send_webhook_alert(alert_type, alert_message, severity)
    
    def send_email_alert(self, alert_type, message, severity):
        try:
            email_config = self.config['alerts']['email']
            
            msg = MIMEMultipart()
            msg['From'] = email_config['from']
            msg['To'] = email_config['to']
            msg['Subject'] = f"API Gateway Alert: {alert_type} [{severity}]"
            
            msg.attach(MIMEText(message, 'plain'))
            
            server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])
            server.starttls()
            server.login(email_config['username'], email_config['password'])
            server.send_message(msg)
            server.quit()
            
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")
    
    def send_webhook_alert(self, alert_type, message, severity):
        try:
            webhook_url = self.config['alerts']['webhook_url']
            data = {
                'alert_type': alert_type,
                'message': message,
                'severity': severity,
                'timestamp': datetime.now().isoformat()
            }
            
            req = urllib.request.Request(
                webhook_url,
                data=json.dumps(data).encode('utf-8'),
                headers={'Content-Type': 'application/json'}
            )
            
            with urllib.request.urlopen(req) as response:
                if response.status != 200:
                    self.logger.error(f"Webhook alert failed: {response.status}")
                    
        except Exception as e:
            self.logger.error(f"Failed to send webhook alert: {e}")

class SecurityGateway(BaseHTTPRequestHandler):
    # Class variables for shared state
    rate_limits = {}
    failed_attempts = {}
    config = {}
    db_manager = None
    threat_detector = None
    alert_manager = None
    
    def log_message(self, format, *args):
        # Override to use our logger
        logging.info(f"{self.client_address[0]} - {format % args}")
    
    def do_GET(self):
        self.handle_request()
    
    def do_POST(self):
        self.handle_request()
    
    def do_PUT(self):
        self.handle_request()
    
    def do_DELETE(self):
        self.handle_request()
    
    def do_PATCH(self):
        self.handle_request()
    
    def do_OPTIONS(self):
        self.handle_cors_preflight()
    
    def handle_cors_preflight(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key')
        self.send_header('Access-Control-Max-Age', '86400')
        self.end_headers()
    
    def handle_request(self):
        start_time = time.time()
        client_ip = self.get_client_ip()
        threat_level = 'LOW'
        blocked = False
        
        try:
            # Security checks
            if not self.security_checks(client_ip):
                blocked = True
                threat_level = 'HIGH'
                return
            
            # Threat detection
            threats = self.detect_threats()
            if threats:
                threat_level = max([t['severity'] for t in threats], key=lambda x: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].index(x))
                
                # Block if critical threat
                if any(t['severity'] == 'CRITICAL' for t in threats):
                    self.block_request("Critical threat detected")
                    blocked = True
                    return
            
            # Forward request to backend
            self.forward_request()
            
        except Exception as e:
            logging.error(f"Request handling error: {e}")
            self.send_error(500, "Internal server error")
        
        finally:
            # Log request
            response_time = time.time() - start_time
            user_agent = self.headers.get('User-Agent', '')
            status_code = getattr(self, '_status_code', 200)
            
            self.db_manager.log_request(
                client_ip, self.command, self.path, user_agent,
                status_code, response_time, threat_level, blocked
            )
    
    def get_client_ip(self):
        # Check for forwarded IP headers
        forwarded_headers = ['X-Forwarded-For', 'X-Real-IP', 'CF-Connecting-IP']
        
        for header in forwarded_headers:
            if header in self.headers:
                ip = self.headers[header].split(',')[0].strip()
                if self.is_valid_ip(ip):
                    return ip
        
        return self.client_address[0]
    
    def is_valid_ip(self, ip):
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    def security_checks(self, client_ip):
        # IP blocking check
        if self.db_manager.is_ip_blocked(client_ip):
            self.send_error(403, "IP blocked")
            return False
        
        # Rate limiting
        if not self.check_rate_limit(client_ip):
            self.send_error(429, "Rate limit exceeded")
            self.increment_failed_attempts(client_ip)
            return False
        
        # API key validation
        if not self.validate_api_key():
            self.send_error(401, "Invalid or missing API key")
            self.increment_failed_attempts(client_ip)
            return False
        
        # Request size check
        content_length = int(self.headers.get('Content-Length', 0))
        max_size = self.config.get('security', {}).get('max_request_size', 1048576)
        if content_length > max_size:
            self.send_error(413, "Request too large")
            return False
        
        return True
    
    def check_rate_limit(self, client_ip):
        current_time = time.time()
        rate_config = self.config.get('security', {}).get('rate_limit', {})
        requests_per_minute = rate_config.get('requests_per_minute', 50)
        window_seconds = rate_config.get('window_seconds', 60)
        
        if client_ip not in self.rate_limits:
            self.rate_limits[client_ip] = []
        
        # Clean old requests
        self.rate_limits[client_ip] = [
            req_time for req_time in self.rate_limits[client_ip]
            if current_time - req_time < window_seconds
        ]
        
        if len(self.rate_limits[client_ip]) >= requests_per_minute:
            return False
        
        self.rate_limits[client_ip].append(current_time)
        return True
    
    def validate_api_key(self):
        api_key = self.headers.get('X-API-Key') or self.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not api_key:
            return False
        
        # Simple validation - in production, use proper key management
        valid_keys = self.config.get('security', {}).get('api_keys', [])
        return api_key in valid_keys
    
    def detect_threats(self):
        # Get request data
        request_data = self.path
        if self.command in ['POST', 'PUT', 'PATCH']:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                try:
                    body = self.rfile.read(content_length).decode('utf-8')
                    request_data += body
                    # Reset rfile for later use
                    import io
                    self.rfile = io.BytesIO(body.encode('utf-8'))
                except:
                    pass
        
        threats = self.threat_detector.detect_threats(request_data, dict(self.headers))
        
        # Log threats
        client_ip = self.get_client_ip()
        for threat in threats:
            self.db_manager.log_threat(
                client_ip, threat['type'], threat['pattern'],
                threat['severity'], request_data, False
            )
            
            # Send alert for high/critical threats
            if threat['severity'] in ['HIGH', 'CRITICAL']:
                self.alert_manager.send_alert(
                    f"Threat Detected: {threat['type']}",
                    f"IP: {client_ip}\nPattern: {threat['pattern']}\nData: {request_data[:500]}",
                    threat['severity']
                )
        
        return threats
    
    def increment_failed_attempts(self, client_ip):
        current_time = time.time()
        
        if client_ip not in self.failed_attempts:
            self.failed_attempts[client_ip] = []
        
        # Clean old attempts (last hour)
        self.failed_attempts[client_ip] = [
            attempt_time for attempt_time in self.failed_attempts[client_ip]
            if current_time - attempt_time < 3600
        ]
        
        self.failed_attempts[client_ip].append(current_time)
        
        # Auto-block after too many failed attempts
        if len(self.failed_attempts[client_ip]) >= 10:
            self.db_manager.block_ip(client_ip, "Too many failed attempts", 24)
            self.alert_manager.send_alert(
                "IP Auto-blocked",
                f"IP {client_ip} blocked due to {len(self.failed_attempts[client_ip])} failed attempts",
                "HIGH"
            )
    
    def block_request(self, reason):
        client_ip = self.get_client_ip()
        self.send_error(403, f"Request blocked: {reason}")
        
        self.alert_manager.send_alert(
            "Request Blocked",
            f"IP: {client_ip}\nReason: {reason}\nPath: {self.path}",
            "HIGH"
        )
    
    def forward_request(self):
        try:
            backend_config = self.config.get('gateway', {})
            backend_host = backend_config.get('backend', 'localhost:8080')
            use_https = backend_config.get('use_https', False)
            
            protocol = 'https' if use_https else 'http'
            backend_url = f"{protocol}://{backend_host}{self.path}"
            
            # Create request
            req = urllib.request.Request(backend_url, method=self.command)
            
            # Copy headers (exclude hop-by-hop headers)
            hop_by_hop = ['connection', 'keep-alive', 'proxy-authenticate',
                         'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade']
            
            for header, value in self.headers.items():
                if header.lower() not in hop_by_hop and header.lower() != 'host':
                    req.add_header(header, value)
            
            # Handle request body
            if self.command in ['POST', 'PUT', 'PATCH']:
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length > 0:
                    req.data = self.rfile.read(content_length)
            
            # Create SSL context for HTTPS
            if use_https:
                ssl_context = ssl.create_default_context()
                if backend_config.get('verify_ssl', True) == False:
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
            else:
                ssl_context = None
            
            # Make request
            with urllib.request.urlopen(req, context=ssl_context) as response:
                self._status_code = response.status
                
                # Send response
                self.send_response(response.status)
                
                # Copy response headers
                for header, value in response.headers.items():
                    if header.lower() not in hop_by_hop:
                        self.send_header(header, value)
                
                # Add security headers
                security_headers = {
                    'X-Content-Type-Options': 'nosniff',
                    'X-Frame-Options': 'DENY',
                    'X-XSS-Protection': '1; mode=block',
                    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
                    'Content-Security-Policy': "default-src 'self'",
                    'Referrer-Policy': 'strict-origin-when-cross-origin'
                }
                
                for header, value in security_headers.items():
                    self.send_header(header, value)
                
                # CORS headers
                allowed_origins = self.config.get('security', {}).get('allowed_origins', ['*'])
                origin = self.headers.get('Origin')
                if origin and (origin in allowed_origins or '*' in allowed_origins):
                    self.send_header('Access-Control-Allow-Origin', origin)
                
                self.end_headers()
                
                # Copy response body
                self.wfile.write(response.read())
                
        except urllib.error.HTTPError as e:
            self._status_code = e.code
            self.send_error(e.code, e.reason)
        except Exception as e:
            self._status_code = 500
            logging.error(f"Forward request error: {e}")
            self.send_error(500, "Backend connection failed")

def setup_logging(config):
    log_config = config.get('logging', {})
    log_level = getattr(logging, log_config.get('level', 'INFO'))
    log_format = log_config.get('format', '%(asctime)s - %(levelname)s - %(message)s')
    log_file = log_config.get('file', 'gateway.log')
    
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )

def load_config(config_file):
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.warning(f"Config file {config_file} not found, using defaults")
        return {}
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON in config file: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Advanced API Security Gateway')
    parser.add_argument('--port', type=int, default=8000, help='Gateway port')
    parser.add_argument('--backend', default='localhost:8080', help='Backend server')
    parser.add_argument('--config', default='config.json', help='Configuration file')
    parser.add_argument('--db', default='gateway.db', help='Database file')
    
    args = parser.parse_args()
    
    # Load configuration
    config = load_config(args.config)
    
    # Override with command line arguments
    if not config.get('gateway'):
        config['gateway'] = {}
    config['gateway']['port'] = args.port
    config['gateway']['backend'] = args.backend
    
    # Setup logging
    setup_logging(config)
    
    # Initialize components
    db_manager = DatabaseManager(args.db)
    threat_detector = ThreatDetector()
    alert_manager = AlertManager(config)
    
    # Set class variables
    SecurityGateway.config = config
    SecurityGateway.db_manager = db_manager
    SecurityGateway.threat_detector = threat_detector
    SecurityGateway.alert_manager = alert_manager
    
    logging.info(f"Starting Advanced API Security Gateway on port {args.port}")
    logging.info(f"Backend: {args.backend}")
    logging.info(f"Database: {args.db}")
    
    server = HTTPServer(('', args.port), SecurityGateway)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Shutting down gateway...")
        server.shutdown()

if __name__ == '__main__':
    main()