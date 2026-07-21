"""Core security logic for the Offensive IT-Tester agent.
Extracted for unit testing and coverage measurement (Section 13)."""
import re, time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Set, List


@dataclass
class ScopeDefinition:
    authorized_hosts: Set[str] = field(default_factory=set)
    authorized_ports: Set[int] = field(default_factory=set)
    allowed_methods: Set[str] = field(default_factory=lambda: {'GET', 'POST'})
    blocked_payloads: Set[str] = field(default_factory=lambda: {'DROP', 'DELETE FROM', 'rm -rf', 'shutdown'})
    max_requests_per_minute: int = 10
    test_window_start: datetime = field(default_factory=datetime.now)
    test_window_end: datetime = field(default_factory=lambda: datetime.now() + timedelta(hours=2))

    def is_host_authorized(self, host): return host in self.authorized_hosts
    def is_port_authorized(self, port): return port in self.authorized_ports
    def is_within_window(self):
        return self.test_window_start <= datetime.now() <= self.test_window_end
    def contains_blocked_content(self, payload):
        u = payload.upper()
        return any(b.upper() in u for b in self.blocked_payloads)


class ScopeGate:
    def __init__(self, scope): self.scope = scope; self.request_timestamps = []
    def check(self, host, port, method, payload):
        if not self.scope.is_host_authorized(host): return False, "host"
        if not self.scope.is_port_authorized(port): return False, "port"
        if method.upper() not in self.scope.allowed_methods: return False, "method"
        if not self.scope.is_within_window(): return False, "window"
        if self.scope.contains_blocked_content(payload): return False, "destructive"
        now = time.time()
        self.request_timestamps = [t for t in self.request_timestamps if now - t < 60]
        if len(self.request_timestamps) >= self.scope.max_requests_per_minute:
            return False, "rate"
        return True, "ALLOWED"
    def record_request(self): self.request_timestamps.append(time.time())


class SQLiDetector:
    ERRORS = ['sql syntax', 'mysql_fetch', 'unclosed quotation', 'odbc', 'syntax error', 'sqlite3']
    def check(self, payload, body, code, t):
        bl = body.lower()
        err = any(e in bl for e in self.ERRORS)
        timing = t > 5.0 and 'sleep' in payload.lower()
        return {'vulnerable': err or timing, 'confidence': 'high' if err else ('medium' if timing else 'none')}


class XSSDetector:
    def check(self, payload, body, code, t):
        reflected = payload in body
        script = '<script' in body.lower() and payload.lower() in body.lower()
        return {'vulnerable': reflected or script, 'confidence': 'high' if script else ('medium' if reflected else 'none')}


class CSRFDetector:
    def check(self, payload, body, code, t):
        accepted = code in (200, 301, 302)
        no_token = 'csrf' not in body.lower() and 'token' not in body.lower()
        return {'vulnerable': accepted and no_token, 'confidence': 'medium' if (accepted and no_token) else 'none'}


class SSRFDetector:
    STRONG = ['instance-id', 'ami-id', 'computemetadata', '169.254.169.254', 'internal service data']
    PRIVATE_IP = re.compile(r'\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b')
    def check(self, payload, body, code, t):
        b = body.lower()
        strong = any(s in b for s in self.STRONG) or bool(self.PRIVATE_IP.search(body))
        return {'vulnerable': strong, 'confidence': 'high' if strong else 'none'}


class CmdInjDetector:
    CANARY = 'pentest_canary_12345'
    UID_SHAPE = re.compile(r'\buid=\d+\([^)]+\)')
    PASSWD_SHAPE = re.compile(r'root:.*?:0:0:')
    def check(self, payload, body, code, t):
        canary = self.CANARY in body
        structured = bool(self.UID_SHAPE.search(body) or self.PASSWD_SHAPE.search(body))
        return {'vulnerable': canary or structured, 'confidence': 'high' if canary else ('medium' if structured else 'none')}


def build_detectors():
    return {'SQLi': SQLiDetector(), 'XSS': XSSDetector(), 'CSRF': CSRFDetector(),
            'SSRF': SSRFDetector(), 'CmdInj': CmdInjDetector()}


class MockTarget:
    """Simulates a vulnerable web app for demonstration.
    In production, replace with actual HTTP requests to DVWA/Juice Shop."""

    VULNERABLE_ENDPOINTS = {
        '/login': {'methods': ['GET', 'POST'], 'contexts': ['username', 'password'], 'vulns': ['SQLi']},
        '/search': {'methods': ['GET'], 'contexts': ['query'], 'vulns': ['XSS', 'SQLi']},
        '/profile': {'methods': ['POST'], 'contexts': ['bio', 'name'], 'vulns': ['XSS']},
        '/ping': {'methods': ['POST'], 'contexts': ['host'], 'vulns': ['CmdInj']},
        '/fetch': {'methods': ['GET'], 'contexts': ['url'], 'vulns': ['SSRF']},
        '/transfer': {'methods': ['POST'], 'contexts': ['amount', 'to_account'], 'vulns': ['CSRF']},
    }

    def enumerate_surfaces(self) -> List[dict]:
        surfaces = []
        for path, info in self.VULNERABLE_ENDPOINTS.items():
            for ctx in info['contexts']:
                for method in info['methods']:
                    surfaces.append({'path': path, 'method': method,
                        'parameter': ctx, 'expected_vulns': info['vulns']})
        return surfaces

    def send_request(self, path, method, parameter, payload, attack_class=None):
        endpoint = self.VULNERABLE_ENDPOINTS.get(path, {})
        vulns = endpoint.get('vulns', [])
        body = f'<html><body>Result for: {parameter}</body></html>'
        status, resp_time = 200, 0.1
        if attack_class == 'SQLi' and 'SQLi' in vulns:
            if "'" in payload or '--' in payload:
                body = f"Error: You have an error in your SQL syntax near '{payload[:20]}'"; status = 500
            if 'sleep' in payload.lower():
                resp_time = 6.0
        elif attack_class == 'XSS' and 'XSS' in vulns:
            body = f'<html><body>Search results for: {payload}</body></html>'
        elif attack_class == 'CmdInj' and 'CmdInj' in vulns:
            if '|' in payload or ';' in payload or '&&' in payload:
                body = 'PING result: uid=33(www-data) gid=33(www-data)'
        elif attack_class == 'SSRF' and 'SSRF' in vulns:
            if '127.0.0.1' in payload or 'localhost' in payload or '10.' in payload:
                body = 'Response from localhost: internal service data'
        elif attack_class == 'CSRF' and 'CSRF' in vulns:
            body = 'Transfer successful'; status = 200
        return {'body': body, 'status_code': status, 'response_time': resp_time}


def default_scope():
    """The same authorized-lab scope used throughout the notebook."""
    return ScopeDefinition(authorized_hosts={'127.0.0.1', 'localhost', 'dvwa.local'},
                           authorized_ports={80, 8080, 5001}, max_requests_per_minute=30)
