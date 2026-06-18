import requests
import socket
import re
import math
import urllib.parse
import concurrent.futures
import threading
import time as t
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from api_integrations import (
    check_virustotal, check_shodan,
    check_google_safe_browsing, check_hibp_domain,
    check_nvd_cves, check_dns_security, check_ssl_details
)
import difflib
import tldextract
import html

requests.packages.urllib3.disable_warnings()

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 143, 443, 445, 465, 587, 993, 995,
                1433, 1521, 2049, 3306, 3389, 4444, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017]

PORT_META = {
    21: ('FTP', 'high'), 22: ('SSH', 'medium'), 23: ('Telnet', 'critical'), 25: ('SMTP', 'low'),
    53: ('DNS', 'low'), 80: ('HTTP', 'low'), 110: ('POP3', 'medium'), 135: ('RPC', 'high'),
    143: ('IMAP', 'medium'), 443: ('HTTPS', 'info'), 445: ('SMB', 'critical'), 465: ('SMTPS', 'low'),
    587: ('SMTP-Sub', 'low'), 993: ('IMAPS', 'info'), 995: ('POP3S', 'info'), 1433: ('MSSQL', 'critical'),
    1521: ('Oracle', 'critical'), 2049: ('NFS', 'high'), 3306: ('MySQL', 'critical'),
    3389: ('RDP', 'critical'), 4444: ('Metasploit', 'critical'), 5432: ('PostgreSQL', 'critical'),
    5900: ('VNC', 'critical'), 6379: ('Redis', 'critical'), 8080: ('HTTP-Alt', 'medium'),
    8443: ('HTTPS-Alt', 'low'), 8888: ('HTTP-Dev', 'medium'), 9200: ('Elasticsearch', 'critical'),
    27017: ('MongoDB', 'critical'),
}

# Parameters that are never injectable
SKIP_PARAMS = {
    'submit', 'change', 'login', 'send', 'token', 'user_token',
    'csrf', 'csrfmiddlewaretoken', 'authenticity_token', 'nonce',
    '__requestverificationtoken', 'button', 'action', 'btnsubmit',
    'password_new', 'password_conf', 'pass_conf', 'go', 'search_by',
    'btnlogin', 'btnregister', 'btnchange', 'sign_in', 'log_in',
}

# Extensions that are not scannable targets
SKIP_EXTENSIONS = {
    '.md', '.txt', '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.svg',
    '.ico', '.css', '.js', '.woff', '.woff2', '.ttf', '.eot',
    '.xml', '.zip', '.tar', '.gz', '.mp4', '.mp3', '.rst', '.csv',
}

# SQL error patterns — must be DB-engine-specific, never generic words
SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning:\s+mysqli?_",
    r"mysql_fetch_array\(\)",
    r"mysqli_sql_exception",
    r"pg_query\(\).*failed",
    r"psql.*error",
    r"sqlite3?\.operationalerror",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"microsoft ole db provider for sql server",
    r"com\.microsoft\.sqlserver\.jdbc",
    r"ora-\d{4,5}:",
    r"odbc sql server driver.*\[sql server\]",
    r"supplied argument is not a valid mysql",
    r"column count doesn't match value count at row",
]

# Params likely to interact with database queries
DB_PARAM_HINTS = {
    'id', 'uid', 'userid', 'user_id', 'item', 'product_id', 'cat', 'category',
    'page', 'pid', 'nid', 'aid', 'article', 'post', 'news', 'blog', 'entry',
    'record', 'row', 'key', 'ref', 'query', 'search', 'q', 'name', 'username',
    'user', 'email', 'title', 'type', 'order', 'sort',
}

# URL path segments that suggest a DB-backed endpoint
DB_PATH_HINTS = {
    'sqli', 'sql', 'login', 'search', 'product', 'item', 'article', 'news',
    'blog', 'post', 'user', 'profile', 'account', 'view', 'detail',
    'vulnerabilities', 'dvwa',
}

# Domains that are known-benign — skip aggressive injection tests
TRUSTED_DOMAINS = {
    'google.com', 'google.co.in', 'google.co.uk', 'google.com.au',
    'facebook.com', 'twitter.com', 'x.com', 'instagram.com',
    'linkedin.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'youtube.com', 'wikipedia.org', 'cloudflare.com', 'github.com',
}

SENSITIVE_FILES = [
    ('/.env', 'Environment File', 'critical'),
    ('/.git/HEAD', 'Git Repository', 'high'),
    ('/config.php', 'Config File', 'high'),
    ('/wp-config.php', 'WordPress Config', 'critical'),
    ('/backup.sql', 'Database Backup', 'critical'),
    ('/database.sql', 'Database Backup', 'critical'),
    ('/phpinfo.php', 'PHP Info Page', 'medium'),
    ('/server-status', 'Apache Status', 'medium'),
    ('/.htaccess', 'Apache Config', 'medium'),
    ('/robots.txt', 'Robots File', 'info'),
    ('/sitemap.xml', 'Sitemap', 'info'),
    ('/crossdomain.xml', 'Flash Policy', 'info'),
    ('/.DS_Store', 'Mac DS_Store', 'medium'),
    ('/package.json', 'NPM Package File', 'low'),
    ('/composer.json', 'PHP Composer', 'low'),
    ('/web.config', 'IIS Config', 'medium'),
    ('/.bash_history', 'Bash History', 'critical'),
    ('/id_rsa', 'SSH Private Key', 'critical'),
]

FILE_SIGNATURES = {
    '.env': ['APP_KEY=', 'DB_PASSWORD=', 'DATABASE_URL=', 'SECRET_KEY='],
    '.git/HEAD': ['ref: refs/heads/'],
    'config.php': ['$db_host', '$db_user', '$db_pass', 'mysqli_connect(', 'PDO('],
    'wp-config.php': ['DB_NAME', 'DB_PASSWORD', '$table_prefix'],
    'phpinfo.php': ['<title>phpinfo()', 'PHP Version', 'Zend Engine', 'php credits'],
    'web.config': ['<configuration', '<system.web', '<system.webServer'],
    'backup.sql': ['CREATE TABLE', 'INSERT INTO', 'DROP TABLE'],
    'database.sql': ['CREATE TABLE', 'INSERT INTO', 'DROP TABLE'],
    '.bash_history': ['sudo ', 'ssh ', 'mysql ', 'curl '],
    'id_rsa': ['-----BEGIN RSA PRIVATE KEY-----', '-----BEGIN OPENSSH PRIVATE KEY-----'],
}

WAF_SIGNATURES = {
    'Cloudflare': ['cloudflare', 'cf-ray', '__cfduid', 'cf-cache-status'],
    'AWS WAF': ['x-amzn-requestid', 'x-amz-cf-id'],
    'Akamai': ['akamai', 'x-akamai-request-id'],
    'Sucuri': ['x-sucuri-id', 'sucuri'],
    'ModSecurity': ['mod_security', 'modsecurity'],
    'Imperva': ['incapsula', 'x-iinfo'],
    'Barracuda': ['barra_counter_session'],
    'F5 BIG-IP': ['bigip', 'f5'],
}

ROBOTS_SENSITIVE_HINTS = [
    '/admin', '/backup', '/internal', '/private', '/dashboard', '/config',
]


class _TimeoutAdapter(HTTPAdapter):
    def __init__(self, timeout=10, *args, **kwargs):
        self._timeout = timeout
        super().__init__(*args, **kwargs)

    def send(self, *args, **kwargs):
        kwargs.setdefault('timeout', self._timeout)
        return super().send(*args, **kwargs)


class VulnScanner:
    def __init__(self, url, options=None):
        self.url = url.rstrip('/')
        self.opts = options or {}
        self.parsed = urllib.parse.urlparse(self.url)
        self.hostname = self.parsed.hostname or ''
        self.is_trusted = self._check_trusted_domain()

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.session.verify = False

        adapter = _TimeoutAdapter(timeout=10)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        self.results = {
            'vulnerabilities': [], 'ports': [], 'technologies': [],
            'dns_security': {}, 'ssl_info': {}, 'waf': None,
            'threat_intel': {}, 'score': 0,
        }
        self._vuln_ids = set()
        self._vuln_lock = threading.Lock()
        self.discovered_urls = []

    # ─────────────────────────────────────────────────────────────────────────
    def _check_trusted_domain(self):
        """Returns True if the target is a known-benign production domain."""
        ext = tldextract.extract(self.hostname)
        root = f'{ext.domain}.{ext.suffix}'.lower()
        return root in TRUSTED_DOMAINS

    # ─────────────────────────────────────────────────────────────────────────
    def _add(self, vuln):
        """Thread-safe, deduplicated vulnerability registration."""
        vuln.setdefault('confidence', 'medium')
        uid = vuln.get('id', vuln.get('name', ''))
        with self._vuln_lock:
            if uid not in self._vuln_ids:
                self._vuln_ids.add(uid)
                self.results['vulnerabilities'].append(vuln)

    # ─────────────────────────────────────────────────────────────────────────
    def _crawl(self, max_pages=20):
        """
        Crawl the site collecting HTML pages only.
        Limits depth and skips assets, error pages, and off-domain links.
        """
        discovered = set()
        queue = [self.url]

        while queue and len(discovered) < max_pages:
            current = queue.pop(0)
            if current in discovered:
                continue

            # Skip non-HTML extensions
            path = urllib.parse.urlparse(current).path.lower()
            ext = ('.' + path.rsplit('.', 1)[-1]) if ('.' in path.split('/')[-1]) else ''
            if ext in SKIP_EXTENSIONS:
                continue

            discovered.add(current)

            try:
                r = self.session.get(current, timeout=6, allow_redirects=True)
                if r.status_code >= 400:
                    continue
                if 'text/html' not in r.headers.get('content-type', '').lower():
                    continue

                soup = BeautifulSoup(r.text, 'html.parser')
                for a in soup.find_all('a', href=True):
                    href = urllib.parse.urljoin(current, a['href']).split('#')[0].strip()
                    p = urllib.parse.urlparse(href)
                    if p.netloc != self.parsed.netloc:
                        continue
                    link_ext = ('.' + p.path.lower().rsplit('.', 1)[-1]) if ('.' in p.path.split('/')[-1]) else ''
                    if link_ext in SKIP_EXTENSIONS:
                        continue
                    if href not in discovered:
                        queue.append(href)
            except Exception:
                pass

        return list(discovered)

    # ─────────────────────────────────────────────────────────────────────────
    def run(self):
        try:
            resp = self.session.get(self.url, allow_redirects=True, timeout=10)
        except Exception as e:
            return {**self.results, 'error': str(e), 'status': 'error'}

        headers = resp.headers
        body = resp.text
        soup = BeautifulSoup(body, 'html.parser')

        # Only crawl non-trusted domains to save time
        if not self.is_trusted:
            self.discovered_urls = self._crawl()
        else:
            self.discovered_urls = [self.url]

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            futures = {}

            if self.opts.get('scan_owasp', True):
                futures['owasp'] = ex.submit(self._check_owasp, resp, headers, body, soup)

            if self.opts.get('scan_injection', True) and not self.is_trusted:
                futures['injection'] = ex.submit(self._check_injection, resp, soup)

            if self.opts.get('scan_ports', True):
                futures['ports'] = ex.submit(self._scan_ports)

            if self.opts.get('scan_tech', True):
                futures['tech'] = ex.submit(self._detect_tech, headers, body)

            if self.opts.get('scan_ssl', True):
                futures['ssl'] = ex.submit(self._check_ssl)

            if self.opts.get('scan_dns', True):
                futures['dns'] = ex.submit(self._check_dns)

            futures['waf'] = ex.submit(self._detect_waf, headers, body)
            futures['files'] = ex.submit(self._check_sensitive_files)
            futures['methods'] = ex.submit(self._check_http_methods)
            futures['cookies'] = ex.submit(self._check_cookies, resp)
            futures['cors'] = ex.submit(self._check_cors)
            futures['redirect'] = ex.submit(self._check_open_redirect)

            if self.opts.get('scan_threat_intel', True):
                futures['vt'] = ex.submit(check_virustotal, self.url)
                futures['shodan'] = ex.submit(check_shodan, self.hostname)
                futures['gsb'] = ex.submit(check_google_safe_browsing, self.url)
                futures['hibp'] = ex.submit(check_hibp_domain, self.hostname)

            concurrent.futures.wait(futures.values())

        threat_intel = {}
        for key in ('vt', 'shodan', 'gsb', 'hibp'):
            if key in futures:
                try:
                    threat_intel[key] = futures[key].result()
                except Exception:
                    pass

        self.results['threat_intel'] = threat_intel
        self.results['score'] = self._calc_risk_score()
        return {**self.results, 'status': 'complete', 'url': self.url}

    # ─────────────────────────────────────────────────────────────────────────
    def _extract_injectable_params(self, target_url, page_soup):
        """
        Return {param: default_value} for params safe to inject into.
        Excludes buttons, CSRF tokens, and non-text inputs.
        """
        parsed = urllib.parse.urlparse(target_url)
        params = {}

        # URL query params
        for key, vals in urllib.parse.parse_qs(parsed.query).items():
            if key.lower() in SKIP_PARAMS:
                continue
            val = vals[0] if vals else '1'
            if val.lower() in ('submit', 'login', 'send', 'change', 'go', 'search'):
                continue
            params[key] = val

        # Form inputs
        for form in page_soup.find_all('form'):
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = (inp.get('name') or '').strip()
                if not name:
                    continue
                itype = inp.get('type', 'text').lower()
                if itype in ('submit', 'button', 'image', 'reset', 'file', 'checkbox', 'radio', 'hidden'):
                    continue
                if name.lower() in SKIP_PARAMS:
                    continue
                default = (inp.get('value') or '').strip() or '1'
                if default.lower() in ('submit', 'login', 'send', 'change', 'go'):
                    continue
                params[name] = default

        return params

    # ─────────────────────────────────────────────────────────────────────────
    def _is_db_param(self, param_key, target_url):
        """Heuristic: does this param/URL likely interact with a database?"""
        if param_key.lower() in DB_PARAM_HINTS:
            return True
        path = urllib.parse.urlparse(target_url).path.lower()
        return any(hint in path for hint in DB_PATH_HINTS)

    # ─────────────────────────────────────────────────────────────────────────
    def _baseline_has_sql_error(self, text):
        """True if the unmodified page already contains a SQL error string."""
        tl = text.lower()
        return any(re.search(p, tl) for p in SQL_ERROR_PATTERNS)

    # ─────────────────────────────────────────────────────────────────────────
    def _check_xss_context(self, response_body, payload):
        """
        Returns True only if the raw (unescaped) payload appears inside an
        executable HTML context — a <script> block, an event-handler attribute,
        or a javascript: URI — not merely as visible page text.
        """
        body_lower = response_body.lower()
        payload_lower = payload.lower()
        idx = body_lower.find(payload_lower)
        if idx == -1:
            return False

        # Must not be HTML-entity-encoded
        segment = response_body[idx: idx + len(payload) + 5]
        if '&lt;' in segment or '&gt;' in segment or '&#' in segment:
            return False

        # Context window before the payload
        pre = body_lower[max(0, idx - 300): idx]
        post = body_lower[idx: min(len(body_lower), idx + len(payload_lower) + 50)]

        # Inside a <script>...</script> block?
        last_script_open = pre.rfind('<script')
        last_script_close = pre.rfind('</script>')
        if last_script_open != -1 and last_script_open > last_script_close:
            return True

        # Payload IS a script tag pair and it is unencoded
        if '<script>' in payload_lower and '</script>' in payload_lower:
            return True

        # Inside an event handler attribute value
        event_attrs = ('onerror=', 'onload=', 'onclick=', 'onmouseover=',
                        'onfocus=', 'onblur=', 'oninput=', 'onsubmit=')
        if any(ev in post for ev in event_attrs):
            return True
        if any(ev in payload_lower for ev in event_attrs):
            return True

        # Inside a javascript: URI
        if 'javascript:' in payload_lower:
            surround = pre[-30:] + post[:30]
            if 'href=' in surround or 'src=' in surround or 'action=' in surround:
                return True

        return False

    # ─────────────────────────────────────────────────────────────────────────
    def _check_owasp(self, resp, headers, body, soup):
        h = headers

        # ── A01 — Broken Access Control ──────────────────────────────────────
        if not self.is_trusted:
            admin_paths = ['/admin', '/admin/users', '/dashboard', '/api/users', '/api/admin']
            for path in admin_paths:
                try:
                    r = self.session.get(self.url + path, allow_redirects=False, timeout=6)
                    sim = difflib.SequenceMatcher(None, resp.text[:5000], r.text[:5000]).ratio()
                    admin_kw = ['admin dashboard', 'user management', 'administrator',
                                'control panel', 'role management', 'site settings']
                    if (r.status_code == 200 and len(r.text) > 500
                            and sim < 0.70
                            and any(k in r.text.lower() for k in admin_kw)):
                        self._add({
                            'id': 'A01-BAC', 'owasp_id': 'A01:2025', 'category': 'owasp',
                            'name': 'Broken Access Control',
                            'severity': 'medium', 'confidence': 'low',
                            'description': f'Sensitive endpoint accessible without authentication: {path}',
                            'impact': 'Unauthenticated access to admin functions, data exfiltration',
                            'recommendation': 'Implement deny-by-default RBAC. Verify every request server-side.',
                            'evidence': f'GET {self.url + path} → HTTP 200 ({len(r.text)} bytes)',
                            'cvss': '5.3',
                        })
                        break
                except Exception:
                    pass

            # IDOR — numeric IDs
            if '?' in self.url:
                params = urllib.parse.parse_qs(self.parsed.query)
                for key, vals in params.items():
                    if vals and vals[0].isdigit():
                        test_id = str(int(vals[0]) + 1)
                        test_url = self.url.replace(f'{key}={vals[0]}', f'{key}={test_id}')
                        try:
                            r = self.session.get(test_url, timeout=6)
                            sim = difflib.SequenceMatcher(None, resp.text[:5000], r.text[:5000]).ratio()
                            if r.status_code == 200 and len(r.text) > 500 and sim < 0.40:
                                self._add({
                                    'id': 'A01-IDOR', 'owasp_id': 'A01:2025', 'category': 'owasp',
                                    'name': 'IDOR — Insecure Direct Object Reference',
                                    'severity': 'medium', 'confidence': 'low',
                                    'description': f'Changing numeric parameter `{key}` returns a different valid resource.',
                                    'impact': "Unauthorized access to other users' data",
                                    'recommendation': 'Validate object ownership on every request. Use UUIDs.',
                                    'evidence': f'?{key}={vals[0]} vs ?{key}={test_id} — different valid responses',
                                    'cvss': '5.8',
                                })
                        except Exception:
                            pass

        # ── A02 — Cryptographic Failures ─────────────────────────────────────
        if self.url.startswith('http://') and 'localhost' not in self.url:
            self._add({
                'id': 'A02-HTTPS', 'owasp_id': 'A02:2025', 'category': 'owasp',
                'name': 'No HTTPS — Cleartext Transmission',
                'severity': 'critical', 'confidence': 'high',
                'description': 'Site served over unencrypted HTTP.',
                'impact': 'Credential theft, session hijacking, MITM attacks',
                'recommendation': 'Obtain TLS certificate. Redirect all HTTP to HTTPS. Enable HSTS.',
                'evidence': f'URL: {self.url}',
                'cvss': '7.5',
            })

        if self.url.startswith('https://'):
            hsts = h.get('strict-transport-security', '').lower()
            if not hsts:
                self._add({
                    'id': 'A02-HSTS', 'owasp_id': 'A02:2025', 'category': 'owasp',
                    'name': 'HSTS Header Not Configured',
                    'severity': 'low', 'confidence': 'high',
                    'description': 'HTTPS response missing Strict-Transport-Security header.',
                    'impact': 'Browsers may allow insecure HTTP connections before HTTPS is enforced.',
                    'recommendation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
                    'evidence': 'Response missing Strict-Transport-Security header',
                    'cvss': '3.7',
                })
            elif 'max-age=0' in hsts:
                self._add({
                    'id': 'A02-HSTS-ZERO', 'owasp_id': 'A02:2025', 'category': 'owasp',
                    'name': 'HSTS Effectively Disabled (max-age=0)',
                    'severity': 'low', 'confidence': 'high',
                    'description': 'HSTS header present but max-age=0 disables it.',
                    'impact': 'Browsers will not enforce HTTPS-only communication.',
                    'recommendation': 'Set a positive max-age such as 31536000.',
                    'evidence': f'Strict-Transport-Security: {hsts}',
                    'cvss': '3.1',
                })
            else:
                try:
                    max_age = int(re.search(r'max-age=(\d+)', hsts).group(1))
                    if 0 < max_age < 86400:
                        self._add({
                            'id': 'A02-HSTS-WEAK', 'owasp_id': 'A02:2025', 'category': 'owasp',
                            'name': 'Weak HSTS Configuration',
                            'severity': 'info', 'confidence': 'high',
                            'description': 'HSTS max-age is very short.',
                            'impact': 'Browsers may not retain HTTPS enforcement long-term.',
                            'recommendation': 'Use max-age=31536000.',
                            'evidence': f'Strict-Transport-Security: {hsts}',
                            'cvss': '0.0',
                        })
                except Exception:
                    pass

        # ── A04 — Rate Limiting on Login ──────────────────────────────────────
        if not self.is_trusted:
            login_forms = soup.find_all('form', action=lambda a: a and any(
                x in str(a).lower() for x in ['login', 'signin', 'auth']))
            login_forms = login_forms or soup.find_all('form')
            for form in login_forms[:2]:
                if form.find_all('input', {'type': 'password'}):
                    try:
                        action = form.get('action', self.url)
                        if not action.startswith('http'):
                            action = self.url + '/' + action.lstrip('/')
                        responses = [
                            self.session.post(action,
                                                data={'username': 'scanner_test', 'password': 'wrong'},
                                                timeout=4, allow_redirects=False)
                            for _ in range(10)
                        ]
                        last = responses[-1]
                        bl = last.text.lower()
                        rate_limited = (last.status_code == 429
                                        or any(x in bl for x in
                                                ['too many requests', 'rate limit', 'captcha',
                                                'temporarily blocked', 'locked']))
                        if not rate_limited:
                            self._add({
                                'id': 'A04-RATELIMIT', 'owasp_id': 'A04:2025', 'category': 'owasp',
                                'name': 'No Rate Limiting on Login',
                                'severity': 'low', 'confidence': 'low',
                                'description': 'Login accepts unlimited requests without lockout.',
                                'impact': 'Brute-force credential attacks',
                                'recommendation': 'Implement rate limiting, CAPTCHA, and account lockout.',
                                'evidence': f'10 rapid POST requests to {action} — no lockout',
                                'cvss': '3.7',
                            })
                    except Exception:
                        pass
                    break

        # ── A05 — Security Misconfiguration (headers) ─────────────────────────
        sec_headers = {
            'content-security-policy': ('Content-Security-Policy', 'medium', '5.3'),
            'x-frame-options': ('X-Frame-Options', 'low', '3.1'),
            'x-content-type-options': ('X-Content-Type-Options', 'low', '3.1'),
        }
        optional_headers = {
            'referrer-policy': 'Referrer-Policy',
            'permissions-policy': 'Permissions-Policy',
            'cross-origin-embedder-policy': 'Cross-Origin-Embedder-Policy',
            'cross-origin-opener-policy': 'Cross-Origin-Opener-Policy',
        }
        missing = [(n, s, c) for k, (n, s, c) in sec_headers.items() if k not in h]
        missing_opt = [n for k, n in optional_headers.items() if k not in h]
        if missing:
            sev = 'medium' if any(s == 'medium' for _, s, _ in missing) else 'low'
            cvss = '5.3' if sev == 'medium' else '3.1'
            ev = 'Missing: ' + ', '.join(f'{n} (CVSS {c})' for n, _, c in missing)
            if missing_opt:
                ev += ' | Optional Missing: ' + ', '.join(missing_opt)
            self._add({
                'id': 'A05-HEADERS', 'owasp_id': 'A05:2025', 'category': 'owasp',
                'name': 'Missing Security Headers',
                'severity': sev, 'confidence': 'high',
                'description': f'{len(missing)}/{len(sec_headers)} important security headers absent.',
                'impact': 'Increased exposure to XSS, clickjacking, and MIME-sniffing.',
                'recommendation': 'Configure missing headers in your web server or framework.',
                'evidence': ev,
                'cvss': cvss,
            })

        # ── A06 — Vulnerable Components ──────────────────────────────────────
        js_libs = [
            (r'jquery[/-](\d+\.\d+\.?\d*)', 'jQuery', '3.7.0'),
            (r'bootstrap[/-](\d+\.\d+\.?\d*)', 'Bootstrap', '5.3.0'),
            (r'angular[/-](\d+\.\d+\.?\d*)', 'Angular', '17.0.0'),
            (r'react[/-](\d+\.\d+\.?\d*)', 'React', '18.0.0'),
            (r'vue[/-](\d+\.\d+\.?\d*)', 'Vue.js', '3.3.0'),
        ]
        for pattern, lib, safe_ver in js_libs:
            m = re.search(pattern, body, re.I)
            if m:
                ver = m.group(1)
                if [int(x) for x in re.findall(r'\d+', ver)] < [int(x) for x in re.findall(r'\d+', safe_ver)]:
                    self._add({
                        'id': f'A06-{lib.upper().replace(".", "").replace(" ", "")}',
                        'owasp_id': 'A06:2025', 'category': 'owasp',
                        'name': f'Outdated Component — {lib} v{ver}',
                        'severity': 'medium', 'confidence': 'medium',
                        'description': f'{lib} v{ver} is outdated (safe: v{safe_ver}).',
                        'impact': 'XSS, prototype pollution, component-specific CVEs',
                        'recommendation': f'Update {lib} to v{safe_ver} or latest stable.',
                        'evidence': f'Detected {lib} v{ver} in page source',
                        'cvss': '6.1',
                    })

        # ── A08 — SRI ─────────────────────────────────────────────────────────
        scripts = soup.find_all('script', src=True)
        ext_no_sri = [s['src'] for s in scripts
                    if any(cdn in s['src'] for cdn in ['cdn.', 'cdnjs.', 'jsdelivr.', 'unpkg.'])
                    and not s.get('integrity')]
        if ext_no_sri:
            self._add({
                'id': 'A08-SRI', 'owasp_id': 'A08:2025', 'category': 'owasp',
                'name': 'Missing Subresource Integrity (SRI)',
                'severity': 'medium', 'confidence': 'high',
                'description': f'{len(ext_no_sri)} CDN scripts loaded without integrity checks.',
                'impact': 'Supply chain attack if CDN is compromised',
                'recommendation': 'Add integrity+crossorigin attributes (https://www.srihash.org).',
                'evidence': f'No SRI: {ext_no_sri[0]}',
                'cvss': '6.8',
            })

        # ── A10 — SSRF ────────────────────────────────────────────────────────
        if self.parsed.query and not self.is_trusted:
            params = urllib.parse.parse_qs(self.parsed.query)
            ssrf_params = [k for k in params if any(x in k.lower() for x in
                            ['url', 'redirect', 'next', 'dest', 'path', 'link', 'src', 'uri', 'fetch', 'load'])]
            if ssrf_params:
                self._add({
                    'id': 'A10-SSRF', 'owasp_id': 'A10:2025', 'category': 'owasp',
                    'name': 'Potential SSRF — URL-Like Parameters',
                    'severity': 'info', 'confidence': 'low',
                    'description': f'Parameters {ssrf_params} may trigger server-side URL fetching.',
                    'impact': 'Internal network enumeration, cloud metadata exfiltration, RCE',
                    'recommendation': 'Validate/whitelist all server-side URL destinations.',
                    'evidence': f'URL-like params: {", ".join(ssrf_params)}',
                    'cvss': '0.0',
                })

    # ─────────────────────────────────────────────────────────────────────────
    def _check_injection(self, base_resp, soup):
        """
        Runs SQL, XSS, SSTI, LFI, CSRF, and XXE checks across discovered URLs.
        Skips trusted domains entirely. Each finding ID is reported only once.
        """
        targets = self.discovered_urls or [self.url]

        found = {
            'sqli_error': False, 'sqli_time': False,
            'xss_reflect': False, 'xss_stored': False,
            'ssti': False, 'lfi': False, 'csrf': False,
        }

        for target in targets:
            parsed = urllib.parse.urlparse(target)
            path_lower = parsed.path.lower()
            ext = ('.' + path_lower.rsplit('.', 1)[-1]) if ('.' in path_lower.split('/')[-1]) else ''
            if ext in SKIP_EXTENSIONS:
                continue

            try:
                page_resp = self.session.get(target, timeout=8, allow_redirects=True)
                if page_resp.status_code >= 400:
                    continue
                if 'text/html' not in page_resp.headers.get('content-type', '').lower():
                    continue
                page_soup = BeautifulSoup(page_resp.text, 'html.parser')
            except Exception:
                continue

            try:
                baseline_resp = self.session.get(target, timeout=8)
                baseline_text = baseline_resp.text
            except Exception:
                baseline_text = ''

            test_params = self._extract_injectable_params(target, page_soup)

            # ── SQL Injection — Error-Based ───────────────────────────────────
            if not found['sqli_error']:
                if self._baseline_has_sql_error(baseline_text):
                    pass  # Skip — page already has SQL errors
                else:
                    sql_payloads = ["'", "''", "1'"]
                    for payload in sql_payloads:
                        if found['sqli_error']:
                            break
                        db_params = [k for k in test_params if self._is_db_param(k, target)]
                        for param_key in db_params[:4]:
                            new_params = dict(test_params)
                            new_params[param_key] = payload
                            test_url = parsed._replace(
                                query=urllib.parse.urlencode(new_params)
                            ).geturl()
                            try:
                                r = self.session.get(test_url, timeout=8)
                                matched = None
                                for pat in SQL_ERROR_PATTERNS:
                                    m = re.search(pat, r.text, re.I)
                                    if m and m.group(0).lower() not in baseline_text.lower():
                                        matched = m.group(0)
                                        break
                                if matched:
                                    self._add({
                                        'id': 'SQL-ERROR', 'category': 'injection',
                                        'name': 'SQL Injection — Error-Based',
                                        'severity': 'high', 'confidence': 'high',
                                        'description': 'DB error returned after SQL meta-character injection.',
                                        'impact': 'Unauthorized DB access, data disclosure, auth bypass.',
                                        'recommendation': 'Use parameterized queries. Never expose DB errors.',
                                        'evidence': (f'URL: {target} | Param: `{param_key}` | '
                                                    f'Payload: `{payload}` | Error: {matched[:120]}'),
                                        'cvss': '8.1',
                                    })
                                    found['sqli_error'] = True
                                    break
                            except Exception:
                                pass

            # ── SQL Injection — Time-Based ────────────────────────────────────
            if not found['sqli_time']:
                db_params = [k for k in test_params if self._is_db_param(k, target)]
                if db_params:
                    try:
                        t0 = t.time()
                        self.session.get(target, timeout=10)
                        baseline_elapsed = t.time() - t0

                        param_key = db_params[0]
                        time_payload = "1'; SELECT SLEEP(3)--"
                        new_params = dict(test_params)
                        new_params[param_key] = time_payload
                        test_url = parsed._replace(
                            query=urllib.parse.urlencode(new_params)
                        ).geturl()

                        t1 = t.time()
                        self.session.get(test_url, timeout=12)
                        elapsed = t.time() - t1

                        if (elapsed - baseline_elapsed) >= 2.5:
                            self._add({
                                'id': 'SQL-TIME', 'category': 'injection',
                                'name': 'Potential SQL Injection — Time-Based Blind',
                                'severity': 'high', 'confidence': 'medium',
                                'description': 'Response time increased significantly after time-delay payload.',
                                'impact': 'Blind SQL injection enabling data extraction.',
                                'recommendation': 'Use parameterized queries. Validate all user input.',
                                'evidence': (f'URL: {target} | Param: `{param_key}` | '
                                            f'Payload: `{time_payload}` | '
                                            f'Response: {elapsed:.2f}s (baseline: {baseline_elapsed:.2f}s)'),
                                'cvss': '7.5',
                            })
                            found['sqli_time'] = True
                    except Exception:
                        pass

            # ── Reflected XSS ─────────────────────────────────────────────────
            if not found['xss_reflect'] and test_params:
                xss_payloads = [
                    '<script>alert(1)</script>',
                    '"><script>alert(1)</script>',
                    "'><script>alert(1)</script>",
                    '<img src=x onerror=alert(1)>',
                ]
                for payload in xss_payloads:
                    if found['xss_reflect']:
                        break
                    for param_key, param_val in list(test_params.items())[:5]:
                        if not param_key:  # Guard against empty param names
                            continue
                        new_params = dict(test_params)
                        new_params[param_key] = payload
                        test_url = parsed._replace(
                            query=urllib.parse.urlencode(new_params)
                        ).geturl()
                        try:
                            r = self.session.get(test_url, timeout=8)
                            if 'text/html' not in r.headers.get('content-type', '').lower():
                                continue
                            rbody = r.text
                            payload_lower = payload.lower()
                            escaped = html.escape(payload).lower()

                            reflected_raw = payload_lower in rbody.lower()
                            only_escaped = escaped in rbody.lower() and not reflected_raw

                            if reflected_raw and not only_escaped:
                                if self._check_xss_context(rbody, payload):
                                    self._add({
                                        'id': 'XSS-REFLECT', 'category': 'injection',
                                        'name': 'Potential Reflected XSS',
                                        'severity': 'medium', 'confidence': 'medium',
                                        'description': 'Input reflected into HTML without sufficient encoding.',
                                        'impact': 'Attackers may inject malicious client-side scripts.',
                                        'recommendation': 'Apply context-aware output encoding.',
                                        'evidence': (f'URL: {target} | Param: `{param_key}` | '
                                                    f'Payload: `{payload}`'),
                                        'cvss': '5.3',
                                    })
                                    found['xss_reflect'] = True
                                    break
                        except Exception:
                            pass

            # ── Stored XSS ────────────────────────────────────────────────────
            if not found['xss_stored']:
                for form in page_soup.find_all('form')[:3]:
                    if found['xss_stored']:
                        break
                    if form.get('method', '').upper() not in ('POST', ''):
                        continue

                    # Collect injectable text fields
                    text_fields = []
                    all_fields = {}
                    for inp in form.find_all(['input', 'textarea']):
                        n = (inp.get('name') or '').strip()
                        if not n:
                            continue
                        itype = inp.get('type', 'text').lower()
                        if itype in ('submit', 'button', 'image', 'reset', 'file'):
                            continue
                        val = (inp.get('value') or '').strip()
                        # Preserve CSRF token value as-is
                        if any(tok in n.lower() for tok in ['token', 'csrf', 'nonce']):
                            all_fields[n] = val
                        elif itype == 'hidden':
                            all_fields[n] = val
                        elif n.lower() not in SKIP_PARAMS:
                            text_fields.append(n)
                            all_fields[n] = val

                    if not text_fields:
                        continue

                    action = form.get('action', target)
                    if not action.startswith('http'):
                        action = target.rstrip('/') + '/' + action.lstrip('/')

                    try:
                        xss_payload = '<script>alert(1)</script>'
                        post_data = dict(all_fields)
                        post_data[text_fields[0]] = xss_payload

                        self.session.post(action, data=post_data, timeout=8)
                        verify = self.session.get(target, timeout=8)
                        vbody = verify.text
                        escaped_pl = html.escape(xss_payload).lower()
                        raw_found = xss_payload.lower() in vbody.lower()
                        only_escaped = escaped_pl in vbody.lower() and not raw_found

                        if raw_found and not only_escaped and self._check_xss_context(vbody, xss_payload):
                            self._add({
                                'id': 'XSS-STORED', 'category': 'injection',
                                'name': 'Potential Stored XSS',
                                'severity': 'medium', 'confidence': 'medium',
                                'description': 'Stored user content reflected without encoding.',
                                'impact': 'Persistent client-side script injection.',
                                'recommendation': 'Sanitize input and apply context-aware output encoding.',
                                'evidence': (f'URL: {target} | Payload persisted after POST, '
                                            f'found on page revisit'),
                                'cvss': '5.4',
                            })
                            found['xss_stored'] = True
                    except Exception:
                        pass

            # ── CSRF ─────────────────────────────────────────────────────────
            if not found['csrf']:
                csrf_names = ['csrf', '_csrf', '_token', 'csrf_token', 'authenticity_token',
                                'nonce', '__requestverificationtoken', 'csrfmiddlewaretoken']
                ck = '; '.join(f'{c.name}={c.value}' for c in self.session.cookies).lower()
                has_samesite = 'samesite=lax' in ck or 'samesite=strict' in ck
                for form in page_soup.find_all('form', method=lambda m: m and m.upper() == 'POST'):
                    inputs = [i.get('name', '').lower() for i in form.find_all('input')]
                    has_token = any(tok in field for field in inputs for tok in csrf_names)
                    if not has_token and not has_samesite:
                        self._add({
                            'id': 'CSRF-01', 'category': 'injection',
                            'name': 'Potential CSRF Protection Missing',
                            'severity': 'info', 'confidence': 'low',
                            'description': 'POST form without an obvious CSRF token.',
                            'impact': 'Heuristic only — does not confirm a CSRF vulnerability.',
                            'recommendation': 'Verify CSRF protections: tokens, SameSite cookies, origin validation.',
                            'evidence': f'POST form at {target} missing CSRF token fields',
                            'cvss': '0.0',
                        })
                        found['csrf'] = True
                        break

            # ── SSTI ─────────────────────────────────────────────────────────
            if not found['ssti'] and test_params:
                ssti_tests = [('{{7*7}}', '49'), ('${7*7}', '49')]
                try:
                    ssti_base = self.session.get(target, timeout=6).text.lower()
                except Exception:
                    ssti_base = ''

                for payload, expected in ssti_tests:
                    if found['ssti']:
                        break
                    # Use first non-skip param
                    param_key = next(iter(test_params.keys()), None)
                    if not param_key:
                        continue
                    new_params = dict(test_params)
                    new_params[param_key] = payload
                    test_url = parsed._replace(
                        query=urllib.parse.urlencode(new_params)
                    ).geturl()
                    try:
                        r = self.session.get(test_url, timeout=6)
                        rbody = r.text.lower()

                        # Expected result must appear in response
                        if not re.search(rf'\b{re.escape(expected)}\b', rbody):
                            continue
                        # The literal payload must NOT appear (it should be evaluated)
                        if payload.lower() in rbody:
                            continue
                        # Must not exist in baseline
                        if re.search(rf'\b{re.escape(expected)}\b', ssti_base):
                            continue
                        # Responses must differ meaningfully
                        sim = difflib.SequenceMatcher(None, ssti_base, rbody).ratio()
                        if sim > 0.98:
                            continue
                        # Extra: confirm the number is in an output context (not in JS/CSS)
                        idx = rbody.find(expected)
                        ctx = rbody[max(0, idx - 100): idx + 100]
                        # Skip if it's inside a JS number or CSS value (not template output)
                        if re.search(r'(var|let|const|function|px|em|rem|#)\s*' + re.escape(expected), ctx):
                            continue

                        self._add({
                            'id': 'SSTI-01', 'category': 'injection',
                            'name': 'Potential Server-Side Template Injection',
                            'severity': 'medium', 'confidence': 'medium',
                            'description': 'Template syntax may have been evaluated server-side.',
                            'impact': 'Server-side code execution or sensitive data disclosure.',
                            'recommendation': 'Never render untrusted input in templates. Use sandboxing.',
                            'evidence': (f'URL: {target} | Param: `{param_key}` | '
                                        f'Payload `{payload}` → evaluated result `{expected}` found'),
                            'cvss': '6.5',
                        })
                        found['ssti'] = True
                    except Exception:
                        pass

            # ── LFI ──────────────────────────────────────────────────────────
            if not found['lfi']:
                lfi_paths = ['/../../../etc/passwd', '/..%2F..%2F..%2Fetc%2Fpasswd']
                for lp in lfi_paths:
                    try:
                        r = self.session.get(target.rstrip('/') + lp, timeout=6)
                        # Must contain actual /etc/passwd entries, not search results about it
                        # Require multiple lines matching passwd format: root:x:0:0:
                        passwd_lines = re.findall(r'\w+:[^:]+:\d+:\d+:', r.text)
                        if len(passwd_lines) >= 3:
                            self._add({
                                'id': 'LFI-01', 'category': 'injection',
                                'name': 'Local File Inclusion (LFI)',
                                'severity': 'critical', 'confidence': 'high',
                                'description': 'Path traversal allows reading /etc/passwd.',
                                'impact': 'Full server file system read, RCE via log poisoning',
                                'recommendation': 'Sanitize file path inputs. Use basename().',
                                'evidence': f'URL: {target} | Path `{lp}` → passwd entries found',
                                'cvss': '9.1',
                            })
                            found['lfi'] = True
                            break
                    except Exception:
                        pass

            # ── XXE ───────────────────────────────────────────────────────────
            page_ct = page_resp.headers.get('content-type', '')
            if ('xml' in page_ct or page_soup.find('form', enctype='text/xml')) \
                    and 'XXE-01' not in self._vuln_ids:
                self._add({
                    'id': 'XXE-01', 'category': 'injection',
                    'name': 'Potential XXE — XML Input Accepted',
                    'severity': 'high', 'confidence': 'low',
                    'description': 'Application processes XML — may be vulnerable to XXE.',
                    'impact': 'File disclosure, SSRF, DoS',
                    'recommendation': 'Disable external entity processing. Prefer JSON.',
                    'evidence': f'Content-Type: {page_ct} indicates XML processing',
                    'cvss': '8.2',
                })

    # ─────────────────────────────────────────────────────────────────────────
    def _check_sensitive_files(self):
        try:
            baseline = self.session.get(self.url, timeout=6)
            baseline_text = baseline.text[:10000]
        except Exception:
            return

        for path, name, severity in SENSITIVE_FILES:
            try:
                test_url = self.url + path
                r = self.session.get(test_url, timeout=6, allow_redirects=False)

                if r.status_code != 200:
                    continue
                body = r.text
                if len(body.strip()) < 10:
                    continue

                sim = difflib.SequenceMatcher(None, baseline_text, body[:10000]).ratio()
                if sim > 0.75:
                    continue

                ct = r.headers.get('Content-Type', '').lower()

                if path == '/robots.txt':
                    has_sensitive = any(p in body.lower() for p in ROBOTS_SENSITIVE_HINTS)
                    self._add({
                        'id': 'FILE-ROBOTS', 'category': 'exposure',
                        'name': 'Robots.txt Publicly Accessible',
                        'severity': 'info', 'confidence': 'high',
                        'description': '`/robots.txt` is publicly accessible.',
                        'impact': 'May disclose internal paths.' if has_sensitive else 'No direct security impact.',
                        'recommendation': 'Avoid listing sensitive paths in robots.txt.',
                        'evidence': f'GET {test_url} → HTTP 200 ({len(body)} bytes)',
                        'cvss': '2.6' if has_sensitive else '0.0',
                    })
                    continue

                filename = path.lstrip('/')
                if filename not in FILE_SIGNATURES:
                    continue

                verified = any(sig.lower() in body.lower() for sig in FILE_SIGNATURES[filename])

                # Reject HTML response for files that should be plaintext/binary
                if filename.endswith(('.sql', '.env', '.key', 'id_rsa', '.bash_history')) \
                        and 'html' in ct:
                    verified = False

                if not verified:
                    continue

                self._add({
                    'id': f'FILE-{path.replace("/", "").upper()}',
                    'category': 'exposure',
                    'name': f'Sensitive File Exposed: {name}',
                    'severity': severity, 'confidence': 'high',
                    'description': f'`{path}` appears to contain sensitive information.',
                    'impact': 'Potential credential, config, or asset disclosure.',
                    'recommendation': f'Remove or restrict access to `{path}`.',
                    'evidence': f'GET {test_url} → HTTP 200 ({len(body)} bytes)',
                    'cvss': '8.6' if severity == 'critical' else '5.3',
                })
            except Exception:
                pass

    # ─────────────────────────────────────────────────────────────────────────
    def _check_http_methods(self):
        dangerous = {'TRACE': 'high', 'CONNECT': 'medium', 'PUT': 'low',
                    'DELETE': 'low', 'PATCH': 'info'}
        cvss_map = {'high': '6.5', 'medium': '4.3', 'low': '2.6', 'info': '0.0'}
        try:
            opts = self.session.options(self.url, timeout=6, allow_redirects=False)
            allow = opts.headers.get('Allow', '').upper()
        except Exception:
            allow = ''
        try:
            baseline = self.session.get(self.url, timeout=6, allow_redirects=False)
        except Exception:
            return

        for method, severity in dangerous.items():
            try:
                if allow and method not in allow:
                    continue
                r = self.session.request(method, self.url, timeout=6, allow_redirects=False)
                if r.status_code == 200 and r.text and r.text != baseline.text:
                    self._add({
                        'id': f'METHOD-{method}', 'category': 'owasp', 'owasp_id': 'A05:2025',
                        'name': f'Potentially Dangerous HTTP Method Enabled: {method}',
                        'severity': severity, 'confidence': 'low',
                        'description': f'Server appears to accept {method} requests.',
                        'impact': 'Increased attack surface if method is not required.',
                        'recommendation': f'Disable {method} if not needed.',
                        'evidence': f'{method} {self.url} → HTTP {r.status_code}',
                        'cvss': cvss_map.get(severity, '0.0'),
                    })
            except Exception:
                pass

    # ─────────────────────────────────────────────────────────────────────────
    def _check_cookies(self, resp):
        SESSION_KW = {'session', 'sess', 'auth', 'token', 'jwt', 'login',
                    'sid', 'ssid', 'access', 'csrf', 'identity'}
        LOW_RISK_KW = {'nid', '_ga', '_gid', '_gat', '1p_jar', 'preferences',
                    'consent', 'cookie_notice', 'gdpr'}

        for cookie in resp.cookies:
            if cookie.name.startswith(('__Secure-', '__Host-')):
                if not cookie.secure:
                    self._add({
                        'id': f'COOKIE-PREFIX-{cookie.name}', 'category': 'owasp',
                        'owasp_id': 'A07:2025',
                        'name': f'Malformed Secure-Prefix Cookie — {cookie.name}',
                        'severity': 'low', 'confidence': 'high',
                        'description': f'`{cookie.name}` uses a secure prefix but lacks the Secure attribute.',
                        'impact': 'Browsers may reject the cookie.',
                        'recommendation': 'Always set Secure on __Secure-/__Host- cookies.',
                        'evidence': f'Set-Cookie: {cookie.name}; Secure absent',
                        'cvss': '3.1',
                    })
                continue

            flags = (str(getattr(cookie, '_rest', {})) + str(cookie.__dict__)).lower()
            nl = cookie.name.lower()
            is_session = any(kw in nl for kw in SESSION_KW)
            is_low_risk = any(kw in nl for kw in LOW_RISK_KW)
            httponly = 'httponly' in flags
            samesite = 'samesite' in flags

            issues = []
            if not cookie.secure:
                issues.append('Missing Secure flag')
            if not samesite:
                issues.append('Missing SameSite')
            if is_session and not httponly:
                issues.append('Missing HttpOnly')

            if not issues:
                continue

            if is_session:
                sev = 'medium' if len(issues) >= 2 else 'low'
                cvss = '5.3' if sev == 'medium' else '3.1'
                impact = 'Session cookie exposure to interception or CSRF.'
            elif is_low_risk:
                sev = 'info'
                cvss = '0.0'
                impact = 'Limited impact for analytics/preference cookies.'
            else:
                sev = 'low'
                cvss = '2.6'
                impact = 'Non-session cookie missing security attributes.'

            self._add({
                'id': f'COOKIE-{cookie.name}', 'category': 'owasp', 'owasp_id': 'A07:2025',
                'name': f'Cookie Security Attributes Missing — {cookie.name}',
                'severity': sev, 'confidence': 'high',
                'description': f'`{cookie.name}` missing: {", ".join(issues)}.',
                'impact': impact,
                'recommendation': 'Apply Secure, SameSite, HttpOnly as appropriate.',
                'evidence': f'Set-Cookie: {cookie.name}; issues: {", ".join(issues)}',
                'cvss': cvss,
            })

    # ─────────────────────────────────────────────────────────────────────────
    def _check_cors(self):
        try:
            r = self.session.get(self.url, headers={'Origin': 'https://evil.com'}, timeout=8)
            acao = r.headers.get('access-control-allow-origin', '')
            acac = r.headers.get('access-control-allow-credentials', '')
            if acao == '*':
                self._add({
                    'id': 'CORS-WILDCARD', 'category': 'injection',
                    'name': 'CORS Wildcard Origin',
                    'severity': 'medium', 'confidence': 'high',
                    'description': 'ACAO: * allows any origin to read responses.',
                    'impact': 'Cross-origin data leakage from public endpoints.',
                    'recommendation': 'Replace wildcard with specific trusted origins.',
                    'evidence': 'Access-Control-Allow-Origin: *',
                    'cvss': '5.3',
                })
            elif acao == 'https://evil.com':
                sev = 'critical' if acac.lower() == 'true' else 'high'
                self._add({
                    'id': 'CORS-REFLECT', 'category': 'injection',
                    'name': 'CORS Arbitrary Origin Reflection',
                    'severity': sev, 'confidence': 'high',
                    'description': 'Server reflects arbitrary Origin. Credentials may be included.',
                    'impact': 'Full cross-origin data theft.',
                    'recommendation': 'Validate Origin against a strict whitelist.',
                    'evidence': f'ACAO: {acao}, ACAC: {acac}',
                    'cvss': '9.0' if sev == 'critical' else '7.5',
                })
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    def _check_open_redirect(self):
        redirect_params = ['redirect', 'next', 'url', 'return', 'dest',
                            'destination', 'redir', 'target', 'goto', 'link']
        evil_url = 'https://evil.com'
        safe_patterns = ['sorry', 'interstitial', 'warning', 'blocked', 'safebrowsing', 'consent']

        for param in redirect_params:
            test_url = (self.url + ('?' if '?' not in self.url else '&') +
                        f'{param}={urllib.parse.quote(evil_url)}')
            try:
                r = self.session.get(test_url, timeout=6, allow_redirects=False)
                if r.status_code not in (301, 302, 303, 307, 308):
                    continue
                location = r.headers.get('location', '').lower()
                is_safe = any(p in location for p in safe_patterns)
                is_external = 'evil.com' in location
                if is_external:
                    if is_safe:
                        self._add({
                            'id': 'REDIRECT-SAFE', 'category': 'redirect',
                            'name': 'External Redirect Handled via Interstitial',
                            'severity': 'info', 'confidence': 'high',
                            'description': 'Redirect goes through a warning page — no direct open redirect.',
                            'impact': 'No confirmed open redirect.',
                            'recommendation': 'Continue using allowlists for redirect destinations.',
                            'evidence': f'?{param}={evil_url} → {r.status_code} Location: {location[:200]}',
                            'cvss': '0.0',
                        })
                    else:
                        self._add({
                            'id': 'REDIRECT-01', 'category': 'redirect',
                            'name': 'Potential Open Redirect',
                            'severity': 'medium', 'confidence': 'high',
                            'description': f'`{param}` redirects to arbitrary external domains.',
                            'impact': 'Phishing, credential theft via redirect abuse.',
                            'recommendation': 'Validate redirect targets against a strict allowlist.',
                            'evidence': f'?{param}={evil_url} → {r.status_code} Location: {location[:200]}',
                            'cvss': '6.1',
                        })
                        return
            except Exception:
                pass

    # ─────────────────────────────────────────────────────────────────────────
    def _check_ssl(self):
        if not self.hostname:
            return
        ssl_data = check_ssl_details(self.hostname)
        self.results['ssl_info'] = ssl_data
        if ssl_data.get('expired'):
            self._add({
                'id': 'SSL-EXPIRED', 'category': 'owasp', 'owasp_id': 'A02:2025',
                'name': 'SSL Certificate Expired',
                'severity': 'critical', 'confidence': 'high',
                'description': 'TLS certificate has expired.',
                'impact': 'User warnings, loss of trust, possible MITM',
                'recommendation': "Renew immediately. Use Let's Encrypt.",
                'evidence': f'Certificate expired: {ssl_data.get("expires")}',
                'cvss': '7.5',
            })
        elif ssl_data.get('expiring_soon'):
            days = ssl_data.get('days_remaining', 0)
            sev = 'low' if days <= 7 else 'info'
            self._add({
                'id': 'SSL-EXPIRING', 'category': 'owasp', 'owasp_id': 'A02:2025',
                'name': 'SSL Certificate Expiring Soon',
                'severity': sev, 'confidence': 'high',
                'description': f'Certificate expires in {days} days.',
                'impact': 'Renewal required soon.',
                'recommendation': 'Ensure automatic renewal is configured.',
                'evidence': f'Days remaining: {days}',
                'cvss': '3.1' if sev == 'low' else '0.0',
            })
        if ssl_data.get('weak_cipher'):
            self._add({
                'id': 'SSL-WEAKCIP', 'category': 'owasp', 'owasp_id': 'A02:2025',
                'name': 'Weak SSL Cipher Suite',
                'severity': 'high', 'confidence': 'high',
                'description': f'Cipher {ssl_data.get("cipher")} ({ssl_data.get("bits")} bits).',
                'impact': 'Possible decryption of recorded traffic.',
                'recommendation': 'Use TLS 1.3 and AES-256-GCM cipher suites.',
                'evidence': f'Cipher: {ssl_data.get("cipher")} ({ssl_data.get("bits")} bits)',
                'cvss': '7.4',
            })

    # ─────────────────────────────────────────────────────────────────────────
    def _check_dns(self):
        dns_data = check_dns_security(self.hostname)
        self.results['dns_security'] = dns_data
        ext = tldextract.extract(self.hostname)
        root_domain = f'{ext.domain}.{ext.suffix}'
        has_mx = bool(dns_data.get('mx'))

        if not dns_data.get('spf'):
            self._add({
                'id': 'DNS-SPF', 'category': 'dns',
                'name': 'SPF Record Not Detected',
                'severity': 'low' if has_mx else 'info', 'confidence': 'high',
                'description': 'No SPF TXT record detected.',
                'impact': 'Email spoofing risk.' if has_mx else 'No MX records — limited impact.',
                'recommendation': 'Configure SPF for authorized mail servers.',
                'evidence': f'No SPF TXT record for {self.hostname}',
                'cvss': '3.1' if has_mx else '0.0',
            })
        if not dns_data.get('dmarc'):
            self._add({
                'id': 'DNS-DMARC', 'category': 'dns',
                'name': 'DMARC Record Not Detected',
                'severity': 'low' if has_mx else 'info', 'confidence': 'high',
                'description': 'No DMARC record detected.',
                'impact': 'Reduced email spoofing protection.' if has_mx else 'No MX — limited impact.',
                'recommendation': 'Configure a DMARC policy.',
                'evidence': f'No DMARC at _dmarc.{root_domain}',
                'cvss': '3.1' if has_mx else '0.0',
            })
        if not dns_data.get('dnssec'):
            self._add({
                'id': 'DNS-DNSSEC', 'category': 'dns',
                'name': 'DNSSEC Not Enabled',
                'severity': 'info', 'confidence': 'high',
                'description': 'No DNSSEC DS records detected.',
                'impact': 'DNS relies on traditional trust mechanisms.',
                'recommendation': 'Enable DNSSEC at your registrar.',
                'evidence': f'No DS records for {root_domain}',
                'cvss': '0.0',
            })

    # ─────────────────────────────────────────────────────────────────────────
    def _detect_waf(self, headers, body):
        h_str = str(headers).lower()
        b_str = body.lower()
        for waf_name, sigs in WAF_SIGNATURES.items():
            if any(s.lower() in h_str or s.lower() in b_str for s in sigs):
                self.results['waf'] = waf_name
                return
        try:
            probe = self.session.get(
                self.url + "/?a=<script>alert(1)</script>&b='OR 1=1--", timeout=6)
            if probe.status_code in (403, 406, 429, 503):
                ph = str({k.lower(): v for k, v in probe.headers.items()})
                if 'cloudflare' in ph:
                    self.results['waf'] = 'Cloudflare'
                elif 'sucuri' in ph:
                    self.results['waf'] = 'Sucuri'
                else:
                    self.results['waf'] = f'Unknown WAF (HTTP {probe.status_code})'
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    def _scan_ports(self):
        try:
            ip = socket.gethostbyname(self.hostname)
        except Exception:
            return

        def probe(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                result = s.connect_ex((ip, port))
                s.close()
                state = 'open' if result == 0 else 'closed'
            except Exception:
                state = 'filtered'
            service, risk = PORT_META.get(port, ('Unknown', 'info'))
            return {'port': port, 'state': state, 'service': service,
                    'protocol': 'TCP', 'risk': risk if state == 'open' else 'info'}

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
            results = list(ex.map(probe, COMMON_PORTS))

        self.results['ports'] = results
        for p in results:
            if p['state'] == 'open' and p['risk'] == 'critical':
                self._add({
                    'id': f'PORT-{p["port"]}', 'category': 'ports',
                    'name': f'Critical Service Exposed: {p["service"]} ({p["port"]})',
                    'severity': 'critical', 'confidence': 'high',
                    'description': f'Port {p["port"]} ({p["service"]}) accessible from internet.',
                    'impact': 'Direct exploitation of database/remote access services.',
                    'recommendation': f'Restrict port {p["port"]} to trusted IPs via firewall.',
                    'evidence': f'Port {p["port"]}/TCP OPEN — {p["service"]}',
                    'cvss': '9.0',
                })

    # ─────────────────────────────────────────────────────────────────────────
    def _detect_tech(self, headers, body):
        techs = []
        h = headers

        def add_tech(name, cat, ver=None):
            if not any(x['name'].lower() == name.lower() for x in techs):
                techs.append({'name': name, 'category': cat, 'version': ver})

        server = h.get('server', '')
        if server:
            parts = server.split('/')
            add_tech(parts[0].strip(), 'Web Server',
                    parts[1].split(' ')[0] if len(parts) > 1 else None)

        powered = h.get('x-powered-by', '')
        if powered:
            parts = powered.split('/')
            add_tech(parts[0].strip(), 'Language', parts[1] if len(parts) > 1 else None)

        patterns = [
            (r'wp-content|wp-includes|wp-json', 'WordPress', 'CMS', r'wordpress[\s/]+([\d.]+)'),
            (r'drupal\.org|drupal\.js', 'Drupal', 'CMS', r'Drupal ([\d.]+)'),
            (r'joomla', 'Joomla', 'CMS', r'Joomla[\s/]+([\d.]+)'),
            (r'shopify', 'Shopify', 'E-Commerce', None),
            (r'magento', 'Magento', 'E-Commerce', r'Magento[\s/]+([\d.]+)'),
            (r'laravel', 'Laravel', 'Framework', None),
            (r'django', 'Django', 'Framework', None),
            (r'rails', 'Ruby on Rails', 'Framework', None),
            (r'next\.js|__next', 'Next.js', 'Framework', r'next[\s/]+([\d.]+)'),
            (r'nuxt', 'Nuxt.js', 'Framework', None),
            (r'react|__react', 'React', 'JavaScript', r'react[\s@/]+([\d.]+)'),
            (r'vue\.js|data-v-', 'Vue.js', 'JavaScript', r'vue[\s@/]+([\d.]+)'),
            (r'angular', 'Angular', 'JavaScript', r'angular[\s@/]+([\d.]+)'),
            (r'jquery', 'jQuery', 'JavaScript', r'jquery[\s@/v]+([\d.]+)'),
            (r'bootstrap', 'Bootstrap', 'CSS Framework', r'bootstrap[\s@/]+([\d.]+)'),
            (r'tailwind', 'Tailwind CSS', 'CSS Framework', None),
            (r'cloudflare', 'Cloudflare', 'CDN', None),
            (r'google-analytics|gtag|ga\.js', 'Google Analytics', 'Analytics', None),
            (r'nginx', 'Nginx', 'Web Server', r'nginx/([\d.]+)'),
            (r'apache', 'Apache', 'Web Server', r'Apache/([\d.]+)'),
            (r'node\.js|nodejs', 'Node.js', 'Runtime', r'node/([\d.]+)'),
            (r'php', 'PHP', 'Language', r'PHP/([\d.]+)'),
        ]

        all_text = body + str(headers)
        for pattern, name, cat, ver_pat in patterns:
            if re.search(pattern, all_text, re.I):
                ver = None
                if ver_pat:
                    m = re.search(ver_pat, all_text, re.I)
                    if m:
                        ver = m.group(1)
                add_tech(name, cat, ver)

        if h.get('cf-ray'):
            add_tech('Cloudflare', 'CDN')
        if self.url.startswith('https://'):
            add_tech('TLS/SSL', 'Security')

        self.results['technologies'] = techs

        for tech in techs[:4]:
            if tech['version']:
                cve_data = check_nvd_cves(tech['name'], tech['version'])
                for cve in cve_data.get('cves', []):
                    if float(cve.get('cvss', 0)) >= 7.0:
                        self._add({
                            'id': f'CVE-{cve["id"]}', 'category': 'cve', 'owasp_id': 'A06:2025',
                            'name': f'{cve["id"]} — {tech["name"]} v{tech["version"]}',
                            'severity': 'critical' if float(cve.get('cvss', 0)) >= 9 else 'high',
                            'confidence': 'high',
                            'description': cve.get('description', ''),
                            'impact': 'Component-specific exploitation.',
                            'recommendation': f'Upgrade {tech["name"]} from v{tech["version"]}.',
                            'evidence': f'CVSS {cve.get("cvss")} — {cve.get("published")}',
                            'cvss': str(cve.get('cvss', '')),
                        })

    # ─────────────────────────────────────────────────────────────────────────
    def _calc_risk_score(self):
        SEVERITY_W = {'critical': 35, 'high': 25, 'medium': 15, 'low': 10, 'info': 0}
        CONFIDENCE_W = {'high': 1.0, 'medium': 0.6, 'low': 0.3}
        raw = sum(
            SEVERITY_W.get(v.get('severity', 'info').lower(), 0) *
            CONFIDENCE_W.get(v.get('confidence', 'medium').lower(), 0.6)
            for v in self.results['vulnerabilities']
        )
        return min(round(100 * (1 - math.exp(-raw / 100))), 100)
