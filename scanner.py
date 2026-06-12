import requests
import socket
import re
import ssl
import math
import urllib.parse
import concurrent.futures
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from api_integrations import (
    check_virustotal, check_shodan, check_urlscan,
    check_google_safe_browsing, check_hibp_domain,
    check_nvd_cves, check_dns_security, check_ssl_details
)
import difflib
import re
import tldextract
import html

requests.packages.urllib3.disable_warnings()

COMMON_PORTS = [21,22,23,25,53,80,110,135,143,443,445,465,587,993,995,
                1433,1521,2049,3306,3389,4444,5432,5900,6379,8080,8443,8888,9200,27017]

PORT_META = {
    21:('FTP','high'),22:('SSH','medium'),23:('Telnet','critical'),25:('SMTP','low'),
    53:('DNS','low'),80:('HTTP','low'),110:('POP3','medium'),135:('RPC','high'),
    143:('IMAP','medium'),443:('HTTPS','info'),445:('SMB','critical'),465:('SMTPS','low'),
    587:('SMTP-Sub','low'),993:('IMAPS','info'),995:('POP3S','info'),1433:('MSSQL','critical'),
    1521:('Oracle','critical'),2049:('NFS','high'),3306:('MySQL','critical'),
    3389:('RDP','critical'),4444:('Metasploit','critical'),5432:('PostgreSQL','critical'),
    5900:('VNC','critical'),6379:('Redis','critical'),8080:('HTTP-Alt','medium'),
    8443:('HTTPS-Alt','low'),8888:('HTTP-Dev','medium'),9200:('Elasticsearch','critical'),
    27017:('MongoDB','critical'),
}

SQL_PAYLOADS = [
    ("'", ['mysql_fetch','sql syntax','you have an error','ORA-','PG::','unclosed quotation','sqlite_','syntax error','mysql_num_rows']),
    ("1' OR '1'='1", ['welcome','admin','dashboard','login successful']),
    ("' OR 1=1 --", ['root','admin','user']),
    ("1; SELECT SLEEP(3)--", None),
    ("' UNION SELECT NULL,NULL,NULL--", ['null','union']),
]

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<svg/onload=alert(1)>',
    '{{7*7}}',
]

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

class _TimeoutAdapter(HTTPAdapter):
    def __init__(self, timeout=12, *args, **kwargs):
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
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.session.verify = False

        _adapter = _TimeoutAdapter(timeout=12)
        self.session.mount('http://', _adapter)
        self.session.mount('https://', _adapter)

        self.results = {
            'vulnerabilities': [], 'ports': [], 'technologies': [],
            'dns_security': {}, 'ssl_info': {}, 'waf': None,
            'threat_intel': {}, 'score': 0,
        }
        self._vuln_ids = set()

    def run(self):
        try:

            resp = self.session.get(self.url, allow_redirects=True, timeout=12)
        except Exception as e:
            return {**self.results, 'error': str(e), 'status': 'error'}

        headers = resp.headers   # requests CaseInsensitiveDict — no manual lowering needed
        body    = resp.text
        soup    = BeautifulSoup(body, 'html.parser')

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
            futures = {}

            if self.opts.get('scan_owasp', True):
                futures['owasp'] = ex.submit(self._check_owasp, resp, headers, body, soup)

            if self.opts.get('scan_injection', True):
                futures['injection'] = ex.submit(self._check_injection, resp, soup)

            if self.opts.get('scan_ports', True):
                futures['ports'] = ex.submit(self._scan_ports)

            if self.opts.get('scan_tech', True):
                futures['tech'] = ex.submit(self._detect_tech, headers, body)

            if self.opts.get('scan_ssl', True):
                futures['ssl'] = ex.submit(self._check_ssl)

            if self.opts.get('scan_dns', True):
                futures['dns'] = ex.submit(self._check_dns)

            futures['waf']      = ex.submit(self._detect_waf, headers, body)
            futures['files']    = ex.submit(self._check_sensitive_files)
            futures['methods']  = ex.submit(self._check_http_methods)
            futures['cookies']  = ex.submit(self._check_cookies, resp)
            futures['cors']     = ex.submit(self._check_cors)
            futures['redirect'] = ex.submit(self._check_open_redirect)

            if self.opts.get('scan_threat_intel', True):
                futures['vt']     = ex.submit(check_virustotal, self.url)
                futures['shodan'] = ex.submit(check_shodan, self.hostname)
                futures['gsb']    = ex.submit(check_google_safe_browsing, self.url)
                futures['hibp']   = ex.submit(check_hibp_domain, self.hostname)

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
    def _add(self, vuln):

        vuln.setdefault("confidence", "medium")

        uid = vuln.get(
            'id',
            vuln.get('name', '')
        )

        if uid not in self._vuln_ids:
            self._vuln_ids.add(uid)
            self.results['vulnerabilities'].append(vuln)

    # ─────────────────────────────────────────────────────────────────────────
    def _check_owasp(self, resp, headers, body, soup):
        h = headers  

        # ── A01 — Broken Access Control ──────────────────────────────────────
        admin_paths = ['/admin', '/admin/users', '/dashboard', '/api/users', '/api/admin', '/.env', '/config']
        for path in admin_paths:
            try:
                r = self.session.get(self.url + path, allow_redirects=False, timeout=6)
                homepage_similarity = difflib.SequenceMatcher(
                    None,
                    resp.text[:5000],
                    r.text[:5000]
                ).ratio()

                admin_keywords = [
                    "admin dashboard",
                    "user management",
                    "administrator",
                    "control panel",
                    "role management",
                    "site settings"
                ]

                if (
                    r.status_code == 200
                    and len(r.text) > 500
                    and homepage_similarity < 0.70
                    and any(k in r.text.lower() for k in admin_keywords)
                ):
                    self._add({
                        'id': 'A01-BAC', 'owasp_id': 'A01:2025', 'category': 'owasp',
                        'name': 'Broken Access Control',
                        'severity': 'medium',
                        'description': f'Sensitive endpoint accessible without authentication: {path}',
                        'impact': 'Unauthenticated access to admin functions, data exfiltration',
                        'recommendation': 'Implement deny-by-default RBAC. Verify every request server-side.',
                        'evidence': f'GET {self.url + path} → HTTP 200 ({len(r.text)} bytes)',
                        'cvss': '5.3',
                        'confidence': 'low',
                    })
                    break
            except Exception:
                pass

        # IDOR check — numeric IDs
        if '?' in self.url:
            params = urllib.parse.parse_qs(self.parsed.query)
            for key, vals in params.items():
                if vals and vals[0].isdigit():
                    test_id  = str(int(vals[0]) + 1)
                    test_url = self.url.replace(f'{key}={vals[0]}', f'{key}={test_id}')
                    try:
                        r = self.session.get(test_url, timeout=6)
                        similarity = difflib.SequenceMatcher(
                            None,
                            resp.text[:5000],
                            r.text[:5000]
                        ).ratio()

                        if (
                            r.status_code == 200
                            and len(r.text) > 500
                            and similarity < 0.40
                        ):
                            self._add({
                                'id': 'A01-IDOR', 'owasp_id': 'A01:2025', 'category': 'owasp',
                                'name': 'IDOR — Insecure Direct Object Reference',
                                'severity': 'medium',
                                'description': f'Changing numeric parameter `{key}` returns a different valid resource.',
                                'impact': "Unauthorized access to other users' data",
                                'recommendation': 'Validate object ownership on every request. Use UUIDs instead of sequential IDs.',
                                'evidence': f'?{key}={vals[0]} vs ?{key}={test_id} — different valid responses',
                                'cvss': '5.8',
                                'confidence': 'low',
                            })
                    except Exception:
                        pass

        # ── A02 — Cryptographic Failures ─────────────────────────────────────
        if self.url.startswith('http://') and not self.url.startswith('http://localhost'):
            self._add({
                'id': 'A02-HTTPS', 'owasp_id': 'A02:2025', 'category': 'owasp',
                'name': 'No HTTPS — Cleartext Transmission',
                'severity': 'critical',
                'description': 'Site served over unencrypted HTTP. All data in transit is exposed.',
                'impact': 'Credential theft, session hijacking, MITM attacks',
                'recommendation': 'Obtain TLS certificate. Redirect all HTTP to HTTPS. Enable HSTS.',
                'evidence': f'URL: {self.url}',
                'cvss': '7.5',
            })

        if self.url.startswith('https://'):

            hsts_val = h.get(
                'strict-transport-security',
                ''
            ).lower()

            if not hsts_val:

                self._add({
                    'id': 'A02-HSTS',
                    'owasp_id': 'A02:2025',
                    'category': 'owasp',
                    'name': 'HSTS Header Not Configured',
                    'severity': 'low',
                    'description': (
                        'The HTTPS response does not include the '
                        '`Strict-Transport-Security` header.'
                    ),
                    'impact': (
                        'Browsers may allow insecure HTTP connections '
                        'before HTTPS is enforced.'
                    ),
                    'recommendation': (
                        'Consider enabling HSTS using: '
                        '`Strict-Transport-Security: '
                        'max-age=31536000; includeSubDomains`'
                    ),
                    'evidence': (
                        'Response missing Strict-Transport-Security header'
                    ),
                    'cvss': '3.7',
                })

            elif 'max-age=0' in hsts_val:

                self._add({
                    'id': 'A02-HSTS-ZERO',
                    'owasp_id': 'A02:2025',
                    'category': 'owasp',
                    'name': 'HSTS Effectively Disabled',
                    'severity': 'low',
                    'description': (
                        'The HSTS header is present but configured '
                        'with `max-age=0`, which disables HSTS.'
                    ),
                    'impact': (
                        'Browsers will not enforce HTTPS-only '
                        'communication for future requests.'
                    ),
                    'recommendation': (
                        'Set a positive max-age value such as 31536000.'
                    ),
                    'evidence': (
                        f'Strict-Transport-Security: {hsts_val}'
                    ),
                    'cvss': '3.1',
                })

            elif 'max-age=' in hsts_val:

                try:

                    max_age = int(
                        re.search(
                            r'max-age=(\d+)',
                            hsts_val
                        ).group(1)
                    )

                    if max_age < 86400:

                        self._add({
                            'id': 'A02-HSTS-WEAK',
                            'owasp_id': 'A02:2025',
                            'category': 'owasp',
                            'name': 'Weak HSTS Configuration',
                            'severity': 'info',
                            'description': (
                                'HSTS is enabled but the configured '
                                'max-age value is very short.'
                            ),
                            'impact': (
                                'Browsers may not retain HTTPS '
                                'enforcement for long periods.'
                            ),
                            'recommendation': (
                                'Use a longer max-age such as 31536000.'
                            ),
                            'evidence': (
                                f'Strict-Transport-Security: {hsts_val}'
                            ),
                            'cvss': '0.0',
                        })

                except Exception:
                    pass

        # ── A04 — Insecure Design ─────────────────────────────────────────────
        login_forms  = soup.find_all('form', action=lambda a: a and any(x in str(a).lower() for x in ['login', 'signin', 'auth']))
        login_forms += soup.find_all('form') if not login_forms else []
        for form in login_forms[:2]:
            inputs = form.find_all('input', {'type': 'password'})
            if inputs:
                try:
                    action = form.get('action', self.url)
                    if not action.startswith('http'):
                        action = self.url + '/' + action.lstrip('/')
                        responses = []

                        for _ in range(10):
                            rr = self.session.post(
                                action,
                                data={
                                    'username': 'scanner_test',
                                    'password': 'wrong_password'
                                },
                                timeout=5,
                                allow_redirects=False
                            )
                            responses.append(rr)

                        last = responses[-1]

                        body = last.text.lower()

                        rate_limited = (
                            last.status_code == 429
                            or "too many requests" in body
                            or "rate limit" in body
                            or "captcha" in body
                            or "temporarily blocked" in body
                        )

                        if not rate_limited:
                            self._add({
                            'id': 'A04-RATELIMIT', 'owasp_id': 'A04:2025', 'category': 'owasp',
                            'name': 'No Rate Limiting on Login',
                            'severity': 'low',
                            'description': 'Login endpoint accepts unlimited requests without lockout or throttling.',
                            'impact': 'Brute-force credential attacks',
                            'recommendation': 'Implement rate limiting (max 5 attempts/min), CAPTCHA, and account lockout.',
                            'evidence': f'5 rapid POST requests to {action} — no lockout triggered',
                            'cvss': '3.7',
                            'confidence': 'low',
                        })
                except Exception:
                    pass
                break

        # ── A05 — Security Misconfiguration ──────────────────────────────────

        sec_headers = {
            'content-security-policy': (
                'Content-Security-Policy',
                'medium',
                'Prevents XSS and data injection',
                '5.3'
            ),
            'x-frame-options': (
                'X-Frame-Options',
                'low',
                'Prevents clickjacking',
                '3.1'
            ),
            'x-content-type-options': (
                'X-Content-Type-Options',
                'low',
                'Prevents MIME sniffing',
                '3.1'
            ),
        }

        optional_headers = {
            'referrer-policy': 'Referrer-Policy',
            'permissions-policy': 'Permissions-Policy',
            'cross-origin-embedder-policy': 'Cross-Origin-Embedder-Policy',
            'cross-origin-opener-policy': 'Cross-Origin-Opener-Policy'
        }

        missing = [
            (name, sev, desc, cvss)
            for key, (name, sev, desc, cvss) in sec_headers.items()
            if key not in h
        ]

        missing_optional = [
            name
            for key, name in optional_headers.items()
            if key not in h
        ]

        if missing:

            if any(sev == 'medium' for _, sev, _, _ in missing):
                overall_severity = 'medium'
                overall_cvss = '5.3'

            elif any(sev == 'low' for _, sev, _, _ in missing):
                overall_severity = 'low'
                overall_cvss = '3.1'

            else:
                overall_severity = 'info'
                overall_cvss = '0.0'

            evidence = (
                'Missing: ' +
                ', '.join(
                    f'{n} (CVSS {c})'
                    for n, _, _, c in missing
                )
            )

            if missing_optional:
                evidence += (
                    ' | Optional Missing: ' +
                    ', '.join(missing_optional)
                )

            self._add({
                'id': 'A05-HEADERS',
                'owasp_id': 'A05:2025',
                'category': 'owasp',
                'name': 'Missing Security Headers',
                'severity': overall_severity,
                'confidence': 'medium',
                'description': (
                    f'{len(missing)}/{len(sec_headers)} important '
                    f'security headers are absent.'
                ),
                'impact': (
                    'May increase exposure to XSS, clickjacking '
                    'and MIME-sniffing attacks.'
                ),
                'recommendation': (
                    'Configure the missing security headers in '
                    'your web server or application framework.'
                ),
                'evidence': evidence,
                'cvss': overall_cvss,
            })

        # ── A06 — Vulnerable Components ──────────────────────────────────────
        js_libs = [
            (r'jquery[/-](\d+\.\d+\.?\d*)',   'jQuery',    '3.7.0'),
            (r'bootstrap[/-](\d+\.\d+\.?\d*)', 'Bootstrap', '5.3.0'),
            (r'angular[/-](\d+\.\d+\.?\d*)',   'Angular',   '17.0.0'),
            (r'react[/-](\d+\.\d+\.?\d*)',     'React',     '18.0.0'),
            (r'vue[/-](\d+\.\d+\.?\d*)',       'Vue.js',    '3.3.0'),
        ]
        for pattern, lib, safe_ver in js_libs:
            m = re.search(pattern, body, re.I)
            if m:
                ver       = m.group(1)
                ver_parts  = [int(x) for x in re.findall(r'\d+', ver)]
                safe_parts = [int(x) for x in re.findall(r'\d+', safe_ver)]
                if ver_parts < safe_parts:
                    self._add({
                        'id': f'A06-{lib.upper().replace(".", "")}',
                        'owasp_id': 'A06:2025', 'category': 'owasp',
                        'name': f'Outdated Component — {lib} v{ver}',
                        'severity': 'medium',
                        'description': f'{lib} v{ver} is outdated (current safe: v{safe_ver}). Known vulnerabilities exist.',
                        'impact': 'XSS, prototype pollution, and other component-specific CVEs',
                        'recommendation': f'Update {lib} to v{safe_ver} or latest stable. Use npm audit / Snyk.',
                        'evidence': f'Detected {lib} v{ver} in page source',
                        'cvss': '6.1',
                    })

        # NOTE: A07 cookie checks have been moved entirely to _check_cookies()
        # to avoid duplicate findings inflating the score. That method handles
        # ALL cookie analysis including __Secure-/__Host- prefix logic.

        # ── A08 — Software Integrity ──────────────────────────────────────────
        scripts     = soup.find_all('script', src=True)
        ext_no_sri  = [
            s['src'] for s in scripts
            if any(cdn in s['src'] for cdn in ['cdn.', 'cdnjs.', 'jsdelivr.', 'unpkg.'])
            and not s.get('integrity')
        ]
        if ext_no_sri:
            self._add({
                'id': 'A08-SRI', 'owasp_id': 'A08:2025', 'category': 'owasp',
                'name': 'Missing Subresource Integrity (SRI)',
                'severity': 'medium',
                'description': f'{len(ext_no_sri)} CDN scripts loaded without integrity checks.',
                'impact': 'Supply chain attack if CDN is compromised',
                'recommendation': 'Generate SRI hashes with https://www.srihash.org and add integrity+crossorigin attributes.',
                'evidence': f'No SRI: {ext_no_sri[0]}',
                'cvss': '6.8',
            })

        # ── A09 — Logging / Monitoring ───────────────────────────────

        # ── A10 — SSRF ────────────────────────────────────────────────────────
        if self.parsed.query:
            params      = urllib.parse.parse_qs(self.parsed.query)
            ssrf_params = [k for k in params if any(x in k.lower() for x in
                           ['url', 'redirect', 'next', 'dest', 'path', 'link', 'src', 'uri', 'fetch', 'load'])]
            if ssrf_params:
                self._add({
                    'id': 'A10-SSRF', 'owasp_id': 'A10:2025', 'category': 'owasp',
                    'name': 'Potential SSRF — URL-Like Parameters',
                    'severity': 'info',
                    'description': f'Parameters {ssrf_params} may trigger server-side URL fetching without validation.',
                    'impact': 'Internal network enumeration, cloud metadata exfiltration, RCE',
                    'recommendation': 'Validate/whitelist all server-side URL destinations. Block internal IP ranges.',
                    'evidence': f'URL-like params detected: {", ".join(ssrf_params)}',
                    'cvss': '0.0',
                    'confidence': 'low'
                })

    # ─────────────────────────────────────────────────────────────────────────
    def _check_injection(self, base_resp, soup):
        parsed      = urllib.parse.urlparse(self.url)
        base_params = urllib.parse.parse_qs(parsed.query)
        test_params = base_params if base_params else {'id': ['1'], 'q': ['test']}

        # SQL Injection — error-based

        SQL_ERROR_PATTERNS = [
            r"sql syntax.*mysql",
            r"warning.*mysql",
            r"mysql_fetch",
            r"mysqli_sql_exception",
            r"postgresql.*error",
            r"pg_query",
            r"sqlite.*exception",
            r"sqlite3\.operationalerror",
            r"unclosed quotation mark after the character string",
            r"quoted string not properly terminated",
            r"microsoft ole db provider for sql server",
            r"sqlserverexception",
            r"ora-\d+",
            r"odbc sql server driver",
        ]

        # SQL — error-based
        for payload, _ in SQL_PAYLOADS:
            for param_key in list(test_params.keys())[:3]:

                new_params = {**test_params, param_key: [payload]}
                test_url = parsed._replace(
                    query=urllib.parse.urlencode(new_params, doseq=True)
                ).geturl()

                try:
                    r = self.session.get(test_url, timeout=8)

                    matched_error = None

                    for pattern in SQL_ERROR_PATTERNS:
                        match = re.search(pattern, r.text, re.I)
                        if match:
                            matched_error = match.group(0)
                            break

                    if matched_error:
                        self._add({
                            'id': 'SQL-ERROR',
                            'category': 'injection',
                            'name': 'SQL Injection — Error-Based',
                            'severity': 'high',
                            'description': (
                                'Database error patterns were identified in the HTTP response '
                                'after SQL meta-characters were injected.'
                            ),
                            'impact': (
                                'If exploitable, SQL injection may allow unauthorized '
                                'database access, data disclosure, authentication bypass, '
                                'or modification of records.'
                            ),
                            'recommendation': (
                                'Use parameterized queries / prepared statements exclusively. '
                                'Do not expose database errors in production responses.'
                            ),
                            'evidence': (
                                f'Param `{param_key}` payload `{payload}` '
                                f'→ matched DB error pattern: "{matched_error[:80]}"'
                            ),
                            'cvss': '8.1',
                        })
                        return

                except Exception:
                    pass

        # SQL — time-based blind

        try:
            import time as t

            baseline_start = t.time()
            self.session.get(self.url, timeout=10)
            baseline = t.time() - baseline_start

            payload = "1'; SELECT SLEEP(3)--"

            test_url = (
                self.url +
                ('?' if '?' not in self.url else '&') +
                'id=' + urllib.parse.quote(payload)
            )

            start = t.time()
            self.session.get(test_url, timeout=10)
            elapsed = t.time() - start

            delay = elapsed - baseline

            # Require meaningful delay to reduce false positives
            if delay >= 2.5:

                self._add({
                    'id': 'SQL-TIME',
                    'category': 'injection',
                    'name': 'Potential SQL Injection — Time-Based',
                    'severity': 'high',
                    'description': (
                        'The server response time increased significantly after a '
                        'time-delay SQL payload was supplied.'
                    ),
                    'impact': (
                        'If confirmed, attackers may be able to extract database '
                        'information through blind SQL injection techniques.'
                    ),
                    'recommendation': (
                        'Use parameterized queries and validate user-controlled input. '
                        'Avoid executing dynamic SQL queries.'
                    ),
                    'evidence': (
                        f'Payload `{payload}` caused '
                        f'{elapsed:.2f}s response time '
                        f'(baseline: {baseline:.2f}s)'
                    ),
                    'cvss': '7.5',
                })

        except Exception:
            pass

        # Reflected XSS
        
        xss_found = False
        
        XSS_PAYLOADS = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
        ]

        for payload in XSS_PAYLOADS:

            encoded = urllib.parse.quote(payload)

            test_url = (
                self.url +
                ('?' if '?' not in self.url else '&') +
                f'q={encoded}'
            )

            try:

                r = self.session.get(
                    test_url,
                    timeout=8
                )

                content_type = (
                    r.headers.get(
                        'content-type',
                        ''
                    ).lower()
                )

                if 'text/html' not in content_type:
                    continue

                body = r.text.lower()

                payload_lower = payload.lower()

                escaped_payload = html.escape(
                    payload
                ).lower()

                reflected_raw = (
                    payload_lower in body
                )

                reflected_escaped = (
                    escaped_payload in body
                )

                dangerous_contexts = [
                    '<script>',
                    'onerror=',
                    'onclick=',
                    'onload=',
                    'javascript:',
                ]

                dangerous = any(
                    ctx in body
                    for ctx in dangerous_contexts
                )

                if (
                    reflected_raw
                    and not reflected_escaped
                    and dangerous
                ):

                    self._add({
                        'id': 'XSS-REFLECT',
                        'category': 'injection',
                        'name': 'Potential Reflected XSS',
                        'severity': 'medium',
                        'description': (
                            'User-controlled input appears '
                            'to be reflected into an HTML '
                            'response without sufficient encoding.'
                        ),
                        'impact': (
                            'If exploitable, attackers may '
                            'inject malicious client-side scripts.'
                        ),
                        'recommendation': (
                            'Apply context-aware output encoding '
                            'and validate untrusted input.'
                        ),
                        'evidence': (
                            f'Payload reflected in HTML response: '
                            f'{payload[:40]}'
                        ),
                        'cvss': '5.3',
                    })

                    break

            except Exception:
                pass

        # Stored XSS hint
        if not xss_found:

            forms = soup.find_all('form')

            for form in forms[:3]:

                text_inputs = form.find_all(
                    'input',
                    type=lambda t: t in (
                        None,
                        'text',
                        'search',
                        'comment'
                    )
                )

                if (
                    not text_inputs
                    or form.get('method', '').upper()
                    not in ('POST', '')
                ):
                    continue

                action = form.get('action', self.url)

                if not action.startswith('http'):

                    action = (
                        self.url.rstrip('/')
                        + '/'
                        + action.lstrip('/')
                    )

                try:

                    payload = (
                        '<script>alert(1)</script>'
                    )

                    data = {
                        inp.get('name', 'q'): payload
                        for inp in text_inputs[:2]
                        if inp.get('name')
                    }

                    csrf_inp = form.find(
                        'input',
                        {
                            'name': re.compile(
                                'csrf|token|nonce',
                                re.I
                            )
                        }
                    )

                    if csrf_inp:

                        data[
                            csrf_inp['name']
                        ] = csrf_inp.get(
                            'value',
                            ''
                        )

                    r = self.session.post(
                        action,
                        data=data,
                        timeout=8
                    )

                    body = r.text.lower()

                    escaped_payload = html.escape(
                        payload
                    ).lower()

                    reflected_raw = (
                        payload.lower() in body
                    )

                    reflected_escaped = (
                        escaped_payload in body
                    )

                    dangerous_contexts = [
                        '<script>',
                        'onerror=',
                        'onclick=',
                        'onload=',
                        'javascript:',
                    ]

                    dangerous = any(
                        ctx in body
                        for ctx in dangerous_contexts
                    )

                    if (
                        reflected_raw
                        and not reflected_escaped
                        and dangerous
                    ):

                        self._add({
                            'id': 'XSS-STORED',
                            'category': 'injection',
                            'name': (
                                'Potential Stored XSS'
                            ),
                            'severity': 'medium',
                            'description': (
                                'User-supplied content appears '
                                'to be stored and reflected '
                                'without sufficient encoding.'
                            ),
                            'impact': (
                                'If exploitable, attackers may '
                                'inject persistent client-side '
                                'scripts into application pages.'
                            ),
                            'recommendation': (
                                'Sanitize untrusted input and '
                                'apply context-aware output '
                                'encoding.'
                            ),
                            'evidence': (
                                f'POST to {action} reflected '
                                f'unescaped payload content.'
                            ),
                            'cvss': '5.4',
                        })

                        break

                except Exception:
                    pass

        # CSRF Detection
        forms = soup.find_all(
            'form',
            method=lambda m: m and m.upper() == 'POST'
        )

        csrf_tokens = [
            'csrf',
            '_csrf',
            '_token',
            'csrf_token',
            'authenticity_token',
            'nonce',
            '__requestverificationtoken',
            'csrfmiddlewaretoken'
        ]

        cookie_string = "; ".join(
            f"{c.name}={c.value}"
            for c in self.session.cookies
        ).lower()

        has_samesite = (
            'samesite=lax' in cookie_string
            or 'samesite=strict' in cookie_string
        )

        for form in forms:

            inputs = [
                i.get('name', '').lower()
                for i in form.find_all('input')
            ]

            has_csrf = any(
                token in field
                for field in inputs
                for token in csrf_tokens
            )

            # Only flag if BOTH protections appear absent
            if not has_csrf and not has_samesite:

                action = form.get('action', '/')

                self._add({
                    'id': 'CSRF-01',
                    'category': 'injection',
                    'name': 'Potential CSRF Protection Missing',
                    'severity': 'info',
                    'confidence': 'low',
                    'description': (
                        'POST form detected without an obvious CSRF token. '
                        'Additional CSRF protections may exist.'
                    ),
                    'impact': (
                        'This is a heuristic observation and does not confirm '
                        'a CSRF vulnerability.'
                    ),
                    'recommendation': (
                        'Verify that CSRF protections such as synchronizer tokens, '
                        'SameSite cookies, origin validation, or custom headers are implemented.'
                    ),
                    'cvss': '0.0',
                })

                break

        # Server-Side Template Injection

        SSTI_PAYLOADS = [
            ('{{7*7}}', '49'),
            ('${7*7}', '49'),
            ('<%= 7*7 %>', '49'),
            ('#{7*7}', '49'),
        ]

        try:
            # Baseline response
            baseline = self.session.get(self.url, timeout=6)
            baseline_text = baseline.text.lower()

        except Exception:
            baseline_text = ''


        for payload, expected in SSTI_PAYLOADS:

            test_url = (
                self.url +
                ('?' if '?' not in self.url else '&') +
                'q=' + urllib.parse.quote(payload)
            )

            try:
                r = self.session.get(test_url, timeout=6)

                body = r.text.lower()

                patterns = [
                    rf'>\s*{re.escape(expected)}\s*<',
                    rf'["\']{re.escape(expected)}["\']',
                    rf'\b{re.escape(expected)}\b'
                ]

                matched = False

                for p in patterns:
                    if re.search(p, body):
                        matched = True
                        break

                if not matched:
                    continue

                if payload.lower() in body:
                    continue

                if expected in baseline_text:
                    continue

                similarity = difflib.SequenceMatcher(
                    None,
                    baseline_text,
                    body
                ).ratio()

                # Too similar = likely false positive
                if similarity > 0.98:
                    continue

                idx = body.find(expected)

                if idx == -1:
                    continue

                snippet = body[max(0, idx-40):idx+40]

                self._add({
                    'id': 'SSTI-01',
                    'category': 'injection',
                    'name': 'Potential Server-Side Template Injection',
                    'severity': 'medium',
                    'description': (
                        'User-supplied template syntax may have been evaluated '
                        'server-side.'
                    ),
                    'impact': (
                        'If confirmed, SSTI vulnerabilities may lead to '
                        'server-side code execution or sensitive data disclosure.'
                    ),
                    'recommendation': (
                        'Do not render untrusted user input inside templates. '
                        'Use sandboxing and strict escaping.'
                    ),
                    'evidence': (
                        f'Payload `{payload}` produced response variations '
                        f'consistent with possible template evaluation.'
                    ),
                    'cvss': '6.5',
                })

                break

            except Exception:
                pass

        # Local File Inclusion
        lfi_payloads = ['/../../../etc/passwd', '/..%2F..%2F..%2Fetc%2Fpasswd', '/?file=../../../etc/passwd']
        for p in lfi_payloads:
            try:
                r = self.session.get(self.url.rstrip('/') + p, timeout=6)
                if 'root:' in r.text or 'daemon:x:' in r.text:
                    self._add({
                        'id': 'LFI-01', 'category': 'injection',
                        'name': 'Local File Inclusion (LFI)',
                        'severity': 'critical',
                        'description': 'Path traversal allows reading /etc/passwd from the server.',
                        'impact': 'Full server file system read, credential exposure, RCE via log poisoning',
                        'recommendation': 'Sanitize file path inputs. Use basename(). Run web server with minimal OS privileges.',
                        'evidence': f'Path `{p}` returned /etc/passwd content',
                        'cvss': '9.1',
                    })
                    break
            except Exception:
                pass

        # XXE hint
        content_type = base_resp.headers.get('content-type', '')
        if 'xml' in content_type or soup.find('form', enctype='text/xml'):
            self._add({
                'id': 'XXE-01', 'category': 'injection',
                'name': 'Potential XXE — XML Input Accepted',
                'severity': 'high',
                'description': 'Application appears to process XML. May be vulnerable to XML External Entity injection.',
                'impact': 'File disclosure, SSRF, DoS via billion laughs attack',
                'recommendation': 'Disable external entity processing in XML parsers. Use JSON where possible.',
                'evidence': f'Content-Type: {content_type} suggests XML processing',
                'cvss': '8.2',
            })

    # ─────────────────────────────────────────────────────────────────────────
    def _check_sensitive_files(self):
        
        import difflib

        ROBOTS_SENSITIVE_HINTS = [
            '/admin',
            '/backup',
            '/internal',
            '/private',
            '/dashboard',
            '/config',
        ]

        FILE_SIGNATURES = {
            '.env': [
                'APP_KEY=',
                'DB_PASSWORD=',
                'DATABASE_URL=',
                'SECRET_KEY='
            ],

            '.git/HEAD': [
                'ref: refs/heads/'
            ],

            'config.php': [
                '$db_host',
                '$db_user',
                '$db_pass',
                'mysqli_connect(',
                'PDO('
            ],

            'wp-config.php': [
                'DB_NAME',
                'DB_PASSWORD',
                '$table_prefix'
            ],

            'phpinfo.php': [
                '<title>phpinfo()',
                'php version',
                'zend engine',
                'php credits'
            ],

            'web.config': [
                '<configuration',
                '<system.web',
                '<system.webserver'
            ],

            'backup.sql': [
                'CREATE TABLE',
                'INSERT INTO',
                'DROP TABLE'
            ],

            'database.sql': [
                'CREATE TABLE',
                'INSERT INTO',
                'DROP TABLE'
            ],

            '.bash_history': [
                'sudo ',
                'ssh ',
                'mysql ',
                'curl '
            ],

            'id_rsa': [
                '-----BEGIN RSA PRIVATE KEY-----',
                '-----BEGIN OPENSSH PRIVATE KEY-----'
            ]
        }

        try:
            baseline = self.session.get(
                self.url,
                timeout=6
            )

            baseline_text = baseline.text[:10000]

        except Exception:
            return

        for path, name, severity in SENSITIVE_FILES:

            try:

                test_url = self.url + path

                r = self.session.get(
                    test_url,
                    timeout=6,
                    allow_redirects=False
                )

                if r.status_code != 200:
                    continue

                body = r.text

                if len(body.strip()) < 10:
                    continue

                similarity = difflib.SequenceMatcher(
                    None,
                    baseline_text,
                    body[:10000]
                ).ratio()

                # Skip homepage/SPA responses
                if similarity > 0.75:
                    continue

                content_type = (
                    r.headers.get(
                        'Content-Type',
                        ''
                    ).lower()
                )
                
                if filename in [
                    'config.php',
                    'phpinfo.php',
                    'web.config'
                ]:

                    if 'html' in content_type:

                        if not verified:
                            continue

                # robots.txt handling
                if path == '/robots.txt':

                    has_sensitive_paths = any(
                        p in body.lower()
                        for p in ROBOTS_SENSITIVE_HINTS
                    )

                    self._add({
                        'id': 'FILE-ROBOTS',
                        'category': 'exposure',
                        'name': 'Robots.txt Publicly Accessible',
                        'severity': 'info',
                        'confidence': 'high',
                        'description': (
                            '`/robots.txt` is publicly accessible.'
                        ),
                        'impact': (
                            'May disclose internal paths.'
                            if has_sensitive_paths
                            else
                            'No direct security impact.'
                        ),
                        'recommendation': (
                            'Avoid exposing sensitive paths.'
                        ),
                        'evidence': (
                            f'GET {test_url} → '
                            f'HTTP 200 ({len(body)} bytes)'
                        ),
                        'cvss': (
                            '2.6'
                            if has_sensitive_paths
                            else '0.0'
                        ),
                    })

                    continue

                verified = False

                filename = path.lstrip('/')

                verified = False

                if filename in FILE_SIGNATURES:

                    verified = any(
                        sig.lower() in body.lower()
                        for sig in FILE_SIGNATURES[filename]
                    )

                else:
                    continue

                # Reject HTML pages for files that should not be HTML
                if (
                    filename.endswith(
                        ('.sql', '.env', '.key')
                    )
                    and 'html' in content_type
                ):
                    verified = False

                if not verified:
                    continue

                self._add({
                    'id': f'FILE-{path.replace("/", "").upper()}',
                    'category': 'exposure',
                    'name': f'Sensitive File Exposed: {name}',
                    'severity': severity,
                    'confidence': 'high',
                    'description': (
                        f'`{path}` appears to contain '
                        f'sensitive information.'
                    ),
                    'impact': (
                        'Potential disclosure of credentials, '
                        'configuration data, or internal assets.'
                    ),
                    'recommendation': (
                        f'Remove `{path}` from public access '
                        f'or restrict access.'
                    ),
                    'evidence': (
                        f'GET {test_url} → '
                        f'HTTP 200 ({len(body)} bytes)'
                    ),
                    'cvss': (
                        '8.6'
                        if severity == 'critical'
                        else '5.3'
                    ),
                })

            except Exception:
                pass

    # ─────────────────────────────────────────────────────────────────────────
    def _check_http_methods(self):

        dangerous = {
            'TRACE': 'high',
            'CONNECT': 'medium',
            'PUT': 'low',
            'DELETE': 'low',
            'PATCH': 'info'
        }

        try:
            options = self.session.options(
                self.url,
                timeout=6,
                allow_redirects=False
            )

            allow = options.headers.get(
                "Allow",
                ""
            ).upper()

        except Exception:
            allow = ""

        try:
            baseline = self.session.get(
                self.url,
                timeout=6,
                allow_redirects=False
            )
        except Exception:
            return

        cvss_map = {
            'high': '6.5',
            'medium': '4.3',
            'low': '2.6',
            'info': '0.0'
        }

        for method, severity in dangerous.items():

            try:

                # Skip if OPTIONS explicitly says method isn't allowed
                if allow and method not in allow:
                    continue

                r = self.session.request(
                    method,
                    self.url,
                    timeout=6,
                    allow_redirects=False
                )

                if (
                    r.status_code == 200
                    and len(r.text) > 0
                    and r.text != baseline.text
                ):

                    self._add({
                        'id': f'METHOD-{method}',
                        'category': 'owasp',
                        'owasp_id': 'A05:2025',
                        'name': f'Potentially Dangerous HTTP Method Enabled: {method}',
                        'severity': severity,
                        'confidence': 'low',
                        'description': (
                            f'Server appears to accept {method} requests.'
                        ),
                        'impact': (
                            'Some HTTP methods can increase attack surface '
                            'if they are not required by the application.'
                        ),
                        'recommendation': (
                            f'Review whether {method} is required and disable it if unused.'
                        ),
                        'evidence': (
                            f'{method} {self.url} → HTTP {r.status_code}'
                        ),
                        'cvss': cvss_map.get(severity, '0.0'),
                    })

            except Exception:
                pass

    # ─────────────────────────────────────────────────────────────────────────
    def _check_cookies(self, resp):

        SESSION_COOKIE_KEYWORDS = {
            'session', 'sess', 'auth', 'token', 'jwt',
            'login', 'sid', 'ssid', 'access',
            'csrf', 'identity'
        }

        LOW_RISK_COOKIES = {
            'nid', '_ga', '_gid', '_gat',
            '1p_jar', 'preferences'
        }

        for cookie in resp.cookies:

            if (
                cookie.name.startswith('__Secure-')
                or cookie.name.startswith('__Host-')
            ):

                if not cookie.secure:

                    self._add({
                        'id': f'COOKIE-{cookie.name}',
                        'category': 'owasp',
                        'owasp_id': 'A07:2025',
                        'name': f'Malformed Secure-Prefix Cookie — {cookie.name}',
                        'severity': 'low',
                        'description': (
                            f'Cookie `{cookie.name}` uses a secure prefix '
                            f'but is missing the Secure attribute.'
                        ),
                        'impact': (
                            'Browsers may reject the cookie.'
                        ),
                        'recommendation': (
                            'Ensure Secure is always set on '
                            '__Secure-/__Host- cookies.'
                        ),
                        'evidence': (
                            f'Set-Cookie: {cookie.name}; '
                            f'Secure flag absent'
                        ),
                        'cvss': '3.1',
                    })

                continue

            flags_str = (
                str(getattr(cookie, '_rest', {}))
                + str(cookie.__dict__)
            ).lower()

            issues = []

            name_lower = cookie.name.lower()

            is_session_cookie = any(
                kw in name_lower
                for kw in SESSION_COOKIE_KEYWORDS
            )

            is_low_risk = any(
                kw in name_lower
                for kw in LOW_RISK_COOKIES
            )

            httponly_present = (
                'httponly' in flags_str
            )

            samesite_present = (
                'samesite' in flags_str
            )

            if not cookie.secure:
                issues.append('Missing Secure flag')

            if not samesite_present:
                issues.append('Missing SameSite')

            if is_session_cookie and not httponly_present:
                issues.append('Missing HttpOnly')

            if not issues:
                continue

            if is_session_cookie:

                severity = (
                    'medium' if len(issues) >= 2 else 'low'
                )

                impact = (
                    'Session cookies missing security attributes '
                    'may be exposed to interception or cross-site attacks.'
                )

                cvss = (
                    '5.3' if severity == 'medium' else '3.1'
                )

            elif is_low_risk:

                severity = 'info'

                impact = (
                    'Limited security impact for non-session cookies.'
                )

                cvss = '0.0'

            else:

                severity = 'low'

                impact = (
                    'Non-session cookies are missing recommended '
                    'security attributes.'
                )

                cvss = '2.6'

            self._add({
                'id': f'COOKIE-{cookie.name}',
                'category': 'owasp',
                'owasp_id': 'A07:2025',
                'name': f'Cookie Security Attributes Missing — {cookie.name}',
                'severity': severity,
                'description': (
                    f'Cookie `{cookie.name}` is missing '
                    f'recommended security attributes: '
                    f'{", ".join(issues)}.'
                ),
                'impact': impact,
                'recommendation': (
                    'Apply Secure, SameSite, and HttpOnly '
                    'attributes where appropriate based on '
                    'the cookie purpose.'
                ),
                'evidence': (
                    f'Set-Cookie: {cookie.name}; '
                    f'issues: {", ".join(issues)}'
                ),
                'cvss': cvss,
            })
    # ─────────────────────────────────────────────────────────────────────────
    def _check_cors(self):
        try:
            r    = self.session.get(self.url, headers={'Origin': 'https://evil.com'}, timeout=8)
            acao = r.headers.get('access-control-allow-origin', '')
            acac = r.headers.get('access-control-allow-credentials', '')
            if acao == '*':
                self._add({
                    'id': 'CORS-WILDCARD', 'category': 'injection',
                    'name': 'CORS Wildcard Origin',
                    'severity': 'medium',
                    'description': 'ACAO: * allows any origin to read responses.',
                    'impact': 'Cross-origin data leakage from public endpoints',
                    'recommendation': 'Replace wildcard with specific trusted origins.',
                    'evidence': 'Access-Control-Allow-Origin: *',
                    'cvss': '5.3',
                })
            elif acao == 'https://evil.com':
                sev = 'critical' if acac.lower() == 'true' else 'high'
                self._add({
                    'id': 'CORS-REFLECT', 'category': 'injection',
                    'name': 'CORS Arbitrary Origin Reflection',
                    'severity': sev,
                    'description': 'Server reflects arbitrary Origin header. Credentials may be included.',
                    'impact': 'Full cross-origin data theft if credentials are included',
                    'recommendation': 'Validate Origin against a strict whitelist. Never reflect arbitrary origins.',
                    'evidence': f'ACAO: {acao}, ACAC: {acac}',
                    'cvss': '9.0' if sev == 'critical' else '7.5',
                })
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    def _check_open_redirect(self):

        redirect_params = [
            'redirect', 'next', 'url', 'return',
            'dest', 'destination', 'redir',
            'target', 'goto', 'link'
        ]

        evil_url = 'https://evil.com'

        # Known safe/interstitial redirect indicators
        SAFE_REDIRECT_PATTERNS = [
            'sorry',
            'interstitial',
            'warning',
            'blocked',
            'safebrowsing',
            'consent',
        ]

        for param in redirect_params:

            test_url = (
                self.url +
                ('?' if '?' not in self.url else '&') +
                f'{param}={urllib.parse.quote(evil_url)}'
            )

            try:
                r = self.session.get(
                    test_url,
                    timeout=6,
                    allow_redirects=False
                )

                location = r.headers.get('location', '')

                # Only inspect redirect responses
                if r.status_code not in (301, 302, 303, 307, 308):
                    continue

                location_lower = location.lower()

                # Ignore safe warning/interstitial redirects
                is_safe_redirect = any(
                    pattern in location_lower
                    for pattern in SAFE_REDIRECT_PATTERNS
                )

                # Confirm external redirect
                redirects_external = (
                    'evil.com' in location_lower
                )

                if redirects_external:

                    # Safe handling / interstitial page
                    if is_safe_redirect:

                        self._add({
                            'id': 'REDIRECT-SAFE',
                            'category': 'redirect',
                            'name': 'External Redirect Attempt Handled Safely',
                            'severity': 'info',
                            'description': (
                                'Application redirected through a warning or '
                                'interstitial page instead of directly redirecting '
                                'to the external domain.'
                            ),
                            'impact': (
                                'No confirmed open redirect vulnerability detected.'
                            ),
                            'recommendation': (
                                'Continue validating redirect destinations using '
                                'strict allowlists.'
                            ),
                            'evidence': (
                                f'?{param}={evil_url} '
                                f'→ {r.status_code} Location: {location[:200]}'
                            ),
                            'cvss': '0.0',
                        })

                    # Actual open redirect
                    else:

                        self._add({
                            'id': 'REDIRECT-01',
                            'category': 'redirect',
                            'name': 'Potential Open Redirect',
                            'severity': 'medium',
                            'description': (
                                f'`{param}` parameter redirects users to an '
                                f'external domain based on user-controlled input.'
                            ),
                            'impact': (
                                'Attackers may abuse the redirect for phishing, '
                                'credential theft, or malicious navigation.'
                            ),
                            'recommendation': (
                                'Validate redirect targets against a strict '
                                'allowlist of trusted domains.'
                            ),
                            'evidence': (
                                f'?{param}={evil_url} '
                                f'→ {r.status_code} Location: {location[:200]}'
                            ),
                            'cvss': '6.1',
                        })

                        return

            except Exception:
                pass

    # ─────────────────────────────────────────────────────────────────────────
    def _check_ssl(self):
        if self.hostname:
            ssl_data = check_ssl_details(self.hostname)
            self.results['ssl_info'] = ssl_data
            if ssl_data.get('expired'):
                self._add({
                    'id': 'SSL-EXPIRED', 'category': 'owasp', 'owasp_id': 'A02:2025',
                    'name': 'SSL Certificate Expired',
                    'severity': 'critical',
                    'description': 'TLS certificate has expired. Browsers will show security warnings.',
                    'impact': 'User warnings, loss of trust, possible MITM',
                    'recommendation': "Renew certificate immediately. Use Let's Encrypt for free auto-renewal.",
                    'evidence': f'Certificate expired: {ssl_data.get("expires")}',
                    'cvss': '7.5',
                })
            elif ssl_data.get('expiring_soon'):

                days = ssl_data.get("days_remaining", 0)

                if days <= 7:
                    severity = 'low'
                    cvss = '3.1'
                else:
                    severity = 'info'
                    cvss = '0.0'

                self._add({
                    'id': 'SSL-EXPIRING',
                    'category': 'owasp',
                    'owasp_id': 'A02:2025',
                    'name': 'SSL Certificate Expiring Soon',
                    'severity': severity,
                    'confidence': 'high',
                    'description': (
                        f'Certificate expires in {days} days.'
                    ),
                    'impact': (
                        'Certificate renewal may be required soon.'
                    ),
                    'recommendation': (
                        'Monitor renewal process and ensure automatic renewal is configured.'
                    ),
                    'evidence': f'Days remaining: {days}',
                    'cvss': cvss,
                })
            if ssl_data.get('weak_cipher'):
                self._add({
                    'id': 'SSL-WEAKCIP', 'category': 'owasp', 'owasp_id': 'A02:2025',
                    'name': 'Weak SSL Cipher Suite',
                    'severity': 'high',
                    'description': f'Cipher {ssl_data.get("cipher")} uses {ssl_data.get("bits")}-bit key.',
                    'impact': 'Possible decryption of recorded traffic',
                    'recommendation': 'Configure server to use only TLS 1.3 and strong cipher suites (AES-256-GCM).',
                    'evidence': f'Cipher: {ssl_data.get("cipher")} ({ssl_data.get("bits")} bits)',
                    'cvss': '7.4',
                })

    # ─────────────────────────────────────────────────────────────────────────
    def _check_dns(self):
        dns_data = check_dns_security(self.hostname)
        self.results['dns_security'] = dns_data

        if not dns_data.get('spf'):

            has_mx = bool(dns_data.get('mx'))

            self._add({
                'id': 'DNS-SPF',
                'category': 'dns',
                'name': 'SPF Record Not Detected',
                'severity': 'low' if has_mx else 'info',
                'description': (
                    'No SPF TXT record was detected for the domain.'
                ),
                'impact': (
                    'Email spoofing protections may be reduced '
                    'depending on the domain email configuration.'
                    if has_mx else
                    'No direct security impact identified because '
                    'no MX records were detected.'
                ),
                'recommendation': (
                    'Consider configuring an SPF policy for '
                    'authorized mail servers.'
                ),
                'evidence': (
                    f'No SPF TXT record detected for {self.hostname}'
                ),
                'cvss': '3.1' if has_mx else '0.0',
            })

        ext = tldextract.extract(self.hostname)
        root_domain = f"{ext.domain}.{ext.suffix}"

        if not dns_data.get('dmarc'):

            has_mx = bool(dns_data.get('mx'))

            self._add({
                'id': 'DNS-DMARC',
                'category': 'dns',
                'name': 'DMARC Record Not Detected',
                'severity': 'low' if has_mx else 'info',
                'description': (
                    'No DMARC record was detected for the root domain.'
                ),
                'impact': (
                    'Email spoofing protection and domain-based '
                    'email validation may be reduced.'
                    if has_mx else
                    'No direct security impact identified because '
                    'no MX records were detected.'
                ),
                'recommendation': (
                    'Consider configuring a DMARC policy '
                    'for outbound email protection.'
                ),
                'evidence': (
                    f'No DMARC record detected at '
                    f'_dmarc.{root_domain}'
                ),
                'cvss': '3.1' if has_mx else '0.0',
            })

        ext = tldextract.extract(self.hostname)
        root_domain = f"{ext.domain}.{ext.suffix}"

        if not dns_data.get('dnssec'):

            self._add({
                'id': 'DNS-DNSSEC',
                'category': 'dns',
                'name': 'DNSSEC Not Enabled',
                'severity': 'info',
                'description': (
                    'No DNSSEC DS records were detected '
                    'for the root domain.'
                ),
                'impact': (
                    'DNS responses may rely solely on '
                    'traditional DNS trust mechanisms '
                    'without DNSSEC validation.'
                ),
                'recommendation': (
                    'Consider enabling DNSSEC at the '
                    'domain registrar and DNS provider.'
                ),
                'evidence': (
                    f'No DS records detected for '
                    f'{root_domain}'
                ),
                'cvss': '0.0',
            })

    # ─────────────────────────────────────────────────────────────────────────
    def _detect_waf(self, headers, body):
        h_str = str(headers).lower()
        b_str = body.lower()
        for waf_name, sigs in WAF_SIGNATURES.items():
            if any(sig.lower() in h_str or sig.lower() in b_str for sig in sigs):
                self.results['waf'] = waf_name
                return

        # Probe with attack-like request
        try:
            probe = self.session.get(
                self.url + "/?a=<script>alert(1)</script>&b='OR 1=1--",
                timeout=6
            )
            if probe.status_code in (403, 406, 429, 503):
                waf_hdrs = {k.lower(): v for k, v in probe.headers.items()}
                if 'cloudflare' in str(waf_hdrs):
                    self.results['waf'] = 'Cloudflare'
                elif 'sucuri' in str(waf_hdrs):
                    self.results['waf'] = 'Sucuri'
                else:
                    self.results['waf'] = f'Unknown WAF (HTTP {probe.status_code} on attack payload)'
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
                s      = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.2)
                result = s.connect_ex((ip, port))
                s.close()
                state  = 'open' if result == 0 else 'closed'
            except Exception:
                state = 'filtered'
            service, risk = PORT_META.get(port, ('Unknown', 'info'))
            return {
                'port': port, 'state': state, 'service': service,
                'protocol': 'TCP', 'risk': risk if state == 'open' else 'info',
            }

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            results = list(ex.map(probe, COMMON_PORTS))

        self.results['ports'] = results

        critical_open = [r for r in results if r['state'] == 'open' and r['risk'] == 'critical']
        for p in critical_open:
            self._add({
                'id': f'PORT-{p["port"]}', 'category': 'ports',
                'name': f'Critical Service Exposed: {p["service"]} ({p["port"]})',
                'severity': 'critical',
                'description': f'Port {p["port"]} ({p["service"]}) is accessible from the internet.',
                'impact': 'Direct exploitation of database/remote access services',
                'recommendation': f'Restrict port {p["port"]} to trusted IPs via firewall. Never expose {p["service"]} to the internet.',
                'evidence': f'Port {p["port"]}/TCP OPEN — {p["service"]}',
                'cvss': '9.0',
            })

    # ─────────────────────────────────────────────────────────────────────────
    def _detect_tech(self, headers, body):
        techs = []
        h     = headers  # CaseInsensitiveDict

        def add_tech(name, cat, ver=None):
            if not any(t['name'].lower() == name.lower() for t in techs):
                techs.append({'name': name, 'category': cat, 'version': ver})

        server = h.get('server', '')
        if server:
            parts = server.split('/')
            add_tech(parts[0].strip(), 'Web Server', parts[1].split(' ')[0] if len(parts) > 1 else None)

        powered = h.get('x-powered-by', '')
        if powered:
            parts = powered.split('/')
            add_tech(parts[0].strip(), 'Language', parts[1] if len(parts) > 1 else None)

        patterns = [
            (r'wp-content|wp-includes|wp-json',   'WordPress',    'CMS',          r'wordpress[\s/]+([\d.]+)'),
            (r'drupal\.org|drupal\.js',            'Drupal',       'CMS',          r'Drupal ([\d.]+)'),
            (r'joomla',                            'Joomla',       'CMS',          r'Joomla[\s/]+([\d.]+)'),
            (r'shopify',                           'Shopify',      'E-Commerce',   None),
            (r'magento',                           'Magento',      'E-Commerce',   r'Magento[\s/]+([\d.]+)'),
            (r'laravel',                           'Laravel',      'Framework',    None),
            (r'django',                            'Django',       'Framework',    None),
            (r'rails',                             'Ruby on Rails','Framework',    None),
            (r'express',                           'Express.js',   'Framework',    None),
            (r'next\.js|__next',                   'Next.js',      'Framework',    r'next[\s/]+([\d.]+)'),
            (r'nuxt',                              'Nuxt.js',      'Framework',    None),
            (r'react|__react',                     'React',        'JavaScript',   r'react[\s@/]+([\d.]+)'),
            (r'vue\.js|data-v-',                   'Vue.js',       'JavaScript',   r'vue[\s@/]+([\d.]+)'),
            (r'angular',                           'Angular',      'JavaScript',   r'angular[\s@/]+([\d.]+)'),
            (r'jquery',                            'jQuery',       'JavaScript',   r'jquery[\s@/v]+([\d.]+)'),
            (r'bootstrap',                         'Bootstrap',    'CSS Framework',r'bootstrap[\s@/]+([\d.]+)'),
            (r'tailwind',                          'Tailwind CSS', 'CSS Framework',None),
            (r'cloudflare',                        'Cloudflare',   'CDN',          None),
            (r'google-analytics|gtag|ga\.js',      'Google Analytics','Analytics', None),
            (r'nginx',                             'Nginx',        'Web Server',   r'nginx/([\d.]+)'),
            (r'apache',                            'Apache',       'Web Server',   r'Apache/([\d.]+)'),
            (r'node\.js|nodejs',                   'Node.js',      'Runtime',      r'node/([\d.]+)'),
            (r'php',                               'PHP',          'Language',     r'PHP/([\d.]+)'),
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
            add_tech('TLS/SSL', 'Security', None)

        self.results['technologies'] = techs

        # NVD CVE lookup for detected techs
        for tech in techs[:4]:
            if tech['version']:
                cve_data = check_nvd_cves(tech['name'], tech['version'])
                for cve in cve_data.get('cves', []):
                    if float(cve.get('cvss', 0)) >= 7.0:
                        self._add({
                            'id': f'CVE-{cve["id"]}', 'category': 'cve', 'owasp_id': 'A06:2025',
                            'name': f'{cve["id"]} — {tech["name"]} v{tech["version"]}',
                            'severity': 'critical' if float(cve.get('cvss', 0)) >= 9 else 'high',
                            'description': cve.get('description', ''),
                            'impact': 'Component-specific exploitation based on CVE details',
                            'recommendation': f'Upgrade {tech["name"]} from v{tech["version"]} to a patched version.',
                            'evidence': f'CVSS {cve.get("cvss")} — Published {cve.get("published")}',
                            'cvss': str(cve.get('cvss', '')),
                        })

    # ─────────────────────────────────────────────────────────────────────────
    def _calc_risk_score(self):

        SEVERITY_WEIGHTS = {
            'critical': 20,
            'high': 10,
            'medium': 5,
            'low': 2,
            'info': 0,
        }

        CONFIDENCE_WEIGHTS = {
            'high': 1.0,
            'medium': 0.6,
            'low': 0.3,
        }

        raw = 0

        for vuln in self.results['vulnerabilities']:

            severity = vuln.get('severity', 'info').lower()
            confidence = vuln.get('confidence', 'medium').lower()

            severity_weight = SEVERITY_WEIGHTS.get(severity, 0)
            confidence_weight = CONFIDENCE_WEIGHTS.get(confidence, 0.6)

            raw += severity_weight * confidence_weight

        # Logarithmic normalization
        K = 100

        normalized = round(
            100 * (1 - math.exp(-raw / K))
        )

        return min(normalized, 100)
