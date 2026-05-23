import requests
import time
import socket
import dns.resolver
import ssl
import json
from datetime import datetime
from config import API_KEYS

HEADERS = {'User-Agent': 'VulnScan/1.0 Security Scanner (research)'}

def safe_get(url, headers=None, params=None, timeout=10):
    try:
        r = requests.get(url, headers={**HEADERS, **(headers or {})}, params=params, timeout=timeout)
        return r
    except Exception as e:
        return None

def check_virustotal(target_url):
    key = API_KEYS.get('VIRUSTOTAL', '')
    if not key or key.startswith('YOUR_'):
        return {'enabled': False, 'source': 'VirusTotal'}

    try:
        import base64
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().rstrip('=')
        r = safe_get(
            f'https://www.virustotal.com/api/v3/urls/{url_id}',
            headers={'x-apikey': key}
        )
        if not r or r.status_code != 200:
            # Submit URL first
            submit = requests.post(
                'https://www.virustotal.com/api/v3/urls',
                headers={'x-apikey': key},
                data={'url': target_url}, timeout=10
            )
            if submit.status_code != 200:
                return {'enabled': True, 'error': 'Submission failed', 'source': 'VirusTotal'}
            analysis_id = submit.json()['data']['id']
            time.sleep(15)
            r = safe_get(f'https://www.virustotal.com/api/v3/analyses/{analysis_id}', headers={'x-apikey': key})

        if r and r.status_code == 200:
            data = r.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', data.get('stats', {}))
            results = data.get('last_analysis_results', data.get('results', {}))
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values()) if stats else 0

            flagged_by = [engine for engine, result in (results or {}).items()
                         if result.get('category') in ('malicious', 'suspicious')]

            return {
                'enabled': True, 'source': 'VirusTotal',
                'malicious': malicious, 'suspicious': suspicious,
                'total_engines': total, 'flagged_by': flagged_by[:10],
                'reputation_score': data.get('reputation', 0),
                'severity': 'critical' if malicious >= 5 else 'high' if malicious >= 2 else 'medium' if suspicious >= 3 else 'info',
            }
    except Exception as e:
        return {'enabled': True, 'error': str(e), 'source': 'VirusTotal'}

def check_shodan(hostname):
    key = API_KEYS.get('SHODAN', '')
    if not key or key.startswith('YOUR_'):
        return {'enabled': False, 'source': 'Shodan'}

    try:
        ip = socket.gethostbyname(hostname)
        r = safe_get(f'https://api.shodan.io/shodan/host/{ip}', params={'key': key})
        if r and r.status_code == 200:
            data = r.json()
            ports = data.get('ports', [])
            vulns = list(data.get('vulns', {}).keys())
            services = [f"{item.get('port')}/{item.get('transport','tcp')} ({item.get('product','')} {item.get('version','')})"
                       for item in data.get('data', [])[:10]]
            return {
                'enabled': True, 'source': 'Shodan', 'ip': ip,
                'open_ports': ports,
                'services': services,
                'cves': vulns,
                'country': data.get('country_name'),
                'org': data.get('org'),
                'isp': data.get('isp'),
                'os': data.get('os'),
                'tags': data.get('tags', []),
                'last_update': data.get('last_update'),
            }
        return {'enabled': True, 'source': 'Shodan', 'error': 'Host not found in Shodan index'}
    except Exception as e:
        return {'enabled': True, 'error': str(e), 'source': 'Shodan'}

def check_urlscan(target_url):
    key = API_KEYS.get('URLSCAN', '')
    if not key or key.startswith('YOUR_'):
        return {'enabled': False, 'source': 'URLScan.io'}

    try:
        submit = requests.post(
            'https://urlscan.io/api/v1/scan/',
            headers={'API-Key': key, 'Content-Type': 'application/json'},
            json={'url': target_url, 'visibility': 'private'}, timeout=15
        )
        if submit.status_code not in (200, 201):
            return {'enabled': True, 'error': 'Scan submission failed', 'source': 'URLScan.io'}

        result_url = submit.json().get('api')
        if not result_url:
            return {'enabled': True, 'error': 'No result URL', 'source': 'URLScan.io'}

        for _ in range(6):
            time.sleep(10)
            r = safe_get(result_url)
            if r and r.status_code == 200:
                data = r.json()
                page = data.get('page', {})
                verdicts = data.get('verdicts', {}).get('overall', {})
                requests_list = data.get('data', {}).get('requests', [])
                malicious_requests = [req for req in requests_list
                                     if req.get('response', {}).get('failed')]
                return {
                    'enabled': True, 'source': 'URLScan.io',
                    'screenshot': data.get('task', {}).get('screenshotURL'),
                    'malicious': verdicts.get('malicious', False),
                    'score': verdicts.get('score', 0),
                    'categories': verdicts.get('categories', []),
                    'server': page.get('server'),
                    'ip': page.get('ip'),
                    'country': page.get('country'),
                    'tls_valid': page.get('tlsValidDays', 0) > 0,
                    'tls_days': page.get('tlsValidDays'),
                    'total_requests': len(requests_list),
                    'failed_requests': len(malicious_requests),
                }
        return {'enabled': True, 'error': 'Scan timed out', 'source': 'URLScan.io'}
    except Exception as e:
        return {'enabled': True, 'error': str(e), 'source': 'URLScan.io'}

def check_google_safe_browsing(target_url):
    key = API_KEYS.get('GOOGLE_SAFE_BROWSING', '')
    if not key or key.startswith('YOUR_'):
        return {'enabled': False, 'source': 'Google Safe Browsing'}

    try:
        payload = {
            'client': {'clientId': 'VulnScan', 'clientVersion': '1.0'},
            'threatInfo': {
                'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': target_url}]
            }
        }
        r = requests.post(
            f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}',
            json=payload, timeout=10
        )
        data = r.json()
        matches = data.get('matches', [])
        return {
            'enabled': True, 'source': 'Google Safe Browsing',
            'threats_found': len(matches) > 0,
            'threats': [{'type': m.get('threatType'), 'platform': m.get('platformType')} for m in matches],
            'severity': 'critical' if matches else 'info',
        }
    except Exception as e:
        return {'enabled': True, 'error': str(e), 'source': 'Google Safe Browsing'}

def check_hibp_domain(domain):
    key = API_KEYS.get('HIBP', '')
    if not key or key.startswith('YOUR_'):
        return {'enabled': False, 'source': 'HaveIBeenPwned'}

    try:
        r = safe_get(
            f'https://haveibeenpwned.com/api/v3/breacheddomain/{domain}',
            headers={'hibp-api-key': key}
        )
        if r and r.status_code == 200:
            data = r.json()
            return {
                'enabled': True, 'source': 'HaveIBeenPwned',
                'breached': True, 'emails_found': len(data),
                'severity': 'high',
            }
        return {'enabled': True, 'source': 'HaveIBeenPwned', 'breached': False}
    except Exception as e:
        return {'enabled': True, 'error': str(e), 'source': 'HaveIBeenPwned'}

def check_nvd_cves(tech_name, version=None):
    key = API_KEYS.get('NVD', '')
    headers = {'apiKey': key} if key else {}
    try:
        keyword = f'{tech_name} {version}' if version else tech_name
        r = safe_get(
            'https://services.nvd.nist.gov/rest/json/cves/1.0',
            headers=headers,
            params={'keywordSearch': keyword, 'resultsPerPage': 5, 'cvssV3Severity': 'HIGH'}
        )
        if r and r.status_code == 200:
            vulns = r.json().get('vulnerabilities', [])
            cves = []
            for v in vulns:
                cve = v.get('cve', {})
                metrics = cve.get('metrics', {})
                cvss = (metrics.get('cvssMetricV31') or metrics.get('cvssMetricV30') or [{}])[0]
                score = cvss.get('cvssData', {}).get('baseScore', 0)
                cves.append({
                    'id': cve.get('id'),
                    'description': (cve.get('descriptions', [{}])[0]).get('value', '')[:200],
                    'cvss': score,
                    'severity': cvss.get('cvssData', {}).get('baseSeverity', 'UNKNOWN'),
                    'published': cve.get('published', '')[:10],
                })
            return {'enabled': True, 'source': 'NVD NIST', 'cves': cves, 'tech': tech_name}
    except Exception as e:
        pass
    return {'enabled': True, 'source': 'NVD NIST', 'cves': [], 'tech': tech_name}

def check_dns_security(domain):
    results = {'spf': None, 'dmarc': None, 'dkim': None, 'dnssec': False, 'caa': None}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    try:
        txt = resolver.resolve(domain, 'TXT')
        for r in txt:
            val = r.to_text().strip('"')
            if val.startswith('v=spf1'):
                results['spf'] = val
    except: pass

    try:
        dmarc = resolver.resolve(f'_dmarc.{domain}', 'TXT')
        for r in dmarc:
            val = r.to_text().strip('"')
            if 'v=DMARC1' in val:
                results['dmarc'] = val
    except: pass

    try:
        caa = resolver.resolve(domain, 'CAA')
        results['caa'] = [str(r) for r in caa]
    except: pass

    try:
        ds = resolver.resolve(domain, 'DS')
        if ds:
            results['dnssec'] = True
    except: pass

    return results

def check_ssl_details(hostname, port=443):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, port))
            cert = s.getpeercert()
            cipher = s.cipher()

        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        days_remaining = (not_after - datetime.utcnow()).days

        san = [v for _, v in cert.get('subjectAltName', [])]
        subject = dict(x[0] for x in cert.get('subject', []))

        return {
            'valid': True,
            'days_remaining': days_remaining,
            'expires': cert['notAfter'],
            'issuer': dict(x[0] for x in cert.get('issuer', [])).get('organizationName', 'Unknown'),
            'subject': subject.get('commonName', hostname),
            'san': san[:10],
            'cipher': cipher[0] if cipher else 'Unknown',
            'protocol': cipher[1] if cipher else 'Unknown',
            'bits': cipher[2] if cipher else 0,
            'expired': days_remaining < 0,
            'expiring_soon': 0 < days_remaining < 30,
            'weak_cipher': cipher[2] < 128 if cipher and cipher[2] else False,
        }
    except ssl.SSLError as e:
        return {'valid': False, 'error': str(e)}
    except Exception as e:
        return {'valid': None, 'error': str(e)}
