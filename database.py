import mysql.connector
from datetime import datetime
from config import DB_CONFIG

class Database:
    def __init__(self):
        self.conn = None

    def connect(self):
        if self.conn is None or not self.conn.is_connected():
            self.conn = mysql.connector.connect(**DB_CONFIG)
        return self.conn

    def init(self):
        try:
            cfg = {k: v for k, v in DB_CONFIG.items() if k != 'database'}
            c = mysql.connector.connect(**cfg)
            c.cursor().execute('CREATE DATABASE IF NOT EXISTS vulnscan')
            c.commit(); c.close()
            cur = self.connect().cursor()
            cur.execute('''CREATE TABLE IF NOT EXISTS scans (
                id VARCHAR(20) PRIMARY KEY, url TEXT NOT NULL,
                status VARCHAR(20) DEFAULT 'running', risk_score INT DEFAULT 0,
                vuln_count INT DEFAULT 0, waf VARCHAR(100),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                completed_at DATETIME)''')
            cur.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INT AUTO_INCREMENT PRIMARY KEY, scan_id VARCHAR(20),
                vuln_id VARCHAR(50), owasp_id VARCHAR(20), category VARCHAR(30),
                name VARCHAR(200), severity VARCHAR(20), description TEXT,
                impact TEXT, recommendation TEXT, evidence TEXT, cvss VARCHAR(10),
                FOREIGN KEY (scan_id) REFERENCES scans(id))''')
            cur.execute('''CREATE TABLE IF NOT EXISTS scan_ports (
                id INT AUTO_INCREMENT PRIMARY KEY, scan_id VARCHAR(20),
                port INT, state VARCHAR(20), service VARCHAR(50),
                protocol VARCHAR(10), risk VARCHAR(20),
                FOREIGN KEY (scan_id) REFERENCES scans(id))''')
            cur.execute('''CREATE TABLE IF NOT EXISTS scan_technologies (
                id INT AUTO_INCREMENT PRIMARY KEY, scan_id VARCHAR(20),
                name VARCHAR(100), category VARCHAR(50), version VARCHAR(50),
                FOREIGN KEY (scan_id) REFERENCES scans(id))''')
            print('[DB] Schema ready')
        except Exception as e:
            print(f'[DB] Init warning: {e}')

    def create_scan(self, scan_id, url):
        try:
            self.connect().cursor().execute(
                'INSERT INTO scans (id, url, status) VALUES (%s, %s, %s)',
                (scan_id, url, 'running'))
        except Exception as e:
            print(f'[DB] create_scan: {e}')

    def save_results(self, scan_id, result):
        try:
            c = self.connect().cursor()
            vulns = result.get('vulnerabilities', [])
            for v in vulns:
                c.execute('''INSERT INTO vulnerabilities
                    (scan_id,vuln_id,owasp_id,category,name,severity,description,impact,recommendation,evidence,cvss)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                    (scan_id, v.get('id'), v.get('owasp_id'), v.get('category'), v.get('name'),
                     v.get('severity'), v.get('description'), v.get('impact'),
                     v.get('recommendation'), v.get('evidence'), str(v.get('cvss',''))))
            for p in result.get('ports', []):
                if p['state'] == 'open':
                    c.execute('INSERT INTO scan_ports (scan_id,port,state,service,protocol,risk) VALUES (%s,%s,%s,%s,%s,%s)',
                        (scan_id, p['port'], p['state'], p.get('service'), p.get('protocol','TCP'), p.get('risk','info')))
            for t in result.get('technologies', []):
                c.execute('INSERT INTO scan_technologies (scan_id,name,category,version) VALUES (%s,%s,%s,%s)',
                    (scan_id, t['name'], t.get('category'), t.get('version')))
            c.execute('UPDATE scans SET status=%s,vuln_count=%s,risk_score=%s,waf=%s,completed_at=%s WHERE id=%s',
                ('complete', len(vulns), result.get('score', 0), result.get('waf'), datetime.now(), scan_id))
        except Exception as e:
            print(f'[DB] save_results: {e}')

    def get_scan(self, scan_id):
        try:
            c = self.connect().cursor(dictionary=True)
            c.execute('SELECT * FROM scans WHERE id=%s', (scan_id,))
            scan = c.fetchone()
            if not scan: return None
            c.execute('SELECT * FROM vulnerabilities WHERE scan_id=%s', (scan_id,))
            vulns = c.fetchall()
            c.execute('SELECT * FROM scan_ports WHERE scan_id=%s', (scan_id,))
            ports = c.fetchall()
            c.execute('SELECT * FROM scan_technologies WHERE scan_id=%s', (scan_id,))
            techs = c.fetchall()
            return {
                'status': scan['status'], 'url': scan['url'],
                'score': scan.get('risk_score', 0), 'waf': scan.get('waf'),
                'created_at': str(scan['created_at']),
                'total_vulns': len(vulns),
                'vulnerabilities': [{k:v for k,v in vuln.items() if k not in ('id','scan_id')} for vuln in vulns],
                'ports': [{k:v for k,v in p.items() if k not in ('id','scan_id')} for p in ports],
                'technologies': [{k:v for k,v in t.items() if k not in ('id','scan_id')} for t in techs],
            }
        except Exception as e:
            print(f'[DB] get_scan: {e}')
            return None

    def list_scans(self):
        try:
            c = self.connect().cursor(dictionary=True)
            c.execute('SELECT id,url,status,vuln_count,risk_score,waf,created_at FROM scans ORDER BY created_at DESC LIMIT 100')
            return [{**r, 'created_at': str(r['created_at'])} for r in c.fetchall()]
        except Exception as e:
            print(f'[DB] list_scans: {e}')
            return []

    def get_stats(self):
        try:
            c = self.connect().cursor(dictionary=True)
            c.execute('SELECT COUNT(*) as total FROM scans')
            total = c.fetchone()['total']
            c.execute('SELECT COUNT(*) as total FROM vulnerabilities')
            total_vulns = c.fetchone()['total']
            c.execute('SELECT severity, COUNT(*) as cnt FROM vulnerabilities GROUP BY severity')
            by_sev = {r['severity']: r['cnt'] for r in c.fetchall()}
            c.execute('SELECT COUNT(*) as total FROM scans WHERE status="complete" AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)')
            week = c.fetchone()['total']
            return {'total_scans': total, 'total_vulns': total_vulns, 'by_severity': by_sev, 'scans_this_week': week}
        except Exception as e:
            print(f'[DB] get_stats: {e}')
            return {}

    def update_scan_status(self, scan_id, status):
        try:
            self.connect().cursor().execute('UPDATE scans SET status=%s WHERE id=%s', (status, scan_id))
        except: pass
