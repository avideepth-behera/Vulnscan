# VulnScan — API Keys Configuration

API_KEYS = {
    # https://www.virustotal.com/gui/join-us  (Free: 4 req/min, 500/day)
    'VIRUSTOTAL': 'YOUR_VIRUSTOTAL_API_KEY',

    # https://account.shodan.io/register  (Free: 1 req/sec, no scan credits)
    'SHODAN': 'YOUR_SHODAN_API_KEY',

    # https://urlscan.io/user/signup  (Free: 60 req/min)
    'URLSCAN': 'YOUR_URLSCAN_API_KEY',

    # https://developers.google.com/safe-browsing  (Free with Google Cloud)
    'GOOGLE_SAFE_BROWSING': 'YOUR_GOOGLE_API_KEY',

    # https://haveibeenpwned.com/API/Key  (Paid: $3.50/month) 
    'HIBP': 'YOUR_HIBP_API_KEY',

}

DB_CONFIG = {
    'host': 'localhost',
    'user': 'vulnscan_user',
    'password': 'vulnscan_pass',
    'database': 'vulnscan',
    'autocommit': True,
    'connection_timeout': 10,
}
