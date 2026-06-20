"""
heuristics.py
Comprehensive URL heuristic analysis engine.
Checks for phishing patterns, suspicious structures, and security indicators.
"""

import re
import urllib.parse


SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq',
    '.click', '.download', '.stream', '.info', '.biz', '.loan',
    '.work', '.men', '.date', '.review', '.kim', '.ru', '.site', '.one',
    '.cn', '.vn', '.id', '.me', '.cc', '.ws', '.su', '.cam', '.live', '.online',
    '.bar', '.cyou', '.email', '.icu', '.mobi', '.pro', '.sbs', '.shop', '.vip', '.cx', '.asia'
}

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'rb.gy',
    'short.link', 'cutt.ly', 'is.gd', 'buff.ly', 'adf.ly', 'bl.ink',
    'clck.ru', 'tiny.cc', 'lnkd.in', 'soo.gd', 'bc.vc', 'spoo.me', 'qrsu.io', '1xplayers.com', 'shorturl.at'
}

PHISHING_KEYWORDS = [
    'login', 'verify', 'verifica', 'update', 'account', 'secure', 'bank',
    'confirm', 'wallet', 'password', 'credential', 'signin', 'sign-in',
    'webscr', 'cmd=', 'auth', 'recover', 'billing', 'invoice', 'sign_in.php', 'admin', 'doc', 'share', 'drive', 'btc', 'crypto', 'bonus', 'reward',
    'acct', 'robux', 'shopee', 'gift', 'claim', 'prize', 'support', 'center', 'helpdesk', 'recovery', 'import', 'seed', 'phrase', 'nodereply', 'noreply', 'validate', 'unlock', 'suspend', 'frozen', 'verification', 'limited',
    'portal', 'authorize', 'session', 'token', 'validation', 'suspended', 'unauthorized', 'access', 'webmail', 'cpanel', 'roundcube', 'mailbox', 'free', 'offer', 'winner', 'lucky', 'survey',
    'ecard', 'serviceteam', 'gerenciador', 'empresas', 'email', 'fb-page', 'aumento', 'vernieuwen'
]

DOMAIN_KEYWORDS = [
    'pharmacy', 'support', 'service', 'helpdesk', 'security', 'billing', 'payment', 'official', 'auth', 'recover',
    'bantuan', 'dang-ky', 'login', 'signin', 'verification', 'verify', 'account', 'cash', 'fund', 'money',
    'free', 'gift', 'claim', 'prize', 'wallet', 'unlock', 'suspend', 'robux', 'vbucks', 'shopee', 'banco', 'caixa',
    'usps', 'dhl', 'fedex', 'post', 'parcel', 'delivery', 'tracking', 'shipment', 'tracking-number', 'courier',
    'evobot', 'clovernode', 'techto', '00wnsr', 'enfermeria',
    'grihinie', 'shipman', 'mpaeroz', 'ying8868', 'argosconsultoria', 'fly-the-skies'
]

import os
import json

TARGET_BRANDS = {}
brands_file = os.path.join(os.path.dirname(__file__), '..', 'assets', 'brands.json')
if os.path.exists(brands_file):
    with open(brands_file, 'r') as f:
        data = json.load(f)
        for b, domains in data.items():
            TARGET_BRANDS[b] = domains[0]
else:
    TARGET_BRANDS = {
        'paypal': 'paypal.com', 'google': 'google.com', 'microsoft': 'microsoft.com'
    }

FREE_HOSTS = [
    '.app', 'typedream.app', 'godaddysites.com', 'railway.app', 'netlify.app', 'framer.website', 'weebly.com',
    'vercel.app', 'pages.dev', 'github.io', 'onrender.com', 'herokuapp.com',
    'kesug.com', '000webhostapp.com', 'epizy.com', 'rf.gd', 'pantheonsite.io', 'bplaced.net', 'awardspace.com', 'infinityfree.net', 'blogspot.com', 'wordpress.com',
    'framer.app', 'edgeone.dev', 'linodeobjects.com', 'backblazeb2.com', 'mytemp.website'
]

IPFS_GATEWAYS = [
    'ipfs.dweb.link', 'nftstorage.link', 'pinata.cloud'
]

IP_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)

# Very long base64 segments
B64_PATTERN = re.compile(
    r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
)

# Unicode / Punycode homograph
PUNYCODE_PATTERN = re.compile(r'xn--')


def _levenshtein_dist(s1, s2):
    if len(s1) < len(s2):
        return _levenshtein_dist(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def check_url_heuristics(url: str) -> dict:
    """
    Perform comprehensive heuristic analysis on a URL.
    Returns: Dict with keys: score (0-100), reasons (list[str]), breakdown (dict).
    """
    score = 0
    reasons = []
    breakdown = {}

    def add_score(category: str, points: int, reason: str):
        nonlocal score
        score += points
        reasons.append(reason)
        breakdown[category] = breakdown.get(category, 0) + points

    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        full = url.lower()
        domain_no_port = domain.split(':')[0]

        # 1. IP address instead of domain
        if IP_PATTERN.match(domain_no_port):
            add_score('Infrastructure Reputation', 80, 'IP address used instead of domain name')

        # 2. Suspicious TLDs
        for tld in SUSPICIOUS_TLDS:
            if domain_no_port.endswith(tld):
                add_score('Infrastructure Reputation', 40, f'Suspicious top-level domain: {tld}')
                break

        # 3. Excessive subdomains
        parts = domain_no_port.split('.')
        if len(parts) > 4:
            add_score('Infrastructure Structure', 30, f'Excessive subdomains detected ({len(parts) - 2} levels)')

        # 4. URL shorteners
        for shortener in URL_SHORTENERS:
            if domain_no_port == shortener or domain_no_port.endswith('.' + shortener):
                add_score('Obfuscation', 25, f'URL shortener detected ({shortener})')
                break

        # 5. Phishing keywords
        keyword_hits = []
        for kw in PHISHING_KEYWORDS:
            if kw in path or kw in query or kw in domain_no_port:
                keyword_hits.append(kw)
        if keyword_hits:
            add_score('Credential Harvesting Indicators', min(len(keyword_hits) * 20, 60), f'Phishing keywords found: {", ".join(keyword_hits[:4])}')
            
        domain_hits = []
        for kw in DOMAIN_KEYWORDS:
            if kw in domain_no_port:
                domain_hits.append(kw)
        if domain_hits:
            add_score('Infrastructure Reputation', 30, f'Suspicious keyword in domain: {", ".join(domain_hits[:2])}')

        # 6. Deep Path Hierarchies & Hashes
        path_depth = len([p for p in path.split('/') if p])
        if path_depth > 4:
            add_score('Infrastructure Structure', 25, f'Extremely deep path hierarchy detected ({path_depth} levels)')
        elif path_depth > 3:
            add_score('Infrastructure Structure', 15, f'Deep path hierarchy detected ({path_depth} levels)')
            
        if re.search(r'/[0-9a-f]{6,}(?:/|$)', path):
            add_score('Obfuscation', 20, 'Hexadecimal hash detected in URL path')

        # Length heuristic
        if len(url) > 75:
            add_score('Obfuscation', 15, 'URL is abnormally long (>75 chars)')
        elif len(url) > 120:
            add_score('Obfuscation', 25, 'URL is extremely long (>120 chars)')

        # 7. Numeric Subdomains
        if re.search(r'(?:^|\.)\d+\.', domain_no_port) and not IP_PATTERN.match(domain_no_port):
            add_score('Infrastructure Structure', 20, 'Numeric subdomain detected')

        # 8. Excessive Hyphenation
        if domain_no_port.count('-') > 3:
            add_score('Infrastructure Structure', 20, 'Excessive hyphenation in domain')

        # 9. Free Hosting / PaaS Abuse
        is_free_host = False
        for host in FREE_HOSTS:
            if domain_no_port.endswith(host):
                is_free_host = True
                # Score gently. If no other indicators exist, 25 points won't trigger MALICIOUS.
                add_score('Hosting Reputation', 25, f'PaaS / Free hosting service detected ({host})')
                break

        # 10. IPFS / Decentralized Gateway Abuse
        for gw in IPFS_GATEWAYS:
            if domain_no_port.endswith(gw):
                add_score('Infrastructure Reputation', 60, f'Decentralized storage gateway detected ({gw})')
                break

        # 11. Base64
        if B64_PATTERN.search(path + '?' + query):
            add_score('Obfuscation', 30, 'Long Base64-encoded string detected')

        # 12. HTTP
        if parsed.scheme == 'http':
            add_score('Security Protocol', 20, 'Unencrypted HTTP connection (no HTTPS)')

        # 13. Brand Impersonation / Typosquatting
        import tldextract
        extracted = tldextract.extract(domain_no_port)
        domain_root = extracted.domain
            
        for brand, canonical in TARGET_BRANDS.items():
            # Brand in domain but not canonical
            if brand in domain_no_port:
                if not domain_no_port.endswith(canonical):
                    add_score('Brand Impersonation', 45, f'Domain contains brand "{brand}" but is not canonical ({canonical})')
                    break
            # Brand in path/query
            elif brand in full:
                add_score('Brand Impersonation', 40, f'Target brand name "{brand}" found outside of root domain')
                break
            
            # Typosquatting on domain_root
            if brand != domain_root and len(brand) > 3:
                dist = _levenshtein_dist(domain_root, brand)
                max_dist = 1 if len(brand) <= 5 else 2
                if dist <= max_dist and dist > 0:
                    add_score('Typosquatting', 45, f'Domain visually similar to brand "{brand}"')
                    break

    except Exception as e:
        add_score('Parsing Error', 50, f'URL parsing failed: {str(e)}')

    return {
        'score': min(score, 100),
        'reasons': reasons,
        'breakdown': breakdown
    }
