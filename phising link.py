import re
phishing_keywords = ["login", "verify", "account", "update", "secure", "bank", "password", "signin", "confirm", "0"]

def contains_phishing_keywords(url, keywords=phishing_keywords):
    return any(keyword in url.lower() for keyword in keywords)
def contains_suspicious_patterns(url):
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    if ip_pattern.search(url):
        return True
    subdomain_pattern = re.compile(r'(\w+\.){3,}')
    if subdomain_pattern.search(url):
        return True
    hex_pattern = re.compile(r'%[0-9A-Fa-f]{2}')
    if hex_pattern.search(url):
        return True
    hyphenated_keywords = re.compile(r'\b(\w+-\w+)+\b')
    if hyphenated_keywords.search(url):
        return True

    return False
def scan_for_phishing(urls):
    for url in urls:
        if contains_phishing_keywords(url):
            print(f"Potential phishing URL detected (keyword): {url}")
        elif contains_suspicious_patterns(url):
            print(f"Suspicious URL detected (pattern): {url}")
        else:
            print(f"URL seems safe: {url}")
urls_to_scan = [
    "http://example.com",
    "http://login-bank.com",
    "http://192.168.1.1",
    "http://secure-login.example.com",
    "http://update-password.com",
    "http://go0gle.com",
    "http://secure-verify-acc.com",
    "http://%45%78%61%6d%70%6c%65.com"
]

scan_for_phishing(urls_to_scan)
