# utils.py
import numpy as np
import json
import re
from urllib.parse import urlparse
import tldextract
import socket

class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (np.integer, np.int32, np.int64)):
            return int(obj)
        elif isinstance(obj, (np.floating, np.float32, np.float64)):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, np.bool_):
            return bool(obj)
        return super(NumpyEncoder, self).default(obj)

def convert_numpy_types(obj):
    """Recursively convert numpy types to Python native types"""
    if isinstance(obj, dict):
        return {k: convert_numpy_types(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_numpy_types(v) for v in obj]
    elif isinstance(obj, (np.integer, np.int32, np.int64)):
        return int(obj)
    elif isinstance(obj, (np.floating, np.float32, np.float64)):
        return float(obj)
    elif isinstance(obj, np.bool_):
        return bool(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    else:
        return obj

def is_ip_address(hostname):
    """Check if hostname is an IP address"""
    if not hostname:
        return 0
    # Remove port if present
    hostname = hostname.split(':')[0]
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ip_pattern, hostname):
        # Validate IP ranges
        parts = hostname.split('.')
        for part in parts:
            if not 0 <= int(part) <= 255:
                return 0
        return 1
    return 0

def has_random_string(text):
    """Check if text contains random-looking strings"""
    if not text:
        return 0
    # Calculate entropy (simple version)
    if len(text) > 8:
        char_count = {}
        for char in text:
            char_count[char] = char_count.get(char, 0) + 1
        entropy = 0
        for count in char_count.values():
            p = count / len(text)
            entropy -= p * np.log2(p)
        # High entropy suggests randomness
        if entropy > 4.0:
            return 1
    return 0

def count_sensitive_words(text):
    """Count sensitive words in text"""
    sensitive_words = [
        'login', 'signin', 'password', 'bank', 'paypal', 'account', 
        'verify', 'secure', 'update', 'confirm', 'authenticate',
        'credential', 'security', 'validate', 'signature', 'password',
        'username', 'email', 'phone', 'social', 'security', 'number'
    ]
    count = 0
    text_lower = text.lower()
    for word in sensitive_words:
        count += text_lower.count(word)
    return min(count, 20)

def get_domain_info(url):
    """Extract domain information using tldextract"""
    extracted = tldextract.extract(url)
    return {
        'domain': extracted.domain,
        'suffix': extracted.suffix,
        'subdomain': extracted.subdomain,
        'registered_domain': f"{extracted.domain}.{extracted.suffix}"
    }

def dns_resolves(domain):
    """Check if DNS resolves for a domain"""
    try:
        if not domain:
            return True
        
        # Remove port if present
        domain = domain.split(':')[0]
        
        # For common TLDs, assume they resolve to avoid false positives
        common_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.io', '.co.uk', '.de', '.fr']
        if any(domain.endswith(tld) for tld in common_tlds):
            # If it has a common TLD and reasonable length, assume it resolves
            if 3 <= len(domain) <= 63:
                return True
        
        # Try actual DNS resolution as fallback
        try:
            socket.getaddrinfo(domain, None)
            return True
        except socket.gaierror:
            return False
            
    except Exception as e:
        print(f"DNS resolution error for {domain}, assuming valid: {e}")
        return True