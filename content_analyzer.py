# content_analyzer.py
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin, urlparse
import time
from utils import count_sensitive_words, dns_resolves

class ContentAnalyzer:
    def __init__(self, timeout=5):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
    
    def analyze_url(self, url):
        """Analyze website content with comprehensive error handling"""
        # Initialize with safe defaults
        features = {
            'has_forms': 0,
            'has_password_fields': 0,
            'has_login_forms': 0,
            'external_links_count': 0,
            'internal_links_count': 0,
            'sensitive_words_count': 0,
            'has_popups': 0,
            'has_iframes': 0,
            'has_redirects': 0,
            'ssl_verified': 0,
            'dns_resolves': 0,
            'response_time': 0,
            'content_length': 0,
            'status_code': 0
        }
        
        try:
            # Check DNS first
            domain = urlparse(url).netloc
            features['dns_resolves'] = 1 if dns_resolves(domain) else 0
            
            start_time = time.time()
            
            # Check SSL
            if url.startswith('https://'):
                features['ssl_verified'] = 1
            else:
                features['ssl_verified'] = 0
            
            # Make request with timeout
            response = self.session.get(url, timeout=self.timeout, verify=True, allow_redirects=True)
            features['response_time'] = time.time() - start_time
            features['content_length'] = len(response.content)
            features['status_code'] = response.status_code
            
            # Count redirects safely
            features['has_redirects'] = 1 if len(response.history) > 0 else 0
            
            # Parse HTML content
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Analyze forms safely
            forms = soup.find_all('form')
            features['has_forms'] = 1 if forms else 0
            
            for form in forms:
                if form.find('input', {'type': 'password'}):
                    features['has_password_fields'] = 1
                form_html = str(form).lower()
                if any(word in form_html for word in ['login', 'signin', 'authenticate']):
                    features['has_login_forms'] = 1
            
            # Analyze links safely
            all_links = soup.find_all('a', href=True)
            base_domain = urlparse(url).netloc.lower()
            
            external_count = 0
            internal_count = 0
            
            for link in all_links:
                href = link.get('href', '')
                if href.startswith(('http://', 'https://')):
                    try:
                        link_domain = urlparse(href).netloc.lower()
                        if base_domain in link_domain:
                            internal_count += 1
                        else:
                            external_count += 1
                    except:
                        external_count += 1
                else:
                    internal_count += 1
            
            features['external_links_count'] = external_count
            features['internal_links_count'] = internal_count
            
            # Analyze for popups and iframes
            if soup.find_all(['script', 'div'], string=re.compile(r'alert|popup|modal', re.I)):
                features['has_popups'] = 1
            
            if soup.find_all('iframe'):
                features['has_iframes'] = 1
            
            # Count sensitive words
            text_content = soup.get_text()
            features['sensitive_words_count'] = count_sensitive_words(text_content)
            
        except requests.exceptions.SSLError:
            features['ssl_verified'] = 0
        except requests.exceptions.ConnectionError:
            features['dns_resolves'] = 0
        except requests.exceptions.Timeout:
            features['response_time'] = 10
        except requests.exceptions.TooManyRedirects:
            features['has_redirects'] = 1
        except Exception as e:
            print(f"Content analysis completed with some errors: {e}")
        
        return features
    
    def calculate_content_features(self, content_features, is_known_legitimate=False):
        """Calculate derived features from content analysis"""
        total_links = content_features['external_links_count'] + content_features['internal_links_count']
        
        if total_links > 0:
            pct_external_links = content_features['external_links_count'] / total_links
            pct_external_resource = content_features['external_links_count'] / total_links
        else:
            # Use different defaults based on domain reputation
            if is_known_legitimate:
                pct_external_links = 0.3
                pct_external_resource = 0.2
            else:
                pct_external_links = 0.7
                pct_external_resource = 0.6
        
        # Adjust features based on DNS resolution and domain reputation
        if content_features['dns_resolves'] == 0 and not is_known_legitimate:
            # If DNS doesn't resolve and it's not a known legitimate domain, it's suspicious
            return {
                'PctExtHyperlinks': 0.8,
                'PctExtResourceUrls': 0.7,
                'ExtFavicon': 0,
                'InsecureForms': 1,
                'RelativeFormAction': 0,
                'ExtFormAction': 0,
                'AbnormalFormAction': 1,
                'PctNullSelfRedirectHyperlinks': 0.9,
                'FrequentDomainNameMismatch': 1,
                'FakeLinkInStatusBar': 0,
                'RightClickDisabled': 0,
                'PopUpWindow': 1,
                'SubmitInfoToEmail': 0,
                'IframeOrFrame': 1,
                'MissingTitle': 1,
                'ImagesOnlyInForm': 0,
                'SubdomainLevelRT': -1,
                'UrlLengthRT': -1,
                'PctExtResourceUrlsRT': -1,
                'AbnormalExtFormActionR': -1,
                'ExtMetaScriptLinkRT': -1,
                'PctExtNullSelfRedirectHyperlinksRT': -1,
                'dns_resolves': 0
            }
        elif content_features['dns_resolves'] == 0 and is_known_legitimate:
            # Known legitimate domain with DNS issues - be more lenient
            return {
                'PctExtHyperlinks': 0.4,
                'PctExtResourceUrls': 0.3,
                'ExtFavicon': 0,
                'InsecureForms': 0,
                'RelativeFormAction': 0,
                'ExtFormAction': 0,
                'AbnormalFormAction': 0,
                'PctNullSelfRedirectHyperlinks': 0.3,
                'FrequentDomainNameMismatch': 0,
                'FakeLinkInStatusBar': 0,
                'RightClickDisabled': 0,
                'PopUpWindow': 0,
                'SubmitInfoToEmail': 0,
                'IframeOrFrame': 0,
                'MissingTitle': 0,
                'ImagesOnlyInForm': 0,
                'SubdomainLevelRT': 1,
                'UrlLengthRT': 1,
                'PctExtResourceUrlsRT': 1,
                'AbnormalExtFormActionR': 1,
                'ExtMetaScriptLinkRT': 1,
                'PctExtNullSelfRedirectHyperlinksRT': 1,
                'dns_resolves': 1
            }
        
        # Normal processing when DNS resolves
        return {
            'PctExtHyperlinks': pct_external_links,
            'PctExtResourceUrls': pct_external_resource,
            'ExtFavicon': 0,
            'InsecureForms': 1 if content_features['has_forms'] and not content_features['ssl_verified'] else 0,
            'RelativeFormAction': 0,
            'ExtFormAction': 0,
            'AbnormalFormAction': 0,
            'PctNullSelfRedirectHyperlinks': 0.1 if content_features['has_redirects'] else 0.8,
            'FrequentDomainNameMismatch': 0,
            'FakeLinkInStatusBar': 0,
            'RightClickDisabled': 0,
            'PopUpWindow': content_features['has_popups'],
            'SubmitInfoToEmail': 0,
            'IframeOrFrame': content_features['has_iframes'],
            'MissingTitle': 0,
            'ImagesOnlyInForm': 0,
            'SubdomainLevelRT': -1 if content_features['response_time'] > 5 else 1,
            'UrlLengthRT': -1 if content_features['response_time'] > 5 else 1,
            'PctExtResourceUrlsRT': -1 if pct_external_resource > 0.7 else 1,
            'AbnormalExtFormActionR': -1,
            'ExtMetaScriptLinkRT': -1,
            'PctExtNullSelfRedirectHyperlinksRT': -1,
            'dns_resolves': 1
        }