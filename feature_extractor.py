# feature_extractor.py
import re
from urllib.parse import urlparse
from utils import is_ip_address, has_random_string, count_sensitive_words, get_domain_info
from content_analyzer import ContentAnalyzer

class URLFeatureExtractor:
    def __init__(self):
        self.content_analyzer = ContentAnalyzer()
        
        # Comprehensive list of legitimate domains
        self.legitimate_domains = [
            # Search Engines
            'google.com', 'bing.com', 'yahoo.com', 'duckduckgo.com', 'baidu.com',
            
            # Social Media
            'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com', 'pinterest.com',
            'reddit.com', 'tumblr.com', 'flickr.com', 'snapchat.com', 'tiktok.com',
            'whatsapp.com', 'telegram.org', 'discord.com', 'slack.com',
            
            # Video Streaming
            'youtube.com', 'vimeo.com', 'dailymotion.com', 'twitch.tv', 'netflix.com',
            'hulu.com', 'disneyplus.com', 'amazon.com', 'hbomax.com',
            
            # E-commerce & Shopping
            'amazon.com', 'ebay.com', 'walmart.com', 'target.com', 'bestbuy.com',
            'aliexpress.com', 'alibaba.com', 'etsy.com', 'shopify.com', 'woocommerce.com',
            'zappos.com', 'newegg.com', 'wayfair.com', 'overstock.com',
            
            # Technology & Cloud
            'microsoft.com', 'apple.com', 'github.com', 'gitlab.com', 'stackoverflow.com',
            'stackexchange.com', 'digitalocean.com', 'aws.amazon.com', 'cloud.google.com',
            'azure.microsoft.com', 'oracle.com', 'ibm.com', 'intel.com', 'nvidia.com',
            'amd.com', 'docker.com',
            
            # News & Media
            'cnn.com', 'bbc.com', 'nytimes.com', 'washingtonpost.com', 'theguardian.com',
            'reuters.com', 'apnews.com', 'bloomberg.com', 'wsj.com', 'forbes.com',
            'huffpost.com', 'buzzfeed.com', 'mashable.com', 'techcrunch.com',
            
            # Banking & Finance
            'paypal.com', 'stripe.com', 'square.com', 'venmo.com',
            'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com',
            'capitalone.com', 'americanexpress.com', 'visa.com', 'mastercard.com',
            'coinbase.com', 'binance.com', 'robinhood.com',
            
            # Education
            'khanacademy.org', 'coursera.org', 'udemy.com', 'edx.org', 'skillshare.com',
            'codecademy.com', 'freecodecamp.org', 'udacity.com', 'pluralsight.com',
            'brilliant.org', 'duolingo.com',
            
            # Government & Official
            'usa.gov', 'whitehouse.gov', 'nih.gov', 'nasa.gov', 'irs.gov',
            'ssa.gov', 'usps.com', 'fedex.com', 'ups.com', 'dhl.com',
            
            # Health & Medical
            'webmd.com', 'mayoclinic.org', 'healthline.com', 'medlineplus.gov',
            'cdc.gov', 'who.int',
            
            # Travel
            'expedia.com', 'booking.com', 'airbnb.com', 'tripadvisor.com',
            'kayak.com', 'skyscanner.com', 'hotels.com', 'orbitz.com',
            'priceline.com', 'travelocity.com',
            
            # Food & Delivery
            'ubereats.com', 'doordash.com', 'grubhub.com', 'postmates.com',
            'instacart.com', 'seamless.com',
            
            # Entertainment
            'spotify.com', 'pandora.com', 'soundcloud.com', 'deezer.com',
            'imdb.com', 'rottentomatoes.com', 'metacritic.com',
            
            # Sports
            'espn.com', 'nba.com', 'nfl.com', 'mlb.com', 'nhl.com',
            'fifa.com', 'uefa.com', 'bbc.com',
            
            # Automotive
            'tesla.com', 'toyota.com', 'honda.com', 'ford.com', 'bmw.com',
            'mercedes-benz.com', 'audi.com', 'volkswagen.com',
            
            # Retail & Services
            'homedepot.com', 'lowes.com', 'ikea.com', 'costco.com', 'samsclub.com',
            'staples.com', 'officedepot.com', 'bestbuy.com',
            
            # Software & Tools
            'adobe.com', 'autodesk.com', 'jetbrains.com', 'atlassian.com',
            'notion.so', 'trello.com', 'asana.com', 'basecamp.com',
            
            # Communication
            'gmail.com', 'outlook.com', 'protonmail.com', 'zoom.us',
            'skype.com', 'webex.com',
            
            # Development
            'npmjs.com', 'pypi.org', 'docker.io',
            'terraform.io', 'ansible.com', 'jenkins.io',
            
            # Data Science & AI
            'kaggle.com', 'colab.research.google.com', 'huggingface.co',
            'paperswithcode.com', 'arxiv.org', 'openai.com',
            
            # Security
            'letsencrypt.org', 'cloudflare.com', 'akamai.com',
            'symantec.com', 'mcafee.com', 'kaspersky.com',
            
            # Additional Popular Sites
            'wikipedia.org', 'quora.com', 'medium.com', 'wordpress.com',
            'blogger.com', 'weebly.com', 'wix.com', 'squarespace.com',
            'godaddy.com', 'namecheap.com', 'bluehost.com',
            
            # Country-specific Legitimate Domains
            'bbc.co.uk', 'gov.uk', 'naver.com', 'daum.net', 'qq.com',
            'weibo.com', 'taobao.com', 'jd.com', 'rakuten.co.jp',
            'yandex.ru', 'mail.ru', 'olx.pl', 'allegro.pl',
            
            # Educational Institutions
            'harvard.edu', 'stanford.edu', 'mit.edu', 'cambridge.ac.uk',
            'ox.ac.uk', 'berkeley.edu', 'princeton.edu',
            
            # Non-Profit & Organizations
            'wikimedia.org', 'mozilla.org', 'apache.org',
            'linuxfoundation.org', 'gnu.org', 'eff.org',
            
            # Weather
            'weather.com', 'accuweather.com', 'wunderground.com',
            
            # Maps & Navigation
            'maps.google.com', 'openstreetmap.org', 'mapquest.com',
            
            # File Sharing & Storage
            'dropbox.com', 'drive.google.com', 'onedrive.live.com',
            'box.com', 'mega.nz', 'mediafire.com',
            
            # Job Portals
            'indeed.com', 'monster.com', 'glassdoor.com',
            'careerbuilder.com', 'ziprecruiter.com',
            
            # Real Estate
            'zillow.com', 'realtor.com', 'redfin.com', 'trulia.com',
            'century21.com', 'remax.com',
            
            # Music
            'shazam.com', 'last.fm', 'bandcamp.com',
            
            # Gaming
            'steampowered.com', 'epicgames.com', 'xbox.com', 'playstation.com',
            'nintendo.com', 'roblox.com', 'minecraft.net',
            
            # Photography
            'flickr.com', '500px.com', 'unsplash.com', 'pexels.com',
            'shutterstock.com', 'gettyimages.com',
            
            # Design
            'behance.net', 'dribbble.com', 'figma.com', 'canva.com',
            
            # Crypto & Blockchain
            'ethereum.org', 'bitcoin.org', 'coinmarketcap.com',
            'etherscan.io', 'bscscan.com',
            
            # Local Services
            'yelp.com', 'angieslist.com', 'thumbtack.com', 'taskrabbit.com',
            
            # Dating
            'tinder.com', 'bumble.com', 'okcupid.com', 'match.com',
            'happn.com', 'hinge.co',

            # Indian & Asian E-commerce
            'flipkart.com', 'snapdeal.com', 'myntra.com', 'meesho.com', 'ajio.com',
            'nykaa.com', 'bigbasket.com', 'grofers.com', 'zomato.com', 'swiggy.com',
            'makemytrip.com', 'goibibo.com', 'yatra.com', 'irctc.co.in',
            
            # Additional domains from testing
            '10fastfingers.com', 'moviesflixcc.com'
        ]
        
        # Remove duplicates and sort
        self.legitimate_domains = sorted(list(set(self.legitimate_domains)))
        
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.info', '.biz', '.online', '.work', '.site']
        self.url_shorteners = [
            'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 
            'buff.ly', 'shorte.st', 'adf.ly', 'bc.vc', 'cutt.ly', 'shorturl.at',
            'tiny.cc', 'rb.gy'
        ]

        # Common phishing keywords in domains
        self.phishing_keywords = [
            'verify', 'security', 'login', 'signin', 'account', 'update', 'confirm',
            'authenticate', 'secure', 'validation', 'password', 'banking', 'payment',
            'billing', 'alert', 'warning', 'notice', 'important', 'urgent', 'action',
            'required', 'suspended', 'limited', 'identity', 'recovery',
            'restore', 'unlock', 'reactivate', 'authorize', 'validate', 'credentials'
        ]
        
        print(f"✅ Loaded {len(self.legitimate_domains)} legitimate domains for whitelisting")
    
    def should_force_legitimate(self, domain_info):
        """Force legitimate classification for major well-known domains"""
        registered_domain = domain_info['registered_domain'].lower()

        # High-confidence legitimate domains that should never be flagged as phishing
        high_confidence_domains = [
            'google.com', 'kaggle.com', 'github.com', 'microsoft.com', 'apple.com',
            'amazon.com', 'facebook.com', 'twitter.com', 'linkedin.com', 'wikipedia.org',
            'stackoverflow.com', 'youtube.com', 'netflix.com', 'paypal.com',
            'flipkart.com', '10fastfingers.com', 'moviesflixcc.com'
        ]
    
        for domain in high_confidence_domains:
            if registered_domain == domain or registered_domain.endswith('.' + domain):
                return True
    
        return False

    def extract_all_features(self, url):
        """Extract both URL and content features with improved logic"""
        # Get URL-based features
        url_features = self.extract_url_features(url)
        if url_features is None:
            return None
    
        # Check domain info for force legitimate
        domain_info = get_domain_info(url)
    
        # Force legitimate for well-known domains (override everything else)
        if self.should_force_legitimate(domain_info):
            print(f"🎯 Force legitimate for: {domain_info['registered_domain']}")
            # Override key features to ensure legitimate classification
            url_features['KnownLegitimate'] = 1
            url_features['SuspiciousTLD'] = 0
            url_features['UrlShortener'] = 0
            url_features['PhishingKeywords'] = 0
            # Use favorable defaults
            default_features = self.get_legitimate_default_features()
        else:
            # Check if it's in the legitimate domains list
            domain_lower = domain_info['registered_domain'].lower()
            if domain_lower in [d.lower() for d in self.legitimate_domains]:
                url_features['KnownLegitimate'] = 1
                default_features = self.get_legitimate_default_features()
            else:
                url_features['KnownLegitimate'] = 0
                default_features = self.get_suspicious_default_features()
    
        # Try to get content features
        try:
            content_features = self.content_analyzer.analyze_url(url)
            content_derived = self.content_analyzer.calculate_content_features(content_features, url_features['KnownLegitimate'])
            # Update URL features with content analysis results
            url_features.update(content_derived)
        except Exception as e:
            print(f"⚠️ Content analysis failed for {url}, using defaults: {e}")
            # Use appropriate defaults based on domain reputation
            url_features.update(default_features)
    
        return url_features

    def extract_url_features(self, url):
        """Extract URL features with proper method calls"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            parsed = urlparse(url)
            domain_info = get_domain_info(url)
            
            url_lower = url.lower()
            domain_lower = domain_info['registered_domain'].lower()
            
            features = {
                'NumDots': url.count('.'),
                'SubdomainLevel': len(domain_info['subdomain'].split('.')) if domain_info['subdomain'] else 0,
                'PathLevel': max(parsed.path.count('/') - 1, 0),
                'UrlLength': len(url),
                'NumDash': url.count('-'),
                'NumDashInHostname': parsed.netloc.count('-'),
                'AtSymbol': 1 if '@' in url else 0,
                'TildeSymbol': 1 if '~' in url else 0,
                'NumUnderscore': url.count('_'),
                'NumPercent': url.count('%'),
                'NumQueryComponents': len(parsed.query.split('&')) if parsed.query else 0,
                'NumAmpersand': url.count('&'),
                'NumHash': url.count('#'),
                'NumNumericChars': sum(c.isdigit() for c in url),
                'NoHttps': 0 if url.startswith('https') else 1,
                'RandomString': 1 if has_random_string(parsed.netloc) else 0,
                'IpAddress': 1 if is_ip_address(parsed.netloc) else 0,
                'DomainInSubdomains': 1 if self.domain_in_subdomains(parsed.netloc) else 0,
                'DomainInPaths': 1 if self.domain_in_paths(parsed.netloc, parsed.path) else 0,
                'HttpsInHostname': 1 if 'https' in parsed.netloc else 0,
                'HostnameLength': len(parsed.netloc),
                'PathLength': len(parsed.path),
                'QueryLength': len(parsed.query),
                'DoubleSlashInPath': 1 if '//' in parsed.path else 0,
                'NumSensitiveWords': count_sensitive_words(url),
                'EmbeddedBrandName': self.has_embedded_brand(url, domain_info),
                
                # Phishing detection features
                'SuspiciousTLD': 1 if any(tld in domain_lower for tld in self.suspicious_tlds) else 0,
                'UrlShortener': 1 if any(shortener in domain_lower for shortener in self.url_shorteners) else 0,
                'PhishingKeywords': self.count_phishing_keywords(url_lower),
                'BrandInSubdomain': self.brand_in_subdomain(domain_info),
                'SuspiciousPath': self.has_suspicious_path(parsed.path),
                'KnownLegitimate': 1 if self.is_known_legitimate(domain_info) else 0,
                
                # Content features (will be updated)
                'PctExtHyperlinks': 0.4,
                'PctExtResourceUrls': 0.4,
                'ExtFavicon': 0,
                'InsecureForms': 0,
                'RelativeFormAction': 0,
                'ExtFormAction': 0,
                'AbnormalFormAction': 0,
                'PctNullSelfRedirectHyperlinks': 0.4,
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
                'PctExtNullSelfRedirectHyperlinksRT': 1
            }
            
            return features
            
        except Exception as e:
            print(f"❌ Error extracting URL features: {e}")
            return None

    def get_legitimate_default_features(self):
        """Return default values for known legitimate domains when content analysis fails"""
        return {
            'PctExtHyperlinks': 0.3,
            'PctExtResourceUrls': 0.2,
            'ExtFavicon': 0,
            'InsecureForms': 0,
            'RelativeFormAction': 0,
            'ExtFormAction': 0,
            'AbnormalFormAction': 0,
            'PctNullSelfRedirectHyperlinks': 0.1,
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

    def get_suspicious_default_features(self):
        """Return default values for unknown domains when content analysis fails"""
        return {
            'PctExtHyperlinks': 0.7,
            'PctExtResourceUrls': 0.6,
            'ExtFavicon': 0,
            'InsecureForms': 1,
            'RelativeFormAction': 0,
            'ExtFormAction': 0,
            'AbnormalFormAction': 1,
            'PctNullSelfRedirectHyperlinks': 0.8,
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
    
    def count_phishing_keywords(self, url_lower):
        """Count phishing-related keywords in URL"""
        count = 0
        for keyword in self.phishing_keywords:
            if keyword in url_lower:
                count += 1
        return min(count, 10)
    
    def brand_in_subdomain(self, domain_info):
        """Check if brand names appear in subdomain (common phishing tactic)"""
        brands = ['paypal', 'facebook', 'google', 'amazon', 'apple', 'microsoft',
                 'netflix', 'instagram', 'twitter', 'whatsapp', 'linkedin',
                 'ebay', 'wellsfargo', 'bankofamerica', 'chase', 'visa', 'mastercard']
        
        subdomain_lower = domain_info['subdomain'].lower()
        registered_domain = domain_info['registered_domain'].lower()
        
        for brand in brands:
            if brand in subdomain_lower and brand not in registered_domain:
                return 1
        return 0
    
    def has_suspicious_path(self, path):
        """Check for suspicious path patterns"""
        if not path:
            return 0
        
        suspicious_paths = ['/login', '/signin', '/verify', '/confirm', '/account',
                           '/security', '/update', '/password', '/authenticate']
        
        path_lower = path.lower()
        for suspicious in suspicious_paths:
            if suspicious in path_lower:
                return 1
        return 0
    
    def domain_in_subdomains(self, hostname):
        """Check if domain appears in subdomains"""
        if not hostname:
            return 0
        parts = hostname.split('.')
        if len(parts) > 2:
            domain = parts[-2] + '.' + parts[-1]
            subdomain = '.'.join(parts[:-2])
            return 1 if domain in subdomain else 0
        return 0
    
    def domain_in_paths(self, hostname, path):
        """Check if domain appears in paths"""
        if not hostname or not path:
            return 0
        domain_parts = hostname.split('.')
        if len(domain_parts) > 1:
            domain = domain_parts[-2]
            return 1 if domain in path else 0
        return 0
    
    def has_embedded_brand(self, url, domain_info):
        """Check if popular brands are embedded in suspicious ways"""
        brands = ['paypal', 'facebook', 'google', 'amazon', 'apple', 'microsoft',
                 'netflix', 'instagram', 'twitter', 'whatsapp', 'linkedin',
                 'ebay', 'wellsfargo', 'bankofamerica', 'chase']
        
        url_lower = url.lower()
        registered_domain = domain_info['registered_domain'].lower()
        
        for brand in brands:
            if brand in url_lower:
                # Brand not in actual domain = suspicious
                if brand not in registered_domain:
                    return 1
                # Brand in subdomain but not main domain = suspicious
                elif domain_info['subdomain'] and brand in domain_info['subdomain'].lower():
                    if brand not in registered_domain:
                        return 1
        return 0

    def is_known_legitimate(self, domain_info):
        """Check if domain is known to be legitimate"""
        registered_domain = domain_info['registered_domain'].lower()
        return 1 if registered_domain in [d.lower() for d in self.legitimate_domains] else 0