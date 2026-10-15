import re
import tldextract
from urllib.parse import urlparse
from typing import Dict, List
from dataclasses import dataclass, asdict

# Configure tldextract to use bundled snapshot only (no network at runtime)
# This ensures no network calls are made during feature extraction
_tld_extract = tldextract.TLDExtract(
    fallback_to_snapshot=True,
    cache_fetch_timeout=0,  # Don't wait for network fetch
    suffix_list_urls=(),    # Disable network URLs
)


@dataclass
class URLFeatures:
    url_length: int
    hostname_length: int
    path_length: int
    query_length: int
    num_dots: int
    num_hyphens: int
    num_underscores: int
    num_slashes: int
    num_question_marks: int
    num_equals: int
    num_ampersands: int
    num_at_symbols: int
    num_digits: int
    num_letters: int
    has_ip: int
    has_port: int
    is_https: int
    subdomain_count: int
    tld_length: int
    domain_length: int
    suspicious_tld: int
    url_shortener: int
    suspicious_keywords: int
    brand_in_subdomain: int
    brand_in_path: int
    entropy: float
    path_depth: int
    has_redirect_param: int
    punycode: int


SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'pw', 'top', 'xyz', 'club', 'online', 'site',
    'space', 'website', 'tech', 'store', 'shop', 'live', 'fun', 'click',
    'link', 'download', 'stream', 'video', 'photo', 'pic', 'image'
}

URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'shorte.st', 'cutt.ly', 'rebrand.ly', 'short.io', 's.id',
    'v.gd', 'tr.im', 'urlzs.com', 'tiny.cc', 'lnkd.in', 'db.tt', 'qr.ae'
}

SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'update', 'confirm', 'secure', 'account',
    'password', 'credential', 'bank', 'paypal', 'apple', 'microsoft',
    'google', 'amazon', 'facebook', 'instagram', 'twitter', 'linkedin',
    'netflix', 'steam', 'dropbox', 'onedrive', 'icloud', 'webmail',
    'urgent', 'suspended', 'limited', 'expired', 'verify', 'confirm',
    'click', 'download', 'free', 'gift', 'winner', 'prize', 'bonus',
    'crypto', 'bitcoin', 'wallet', 'investment', 'trading'
]

MAJOR_BRANDS = [
    'google', 'facebook', 'apple', 'microsoft', 'amazon', 'paypal',
    'netflix', 'github', 'twitter', 'instagram', 'linkedin', 'yahoo',
    'outlook', 'office', 'adobe', 'dropbox', 'slack', 'zoom',
    'steam', 'epic', 'origin', 'battle', 'discord', 'telegram',
    'whatsapp', 'signal', 'proton', 'icloud', 'amazonaws', 'azure',
    'cloudflare', 'akamai', 'fastly', 'vercel', 'netlify', 'heroku'
]

# Official registrable domains for major brands
# Used to skip brand_in_subdomain/brand_in_path when URL is on the brand's actual domain
BRAND_OFFICIAL_DOMAINS = {
    'google': {'google.com', 'googleusercontent.com', 'gstatic.com', 'youtube.com', 'blogger.com'},
    'facebook': {'facebook.com', 'fb.com', 'instagram.com', 'whatsapp.com', 'messenger.com'},
    'apple': {'apple.com', 'icloud.com', 'me.com', 'mac.com'},
    'microsoft': {'microsoft.com', 'office.com', 'live.com', 'outlook.com', 'hotmail.com', 'azure.com', 'github.com', 'linkedin.com'},
    'amazon': {'amazon.com', 'amazonaws.com', 'aws.amazon.com', 'audible.com', 'twitch.tv'},
    'paypal': {'paypal.com', 'paypalobjects.com', 'venmo.com', 'braintreepayments.com'},
    'netflix': {'netflix.com', 'nflxext.com', 'nflximg.net'},
    'github': {'github.com', 'github.io', 'githubusercontent.com'},
    'twitter': {'twitter.com', 't.co', 'x.com'},
    'instagram': {'instagram.com', 'cdninstagram.com'},
    'linkedin': {'linkedin.com', 'licdn.com'},
    'yahoo': {'yahoo.com', 'yahoodns.net'},
    'outlook': {'outlook.com', 'live.com', 'hotmail.com'},
    'office': {'office.com', 'office365.com', 'microsoft.com'},
    'adobe': {'adobe.com', 'adobedc.net', 'adobelogin.com'},
    'dropbox': {'dropbox.com', 'dropboxusercontent.com'},
    'slack': {'slack.com', 'slack-edge.com', 'slack-imgs.com'},
    'zoom': {'zoom.us', 'zoom.com'},
    'steam': {'steampowered.com', 'steamcommunity.com', 'steamstatic.com'},
    'epic': {'epicgames.com', 'unrealengine.com'},
    'origin': {'origin.com', 'ea.com'},
    'battle': {'battle.net', 'blizzard.com'},
    'discord': {'discord.com', 'discordapp.com', 'discord.gg'},
    'telegram': {'telegram.org', 'tdesktop.com'},
    'whatsapp': {'whatsapp.com', 'web.whatsapp.com'},
    'signal': {'signal.org'},
    'proton': {'proton.me', 'protonmail.com', 'protonmail.ch'},
    'icloud': {'icloud.com', 'apple.com'},
    'amazonaws': {'amazonaws.com', 'aws.amazon.com'},
    'azure': {'azure.com', 'azure.net', 'microsoft.com'},
    'cloudflare': {'cloudflare.com', 'cloudflare.net'},
    'akamai': {'akamai.com', 'akamaitechnologies.com'},
    'fastly': {'fastly.com', 'fastly.net'},
    'vercel': {'vercel.app', 'vercel.com'},
    'netlify': {'netlify.app', 'netlify.com'},
    'heroku': {'heroku.com', 'herokuapp.com'},
}

def _is_brand_official_domain(brand: str, registrable_domain: str) -> bool:
    """Check if the registrable domain is an official domain for the brand."""
    official = BRAND_OFFICIAL_DOMAINS.get(brand, set())
    return registrable_domain.lower() in official


def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    import math
    counts = Counter(s)
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def extract_features(url: str) -> URLFeatures:
    parsed = urlparse(url)
    extracted = _tld_extract(url)

    hostname = parsed.netloc
    path = parsed.path
    query = parsed.query

    has_ip = 0
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, hostname.split(':')[0]):
        has_ip = 1

    has_port = 1 if ':' in hostname and not has_ip else 0
    is_https = 1 if parsed.scheme == 'https' else 0

    subdomain_count = len([s for s in extracted.subdomain.split('.') if s]) if extracted.subdomain else 0

    tld = extracted.suffix
    suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    full_domain = f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}" if extracted.subdomain else f"{extracted.domain}.{extracted.suffix}"
    url_shortener = 1 if full_domain.lower() in URL_SHORTENERS else 0

    url_lower = url.lower()
    suspicious_keywords = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    brand_in_subdomain = 0
    brand_in_path = 0
    
    # Get registrable domain for official domain check
    registrable_domain = f"{extracted.domain}.{extracted.suffix}".lower() if extracted.suffix else extracted.domain.lower()
    
    for brand in MAJOR_BRANDS:
        # Skip if this is the brand's official domain
        if _is_brand_official_domain(brand, registrable_domain):
            continue
            
        if brand in extracted.subdomain:
            brand_in_subdomain = 1
        if brand in path.lower() and brand not in extracted.domain.lower():
            brand_in_path = 1

    punycode = 1 if 'xn--' in url else 0

    has_redirect_param = 1 if any(param in query.lower() for param in ['redirect', 'url', 'next', 'return', 'goto', 'target']) else 0

    path_depth = len([p for p in path.split('/') if p])

    return URLFeatures(
        url_length=len(url),
        hostname_length=len(hostname),
        path_length=len(path),
        query_length=len(query),
        num_dots=url.count('.'),
        num_hyphens=url.count('-'),
        num_underscores=url.count('_'),
        num_slashes=url.count('/'),
        num_question_marks=url.count('?'),
        num_equals=url.count('='),
        num_ampersands=url.count('&'),
        num_at_symbols=url.count('@'),
        num_digits=sum(c.isdigit() for c in url),
        num_letters=sum(c.isalpha() for c in url),
        has_ip=has_ip,
        has_port=has_port,
        is_https=is_https,
        subdomain_count=subdomain_count,
        tld_length=len(tld),
        domain_length=len(extracted.domain),
        suspicious_tld=suspicious_tld,
        url_shortener=url_shortener,
        suspicious_keywords=suspicious_keywords,
        brand_in_subdomain=brand_in_subdomain,
        brand_in_path=brand_in_path,
        entropy=calculate_entropy(hostname),
        path_depth=path_depth,
        has_redirect_param=has_redirect_param,
        punycode=punycode,
    )


def features_to_array(features: URLFeatures) -> List[float]:
    return [
        features.url_length,
        features.hostname_length,
        features.path_length,
        features.query_length,
        features.num_dots,
        features.num_hyphens,
        features.num_underscores,
        features.num_slashes,
        features.num_question_marks,
        features.num_equals,
        features.num_ampersands,
        features.num_at_symbols,
        features.num_digits,
        features.num_letters,
        features.has_ip,
        features.has_port,
        features.is_https,
        features.subdomain_count,
        features.tld_length,
        features.domain_length,
        features.suspicious_tld,
        features.url_shortener,
        features.suspicious_keywords,
        features.brand_in_subdomain,
        features.brand_in_path,
        features.entropy,
        features.path_depth,
        features.has_redirect_param,
        features.punycode,
    ]


def get_feature_names() -> List[str]:
    return [
        'url_length', 'hostname_length', 'path_length', 'query_length',
        'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
        'num_question_marks', 'num_equals', 'num_ampersands', 'num_at_symbols',
        'num_digits', 'num_letters', 'has_ip', 'has_port', 'is_https',
        'subdomain_count', 'tld_length', 'domain_length', 'suspicious_tld',
        'url_shortener', 'suspicious_keywords', 'brand_in_subdomain',
        'brand_in_path', 'entropy', 'path_depth', 'has_redirect_param', 'punycode'
    ]