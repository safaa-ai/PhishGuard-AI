
import re
import math
import ipaddress
from collections import Counter
from urllib.parse import urlsplit


FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "has_ip",
    "has_at",
    "has_shortener",
    "has_suspicious_keyword",
    "uses_http",
    "has_suspicious_tld",
    "subdomain_count",
    "hyphen_count",
    "digit_count",
    "dot_count",
    "slash_count",
    "question_mark_count",
    "equal_count",
    "ampersand_count",
    "percent_count",
    "path_length",
    "query_length",
    "url_entropy"
]


SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com",
    "ow.ly", "t.co", "is.gd",
    "buff.ly", "cutt.ly"
}


SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "banking",
    "secure", "account", "signin", "password",
    "confirm", "suspended", "wallet",
    "authenticate", "recover"
]


SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "work",
    "zip", "tk", "gq", "ml", "cf"
}


def calculate_entropy(text):

    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)

    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def extract_url_features(url):

    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL cannot be empty.")

    url = url.strip()

    if any(char.isspace() for char in url):
        raise ValueError("URL contains whitespace.")

    # Add HTTPS if the URL has no scheme.
    test_url = url

    if not re.match(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
        test_url
    ):
        test_url = "https://" + test_url

    try:
        parsed = urlsplit(test_url)
        hostname = parsed.hostname or ""

    except ValueError:
        raise ValueError("Invalid URL format.")

    if not hostname or "." not in hostname:
        raise ValueError("Invalid URL: domain is missing or incomplete.")

    hostname = hostname.lower()

    # Normalize the root path:
    # https://example.com and https://example.com/
    # will have the same extracted features.
    if parsed.path == "/":
        parsed = parsed._replace(path="")
        test_url = parsed.geturl()

    features = {}

    # 1. URL Length
    features["url_length"] = len(test_url)

    # 2. Domain Length
    features["domain_length"]= len(hostname)

    # 3. IP Address
    try:
        ipaddress.ip_address(hostname)
        features["has_ip"] = 1
    except ValueError:
        features["has_ip"] = 0

    # 4. @ Symbol
    features["has_at"] = int("@" in test_url)

    # 5. URL Shortener
    features["has_shortener"] = int(
        any(
            hostname == shortener or
            hostname.endswith("." + shortener)
            for shortener in SHORTENERS
        )
    )

    # 6. Suspicious Keywords
    features["has_suspicious_keyword"] = int(
        any(
            keyword in test_url.lower()
            for keyword in SUSPICIOUS_KEYWORDS
        )
    )

    # 7. HTTP Protocol
    features["uses_http"] = int(
        parsed.scheme.lower() == "http"
    )

    # 8. Suspicious TLD
    tld = hostname.rsplit(".", 1)[-1]

    features["has_suspicious_tld"] = int(
        tld in SUSPICIOUS_TLDS
    )

    # 9. Subdomain Count
    try:
        ipaddress.ip_address(hostname)
        subdomain_count = 0
    except ValueError:
        parts = hostname.split(".")
        subdomain_count = max(0, len(parts) - 2)

    features["subdomain_count"] = subdomain_count

    # 10. Hyphen Count
    features["hyphen_count"] = hostname.count("-")

    # 11. Digit Count
    features["digit_count"] = sum(
        char.isdigit() for char in test_url
    )

    # 12. Dot Count
    features["dot_count"] = hostname.count(".")

    # 13. Slash Count
    features["slash_count"] = parsed.path.count("/")

    # 14. Question Mark Count
    features["question_mark_count"] = test_url.count("?")

    # 15. Equal Count
    features["equal_count"] = test_url.count("=")

    # 16. Ampersand Count
    features["ampersand_count"] = test_url.count("&")

    # 17. Percent Count
    features["percent_count"] = test_url.count("%")

    # 18. Path Length
    features["path_length"] = len(parsed.path)

    # 19. Query Length
    features["query_length"] = len(parsed.query)

    # 20. URL Entropy
    features["url_entropy"] = calculate_entropy(test_url)

    return [features[name] for name in FEATURE_NAMES]
