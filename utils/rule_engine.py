import re
from urllib.parse import urlparse

import tldextract

from utils.whois_checker import get_domain_age
from utils.feature_extractor import extract_features


TRUSTED_DOMAINS = [
    "google.com",
    "youtube.com",
    "github.com",
    "microsoft.com",
    "amazon.com",
    "openai.com",
    "wikipedia.org",
    "flipkart.com",
    "pintrest.com",
    "instagram.com",
    "meta.com",
    "x.com"
]


SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "rb.gy",
    "t.co",
    "shorturl.at",
    "is.gd",    
    "ow.ly",
    "buff.ly",  
    "adf.ly",
    "bit.do",   
    "cutt.ly",
    "shorte.st"
]


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "update",
    "bank",
    "signin",
    "wallet",
    "bonus",
    "free",
    "paypal"
]


def extract_domain(url):

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    return parsed.netloc.lower()


def analyze_url(url):

    score = 0

    reasons = []

    url_lower = url.lower()

    domain_age = get_domain_age(url)

    # ----------------------------
    # URL Information
    # ----------------------------

    parsed = urlparse(url)

    hostname = parsed.netloc.lower()

    protocol = parsed.scheme.upper() if parsed.scheme else "HTTPS"

    tld_info = tldextract.extract(url)

    tld = "." + tld_info.suffix if tld_info.suffix else "Unknown"

    # ----------------------------
    # Structural Features
    # ----------------------------

    features = extract_features(url)

    print("DOMAIN AGE:", domain_age)

    domain_name = extract_domain(url)

    print("DOMAIN:", domain_name)

    # ----------------------------
    # Trusted Domain Check
    # ----------------------------

    for trusted_domain in TRUSTED_DOMAINS:

        if (
            domain_name == trusted_domain
            or domain_name.endswith("." + trusted_domain)
        ):

            return {

                "url": url,

                "hostname": hostname,

                "protocol": protocol,

                "tld": tld,

                "risk_score": 0,

                "verdict": "Legitimate",

                "reasons": [
                    "Trusted domain recognised from the internal trusted-domain registry."
                ],

                "domain_age": domain_age,

                "url_length": features["url_length"],

                "hostname_length": features["hostname_length"],

                "subdomain_count": features["subdomain_count"],

                "path_depth": features["path_depth"],

                "query_parameter_count": features["query_parameter_count"],

                "hostname_entropy": features["hostname_entropy"],

                "has_obfuscation": (
                    "Yes"
                    if features["has_obfuscation"]
                    else "No"
                ),

                "has_punycode": (
                    "Yes"
                    if features["has_punycode"]
                    else "No"
                )
            }

    # ----------------------------
    # Long URL
    # ----------------------------

    if len(url) > 60:

        score += 20

        reasons.append(
            "URL length is unusually long"
        )

    # ----------------------------
    # Suspicious Keywords
    # ----------------------------

    keyword_count = 0

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in url_lower:

            keyword_count += 1

    if keyword_count >= 1:

        score += keyword_count * 10

        reasons.append(
            "Suspicious keywords commonly associated with phishing URLs were detected."
        )

    # ----------------------------
    # @ Symbol
    # ----------------------------

    if "@" in url:
 
        score += 20

        reasons.append(
            "URL contains @ symbol"
        )

    # ----------------------------
    # URL Shorteners
    # ----------------------------

    for shortener in SHORTENERS:

        if shortener in url_lower:

            score += 25

            reasons.append(
                "Shortened URL detected"
            )

            break

    # ----------------------------
    # HTTPS Check
    # ----------------------------

    if not url.startswith("https://"):

        score += 15

        reasons.append(
            "Connection is not encrypted (HTTP protocol detected)."
        )

    # ----------------------------
    # Excessive Subdomains
    # ----------------------------

    dot_count = url.count(".")

    if dot_count > 3:

        score += 15

        reasons.append(
            "Abnormally high subdomain count detected"
        )

    # ----------------------------
    # Hyphen Check
    # ----------------------------

    hyphen_count = url.count("-")

    if hyphen_count > 2:

        score += 15

        reasons.append(
            "Excessive hyphens detected"
        )

    # ----------------------------
    # IP Address Detection
    # ----------------------------

    ip_pattern = r"(http[s]?://)?(\d{1,3}\.){3}\d{1,3}"

    if re.search(ip_pattern, url):

        score += 25

        reasons.append(
            "URL uses an IP address instead of a registered domain name."
        )

    # ----------------------------
    # Domain Age Analysis
    # ----------------------------

    if domain_age is not None:

        if domain_age < 180:

            score += 25

            reasons.append(
                "Very new domain detected (less than 6 months old)"
            )

        elif domain_age < 365:

            score += 15

            reasons.append(
                "Relatively new domain detected"
            )

        elif domain_age > 3650:

            score -= 10

            reasons.append(
                "Well-established domain detected"
            )



    # -------------------------------
    # HTTP + Domain Age Rule
    # -------------------------------

    if protocol == "HTTP" and domain_age is None:

        score += 25

        reasons.append(
            "HTTP connection with unverifiable domain registration detected."
        )

    elif protocol == "HTTP" or domain_age is None:

        score += 15

        if protocol == "HTTP":

            reasons.append(
                "Connection is not encrypted (HTTP protocol detected)."
            )

        else:

            reasons.append(
                "Domain age could not be verified."
            )

    if not reasons:

        reasons.append(
            "No major suspicious indicators detected"
        )
    if score < 0:
        score = 0

    return {

        "url": url,

        "hostname": hostname,

        "protocol": protocol,

        "tld": tld,

        "risk_score": score,

        # "verdict": verdict,

        "reasons": reasons,

        "domain_age": domain_age,

        "url_length": features["url_length"],

        "hostname_length": features["hostname_length"],

        "subdomain_count": features["subdomain_count"],

        "path_depth": features["path_depth"],

        "query_parameter_count": features["query_parameter_count"],

        "hostname_entropy": features["hostname_entropy"],

        "has_obfuscation": (
            "Yes"
            if features["has_obfuscation"]
            else "No"
        ),

        "has_punycode": (
            "Yes"
            if features["has_punycode"]
            else "No"
        )
    }