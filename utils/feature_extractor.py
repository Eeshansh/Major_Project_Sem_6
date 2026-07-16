from urllib.parse import urlparse
import math
import re
import tldextract


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "bank",
    "update",
    "signin",
    "paypal",
    "bonus",
    "free"
]


SHORTENERS = [ 
    "bit.ly",
    "tinyurl",
    "goo.gl",
    "t.co",
    "ow.ly",
    "is.gd"
]
OFFICIAL_BRANDS = {
    "google": "google.com",
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "linkedin": "linkedin.com",
    "github": "github.com",
    "netflix": "netflix.com",
    "dropbox": "dropbox.com",
    "adobe": "adobe.com",
    "bankofamerica": "bankofamerica.com",
    "chase": "chase.com"
}


def calculate_entropy(text):

    if len(text) == 0:
        return 0
 
    entropy = 0

    for c in set(text):

        p = text.count(c) / len(text)

        entropy -= p * math.log2(p)

    return round(entropy, 3)


def longest_token(domain):

    tokens = re.split(r"[.-]", domain)

    if not tokens: 
        return 0

    return max(len(token) for token in tokens)
    
def detect_brand_impersonation(hostname):

    for brand, official_domain in OFFICIAL_BRANDS.items():

        if brand in hostname:

            if not hostname.endswith(official_domain):

                return 1

    return 0


def extract_features(url):

    parsed = urlparse(url)

    hostname = parsed.netloc.lower()

    tld_info = tldextract.extract(hostname)

    tld = tld_info.suffix.lower()

    registered_domain = (
        tld_info.domain + "." + tld
        if tld
        else tld_info.domain
    )

    path = parsed.path

    path_depth = len([
        part
        for part in path.split("/")
        if part
    ])

    query = parsed.query

    obfuscated_chars = re.findall(r"%[0-9A-Fa-f]{2}", url)

    no_of_obfuscated_char = len(obfuscated_chars)

    has_obfuscation = int(no_of_obfuscated_char > 0)

    obfuscation_ratio = round(
        no_of_obfuscated_char / max(len(url), 1),
        3
    )
    
    query_parameter_count = query.count("&")
    if query:
        query_parameter_count += 1

    

    suspicious_keyword_count = sum(
        keyword in url.lower()
        for keyword in SUSPICIOUS_KEYWORDS
    )

    digit_count = sum(c.isdigit() for c in url)

    letter_count = sum(c.isalpha() for c in url)

    features = {

        # --------------------
        # Existing Features
        # --------------------

        "url_length": len(url),

        "dot_count": url.count("."),

        "hyphen_count": url.count("-"),

        "has_https": int(url.startswith("https://")),

        "has_ip": int(
            bool(
                re.search(
                    r"\d+\.\d+\.\d+\.\d+",
                    url
                )
            )
        ),

        "has_at_symbol": int("@" in url),

        "uses_shortener": int(
            any(
                s in url.lower()
                for s in SHORTENERS
            )
        ),

        "digit_count": digit_count,

        "subdomain_count":
            len(tld_info.subdomain.split("."))
            if tld_info.subdomain
            else 0,

        "suspicious_keyword_count":
            suspicious_keyword_count,

        # --------------------
        # New Features
        # --------------------

        "hostname_length":
            len(hostname),

        "path_length":
            len(path),

        "path_depth":
            path_depth,

        "query_length":
            len(query),

        "query_parameter_count":
            query_parameter_count,

        "has_obfuscation":
            has_obfuscation,

        "no_of_obfuscated_char":
            no_of_obfuscated_char,

        "obfuscation_ratio":
            obfuscation_ratio,

        "slash_count":
            url.count("/"),

        "question_mark_count":
            url.count("?"),

        "equal_count":
            url.count("="),

        "percent_count":
            url.count("%"),

        "underscore_count":
            url.count("_"),

        "hostname_entropy":
            calculate_entropy(hostname),

        "longest_hostname_token":
            longest_token(hostname),

        "digit_ratio":
            round(
                digit_count /
                max(len(url), 1),
                3
            ),

        "letter_ratio":
            round(
                letter_count /
                max(len(url), 1),
                3
            ),

        "hostname_labels":
            len(hostname.split(".")),

        "starts_with_www":
            int(hostname.startswith("www")),

        "brand_impersonation":
            detect_brand_impersonation(hostname),

        "has_punycode":
            int("xn--" in hostname),

        "tld_is_com": int(tld == "com"),

        "tld_is_org": int(tld == "org"),

        "tld_is_gov": int(
            tld == "gov" or tld.endswith(".gov")
        ),

        "tld_length": len(tld),

        "consecutive_digits":
            len(
                max(
                    re.findall(r"\d+", url),
                    default=""
                )
            )
    }

    # =====================================================
    # ML FEATURE ALIASES (PhiUSIIL + Our Features)
    # =====================================================

    other_special_chars = sum(
        1
        for c in url
        if (
            not c.isalnum()
            and c not in [".", "/", "-", "_", "&", "=", "?", ":"]
        )
    )

    features.update({

        # -------------------------
        # PhiUSIIL Features
        # -------------------------

        "URLLength":
            features["url_length"],

        "DomainLength":
            features["hostname_length"],

        "IsDomainIP":
            features["has_ip"],

        "TLDLength":
            features["tld_length"],

        "NoOfSubDomain":
            features["subdomain_count"],

        "HasObfuscation":
            features["has_obfuscation"],

        "NoOfObfuscatedChar":
            features["no_of_obfuscated_char"],

        "ObfuscationRatio":
            features["obfuscation_ratio"],

        "NoOfLettersInURL":
            letter_count,

        "LetterRatioInURL":
            features["letter_ratio"],

        "NoOfDegitsInURL":
            digit_count,

        "DegitRatioInURL":
            features["digit_ratio"],

        "NoOfEqualsInURL":
            features["equal_count"],

        "NoOfQMarkInURL":
            features["question_mark_count"],

        "NoOfAmpersandInURL":
            url.count("&"),

        "NoOfOtherSpecialCharsInURL":
            other_special_chars,

        "SpacialCharRatioInURL":
            round(
                (
                    other_special_chars
                    + url.count("&")
                    + features["equal_count"]
                    + features["question_mark_count"]
                ) / max(len(url), 1),
                3
            ),

        "IsHTTPS":
            features["has_https"],

        # -------------------------
        # Our Extra Features
        # -------------------------

        "HostnameEntropy":
            features["hostname_entropy"],

        "BrandImpersonation":
            features["brand_impersonation"],

        "HasPunycode":
            features["has_punycode"],

        "SuspiciousKeywordCount":
            features["suspicious_keyword_count"],

        "UsesShortener":
            features["uses_shortener"],

        "PathDepth":
            features["path_depth"],

        "QueryParameterCount":
            features["query_parameter_count"],

        "ConsecutiveDigits":
            features["consecutive_digits"]

    })

    return features