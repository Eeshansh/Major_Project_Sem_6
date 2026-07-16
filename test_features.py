import pandas as pd

from utils.feature_extractor import extract_features

urls = [
    "https://google.com", 
    "https://mail.google.com",
    "https://paypal.com",
    "https://paypal-login-secure-update.com",
    "https://google.com.fake-site.ru",
    "https://github-secure-login.xyz"
]
 
for url in urls:

    print("=" * 60)
    print(url)

    features = extract_features(url)

    df = pd.DataFrame([features])

    print(df[["brand_impersonation"]])