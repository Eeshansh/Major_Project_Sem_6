import joblib
import pandas as pd

from urllib.parse import urlparse
from scipy.sparse import csr_matrix, hstack

from utils.feature_extractor import extract_features


# =====================================================
# LOCKED ML FEATURE SET
# =====================================================

MODEL_FEATURES = [

    # ----------------------------
    # PhiUSIIL Inspired Features
    # ----------------------------

    "URLLength",

    "DomainLength",

    "IsDomainIP",

    "TLDLength",

    "NoOfSubDomain",

    "HasObfuscation",

    "NoOfObfuscatedChar",

    "ObfuscationRatio",

    "NoOfLettersInURL",

    "LetterRatioInURL",

    "NoOfDegitsInURL",

    "DegitRatioInURL",

    "NoOfEqualsInURL",

    "NoOfQMarkInURL",

    "NoOfAmpersandInURL",

    "NoOfOtherSpecialCharsInURL",

    "SpacialCharRatioInURL",

    "IsHTTPS",

    # ----------------------------
    # Our Features
    # ----------------------------

    "HostnameEntropy",

    "BrandImpersonation",

    "HasPunycode",

    "SuspiciousKeywordCount",

    "UsesShortener",

    "PathDepth",

    "QueryParameterCount",

    "ConsecutiveDigits"

]


# =====================================================
# LOAD MODEL
# =====================================================

model = joblib.load("model/model.pkl")

tfidf = joblib.load("model/tfidf.pkl")


def predict_url(url):

    # =====================================================
    # Extract Features
    # =====================================================

    all_features = extract_features(url)

    numeric_df = pd.DataFrame([all_features])

    numeric_df = numeric_df[MODEL_FEATURES]

    numeric_sparse = csr_matrix(numeric_df.values)

    # =====================================================
    # Hostname TF-IDF
    # =====================================================

    hostname = urlparse(url).netloc.lower()

    hostname_tfidf = tfidf.transform([hostname])

    # =====================================================
    # Combine Numeric + TF-IDF
    # =====================================================

    X = hstack([

        numeric_sparse,

        hostname_tfidf

    ])

    # =====================================================
    # Prediction
    # =====================================================

    prediction = model.predict(X)[0]

    probabilities = model.predict_proba(X)[0]

    # =====================================================
    # PhiUSIIL Labels
    #
    # 0 = Phishing
    # 1 = Legitimate
    # =====================================================

    phishing_probability = round(

        probabilities[0] * 100,

        2

    )

    legitimate_probability = round(

        probabilities[1] * 100,

        2

    )



    # ---------------------------------------
    # Generate ML Observations
    # ---------------------------------------

    if prediction == 1:

        if legitimate_probability >= 75:

            ml_message = [
                "Lexical patterns closely resemble legitimate URLs.\n",
                "No significant phishing-related lexical indicators were identified.\n",
                "The submitted URL is likely safe, but always exercise caution.\n"
            ]

        elif legitimate_probability >= 50:

            ml_message = [
                "Lexical analysis favours a legitimate classification.\n",
                "The prediction should be interpreted together with the above findings.\n"
            ]

        else:

            ml_message = [
                "The lexical characteristics are inconclusive.\n",
                "The inbuilt AI model shows only a slight preference towards a legitimate classification.\n",
                "Additional verification is recommended.\n"
            ]

    else:

        if phishing_probability >= 75:

            ml_message = [
                "Strong lexical similarity with phishing URLs was detected.\n",
                "Multiple suspicious lexical patterns were identified.\n",
                "if possible, the source of the submitted URL should be verified before any interaction.\n"
            ]
            

        elif phishing_probability >= 50:

            ml_message = [
                "Lexical similarity with phishing URLs was observed.\n",
                "Some structural characteristics resemble phishing samples.\n",
                "Interpret this prediction together with the above findings.\n"
            ]

        else:

            ml_message = [
                "many suspicious lexical characteristics were identified.\n",
                "The prediction confidence is relatively low.\n",
                "Additional verification is strongly recommended.\n"
            ]

    return {

        "prediction": int(prediction),

        "legitimate_probability":
            legitimate_probability,

        "phishing_probability":
            phishing_probability,

        "ml_message":
            ml_message
    }