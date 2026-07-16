import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report, 
    confusion_matrix
)

from utils.feature_extractor import extract_features
from urllib.parse import urlparse
from sklearn.feature_extraction.text import TfidfVectorizer
from scipy.sparse import hstack, csr_matrix


# ----------------------------
# Load Dataset
# ----------------------------

df = pd.read_csv("dataset/PhiUSIIL_Phishing_URL_Dataset.csv")

print("\nDataset Loaded Successfully\n")

# ----------------------------
# PhiUSIIL Labels
# ----------------------------

print(df["label"].value_counts())

balanced = df.copy()

print("\nPhiUSIIL Dataset Ready\n")


# -------------------------
# URL-only PhiUSIIL Features
# -------------------------

MODEL_FEATURES = [

    # ----------------------------
    # PhiUSIIL Features
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

feature_df = pd.DataFrame(
    balanced["URL"].apply(extract_features).tolist()
)

feature_df = feature_df[MODEL_FEATURES]

# -------------------------
# Hostname TF-IDF Features
# -------------------------

hostnames = balanced["URL"].apply(
    lambda x: urlparse(x).netloc.lower()
)

tfidf = TfidfVectorizer(
    analyzer="char",
    ngram_range=(3,5),
    min_df=5
)

hostname_features = tfidf.fit_transform(hostnames)

numeric_features = csr_matrix(feature_df.values)

X = hstack([
    numeric_features,
    hostname_features
])

y = balanced["label"]


print("\nFeature Extraction Completed\n")

# ----------------------------
# Split Dataset
# ----------------------------

X_train, X_test, y_train, y_test = train_test_split(

    X, 
    y,
    test_size=0.2,
    random_state=42,
    stratify=y

)

# ----------------------------
# Train Random Forest
# ----------------------------

model = RandomForestClassifier(

    n_estimators=300,
    max_depth=20,
    min_samples_split=5,
    random_state=42,
    n_jobs=-1

)

model.fit(X_train, y_train)
feature_names = list(feature_df.columns) + list(tfidf.get_feature_names_out())

importance = pd.DataFrame({
    "Feature": feature_names,
    "Importance": model.feature_importances_
})

importance = importance.sort_values(
    by="Importance",
    ascending=False
)

print("\nFEATURE IMPORTANCE\n")
print(importance.head(30))


print("\nModel Training Completed\n")
print(model.classes_)
print(model.predict_proba(X_test[:5]))

print("\nModel Training Completed\n")

# ----------------------------
# Evaluation
# ----------------------------

y_pred = model.predict(X_test)

print("\nAccuracy")

print(accuracy_score(y_test, y_pred))

print("\nClassification Report")

print(classification_report(y_test, y_pred))

print("\nConfusion Matrix")

print(confusion_matrix(y_test, y_pred))

# ----------------------------
# Save Model
# ----------------------------

joblib.dump(model, "model/model.pkl")
joblib.dump(tfidf, "model/tfidf.pkl")

print("\nRandom Forest Model Saved Successfully\n")