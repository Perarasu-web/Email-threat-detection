import joblib

model = joblib.load("threat_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")


def predict_threat(email_text):

    features = vectorizer.transform([email_text])

    probability = model.predict_proba(features)[0][1]

    if probability >= 0.75:
        level = "HIGH"
    elif probability >= 0.45:
        level = "MEDIUM"
    else:
        level = "LOW"

    return probability, level