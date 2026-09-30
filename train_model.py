from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib

emails = [
    "urgent verify your bank account immediately",
    "click this link to reset your password",
    "your account will be suspended confirm now",
    "you won a prize provide your credentials",
    "urgent payment required click the link",
    "verify your login information immediately",

    "meeting scheduled for tomorrow",
    "please find the project report attached",
    "college examination timetable released",
    "team meeting will start at 10 AM",
    "project submission deadline is Friday",
    "thank you for your email"
]

labels = [1, 1, 1, 1, 1, 1,
          0, 0, 0, 0, 0, 0]

vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(emails)

model = LogisticRegression()
model.fit(X, labels)

joblib.dump(model, "threat_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("Model trained successfully!")