import re
import pickle

# Load saved model and vectorizer
model = pickle.load(open("model/resume_classifier.pkl", "rb"))
vectorizer = pickle.load(open("model/vectorizer.pkl", "rb"))

# Resume text input (example)
resume_text = """
-Jagran College Of Arts Science and Commerce
CGPA 8.99
Secondary School 
-Shivaji Inter College, Keshav Nagar, Kanpur
HTML
CSS
JavaScript
Python
WordPress
Java
MySQL"""

# --- Clean resume text ---
def clean_text(text):
    text = re.sub(r'\S+@\S+', '', text)  # Remove emails
    text = re.sub(r'http\S+', '', text)  # Remove URLs
    text = re.sub(r'\d+', '', text)      # Remove digits
    text = re.sub(r'\W', ' ', text)      # Remove special characters
    text = text.lower()
    return re.sub(r'\s+', ' ', text).strip()

cleaned = clean_text(resume_text)

# --- Vectorize (must pass as a list of one string, not a string directly) ---
vector = vectorizer.transform([cleaned])  # ✅ This is a 2D array

# --- Predict ---
prediction = model.predict(vector)[0]
print("✅ Predicted Job Role:", prediction)
