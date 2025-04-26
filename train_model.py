import pandas as pd
import re
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# --- Load dataset ---
df1 = pd.read_csv("data/resume_dataset.csv")
df2 = pd.read_csv("data/resume_dataset_2.csv")

df = pd.concat([df1, df2], ignore_index=True)


df.dropna(inplace=True)

# List of institution-related terms you want to remove
college_keywords = ['college', 'university', 'school', 'arts', 'science','English','Hindi']

# --- Clean resume text ---
def clean_text(text):
    text = re.sub(r'\S+@\S+', '', text)  # Remove emails
    text = re.sub(r'http\S+', '', text)  # Remove URLs
    text = re.sub(r'\d+', '', text)      # Remove digits
    text = re.sub(r'\W', ' ', text)      # Remove special characters
    text = text.lower()
    

    # Remove institution-related terms
    for keyword in college_keywords:
        text = re.sub(r'\b' + re.escape(keyword) + r'\b', '', text)
    
    return re.sub(r'\s+', ' ', text).strip()

df['cleaned'] = df['Resume'].apply(clean_text)

# --- Prepare features and labels ---
X = df['cleaned']
y = df['Category']

# --- Vectorize text ---
vectorizer = TfidfVectorizer(max_features=1500, ngram_range=(1, 2)) 
X_vec = vectorizer.fit_transform(X)

# --- Train/Test split ---
X_train, X_test, y_train, y_test = train_test_split(X_vec, y, test_size=0.2, random_state=42)

# --- Train model ---
model = LogisticRegression()
model.fit(X_train, y_train)

# --- Evaluate ---
y_pred = model.predict(X_test)
print("✅ Accuracy:", accuracy_score(y_test, y_pred))

# --- Save model and vectorizer ---
pickle.dump(model, open("model/resume_classifier.pkl", "wb"))
pickle.dump(vectorizer, open("model/vectorizer.pkl", "wb"))

print("✅ Model and vectorizer saved!")
# Check which categories the model is struggling with
from sklearn.metrics import classification_report
print(classification_report(y_test, y_pred))
