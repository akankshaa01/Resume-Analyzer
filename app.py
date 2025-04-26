from flask import Flask, render_template, request
import os
import joblib
from utils.extract_text import extract_text_from_pdf
import re
import pickle
import docx2txt
import PyPDF2
from utils.sectioner import split_sections
from flask import Flask, render_template, redirect, request, url_for
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Analysis, migrate
from datetime import datetime
from utils.parser import extract_email
from utils.job_keywords import job_keywords


app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = 'your‑secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///resume.db'
db.init_app(app)

migrate.init_app(app, db)


# Load the model and vectorizer
model = pickle.load(open("model/resume_classifier.pkl", "rb"))
vectorizer = pickle.load(open("model/vectorizer.pkl", "rb"))
college_keywords = ['college', 'university', 'school', 'arts', 'science','English','Hindi']

# Role-based keywords

MONTH_PAT  = r"(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+\d{4}"


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"   


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



def clean_text(text):
    text = re.sub(r'\S+@\S+', '', text)
    text = re.sub(r'http\S+', '', text)
    text = re.sub(r'\d+', '', text)
    text = re.sub(r'\W', ' ', text)
    text = text.lower()
    for keyword in college_keywords:
        text = re.sub(r'\b' + re.escape(keyword) + r'\b', '', text)

    return re.sub(r'\s+', ' ', text).strip()

def extract_text(file_path):
    if file_path.endswith('.pdf'):
        text = ''
        with open(file_path, 'rb') as file:
            reader = PyPDF2.PdfReader(file)
            for page in reader.pages:
                text += page.extract_text() or ''
        return text
    elif file_path.endswith('.docx'):
        return docx2txt.process(file_path)
    else:
        return ''

@app.route("/")
@app.route("/home")
def home():         
    return render_template("index.html")



def score_resume(text):
    text = text.lower()

    score = 0

    # --- Education (20 points)
    if "bachelor" in text or "bca" in text or "b.tech" in text or "mba" in text:
        score += 10
    if "school" in text or "intermediate" in text or "12th" in text:
        score += 5
    if "cgpa" in text or "percentage" in text:
        score += 5

    # --- Skills (30 points)
    skills = ["python", "java", "c++", "html", "css", "javascript", "sql", "flask", "django"]
    skills_found = [s for s in skills if s in text]
    score += min(len(skills_found) * 3, 30)  # 3 points per skill

    # --- Experience (30 points)
    if "intern" in text or "internship" in text:
        score += 10
    if "project" in text:
        score += 10
    if "work experience" in text or "company" in text:
        score += 10

    # --- Format (20 points)
    if re.search(r'[\n•\-]{1,2}\s?[a-z]', text):  # bullets or formatting
        score += 10
    if len(text.split()) > 200:
        score += 10

    return score



def match_keywords(resume_text, selected_role):
    resume_text = resume_text.lower()
    expected = job_keywords.get(selected_role, [])
    matched = [kw for kw in expected if kw in resume_text]
    missing = [kw for kw in expected if kw not in resume_text]
    match_percentage = int(len(matched) / len(expected) * 100) if expected else 0
    return match_percentage, matched, missing


@app.route("/predict", methods=["POST"])
def predict():
    if "resume" not in request.files:
        return "No file uploaded!"

    file = request.files["resume"] 

    if file.filename == "":
        return "No selected file!"

    if file:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)

    resume_text = extract_text(filepath)
    cleaned = clean_text(resume_text)
    vector = vectorizer.transform([cleaned])
    predicted_role = model.predict(vector)[0]
    os.remove(filepath)  # optional: delete after processing
    all_roles = sorted(model.classes_) 
    return render_template('select_role.html', 
                           resume_text=resume_text, 
                           prediction=predicted_role, 
                           roles=all_roles)


def suggest_improvements(text: str, role=None, jd_keywords=None):
    text_low = text.lower()
    sections = split_sections(text)
    sugg = []

    # ── SUMMARY ─────────────────────────────────────────
    if "summary" not in sections:
        sugg.append("Add a Summary / Objective section that highlights your target role and key strengths.")
    elif role and role.lower() not in sections["summary"].lower():
        sugg.append("Mention your target role (e.g., **{}**) explicitly in the summary.".format(role))

    # ── EDUCATION ──────────────────────────────────────
    edu = sections.get("education", "")
    if edu:
        if not re.search(MONTH_PAT, edu, re.I):
            sugg.append("Include start month & year for each education entry.")
        if edu.lower().count("\n") == 0:
            sugg.append("Break education details into multiple lines for readability.")
    else:
        sugg.append("Add an Education section with degree, institute and dates.")

    # ── EXPERIENCE ─────────────────────────────────────
    exp = sections.get("experience", "")
    if exp and len(exp.split()) < 50:
        sugg.append("Provide more detail in the Experience section — responsibilities, tools, results.")
    if not exp:
        sugg.append("Add an Experience section or highlight relevant projects.")

    # ── SKILLS ─────────────────────────────────────────
    skills = sections.get("skills", "").lower()
    base_skills = ["python", "java", "html", "css", "git"]
    if not any(s in skills for s in base_skills):
        sugg.append("Add a dedicated Skills section listing tools & languages (e.g., Python, Git).")

    # role/JD‑specific gaps
    if jd_keywords:
        missing = [kw for kw in jd_keywords if kw not in text_low]
        if missing:
            sugg.append("Consider adding these JD keywords: **{}**".format(", ".join(missing[:10])))
    elif role:
        role_kw = job_keywords.get(role.lower(), [])
        missing = [kw for kw in role_kw if kw not in skills]
        if missing:
            sugg.append("Relevant {} keywords to add: {}".format(role, ", ".join(missing)))

    # ── PROJECTS ───────────────────────────────────────
    proj = sections.get("projects", "")
    if proj and "impact" not in proj.lower():
        sugg.append("For each project, mention impact/results (e.g., ‘reduced load time by 30%’).")

    
    return sugg



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form["name"]
        email = request.form['email']
        pwd   = generate_password_hash(request.form['password'])
        if User.query.filter_by(email=email).first():
            return redirect(url_for("login"))
        new_user = User(name=name, email=email, password=pwd)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("home"))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('home'))   # or wherever
        return "Invalid credentials"
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/history')
@login_required
def history():
    analyses = Analysis.query.filter_by(user_id=current_user.id).order_by(Analysis.created.desc()).all()
    return render_template('history.html', analyses=analyses)


def check_content(resume_text):
    # Example: Check if resume text is not empty
    if resume_text.strip():
        return "✔ Passed"
    return "✘ Failed"

def check_skills(resume_text, selected_role):
    # Example: Check if certain skills are mentioned in the resume
    skills = ['Python', 'C++', 'Java', 'SQL', 'HTML']  # Modify this list based on selected_role
    for skill in skills:
        if skill.lower() in resume_text.lower():
            return "✔ Passed"
    return "✘ Failed"

def check_sections(resume_text):
    required_sections = ['education', 'experience', 'skills', 'contact']
    for section in required_sections:
        if section.lower() not in resume_text.lower():
            return "✘ Failed"
    return "✔ Passed"

def check_format(resume_text):
    # Simple check: Ensure there are no excessive line breaks or weird formatting
    if resume_text.count("\n") > 10:  # Modify logic as needed
        return "✔ Passed"
    return "✘ Failed"

@app.route("/analyze", methods=["POST"])
def analyze():
    resume_text = request.form["resume_text"]
    selected_role = request.form["selected_role"]
    
    email = extract_email(resume_text) or "—"

# Perform checks
    content_check = check_content(resume_text)
    skills_check = check_skills(resume_text, selected_role)
    sections_check = check_sections(resume_text)
    format_check = check_format(resume_text)

    checks = {
        "content_check": content_check,
        "skills_check": skills_check,
        "sections_check": sections_check,
        "format_check": format_check
        }
    
    # analysis
    score = score_resume(resume_text)
    suggestions = suggest_improvements(resume_text, selected_role)
    match_score, matched_keywords, unmatched_keywords = match_keywords(resume_text, selected_role.lower())
    
    # save if logged in
    if current_user.is_authenticated:
        rec = Analysis(
            user_id   = current_user.id,
            role      = selected_role,
            score     = score,
            match_pct = match_score,
            created   = datetime.utcnow(),
            
        )
        db.session.add(rec)
        db.session.commit()    

    return render_template("dashboard.html", 
                           role=selected_role, 
                           score=score, 
                           suggestions=suggestions,
                           match_score=match_score,
                           matched_keywords=matched_keywords,
                           unmatched_keywords=unmatched_keywords,
                           name=current_user.name if current_user.is_authenticated else None,
                           email=email,
                           checks=checks
                           )




if __name__ == "__main__":
    app.run(debug=True)
