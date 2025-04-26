# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from flask_migrate import Migrate

db = SQLAlchemy()
migrate = Migrate()
class User(UserMixin, db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    email    = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)   # hashed
    created  = db.Column(db.DateTime, default=datetime.utcnow)
    name = db.Column(db.String(100))  
    def __repr__(self):
        return f"<User {self.name}>"

class Analysis(db.Model):
    id        = db.Column(db.Integer, primary_key=True)
    user_id   = db.Column(db.Integer, db.ForeignKey('user.id'))
    role      = db.Column(db.String(64))
    score     = db.Column(db.Integer)
    match_pct = db.Column(db.Integer)
    name      = db.Column(db.String(100))   
    created   = db.Column(db.DateTime, default=datetime.utcnow)
