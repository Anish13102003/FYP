from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin  # Import here
import datetime

db = SQLAlchemy()

class User(db.Model, UserMixin):  # User inherits from both db.Model and UserMixin
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    date_joined = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    def __repr__(self):
        return f'<User {self.username}>'
    

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(512), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationship
    user = db.relationship('User', backref=db.backref('files', lazy=True))
    
    def __repr__(self):
        return f'<File {self.filename}>'

class MetadataVector(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vector_index = db.Column(db.Integer, nullable=False)
    salt = db.Column(db.LargeBinary, nullable=False)
    iv = db.Column(db.LargeBinary, nullable=False)
    ciphertext = db.Column(db.LargeBinary, nullable=False)
    tag = db.Column(db.LargeBinary, nullable=False)
    
    def __repr__(self):
        return f'<MetadataVector {self.id}>'

class AccessRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ciphertext_id = db.Column(db.String(20), nullable=False)  # e.g., "CT0", "CT1"
    
    # Relationships
    file = db.relationship('File', backref=db.backref('access_records', lazy=True))
    user = db.relationship('User', backref=db.backref('access_records', lazy=True))
    
    def __repr__(self):
        return f'<AccessRecord {self.id}>'