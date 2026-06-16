from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import datetime

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    date_joined = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    # Store DSCS user information
    dscs_user_id = db.Column(db.String(255))  # Use this for DSCS user identification
    
    def __repr__(self):
        return f'<User {self.username}>'
    

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(512), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Add DSCS-specific file identifier
    dscs_file_id = db.Column(db.String(255))
    
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
    
    # Associate vectors with files
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    file = db.relationship('File', backref=db.backref('vectors', lazy=True))
    
    def __repr__(self):
        return f'<MetadataVector {self.id}>'


class AccessRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ciphertext_id = db.Column(db.String(20), nullable=False)  # e.g., "CT0", "CT1"
    granted_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    granted_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Relationships
    file = db.relationship('File', backref=db.backref('access_records', lazy=True), foreign_keys=[file_id])
    user = db.relationship('User', backref=db.backref('access_records', lazy=True), foreign_keys=[user_id])
    granter = db.relationship('User', backref=db.backref('granted_access', lazy=True), foreign_keys=[granted_by])
    
    def __repr__(self):
        return f'<AccessRecord {self.id}>'

class VerificationLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    challenge_count = db.Column(db.Integer, nullable=False)
    verification_result = db.Column(db.Boolean, nullable=False)
    verified_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    verified_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Relationships
    file = db.relationship('File', backref=db.backref('verification_logs', lazy=True))
    user = db.relationship('User', backref=db.backref('verification_logs', lazy=True))