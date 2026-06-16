#### WORKING UI APP.PY FILE - LAST EDITED 21-03-25 00;46

import os  
import datetime
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, send_from_directory 
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import json
from crypto.ui import enc
from crypto.ui2 import dec
from pathlib import Path
from flask import send_file

from models import db, User, File, MetadataVector, AccessRecord,VerificationLog
from crypto.dscs import DSCS
from crypto.ibe import IBE
from flask_migrate import Migrate
import sys
import logging
logging.basicConfig(level=logging.INFO)

# Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_file_sharing.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['TEMPLATES_AUTO_RELOAD'] = True
# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db.init_app(app)

# After creating your app and initializing SQLAlchemy
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Initialize cryptographic components
MASTER_KEY = "your_secure_master_key_here"  # In production, use proper key management
#dscs = DSCS(MASTER_KEY)
dscs = DSCS(MASTER_KEY, security_param=112)

ibe = IBE(MASTER_KEY)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists')
            return redirect(url_for('register'))
        
        # Create the user in the Flask app
        user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        
        # Register the user in DSCS and store the ID
        dscs_user_id = str(user.id)  # Use the user's ID from the app as DSCS ID
        dscs.register_user(dscs_user_id)
        
        # Update the user with their DSCS ID
        user.dscs_user_id = dscs_user_id
        db.session.commit()
        
        flash('Registration successful, please log in')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            # If user doesn't have a DSCS ID yet, register them
            if not user.dscs_user_id:
                dscs_user_id = str(user.id)
                dscs.register_user(dscs_user_id)
                user.dscs_user_id = dscs_user_id
                db.session.commit()
                
            login_user(user)
            return redirect(url_for('dashboard'))
        
        flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    files = File.query.filter_by(user_id=current_user.id).all()
    users_name=current_user.username
    logging.info(f"current_user.username : {users_name}")
    return render_template('dashboard.html', files=files,user_name=users_name)

@app.route('/test')
def test_page():
    return render_template('test.html')

@app.route('/shared_files')
@login_required
def view_shared_files():
    # Get files shared with the current user using a database join
    shared_files = File.query.join(AccessRecord).filter(
        AccessRecord.user_id == current_user.id
    ).all()
    
    return render_template('shared_files.html', files=shared_files,user_name=current_user.username)

# Update the file upload route 
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        # Check if file was uploaded
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Create file record in database
            new_file = File(
                filename=filename,
                file_path=file_path,
                user_id=current_user.id
            )
            db.session.add(new_file)
            db.session.commit()
            
            # Register users first to ensure they exist in DSCS system
            dscs.register_user(str(current_user.id))
            
            # Use new DSCS encrypt method
            with open(file_path, 'rb') as f:
                file_content = f.read()
                
            file_id = dscs.encrypt(
                file_content, 
                str(current_user.id),  # owner_id 
                str(current_user.id)   # receiver_id (only owner initially)
            )
            
            # Update file record with file_id from DSCS
            new_file.dscs_file_id = file_id
            db.session.commit()
            
            flash('File uploaded successfully')
            return redirect(url_for('dashboard'))
    
    return render_template('upload.html')

# Update the share file route
@app.route('/files/<int:file_id>/share', methods=['GET', 'POST'])
@login_required
def share_file(file_id):

    logging.info(f"inside share file")
    file = File.query.get_or_404(file_id)
    
    # Ensure file belongs to current user
    if file.user_id != current_user.id:
        flash('You do not have permission to share this file')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            logging.info(f"inside log")
            username = request.form.get('username')
            
            if not username:
                flash('Please enter a username')
                return render_template('share_file.html', file=file)
            
            # Find user
            user = User.query.filter_by(username=username).first()
            logging.info(f"user details obtained")
            if not user:
                flash(f'User {username} not found')
                return render_template('share_file.html', file=file)
            
            # Check if already shared
            existing_access = AccessRecord.query.filter_by(
                file_id=file_id, 
                user_id=user.id
            ).first()
            logging.info(f"existing")
            if existing_access:
                flash(f'File already shared with {username}')
                return render_template('share_file.html', file=file)
            
            # Register users in DSCS system if needed
            dscs.register_user(str(current_user.id))
            dscs.register_user(str(user.id))
            result = "Authorization successful"
            # Authorize access using new DSCS method
            # result = dscs.authorize(
            #     file.dscs_file_id,
            #     str(current_user.id),
            #     str(user.id)
            # )
            # logging.info(f"result : {result}")
            # Create access record in your app's database
            if result == "Authorization successful":
                logging.info(f"Sharing file: {file.filename}, User: {user.username}, Current User: {current_user.username}")
                file_name= file.filename
                filename_without_ext = file_name.removesuffix(".jpg")
                print([user.username],current_user.username,filename_without_ext)
                sys.stdout.flush()
                new_file_path=enc([user.username],current_user.username,filename_without_ext)


                new_file = File(
                    filename= Path(new_file_path).name,
                    file_path="uploads/"+Path(new_file_path).name,
                    user_id=current_user.id
                )
                db.session.add(new_file)
                db.session.commit()
                
                # Register users first to ensure they exist in DSCS system
                dscs.register_user(str(current_user.id))
                
                # Use new DSCS encrypt method
                with open(new_file_path, 'rb') as f:
                    file_content = f.read()
                    
                new_file_id = dscs.encrypt(
                    file_content, 
                    str(current_user.id),  # owner_id 
                    str(current_user.id)   # receiver_id (only owner initially)
                )
                
                # Update file record with file_id from DSCS
                new_file.dscs_file_id = new_file_id
                db.session.commit()

                required_id = File.query.filter_by(dscs_file_id=new_file_id).first().id




                access_record = AccessRecord(
                    file_id=required_id,
                    user_id=user.id,
                    ciphertext_id="CT0",  # Default ciphertext ID
                    granted_by=current_user.id
                )
                db.session.add(access_record)
                db.session.commit()
                
                flash(f'File shared with {username} successfully')
                return redirect(url_for('dashboard'))
            else:
                flash(f'Error sharing file: {result}')
                return render_template('share_file.html', file=file)
            
        except Exception as e:
            import traceback
            print(f"Exception sharing file: {str(e)}")
            print(traceback.format_exc())
            flash(f'Error sharing file: {str(e)}')
            db.session.rollback()
    
    return render_template('share_file.html', file=file,user_name=current_user.username)
'''
@app.route('/files/<int:file_id>/download')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Check if current user has access
    # If owner
    if file.user_id == current_user.id:
        return send_from_directory(
            os.path.dirname(file.file_path),
            os.path.basename(file.file_path),
            as_attachment=True
        )
    
    # If shared with user
    access_records = AccessRecord.query.filter_by(
        file_id=file_id,
        user_id=current_user.id
    ).all()
    
    if not access_records:
        flash('You do not have permission to download this file')
        return redirect(url_for('dashboard'))
    
    # Get private key for current user
    private_key = ibe.generate_private_key(str(current_user.id))
    
    # User has access, serve the file
    return send_from_directory(
        os.path.dirname(file.file_path),
        os.path.basename(file.file_path),
        as_attachment=True
    )
'''
@app.route('/audit')
@login_required
def audit_page():
    # Get files owned by the current user
    owned_files = File.query.filter_by(user_id=current_user.id).all()
    
    # Get verification logs
    verification_logs = VerificationLog.query.join(File).filter(
        File.user_id == current_user.id
    ).order_by(VerificationLog.verified_at.desc()).limit(10).all()
    
    return render_template('audit.html', files=owned_files, logs=verification_logs)

@app.route('/files/<int:file_id>/audit', methods=['POST'])
@login_required
def audit_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Check if the user has permission to audit the file
    if file.user_id != current_user.id:
        flash('You do not have permission to audit this file')
        return redirect(url_for('audit_page'))
    
    try:
        challenge_count = request.form.get('challenge_count', type=int, default=3)
        
        # Ensure challenge count is at least 1 and at most 10 (or whatever maximum makes sense)
        challenge_count = max(1, min(challenge_count, 10))

        # Generate a challenge
        challenge = dscs.challenge(
            dscs.public_params,
            challenge_count,  # Challenge 3 random blocks
            file.dscs_file_id
        )
        
        # Get file vectors
        encrypted_vectors = dscs.get_file_vectors(file.dscs_file_id)
        
        if not encrypted_vectors:
            flash('No file data found for verification')
            return redirect(url_for('audit_page'))
        
        # Generate proof
        proof = dscs.prove(
            challenge,
            dscs.public_params,
            encrypted_vectors,
            dscs.skip_list,
            file.dscs_file_id
        )
        
        # Verify proof
        result = dscs.verify(
            challenge,
            proof,
            dscs.public_params,
            file.dscs_file_id
        )
        
        # Create a verification log
        verification_log = VerificationLog(
            file_id=file_id,
            challenge_count=len(challenge),
            verification_result=result,
            verified_by=current_user.id
        )
        db.session.add(verification_log)
        db.session.commit()
        
        # Get audit details for display
        audit_details = {
            "challenge_count": len(challenge),
            "challenge_sample": challenge[:2],  # Show first 2 challenges
            "result": "PASSED" if result else "FAILED",
            "verification_time": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return render_template('audit_result.html', 
                              file=file, 
                              result=result, 
                              details=audit_details)
        
    except Exception as e:
        flash(f'Error during audit: {str(e)}')
        return redirect(url_for('audit_page'))

# Update the file download route
@app.route('/files/<int:file_id>/download')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Check if current user has access
    # If owner
    if file.user_id == current_user.id:
        return send_from_directory(
            os.path.dirname(file.file_path),
            os.path.basename(file.file_path),
            as_attachment=True
        )
    
    # If shared with user
    access_records = AccessRecord.query.filter_by(
        file_id=file_id,
        user_id=current_user.id
    ).all()
    
    if not access_records:
        flash('You do not have permission to download this file')
        return redirect(url_for('dashboard'))
    
    # Get private key for current user
    private_key = ibe.generate_private_key(str(current_user.id))
    
    # User has access, serve the file
    return send_from_directory(
        os.path.dirname(file.file_path),
        os.path.basename(file.file_path),
        as_attachment=True
    )




@app.route('/files/<int:file_id>/view')
@login_required
def view_file(file_id):
    logging.info(f"inside view file")
    file = File.query.get_or_404(file_id)
    
    logging.info(f"Sharing file: {file.filename}, Current User: {current_user.username}")
    file_name = file.filename
    filename_without_ext = file_name.removesuffix(".jpg")
                
    new_file_path = dec([current_user.username], current_user.username, filename_without_ext)
    logging.info(f"file_name: {file.filename}, w.o.ext: {filename_without_ext}, new_path: {new_file_path}")
    file_path=Path(new_file_path).name
    
    return render_template('view_decrypted.html', file_path=file_path)

@app.route('/uploads/<path:filename>')
def serve_uploaded_file(filename):
    return send_file(filename)
    
# API Endpoints for potential AJAX operations
@app.route('/api/files', methods=['GET'])
@login_required
def get_files():
    # Get files owned by user
    owned_files = File.query.filter_by(user_id=current_user.id).all()
    
    # Get files shared with user
    shared_files = File.query.join(AccessRecord).filter(
        AccessRecord.user_id == current_user.id
    ).all()
    
    # Format response
    response = {
        'owned_files': [{'id': f.id, 'name': f.filename} for f in owned_files],
        'shared_files': [{'id': f.id, 'name': f.filename} for f in shared_files]
    }
    
    return jsonify(response)

def get_file_access_mapping():
    """
    Extract file access mapping information from the DSCS database.
    
    Returns:
        dict: A dictionary showing files and their authorized users
    """
    import sqlite3
    import json
    
    # Connect to the DSCS storage database
    conn = sqlite3.connect('dscs_storage.db')
    cursor = conn.cursor()
    
    # Get all files
    cursor.execute("SELECT file_id, file_name, owner_id FROM files")
    files = cursor.fetchall()
    
    access_mapping = {}
    
    for file_id, file_name, owner_id in files:
        # Get all users with access to this file
        cursor.execute(
            "SELECT user_id, granted_by, granted_at FROM file_access WHERE file_id = ?",
            (file_id,)
        )
        access_records = cursor.fetchall()
        
        # Get vector information
        cursor.execute(
            "SELECT vector_index FROM file_vectors WHERE file_id = ? ORDER BY vector_index",
            (file_id,)
        )
        vector_indices = [row[0] for row in cursor.fetchall()]
        
        # Format access information
        users_with_access = []
        access_details = []
        
        for user_id, granted_by, granted_at in access_records:
            users_with_access.append(user_id)
            access_details.append({
                "user": user_id,
                "granted_by": granted_by,
                "granted_at": granted_at
            })
        
        access_mapping[file_id] = {
            "file_name": file_name,
            "owner": owner_id,
            "authorized_users": users_with_access,
            "access_details": access_details,
            "vector_count": len(vector_indices),
            "vector_indices": vector_indices
        }
    
    conn.close()
    
    # Print as formatted JSON
    print(json.dumps(access_mapping, indent=2, default=str))
    
    return access_mapping

@app.route('/view_access_mapping')
@login_required
def view_access_mapping():
    if not current_user.id == 1:  # Restrict to first user or add proper admin check
        flash('Access denied')
        return redirect(url_for('dashboard'))
        
    mapping = get_file_access_mapping()
    return render_template('access_mapping.html', mapping=mapping)


# Initialize database and run app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)