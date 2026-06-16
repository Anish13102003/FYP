import os
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import json

from models import db, User, File, MetadataVector, AccessRecord
from crypto.dscs import DSCS
from crypto.ibe import IBE

# Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secure_file_sharing.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Initialize cryptographic components
MASTER_KEY = "your_secure_master_key_here"  # In production, use proper key management
dscs = DSCS(MASTER_KEY)
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
        
        user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(user)
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
    return render_template('dashboard.html', files=files)


@app.route('/shared_files')
@login_required
def view_shared_files():
    # Get files shared with the current user using a database join
    shared_files = File.query.join(AccessRecord).filter(
        AccessRecord.user_id == current_user.id
    ).all()
    
    return render_template('shared_files.html', files=shared_files)


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
            
            # Create file record
            new_file = File(
                filename=filename,
                file_path=file_path,
                user_id=current_user.id
            )
            db.session.add(new_file)
            db.session.commit()
            
            # Initialize metadata JSON for this file
            metadata = {
                str(current_user.id): {
                    str(new_file.id): {
                        "CT0": []  # Empty list of authorized users initially
                    }
                }
            }
            
            # Split and secure metadata using DSCS
            vectors = dscs.split_json(metadata)
            
            # Store vectors in database
            for vector in vectors:
                new_vector = MetadataVector(
                    vector_index=vector['index'],
                    salt=vector['salt'],
                    iv=vector['encrypted']['iv'],
                    ciphertext=vector['encrypted']['ciphertext'],
                    tag=vector['encrypted']['tag']
                )
                db.session.add(new_vector)
            
            db.session.commit()
            flash('File uploaded successfully')
            return redirect(url_for('dashboard'))
    
    return render_template('upload.html')

@app.route('/files/<int:file_id>/share', methods=['GET', 'POST'])
@login_required
def share_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Ensure file belongs to current user
    if file.user_id != current_user.id:
        flash('You do not have permission to share this file')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            
            # Find user
            user = User.query.filter_by(username=username).first()
            if not user:
                flash(f'User {username} not found')
                return redirect(url_for('share_file', file_id=file_id))
            
            # Get all metadata vectors
            vectors = []
            for vector_db in MetadataVector.query.all():
                vector = {
                    'index': vector_db.vector_index,
                    'salt': vector_db.salt,
                    'encrypted': {
                        'iv': vector_db.iv,
                        'ciphertext': vector_db.ciphertext,
                        'tag': vector_db.tag
                    }
                }
                vectors.append(vector)
            
            # If no vectors exist yet, create initial metadata
            if not vectors:
                initial_metadata = {
                    str(current_user.id): {
                        str(file_id): {
                            "CT0": []
                        }
                    }
                }
                vectors = dscs.split_json(initial_metadata)
            
            # Update metadata JSON
            updated_vectors = dscs.update_json_with_new_access(
                vectors, 
                str(current_user.id), 
                str(file_id), 
                str(user.id)
            )
            
            # Delete old vectors
            MetadataVector.query.delete()
            
            # Store updated vectors
            for vector in updated_vectors:
                new_vector = MetadataVector(
                    vector_index=vector['index'],
                    salt=vector['salt'],
                    iv=vector['encrypted']['iv'],
                    ciphertext=vector['encrypted']['ciphertext'],
                    tag=vector['encrypted']['tag']
                )
                db.session.add(new_vector)
            
            # Create access record
            access_record = AccessRecord(
                file_id=file_id,
                user_id=user.id,
                ciphertext_id="CT0"  # Default to CT0 if we can't determine
            )
            
            try:
                # Try to get the latest CT key if possible
                metadata = dscs.reconstruct_json(updated_vectors)
                ct_keys = list(metadata[str(current_user.id)][str(file_id)].keys())
                if ct_keys:
                    latest_ct = max(ct_keys, key=lambda k: int(k[2:]) if k.startswith('CT') and k[2:].isdigit() else 0)
                    access_record.ciphertext_id = latest_ct
            except Exception as e:
                print(f"Error getting latest CT: {e}")
                # Continue with default CT0
            
            db.session.add(access_record)
            db.session.commit()
            
            flash(f'File shared with {username}')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            print(f"Error sharing file: {e}")
            flash(f'Error sharing file: {str(e)}')
            db.session.rollback()
    
    return render_template('share_file.html', file=file)
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

from flask import send_from_directory  # This should go at the top of your app.py file

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
    
    # Note: In a real implementation, you would use this private key to decrypt
    # content that was encrypted specifically for this user. Since we're using
    # IBE primarily for the JSON metadata in this example, we're not encrypting
    # the actual file content.
    
    # User has access, serve the file
    return send_from_directory(
        os.path.dirname(file.file_path),
        os.path.basename(file.file_path),
        as_attachment=True
    )

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

# Initialize database and run app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)