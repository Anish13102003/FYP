from app import app, db
from models import User, File, MetadataVector, AccessRecord, VerificationLog
import sqlite3

with app.app_context():
    # Add the missing columns to existing tables
    conn = sqlite3.connect('secure_file_sharing.db')
    cursor = conn.cursor()
    
    # Check and add columns to user table
    cursor.execute("PRAGMA table_info(user)")
    user_columns = [column[1] for column in cursor.fetchall()]
    if 'dscs_user_id' not in user_columns:
        print("Adding dscs_user_id column to user table")
        cursor.execute("ALTER TABLE user ADD COLUMN dscs_user_id TEXT")
    
    # Check and add columns to file table
    cursor.execute("PRAGMA table_info(file)")
    file_columns = [column[1] for column in cursor.fetchall()]
    if 'dscs_file_id' not in file_columns:
        print("Adding dscs_file_id column to file table")
        cursor.execute("ALTER TABLE file ADD COLUMN dscs_file_id TEXT")
    
    # Check and add columns to access_record table
    cursor.execute("PRAGMA table_info(access_record)")
    access_record_columns = [column[1] for column in cursor.fetchall()]
    if 'granted_at' not in access_record_columns:
        print("Adding granted_at column to access_record table")
        cursor.execute("ALTER TABLE access_record ADD COLUMN granted_at DATETIME")
    if 'granted_by' not in access_record_columns:
        print("Adding granted_by column to access_record table")
        cursor.execute("ALTER TABLE access_record ADD COLUMN granted_by INTEGER REFERENCES user(id)")
    
    # Check and add columns to metadata_vector table
    cursor.execute("PRAGMA table_info(metadata_vector)")
    metadata_vector_columns = [column[1] for column in cursor.fetchall()]
    if 'file_id' not in metadata_vector_columns:
        print("Adding file_id column to metadata_vector table")
        cursor.execute("ALTER TABLE metadata_vector ADD COLUMN file_id INTEGER REFERENCES file(id)")
    
    conn.commit()
    conn.close()
    
    print("Database schema updated successfully")