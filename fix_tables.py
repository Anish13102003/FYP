from app import app, db
import sqlite3

with app.app_context():
    # Connect to the database
    conn = sqlite3.connect('instance/secure_file_sharing.db')  # Adjust path if needed
    cursor = conn.cursor()
    
    # Add missing columns to user table
    try:
        cursor.execute("ALTER TABLE user ADD COLUMN dscs_user_id TEXT")
        print("Added dscs_user_id to user table")
    except sqlite3.OperationalError as e:
        print(f"Note: {e}")
    
    # Add missing columns to file table
    try:
        cursor.execute("ALTER TABLE file ADD COLUMN dscs_file_id TEXT")
        print("Added dscs_file_id to file table")
    except sqlite3.OperationalError as e:
        print(f"Note: {e}")
    
    # Add missing columns to access_record table
    try:
        cursor.execute("ALTER TABLE access_record ADD COLUMN granted_at DATETIME")
        print("Added granted_at to access_record table")
    except sqlite3.OperationalError as e:
        print(f"Note: {e}")
    
    try:
        cursor.execute("ALTER TABLE access_record ADD COLUMN granted_by INTEGER REFERENCES user(id)")
        print("Added granted_by to access_record table")
    except sqlite3.OperationalError as e:
        print(f"Note: {e}")
    
    # Add missing columns to metadata_vector table
    try:
        cursor.execute("ALTER TABLE metadata_vector ADD COLUMN file_id INTEGER REFERENCES file(id)")
        print("Added file_id to metadata_vector table")
    except sqlite3.OperationalError as e:
        print(f"Note: {e}")
    
    conn.commit()
    conn.close()
    
    print("\nDatabase update complete")