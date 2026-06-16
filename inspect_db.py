from app import app, db
import sqlite3

with app.app_context():
    # Connect to the database
    conn = sqlite3.connect('secure_file_sharing.db')
    cursor = conn.cursor()
    
    # Get all table names in the database
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [table[0] for table in cursor.fetchall()]
    print("Tables in database:", tables)
    
    # Based on tables found, let's try to add columns
    for table in tables:
        print(f"\nColumns in table '{table}':")
        cursor.execute(f"PRAGMA table_info({table})")
        columns = cursor.fetchall()
        for col in columns:
            print(f"  {col[1]} ({col[2]})")
    
    conn.close()
    
    print("\nDatabase inspection complete")