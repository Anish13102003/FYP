from app import app, db
from models import User, File, MetadataVector, AccessRecord, VerificationLog

with app.app_context():
    # Create all tables
    print("Creating database tables...")
    db.create_all()
    print("Database tables created successfully!")
    
    # Print all created tables
    engine = db.engine
    inspector = db.inspect(engine)
    schema_names = inspector.get_schema_names()
    
    for schema in schema_names:
        print(f"Schema: {schema}")
        for table_name in inspector.get_table_names(schema=schema):
            print(f"  Table: {table_name}")
            for column in inspector.get_columns(table_name, schema=schema):
                print(f"    Column: {column['name']}, Type: {column['type']}")