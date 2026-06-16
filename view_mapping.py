from app import app, get_file_access_mapping
import json

# Run with app context
with app.app_context():
    try:
        mapping = get_file_access_mapping()
        # Print it in a nice formatted way
        print(json.dumps(mapping, indent=2, default=str))
    except Exception as e:
        print(f"Error retrieving mapping: {e}")