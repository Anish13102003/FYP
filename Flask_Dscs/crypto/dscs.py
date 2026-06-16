import os
import json
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class DSCS:
    def __init__(self, master_key):
        self.master_key = master_key
        self.vector_count = 3  # Number of file vectors to split into
    
    def _derive_key(self, input_data, salt=None):
        """Derive encryption key from master key and input data"""
        if not salt:
            salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac('sha256', 
                                 self.master_key.encode(), 
                                 salt + str(input_data).encode(), 
                                 100000)
        return key, salt
    
    def _encrypt_data(self, data, key):
        """Encrypt data with AES-GCM"""
        iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        
        # Convert data to bytes if it's not already
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return {
            'iv': iv,
            'ciphertext': ciphertext,
            'tag': encryptor.tag
        }
    
    def _decrypt_data(self, enc_data, key):
        """Decrypt data encrypted with AES-GCM"""
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(enc_data['iv'], enc_data['tag']),
            backend=default_backend()
        ).decryptor()
        
        return decryptor.update(enc_data['ciphertext']) + decryptor.finalize()
    
    def split_json(self, json_data):
        """Split JSON data into vector files using DSCS I protocol"""
        print(f"Splitting JSON: {json_data}")
        # Convert JSON to string - ensure we use double quotes for valid JSON
        data_str = json.dumps(json_data, ensure_ascii=False)
        print(f"JSON string to split: {data_str}")
        
        # Split into vectors based on DSCS I protocol
        vectors = []
        chunk_size = max(1, len(data_str) // self.vector_count)
        
        for i in range(self.vector_count):
            start = i * chunk_size
            end = start + chunk_size if i < self.vector_count - 1 else len(data_str)
            chunk = data_str[start:end]
            
            # Generate unique key for this vector
            key, salt = self._derive_key(i)
            
            # Encrypt the chunk
            encrypted = self._encrypt_data(chunk, key)
            
            # Store vector with metadata
            vectors.append({
                'index': i,
                'salt': salt,
                'encrypted': encrypted
            })
        
        return vectors
    
    def reconstruct_json(self, vectors):
        """Reconstruct JSON data from vector files with enhanced error handling"""
        try:
            # Sort vectors by index
            vectors.sort(key=lambda x: x['index'])
            
            # Decrypt and combine chunks
            chunks = []
            for vector in vectors:
                try:
                    key, _ = self._derive_key(vector['index'], vector['salt'])
                    decrypted = self._decrypt_data(vector['encrypted'], key)
                    chunks.append(decrypted.decode('utf-8', errors='replace'))
                except Exception as e:
                    print(f"Error decrypting vector {vector['index']}: {e}")
            
            # Combine chunks and parse JSON
            json_str = ''.join(chunks)
            print(f"Reconstructed JSON string: {json_str}")
            
            # Try to parse the JSON with error handling
            try:
                return json.loads(json_str)
            except json.JSONDecodeError as e:
                print(f"JSON decode error: {e}")
                
                # Fix common JSON issues
                json_str = json_str.replace("'", '"')  # Replace single quotes with double quotes
                
                # Ensure proper structure
                if not json_str.startswith('{'):
                    json_str = '{' + json_str
                if not json_str.endswith('}'):
                    json_str = json_str + '}'
                
                print(f"Attempting to parse fixed JSON: {json_str}")
                return json.loads(json_str)
                
        except Exception as e:
            print(f"Error in reconstruct_json: {e}")
            # Return a minimal valid JSON if reconstruction fails
            return {"error": "reconstruction_failed"}

    def update_json_with_new_access(self, vectors, user_id, image_id, new_authorized_user):
        """Update JSON data with new access rights and re-split"""
        print(f"Updating access: user={user_id}, image={image_id}, new_auth_user={new_authorized_user}")
        
        try:
            # First reconstruct the current JSON
            json_data = self.reconstruct_json(vectors)
            print(f"Reconstructed JSON data: {json_data}")
            
            # Check if user exists
            if user_id not in json_data:
                json_data[user_id] = {}
            
            # Check if image exists for this user
            if image_id not in json_data[user_id]:
                json_data[user_id][image_id] = {}
            
            # Generate a new CT for the updated set of authorized users
            # Find highest CT index
            ct_indices = [int(ct[2:]) for ct in json_data[user_id][image_id].keys() if ct.startswith('CT')]
            new_ct_index = 0 if not ct_indices else max(ct_indices) + 1
            
            # Get all currently authorized users for this image
            authorized_users = set()
            for ct, users in json_data[user_id][image_id].items():
                if isinstance(users, list):
                    authorized_users.update(users)
                elif isinstance(users, str):
                    authorized_users.add(users)
            
            # Add new user
            authorized_users.add(new_authorized_user)
            
            # Create new CT with updated user set
            new_ct_key = f"CT{new_ct_index}"
            json_data[user_id][image_id][new_ct_key] = list(authorized_users)
            
            print(f"Updated JSON data: {json_data}")
            
            # Re-split the updated JSON
            return self.split_json(json_data)
            
        except Exception as e:
            print(f"Error in update_json_with_new_access: {e}")
            
            # Create a brand new JSON structure if updating fails
            json_data = {
                user_id: {
                    image_id: {
                        "CT0": [new_authorized_user]
                    }
                }
            }
            print(f"Created new JSON data: {json_data}")
            return self.split_json(json_data)