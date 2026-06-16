import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class IBE:
    def __init__(self, master_key):
        self.master_key = master_key
    
    def generate_private_key(self, identity):
        """Generate a private key for a given identity"""
        # In a real IBE system, this would use bilinear pairings and more complex math
        # This is a simplified version for demonstration
        key = hashlib.pbkdf2_hmac('sha256', 
                                  self.master_key.encode(), 
                                  identity.encode(), 
                                  100000)
        return key
    
    def encrypt(self, message, recipient_identities):
        """Encrypt a message for a set of recipient identities"""
        # Generate a random symmetric key
        sym_key = os.urandom(32)
        
        # Encrypt the message with this key
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(sym_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Padding
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        
        # Encrypt
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # For each recipient, encrypt the symmetric key with their identity
        encrypted_keys = {}
        for identity in recipient_identities:
            # Generate identity hash
            identity_hash = hashlib.sha256(identity.encode()).digest()
            
            # XOR symmetric key with identity hash (simplified IBE)
            encrypted_key = bytes(a ^ b for a, b in zip(sym_key, identity_hash))
            encrypted_keys[identity] = encrypted_key
        
        return {
            'iv': iv,
            'ciphertext': ciphertext,
            'encrypted_keys': encrypted_keys
        }
    
    def decrypt(self, encrypted_data, identity, private_key):
        """Decrypt a message using identity and private key"""
        # Get the encrypted symmetric key for this identity
        if identity not in encrypted_data['encrypted_keys']:
            raise ValueError(f"No key found for identity: {identity}")
        
        encrypted_key = encrypted_data['encrypted_keys'][identity]
        
        # Generate identity hash
        identity_hash = hashlib.sha256(identity.encode()).digest()
        
        # Recover symmetric key
        sym_key = bytes(a ^ b for a, b in zip(encrypted_key, identity_hash))
        
        # Decrypt the message
        iv = encrypted_data['iv']
        cipher = Cipher(algorithms.AES(sym_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt
        padded_plaintext = decryptor.update(encrypted_data['ciphertext']) + decryptor.finalize()
        
        # Unpad
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext.decode()