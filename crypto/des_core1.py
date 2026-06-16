import io
from PIL import Image
from des_cons1 import (
    IP_TABLE, FP_TABLE, E_TABLE, P_TABLE, S_BOXES
)

class DES:
    def __init__(self, round_keys):
        """Initialize with pregenerated round keys for each round"""
        if len(round_keys) != 16:
            raise ValueError("Must provide 16 round keys")
        
        for key in round_keys:
            if len(key) != 48:
                raise ValueError("Each round key must be 48 bits")
        
        self.round_keys = round_keys
    
    def _initial_permutation(self, block):
        """Initial permutation for 64-bit data block"""
        return ''.join(block[i-1] for i in IP_TABLE)
    
    def _final_permutation(self, block):
        """Final permutation for 64-bit data block (inverse of initial permutation)"""
        return ''.join(block[i-1] for i in FP_TABLE)
    
    def _expansion(self, block):
        """Expand 32-bit block to 48 bits using expansion permutation"""
        return ''.join(block[i-1] for i in E_TABLE)
    
    def _substitution(self, block):
        """Apply S-box substitution on 48-bit input, producing 32-bit output"""
        # Split the 48-bit input into 8 6-bit chunks
        chunks = [block[i:i+6] for i in range(0, 48, 6)]
        result = ""
        
        # Process each chunk through the corresponding S-box
        for i, chunk in enumerate(chunks):
            # First and last bits determine row, middle 4 bits determine column
            row = int(chunk[0] + chunk[5], 2)
            col = int(chunk[1:5], 2)
            
            # Get the value from the S-box and convert to 4-bit binary
            val = S_BOXES[i][row][col]
            result += format(val, '04b')
            
        return result
    
    def _permutation(self, block):
        """Permutation function for the output of S-boxes"""
        return ''.join(block[i-1] for i in P_TABLE)
    
    def _f_function(self, right_half, round_key):
        """Feistel function combining expansion, key mixing, substitution, and permutation"""
        # 1. Expand the 32-bit right half to 48 bits
        expanded = self._expansion(right_half)
        
        # 2. XOR with the round key
        xor_result = ''.join('1' if expanded[i] != round_key[i] else '0' for i in range(48))
        
        # 3. Pass through S-boxes to get 32 bits
        s_result = self._substitution(xor_result)
        
        # 4. Permutation
        return self._permutation(s_result)
    
    def _process_block(self, block, encrypt=True):
        """Process a 64-bit block with the DES algorithm"""
        # Apply initial permutation
        block = self._initial_permutation(block)
        
        # Split into left and right halves
        left = block[:32]
        right = block[32:]
        
        # 16 rounds of processing
        # For encryption, use keys in order; for decryption, use keys in reverse order
        key_order = range(16) if encrypt else range(15, -1, -1)
        
        for i in key_order:
            # Save the previous right half
            old_right = right
            
            # Apply Feistel function to right half using the appropriate round key
            f_result = self._f_function(right, self.round_keys[i])
            
            # New right half is the previous left half XORed with f_result
            right = ''.join('1' if left[j] != f_result[j] else '0' for j in range(32))
            
            # New left half is the previous right half
            left = old_right
        
        # Final swap (not part of the rounds)
        combined = right + left
        
        # Apply final permutation and return
        return self._final_permutation(combined)
    
    def encrypt_block(self, block):
        """Encrypt a 64-bit block"""
        return self._process_block(block, encrypt=True)
    
    def decrypt_block(self, block):
        """Decrypt a 64-bit block"""
        return self._process_block(block, encrypt=False)
    
    def _bytes_to_binary(self, data_bytes):
        """Convert bytes to a binary string"""
        binary = ""
        for byte in data_bytes:
            binary += format(byte, '08b')
        return binary
    
    def _binary_to_bytes(self, binary):
        """Convert a binary string to bytes"""
        return bytes(int(binary[i:i+8], 2) for i in range(0, len(binary), 8))
    
    def _pad_data(self, binary_data):
        """Pad the binary data to a multiple of 64 bits"""
        padding_length = 64 - (len(binary_data) % 64)
        if padding_length == 0:
            padding_length = 64  # Add a full block if already aligned
        
        # PKCS#7 padding - add bytes with the value equal to the padding length
        # Convert padding length to bits (1 byte = 8 bits)
        padding = format(padding_length // 8, '08b') * (padding_length // 8)
        return binary_data + padding
    
    def _unpad_data(self, binary_data):
        """Remove PKCS#7 padding"""
        # Convert the last byte to integer
        last_byte = int(binary_data[-8:], 2)
        
        # Remove the padding bytes
        return binary_data[:-last_byte*8]
    
    def encrypt_data(self, data):
        """Encrypt arbitrary data"""
        # Convert data to binary string
        binary_data = self._bytes_to_binary(data)
        
        # Pad the data
        padded_data = self._pad_data(binary_data)
        
        # Process in 64-bit blocks
        encrypted_binary = ""
        for i in range(0, len(padded_data), 64):
            block = padded_data[i:i+64]
            encrypted_block = self.encrypt_block(block)
            encrypted_binary += encrypted_block
        
        # Convert back to bytes
        return self._binary_to_bytes(encrypted_binary)
    
    def decrypt_data(self, data):
        """Decrypt data"""
        # Convert data to binary string
        binary_data = self._bytes_to_binary(data)
        
        # Process in 64-bit blocks
        decrypted_binary = ""
        for i in range(0, len(binary_data), 64):
            block = binary_data[i:i+64]
            decrypted_block = self.decrypt_block(block)
            decrypted_binary += decrypted_block
        
        # Remove padding
        unpadded_binary = self._unpad_data(decrypted_binary)
        
        # Convert back to bytes
        return self._binary_to_bytes(unpadded_binary)
    
    def encrypt_image(self, input_file, output_file):
        """Encrypt an image file and save it"""
        try:
            # Open the original image
            img = Image.open(input_file)
            width, height = img.size
            format = img.format
            mode = img.mode
            
            # Convert image to bytes
            img_bytes = io.BytesIO()
            img.save(img_bytes, format=format)
            img_bytes = img_bytes.getvalue()
            
            # Encrypt the image bytes
            encrypted_bytes = self.encrypt_data(img_bytes)
            
            # Save the encrypted data to a new file
            with open(output_file, 'wb') as f_out:
                f_out.write(encrypted_bytes)
                
            print(f"Image encrypted successfully. Original dimensions: {width}x{height}, Format: {format}")
            return True
        except Exception as e:
            print(f"Error encrypting image: {e}")
            return False
    
    def decrypt_image(self, input_file, output_file):
        """Decrypt an image file and save it"""
        try:
            # Read the encrypted image bytes
            with open(input_file, 'rb') as f_in:
                encrypted_bytes = f_in.read()
            
            # Decrypt the bytes
            decrypted_bytes = self.decrypt_data(encrypted_bytes)
            
            # Try to create an image from the decrypted bytes
            try:
                img = Image.open(io.BytesIO(decrypted_bytes))
                img.save(output_file)
                print(f"Image decrypted successfully. Dimensions: {img.size}, Format: {img.format}")
            except Exception as e:
                # If failed to parse as image, save the raw bytes
                print(f"Warning: Could not parse decrypted data as image: {e}")
                print("Saving raw decrypted bytes...")
                with open(output_file, 'wb') as f_out:
                    f_out.write(decrypted_bytes)
            
            return True
        except Exception as e:
            print(f"Error decrypting image: {e}")
            return False