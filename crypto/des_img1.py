import os
import sys
from PIL import Image
from des_core1 import DES
from des_cons1 import get_round_keys_from_hex

def main():
    print("DES Image Encryption/Decryption")
    print("-------------------------------")
    
    # Get operation mode
    while True:
        mode = input("Choose operation (e for encrypt, d for decrypt): ").lower()
        if mode in ['e', 'd']:
            break
        print("Invalid choice. Please enter 'e' or 'd'.")
    
    # Get input file
    input_file = input("Enter path to input image file: ")
    if not os.path.exists(input_file):
        print(f"Error: File '{input_file}' not found.")
        sys.exit(1)
        
    # Validate image file for encryption
    if mode == 'e':
        try:
            Image.open(input_file)
        except Exception:
            print(f"Error: '{input_file}' is not a valid image file.")
            sys.exit(1)
    
    # Get output file
    if mode == 'e':
        output_file = input("Enter path for encrypted output file: ")
    else:
        output_file = input("Enter path for decrypted output image: ")
        # Make sure output has an image extension
        if not any(output_file.lower().endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.bmp', '.gif']):
            output_file += '.png'
            print(f"Added image extension: output will be saved as {output_file}")
    
    # Get encryption key (hexadecimal string)
    print("\nKey Information:")
    print("You need to provide a hexadecimal string that will be used to derive 16 round keys.")
    print("The system will take the first 1024 bits (256 hex characters) of your input.")
    print("This will be split into 16 parts, with each part serving as a key for one round.")
    print("Example of a hex string: 1a2b3c4d... (continuing for many characters)")
    print("For security, using at least 256 hex characters (1024 bits) is recommended.")
    print("If your key is shorter, it will be repeated until it reaches the required length.")
    print()
    
    hex_key = input("Enter your hexadecimal encryption key: ")
    
    # Check for valid hex characters
    valid_chars = set('0123456789abcdefABCDEF')
    if not all(c in valid_chars for c in hex_key):
        print("Warning: Input contains non-hexadecimal characters. These will be ignored.")
        # Filter out non-hex characters for display
        valid_key = ''.join(c for c in hex_key if c in valid_chars)
        print(f"Valid characters in key: {valid_key}")
    
    try:
        # Generate round keys from the hex string
        round_keys = get_round_keys_from_hex(hex_key)
        
        if len(round_keys) != 16:
            print("Error: Failed to generate 16 round keys.")
            sys.exit(1)
            
        # Calculate how many times the key was repeated (for user info)
        valid_key = ''.join(c for c in hex_key if c in valid_chars)
        if valid_key:
            binary_length = len(valid_key) * 4  # Each hex char is 4 bits
            repetitions = 1024 // binary_length
            if repetitions > 1 or 1024 % binary_length != 0:
                repetitions = (1024 // binary_length) + 1
                print(f"Your key was repeated {repetitions} times to reach the required length.")
        
        # Initialize DES with the round keys
        des = DES(round_keys)
        
        # Perform encryption or decryption
        if mode == 'e':
            print(f"Encrypting image {input_file}...")
            success = des.encrypt_image(input_file, output_file)
            if success:
                print(f"Encryption complete. Output saved to {output_file}")
        else:
            print(f"Decrypting to image {input_file}...")
            success = des.decrypt_image(input_file, output_file)
            if success:
                print(f"Decryption complete. Output saved to {output_file}")
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()