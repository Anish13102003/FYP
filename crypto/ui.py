from crypto import ibbet_prof as ibe
import os
import sys
from PIL import Image
from des_core1 import DES
from des_cons1 import get_round_keys_from_hex
def enc(users,id,input_file):
    print("u have clicked the share button")
    # file_name=input("enter the file name : ")
    # id=input("enter the user id : ")
    # users = ["user1@example.com", "user2@example.com", "user3@example.com"]
    # id = "alice@example.com"

    key=ibe.encrypt_M(id,users)
    #print("original msg : ",key)
    # pt=ibe.decrypt_M(id,users)
    # print("after dec : ",pt)
    #VERIFIED DECRYPTION IS SUCCESSFULL

    key_des = ibe.serial(key)
    # print("serialized : ",serialized_result)

    # Get input file
    #input_file = input("Enter nameo  input image file: ")
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  
    UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
    output_file=UPLOAD_DIR+"/"+input_file+"_enc.jpg"
    input_file= UPLOAD_DIR+"/"+input_file+".jpg"
    if not os.path.exists(input_file):
        print(f"Error: File '{input_file}' not found.")
        sys.exit(1)

    try:
        Image.open(input_file)
    except Exception:
        print(f"Error: '{input_file}' is not a valid image file.")
        sys.exit(1)

    valid_chars = set('0123456789abcdefABCDEF')
    if not all(c in valid_chars for c in key_des):
        print("Warning: Input contains non-hexadecimal characters. These will be ignored.")
            # Filter out non-hex characters for display
        valid_key = ''.join(c for c in key_des if c in valid_chars)
        print(f"Valid characters in key: {valid_key}")
            
    try:
        # Generate round keys from the hex string
        round_keys = get_round_keys_from_hex(key_des)
        
        if len(round_keys) != 16:
            print("Error: Failed to generate 16 round keys.")
            sys.exit(1)
            
        # Calculate how many times the key was repeated (for user info)
        valid_key = ''.join(c for c in key_des if c in valid_chars)
        if valid_key:
            binary_length = len(valid_key) * 4  # Each hex char is 4 bits
            repetitions = 1024 // binary_length
            if repetitions > 1 or 1024 % binary_length != 0:
                repetitions = (1024 // binary_length) + 1
                print(f"Your key was repeated {repetitions} times to reach the required length.")
        
        # Initialize DES with the round keys
        des = DES(round_keys)

        print(f"Encrypting image {input_file}...")
        success = des.encrypt_image(input_file, output_file)
        if success:
            print(f"Encryption complete. Output saved to {output_file}")
            
        

    except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
    return output_file

# enc(["user1@example.com", "user2@example.com", "user3@example.com"],"alice@example.com","img")