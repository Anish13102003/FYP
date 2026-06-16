#!/usr/bin/env python3
"""
Identity-Based Encryption (IBE) with Bilinear Pairing and Map-to-Point Hash

This module implements an Identity-Based Encryption scheme using bilinear 
pairings with secure authorization and transformation capabilities.
"""
import sys
sys.path.append('/home/maha/pbc-0.5.14/charm')
import hashlib
import logging
from typing import Tuple, List, Union, Dict, Any

from Crypto.Hash import SHA256
from Crypto.Util.number import getRandomInteger
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair

import hashlib
import json
import os

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("IBE")

# Initialize pairing group - Using MNT224 curve
GROUP = PairingGroup('MNT224')

class IBBET:
    """Identity-Based Encryption implementation with map-to-point hashing."""
    
    def __init__(self):
        """Initialize the IBE system with random generators and master key."""
        # System parameters
        self.a = GROUP.random(ZR)  # Master secret key
        self.g = GROUP.random(G1)  # Generator for G1
        self.h = GROUP.random(G2)  # Generator for G2
        self.u = GROUP.random(G1)  # Additional generator
        self.g1 = self.g ** self.a  # Public parameter g^a
        
        logger.info("IBE system initialized with fresh parameters")
    
    def get_public_params(self) -> Dict[str, Any]:
        """Return the public parameters of the IBE system."""
        return {
            'g': self.g,
            'h': self.h,
            'u': self.u,
            'g1': self.g1,
        }
    
   
    def hash_to_zr(self,id_str: str) -> ZR:
        """
        Hash function H0: maps an identity to an element in ZR.
        
        Args:
            id_str: Identity string to hash
            
        Returns:
            An element in ZR representing the hashed identity
        """
        h = SHA256.new()
        h.update(id_str.encode())
        return GROUP.init(ZR, int.from_bytes(h.digest(), 'big'))
    
    
    def hash_pairing(self,pairing_element: Any) -> int:
        """
        Hash function H1: maps a pairing to a scalar.
        
        Args:
            pairing_element: GT element from a pairing operation
            
        Returns:
            A scalar value derived from hashing the pairing element
        """
        pairing_bytes = GROUP.serialize(pairing_element)
        hashed_value = hashlib.sha3_256(pairing_bytes).digest()
        q = GROUP.order()  # Order of the group
        hashed_scalar = int.from_bytes(hashed_value, "big") % q
        return hashed_scalar
    
    def map_to_point(self, value: Any) -> Dict[str, int]:
        """
        Map a bilinear pairing result to a point encoding.
        
        Args:
            value: A GT element from a pairing operation
            
        Returns:
            Dictionary with x,y coordinates representing the mapped point
        """
        # Serialize the pairing element to bytes
        serialized = GROUP.serialize(value)
        
        # Use SHA3-512 to get 64 bytes (512 bits)
        hash_bytes = hashlib.sha3_512(serialized).digest()
        
        # Split into two 32-byte (256-bit) values for x and y
        x_bytes = hash_bytes[:32]
        y_bytes = hash_bytes[32:]
        
        # Convert to integers
        x = int.from_bytes(x_bytes, byteorder='big')
        y = int.from_bytes(y_bytes, byteorder='big')
        
        return {'x': x, 'y': y}
    
    def generate_secret_key(self, identity: str) -> G1:
        """
        Generate a secret key for a given identity.
        
        Args:
            identity: The identity string for key generation
            
        Returns:
            The secret key as an element in G1
        """

        print("identity : ",identity)
        h0_id = self.hash_to_zr(identity)
        exp = (self.a + h0_id) ** -1  # Compute inverse in ZR
        sk_id = self.g ** exp  # Compute SK_ID in G1
        logger.info(f"Generated secret key for identity: {identity}")
        return sk_id
    
    def encrypt(self, message: GT, recipient_id: str) -> Tuple[GT, G2, G1]:
        """
        Encrypt a message for a specific identity.
        
        Args:
            message: The plaintext message (GT element)
            recipient_id: Identity of the recipient
            
        Returns:
            Tuple containing the ciphertext components
        """
        s = GROUP.random(ZR)  # Random value in ZR
        h0_id = self.hash_to_zr(recipient_id)
        e_gh = pair(self.g, self.h)
        # Compute ciphertext components
        c0 = message * (e_gh ** s)  # M * e(g,h)^s
        c1 = self.h ** (s * (self.a + h0_id))  # h^(s*(a+H0(ID)))
        c2 = self.u ** (s * (self.a + h0_id))  # u^(s*(a+H0(ID)))
        
        logger.info(f"Message encrypted for identity: {recipient_id}")
        return (c0, c1, c2)
    
    def decrypt(self, ciphertext: Tuple[GT, G2, G1], secret_key: G1) -> GT:
        """
        Decrypt a ciphertext using a secret key.
        
        Args:
            ciphertext: The ciphertext tuple (C0, C1, C2)
            secret_key: The secret key for decryption
            
        Returns:
            The decrypted message as a GT element
        """
        c0, c1, _ = ciphertext
        
        # Compute e(SK_ID, C1) in GT
        e_sk_c1 = pair(secret_key, c1)
        
        # Recover the message
        message = c0 * (e_sk_c1 ** -1)
        
        logger.info("Message decrypted successfully")
        return message
    
    def generate_auth_token(self, user_set: List[str], user_secret_key: G1) -> Tuple[G1, G2, int, G1]:
        """
        Generate an authorization token for delegating decryption rights.
        
        Args:
            user_set: List of authorized user identities
            user_secret_key: Secret key of the delegating user
            
        Returns:
            Authorization token as a tuple (d1, d2, d3, d4)
        """
        t = GROUP.random(ZR)  # Random value t
        r = GROUP.random(ZR)  # Random value r
        
        # Compute d1 = g^(-t)
        d1 = self.g1 ** -t
        
        # Compute d2 = h^(t * Π(a + H0(ID)))
        product = GROUP.init(ZR, 1)
        for identity in user_set:
            product *= (self.a + self.hash_to_zr(identity))
        
        d2 = self.h ** (t * product)
        
        # Compute d3 = H1(e(g,h)^t) * h^r
        pairing_value = pair((self.g ** t), self.h)
        hash_value = self.hash_pairing(pairing_value)
        d3 = hash_value * (self.h ** r)
        
        # Compute d4 = SK_ID * u^(-r)
        u_inv_r = self.u ** -r
        d4 = user_secret_key * u_inv_r
        
        logger.info(f"Generated authorization token for {len(user_set)} identities")
        return (d1, d2, d3, d4)
    
    def transform_ciphertext(self, 
                           ciphertext: Tuple[GT, G2, G1], 
                           auth_token: Tuple[G1, G2, int, G1]) -> Tuple[G1, G2, int, G1, GT]:
        """
        Transform a ciphertext using an authorization token.
        
        Args:
            ciphertext: Original ciphertext tuple (C0, C1, C2)
            auth_token: Authorization token (d1, d2, d3, d4)
            
        Returns:
            Transformed ciphertext (c1, c2, c3, c4, c5)
        """
        d1, d2, d3, d4 = auth_token
        c0, c1, c2 = ciphertext
        
        c1_new = d1
        c2_new = d2
        c3_new = d3
        c4_new = c2
        
        # Compute c5 = C0 / e(C1, d4)
        pairing_value = pair(c1, d4)
        c5_new = c0 / pairing_value
        
        logger.info("Ciphertext transformed successfully")
        return (c1_new, c2_new, c3_new, c4_new, c5_new)
    
    def compute_alpha_change(self, 
                           target_id: str, 
                           user_set: List[str]) -> ZR:
        """
        Compute the alpha change factor for reencryption.
        
        Args:
            target_id: Target identity for reencryption
            user_set: Set of authorized identities
            
        Returns:
            Alpha change factor as ZR element
        """
        product1 = GROUP.init(ZR, 1)
        product2 = GROUP.init(ZR, 1)
        
        for identity in user_set:
            if identity == target_id:
                continue
            
            h0_id = self.hash_to_zr(identity)
            product1 *= (self.a + h0_id)
            product2 *= h0_id
        
        result = (product1 - product2) / self.a
        return result
    
    def compute_b_value(self, 
                      alpha_change: ZR,
                      secret_key: G1, 
                      target_id: str,
                      user_set: List[str],
                      c1: G1, 
                      c2: G2) -> GT:
        """
        Compute the B value needed for decryption.
        
        Args:
            alpha_change: Alpha change factor
            secret_key: Secret key of the target identity
            target_id: Target identity
            user_set: Set of authorized identities
            c1, c2: Transformed ciphertext components
            
        Returns:
            The B value as a GT element
        """
        h_a = self.h ** alpha_change
        temp1 = pair(c1, h_a)
        temp2 = pair(secret_key, c2)
        temp3 = temp1 * temp2
        
        product = GROUP.init(ZR, 1)
        for identity in user_set:
            if identity == target_id:
                continue
            product *= self.hash_to_zr(identity)
        
        b_value = temp3 ** (1 / product)
        return b_value
    
    def compute_hr(self, c3: int, b_value: GT) -> G2:
        """
        Compute the h^r value from c3 and B.
        
        Args:
            c3: Third component of transformed ciphertext
            b_value: Computed B value
            
        Returns:
            h^r as a G2 element
        """
        temp = self.hash_pairing(b_value)
        h_r = c3 / temp
        return h_r
    
    def decrypt_transformed(self, c5: GT, c4: G1, h_r: G2) -> GT:
        """
        Decrypt a transformed ciphertext.
        
        Args:
            c5: Fifth component of transformed ciphertext
            c4: Fourth component of transformed ciphertext
            h_r: Computed h^r value
            
        Returns:
            The decrypted message as a GT element
        """
        temp = pair(h_r, c4)
        message = c5 / temp
        
        logger.info("Transformed ciphertext decrypted successfully")
        return message
    
    def hash_bilinear_result(self, bilinear_result: List[List[GT]]) -> Dict:
        """
        Hash bilinear mapping results using map-to-point encoding.
        
        Args:
            bilinear_result: Matrix of bilinear mapping results
            
        Returns:
            Dictionary containing point encodings and combined hash
        """
        # Map each element to a point
        point_encodings = []
        for row in bilinear_result:
            encoded_row = []
            for value in row:
                point = self.map_to_point(value)
                encoded_row.append(point)
            point_encodings.append(encoded_row)
        
        # Combine all points into a final hash
        combined_x = 0
        combined_y = 0
        
        # Simple combining function using XOR
        for row in point_encodings:
            for point in row:
                combined_x ^= point['x']
                combined_y ^= point['y']
        
        # Return results
        return {
            'point_encodings': point_encodings,
            'final_point': {'x': combined_x, 'y': combined_y},
            'hex_point': {
                'x': hex(combined_x),
                'y': hex(combined_y)
            }
        }
def save_transformed_ciphertext(transformed_ct, filename="transformed_ciphertext.txt"):
    c1_bytes = GROUP.serialize(transformed_ct[0])
    c2_bytes = GROUP.serialize(transformed_ct[1])
    c3_bytes = GROUP.serialize(transformed_ct[2])
    c4_bytes = GROUP.serialize(transformed_ct[3])
    c5_bytes = GROUP.serialize(transformed_ct[4])

       # Convert binary data to hexadecimal strings
    data = {
        "c1": c1_bytes.hex(),
        "c2": c2_bytes.hex(),
        "c3": c3_bytes.hex(),
        "c4": c4_bytes.hex(),
        "c5": c5_bytes.hex()
    }
    
    # Write to file as JSON
    with open(filename, 'w') as file:
        json.dump(data, file)
    
    print(f"Transformed ciphertext saved to {filename}")


# Function to load transformed ciphertext from a file
def load_transformed_ciphertext(filename="transformed_ciphertext.txt"):
    # Read the JSON data from the file
    with open(filename, 'r') as file:
        data = json.load(file)
    
    # Convert hexadecimal strings back to binary
    c1_bytes = bytes.fromhex(data["c1"])
    c2_bytes = bytes.fromhex(data["c2"])
    c3_bytes = bytes.fromhex(data["c3"])
    c4_bytes = bytes.fromhex(data["c4"])
    c5_bytes = bytes.fromhex(data["c5"])
    
    # Deserialize the binary data back to group elements
    c1 = GROUP.deserialize(c1_bytes)
    c2 = GROUP.deserialize(c2_bytes)
    c3 = GROUP.deserialize(c3_bytes)
    c4 = GROUP.deserialize(c4_bytes)
    c5 = GROUP.deserialize(c5_bytes)
    
    # Return the reconstructed transformed ciphertext
    return (c1, c2, c3, c4, c5)



def encrypt_M(id,users):
    ibe = IBBET()
    message = GROUP.random(GT)
    sk_id = ibe.generate_secret_key(id)
     # Encrypt message for Alice
    ciphertext = ibe.encrypt(message, id)
   # Alice generates an authorization token for the user set
    auth_token = ibe.generate_auth_token(users, sk_id)
   # Transform the ciphertext using the authorization token
    transformed_ct = ibe.transform_ciphertext(ciphertext, auth_token)
    save_transformed_ciphertext(transformed_ct, "transformed_ciphertext.txt")
    return message

def decrypt_M(id,users):
    ibe = IBBET()
    sk_id = ibe.generate_secret_key(id)
    # Load the transformed ciphertext from the file
    loaded_transformed_ct = load_transformed_ciphertext("transformed_ciphertext.txt")
    print("Loaded Transformed Ciphertext from File")

    # Unpack the transformed ciphertext
    c1, c2, c3, c4, c5 = loaded_transformed_ct
    alpha_change = ibe.compute_alpha_change(id, users)
    # print(f"Alpha Change: {alpha_change}")
    
    b_value = ibe.compute_b_value(alpha_change, sk_id, id, users, c1, c2)
    # print(f"B Value: {b_value}")
    
    h_r = ibe.compute_hr(c3, b_value)
    # print(f"h^r: {h_r}")
    
    # Bob decrypts the transformed ciphertext
    recovered_msg = ibe.decrypt_transformed(c5, c4, h_r)
    print(f"Recovered Message: {recovered_msg} /n")

    return recovered_msg

def serial(ct):
    serialized_result = GROUP.serialize(ct)
    hex_result = serialized_result.hex()     # Convert bytes to hex
    return hex_result


def demo():
    """Run a demonstration of the IBE system with map-to-point hashing."""
    # Initialize the IBE system
    ibe = IBBET()
    
    # Define user identities
    user_set = ["user1@example.com", "user2@example.com", "user3@example.com"]
    alice_id = "alice@example.com"
    bob_id = "bob@example.com"
    
    # Generate a random message
    message = GROUP.random(GT)
    print(f"Original Message: {message} /n")
    
    # Generate secret keys
    alice_sk = ibe.generate_secret_key(alice_id)
    bob_sk = ibe.generate_secret_key(bob_id)
    
    # Encrypt message for Alice
    ciphertext = ibe.encrypt(message, alice_id)
    print(f"Ciphertext: {ciphertext} /n")
    
    # Alice decrypts directly
    decrypted_msg = ibe.decrypt(ciphertext, alice_sk)
    # print(f"Decrypted Message: {decrypted_msg}")
    assert message == decrypted_msg, "Direct decryption failed!"
    
    # Alice generates an authorization token for the user set
    auth_token = ibe.generate_auth_token(user_set, alice_sk)
    # print(f"Authorization Token: {auth_token}")
    
    # Transform the ciphertext using the authorization token
    transformed_ct = ibe.transform_ciphertext(ciphertext, auth_token)
    # print(f"Transformed Ciphertext: {transformed_ct}")
    
    # Bob (who is in the user set) wants to decrypt
    alpha_change = ibe.compute_alpha_change(alice_id, user_set)
    # print(f"Alpha Change: {alpha_change}")
    
    # Bob computes the necessary values for decryption
    c1, c2, c3, c4, c5 = transformed_ct
    b_value = ibe.compute_b_value(alpha_change, alice_sk, alice_id, user_set, c1, c2)
    # print(f"B Value: {b_value}")
    
    h_r = ibe.compute_hr(c3, b_value)
    # print(f"h^r: {h_r}")
    
    # Bob decrypts the transformed ciphertext
    recovered_msg = ibe.decrypt_transformed(c5, c4, h_r)
    print(f"Recovered Message: {recovered_msg} /n")
    
    assert message == recovered_msg, "Transformed decryption failed!"
    print("All decryption tests passed successfully!")
    
    # Demonstrate bilinear result hashing
    bilinear_result = [
        [
            message, 
            message * (GROUP.random(GT)), 
            message ** (GROUP.random(ZR))
        ],
        [
            (GROUP.random(GT)) * message, 
            GROUP.random(GT), 
            message ** 2
        ]
    ]
    
    hash_result = ibe.hash_bilinear_result(bilinear_result)
    print("\nMap-to-Point Hash Results:")
    print(f"Final Point: {hash_result['final_point']}")
    print(f"Hex Representation: {hash_result['hex_point']}")


if __name__ == "__main__":
    demo()