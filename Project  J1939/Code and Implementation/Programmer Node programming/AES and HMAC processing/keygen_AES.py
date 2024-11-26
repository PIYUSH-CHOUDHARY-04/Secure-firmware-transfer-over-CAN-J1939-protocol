# following code generates the random IV and key size for AES algorithms
# IV size is fixed to 16 bytes whereas key size can be 16/24/32 bytes depending upon user input.

import os
key_size=int(input("Key_size : "))

if key_size!=16 and key_size!=24 and key_size!=32 :
	os.exit()

def generate_key_iv(key_size, iv_size=16):
    """
    Generate a cryptographic key and initialization vector (IV).

    Args:
        key_size (int): Size of the key in bytes. Default is 32 bytes (AES-256).
        iv_size (int): Size of the IV in bytes. Default is 16 bytes (AES block size).

    Returns:
        tuple: A tuple containing the key and IV in hexadecimal format.
    """
    # Generate a random cryptographic key
    key = os.urandom(key_size)
    # Generate a random initialization vector (IV)
    iv = os.urandom(iv_size)
     # Format as 0x... strings for each byte
    key_formatted = [f"0x{byte:02x}" for byte in key]
    iv_formatted = [f"0x{byte:02x}" for byte in iv]
    return key_formatted, iv_formatted

    

# Generate a 256-bit (32-byte) key and 128-bit (16-byte) IV
key, iv = generate_key_iv(key_size)

# Display the results
if key_size==16 :
	print(f"Random Cryptographic Key (AES128): {key}")
elif key_size==24 :
	print(f"Random Cryptographic Key (AES192): {key}")
elif key_size==32 :
	print(f"Random Cryptographic Key (AES256): {key}")
print(f"Initialization Vector (IV): {iv}")
