import string
import random


def generate_random_key(size):
    """Generates a random encryption key of the specified size."""
    return bytes([random.randint(0, 255) for _ in range(size)])

def main():
    # Generate the random key
    AES_KEY = generate_random_key(32)
    IV = generate_random_key(16)
    hmac_key_size=random.randint(15,50)
    HMAC_KEY = generate_random_key(hmac_key_size)

    # Write the key to the specified file
    with open("AES256CBC_KEY.bin", "wb") as file:
            file.write(AES_KEY)
    with open("IV.bin", "wb") as file:
            file.write(IV)
    with open("HMAC_KEY.bin","wb") as file:
            file.write(HMAC_KEY)

if __name__ == "__main__":
    main()

