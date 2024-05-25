from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import qrcode
from io import BytesIO
import hashlib
import os
import time

# Define bus ticket details (replace with actual details)
ticket_details = {
    "ticket_id": "123456",
    "passenger_name": "Varun Jakanur",
    "departure_city": "Hubli",
    "arrival_city": "Dharwad",
    "departure_time": "2023-10-09 10:00 AM",
}

# Convert ticket details to a JSON string
import json
ticket_json = json.dumps(ticket_details)


# Generate a random AES key
key = get_random_bytes(16)  # 128-bit key


start_time = time.time()

# Initialize AES cipher
cipher = AES.new(key, AES.MODE_EAX)

# Encrypt the ticket JSON
cipher_text, tag = cipher.encrypt_and_digest(ticket_json.encode())

# Encode the encrypted data and tag as base64
encoded_cipher_text = base64.b64encode(cipher_text).decode()
encoded_tag = base64.b64encode(tag).decode()

# Combine the encrypted data and tag into a single string
qr_data = f"{encoded_cipher_text}:{encoded_tag}"

end_time = time.time()


# Create a QR code instance
qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_L,
    box_size=10,
    border=4,
)

# Add data to the QR code
qr.add_data(qr_data)

# Make the QR code
qr.make(fit=True)

# Create an image from the QR code
img = qr.make_image(fill_color="black", back_color="white")

# Save the QR code image to a file
img.save("C:/Users/HP/Desktop/bus_ticket_qr_AES.png")

# Save the encrypted ticket details to a file (for later decryption)
with open("encrypted_ticket.bin", "wb") as file:
    file.write(cipher_text)

# Save the AES key securely (for decryption)
# In a real scenario, you should securely store the key, possibly using a key management system.
with open("aes_key.bin", "wb") as key_file:
    key_file.write(key)


#Avelanche effect for AES
def avalanche_effect(input_data):
    # Use a hash function (e.g., SHA-256)
    #hash_object = hashlib.sha256()
    hash_object1 = hashlib.md5()
    hash_object2 = hashlib.md5()

    # Update the hash object with the input data
    hash_object1.update(input_data[0].encode('utf-8'))
    hash_object2.update(input_data[1].encode('utf-8'))

    # Get the hexadecimal representation of the hash
    hash1 = hash_object1.hexdigest()
    hash2 = hash_object2.hexdigest()

    return hash1 , hash2


hash_result1, hash_result2 = avalanche_effect(ticket_json)
print("=====================================================================================================================================================================")
print("=====================================================================================================================================================================")
print(f"Input 1: {ticket_json}\n \n Hash 1: {hash_result1}")
print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
print(f"\nInput 2: {ticket_json}\n \nHash 2: {hash_result2}")

print("=====================================================================================================================================================================")
print("=====================================================================================================================================================================")




# To decrypt, you would need the key and the tag
decipher = AES.new(key, AES.MODE_EAX, nonce=cipher.nonce)
decrypted_data = decipher.decrypt_and_verify(cipher_text, tag)

print("\n Decrypted Data:", decrypted_data.decode('utf-8'))

print("=====================================================================================================================================================================")
print("=====================================================================================================================================================================")




def pad_data(data):
    # Pad the data to be a multiple of 16 bytes (AES block size)
    pad_length = 16 - (len(data) % 16)
    return data + bytes([pad_length] * pad_length)

def encrypt_aes(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

def encrypt_file_aes(input_file, output_file, key):
    with open(input_file, 'rb') as file:
        plaintext = file.read()

    plaintext = pad_data(plaintext)
    ciphertext = encrypt_aes(plaintext, key)

    with open(output_file, 'wb') as file:
        file.write(ciphertext)

def decrypt_aes(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)

def decrypt_file_aes(input_file, output_file, key):
    with open(input_file, 'rb') as file:
        ciphertext = file.read()

    decrypted_data = decrypt_aes(ciphertext, key)

    # Remove padding
    pad_length = decrypted_data[-1]
    decrypted_data = decrypted_data[:-pad_length]

    with open(output_file, 'wb') as file:
        file.write(decrypted_data)

def generate_aes_key():
    return get_random_bytes(16)  # AES-128 key size is 16 bytes

# Example usage:
if __name__ == "__main__":
    input_image_file = 'C:/Users/HP/Desktop/ML/APJ.jpg'
    encrypted_image_file = 'C:/Users/HP/Desktop/IS/encrypted_image_aes.aes'
    decrypted_image_file = 'C:/Users/HP/Desktop/IS/decrypted_image_aes.jpg'

    input_audio_file = 'C:/Users/HP/Downloads/piano.wav'
    encrypted_audio_file = 'C:/Users/HP/Desktop/IS/encrypted_audio_aes.aes'
    decrypted_audio_file = 'C:/Users/HP/Desktop/IS/decrypted_audio_aes.wav'

    aes_key = generate_aes_key()

    # Image encryption
    encrypt_file_aes(input_image_file, encrypted_image_file, aes_key)
    decrypt_file_aes(encrypted_image_file, decrypted_image_file, aes_key)

    # Audio encryption
    encrypt_file_aes(input_audio_file, encrypted_audio_file, aes_key)
    decrypt_file_aes(encrypted_audio_file, decrypted_audio_file, aes_key)



#Time taken for encryption
encryption_time = end_time - start_time

# Calculate the space consumed by the ciphertext
ciphertext_size_bytes = len(qr_data)
ciphertext_size_kilobytes = ciphertext_size_bytes / 1024.0

print(f"Ciphertext Size: {ciphertext_size_bytes} bytes ({ciphertext_size_kilobytes:.2f} KB)")
print(f"Encryption Time: {encryption_time} seconds")