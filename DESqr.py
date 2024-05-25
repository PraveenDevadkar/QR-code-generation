import qrcode
from pyDes import des, PAD_PKCS5
from PIL import Image
import hashlib
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import os
import time

# Ticket information
ticket_data = {
    "ticket_id": "12345",
    "passenger_name": "John Doe",
    "departure": "City A",
    "destination": "City B",
    "departure_date": "2023-12-01",
    "ticket_price": "$20.00",
    "seat_number": "A12",
}

# Convert ticket data to a formatted string
ticket_info = "\n".join([f"{key}: {value}" for key, value in ticket_data.items()])

# DES encryption
key = "DESCrypt"  # 8-byte key (64 bits)

start_time = time.time()

ticket_info = ticket_info.encode('utf-8')
k = des(key, PAD_PKCS5)
encrypted_ticket_info = k.encrypt(ticket_info)


end_time = time.time()

# Generate a QR code with the encrypted ticket information
qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_L,
    box_size=10,
    border=4,
)
qr.add_data(encrypted_ticket_info)
qr.make(fit=True)

img = qr.make_image(fill_color="black", back_color="white")

# Save the QR code to an image file
img.save("C:/Users/HP/Desktop/bus_ticket_qr_DES.png")



#Avelanche effect for DES
ticket_info_str = str(ticket_info)

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


hash_result1, hash_result2 = avalanche_effect(ticket_info_str)

print("----------------------------------------------------------------------------------------------------------------------------------------------------------------------")
print("----------------------------------------------------------------------------------------------------------------------------------------------------------------------")

print(f"Input 1: {ticket_info} \n\nHash 1: {hash_result1}")
print("----------------------------------------------------------------------------------------------------------------------------------------------------------------------")
print("----------------------------------------------------------------------------------------------------------------------------------------------------------------------")

print(f"\nInput 2: {ticket_info}\n\nHash 2: {hash_result2}")

print("----------------------------------------------------------------------------------------------------------------------------------------------------------------------")
print("----------------------------------------------------------------------------------------------------------------------------------------------------------------------")


# Decrypt using the same key
decrypted_ticket_info = k.decrypt(encrypted_ticket_info).decode('utf-8')

# Check if the decryption is successful
print(f"Original Ticket Info:\n{ticket_info.decode('utf-8')}")
print(f"\nDecrypted Ticket Info:\n{decrypted_ticket_info}")

print("----------------------------------------------------------------------------------------------------------------------------------------------------------------------")
print("----------------------------------------------------------------------------------------------------------------------------------------------------------------------")




def pad_data(data):
    # Pad the data to be a multiple of 8 bytes
    pad_length = 8 - (len(data) % 8)
    return data + bytes([pad_length] * pad_length)

def encrypt_des(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)

def encrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as file:
        plaintext = file.read()

    plaintext = pad_data(plaintext)
    ciphertext = encrypt_des(plaintext, key)

    with open(output_file, 'wb') as file:
        file.write(ciphertext)

def decrypt_des(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.decrypt(data)

def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as file:
        ciphertext = file.read()

    decrypted_data = decrypt_des(ciphertext, key)

    # Remove padding
    pad_length = decrypted_data[-1]
    decrypted_data = decrypted_data[:-pad_length]

    with open(output_file, 'wb') as file:
        file.write(decrypted_data)

def generate_key():
    return get_random_bytes(8)

# Example usage:
if __name__ == "__main__":
    input_image_file = 'C:/Users/HP/Desktop/ML/APJ.jpg'
    encrypted_image_file = 'C:/Users/HP/Desktop/IS/encrypted_image_des.des'
    decrypted_image_file = 'C:/Users/HP/Desktop/IS/decrypted_image_des.jpg'

    input_audio_file = 'C:/Users/HP/Downloads/piano.wav'
    encrypted_audio_file = 'C:/Users/HP/Desktop/IS/encrypted_audio_des.des'
    decrypted_audio_file = 'C:/Users/HP/Desktop/IS/decrypted_audio_des.wav'

    key = generate_key()

    # Image encryption
    encrypt_file(input_image_file, encrypted_image_file, key)
    decrypt_file(encrypted_image_file, decrypted_image_file, key)

    # Audio encryption
    encrypt_file(input_audio_file, encrypted_audio_file, key)
    decrypt_file(encrypted_audio_file, decrypted_audio_file, key)



#Time taken for encryption
encryption_time = end_time - start_time


# Calculate the space consumed by the ciphertext
ciphertext_size_bytes = len(encrypted_ticket_info)
ciphertext_size_kilobytes = ciphertext_size_bytes / 1024.0

#print(f"")
print(f"Ciphertext Size: {ciphertext_size_bytes} bytes ({ciphertext_size_kilobytes:.2f} KB)")
print(f"Encryption Time: {encryption_time} seconds")