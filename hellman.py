import qrcode
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import json
import cv2
import hashlib

# Generate ECC Diffie-Hellman key pair for the bus terminal
bus_terminal_private_key = ec.generate_private_key(ec.SECP256R1())
bus_terminal_public_key = bus_terminal_private_key.public_key()

# Serialize the public key to share with the bus user
bus_terminal_public_key_bytes = bus_terminal_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# In a real system, share the bus_terminal_public_key_bytes with the bus user.

# User receives the bus_terminal_public_key_bytes and generates their own key pair
# User generates ECC Diffie-Hellman key pair
user_private_key = ec.generate_private_key(ec.SECP256R1())
user_public_key = user_private_key.public_key()

# Perform key exchange
shared_secret = user_private_key.exchange(ec.ECDH(), bus_terminal_public_key)

# You can use the shared_secret for encryption or other purposes



# Combine ticket information and shared secret as a dictionary
ticket_info = {
    "person_name": "Praveen",
    "cost": 100,
    "source": "Hirekodi",
    "destination": "Chikodi",
    "shared_secret": shared_secret.hex(),
}

# Serialize the dictionary to JSON
ticket_info_json = json.dumps(ticket_info)

# Create a QR code for the ticket information
qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_L,
    box_size=10,
    border=4,
)
qr.add_data(ticket_info_json)
qr.make(fit=True)

# Create a QR code image
img = qr.make_image(fill_color="black", back_color="white")
img.save("C:/Users/HP/Desktop/bus_ticket_qr.png")

print("QR code generated with ticket information.")

# To decode and extract the information from the scanned QR code:
print("Please scan the QR code with your phone or a QR code scanner.")
input("Press Enter when the QR code is scanned...")
# qr_scanned_data contains the scanned QR code data
# Open a webcam and read the QR code



#Avelanche effect for Diffe hellman
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


hash_result1, hash_result2 = avalanche_effect(ticket_info_json)
print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")

print(f"Input 1: {ticket_info_json}\n \nHash 1: {hash_result1} \n")

print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n")

print(f"\nInput 2: {ticket_info_json}\n\nHash 2: {hash_result2} \n")

print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")






























