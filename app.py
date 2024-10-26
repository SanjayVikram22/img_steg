from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from PIL import Image
import numpy as np
import io
import os
import random
from cryptography.fernet import Fernet

app = Flask(__name__)
CORS(app)

def simulate_bb84_protocol():
    """Simulate the BB84 protocol to generate a shared secret key."""
    key_length = 16  # Define the desired key length for simplicity
    alice_bits = [random.choice([0, 1]) for _ in range(key_length)]
    alice_bases = [random.choice(['+', 'x']) for _ in range(key_length)]

    # Simulating Bob's random measurements
    bob_bases = [random.choice(['+', 'x']) for _ in range(key_length)]
    bob_measurements = [alice_bits[i] if alice_bases[i] == bob_bases[i] else random.choice([0, 1]) for i in range(key_length)]

    # Alice and Bob discard bits where their bases differ
    shared_key_bits = [alice_bits[i] for i in range(key_length) if alice_bases[i] == bob_bases[i]]
    shared_key_str = ''.join(map(str, shared_key_bits))
    
    # Convert the binary string to a symmetric key usable with Fernet
    shared_key = Fernet.generate_key()[:len(shared_key_str)]  # Adjust length to match Fernet key requirements
    return shared_key

def encrypt_message(message, key):
    """Encrypt the message using a BB84-simulated key with Fernet symmetric encryption."""
    fernet = Fernet(key)
    return fernet.encrypt(message.encode())

def decrypt_message(encrypted_message, key):
    """Decrypt the message using the BB84-simulated key."""
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()

def text_to_binary(data):
    """Convert bytes data to binary string."""
    return ''.join(format(byte, '08b') for byte in data)

def binary_to_text(binary_string):
    """Convert binary string to bytes data and decode to text."""
    chars = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    return bytes(int(char, 2) for char in chars)

def encode_image(image, binary_data):
    """Encode binary data into an image using LSB steganography."""
    pixels = np.array(image.convert('RGB'))
    pixels_flat = pixels.flatten()
    text_index = 0

    for i in range(len(pixels_flat)):
        if text_index < len(binary_data):
            pixel = pixels_flat[i]
            new_pixel = pixel & ~1 | int(binary_data[text_index])
            pixels_flat[i] = new_pixel
            text_index += 1
        else:
            break

    encoded_pixels = pixels_flat.reshape(pixels.shape)
    return Image.fromarray(encoded_pixels.astype('uint8'), 'RGB')

def decode_image(encoded_image):
    """Decode binary data from an image using LSB steganography."""
    pixels = np.array(encoded_image.convert('RGB'))
    pixels_flat = pixels.flatten()
    binary_data = ''.join(str(pixel & 1) for pixel in pixels_flat)
    
    # Stop at the end delimiter (used here as '1111111111111110')
    delimiter = '1111111111111110'
    if delimiter in binary_data:
        binary_data = binary_data[:binary_data.index(delimiter)]
    return binary_data

@app.route('/encode', methods=['POST'])
def encode():
    try:
        # Step 1: Get image and text inputs
        image_file = request.files['image']
        text = request.form['text']
        bb84_key = simulate_bb84_protocol()  # Simulate BB84 to generate a shared symmetric key

        # Step 2: Encrypt the message using the BB84-simulated key
        encrypted_message = encrypt_message(text, bb84_key)
        binary_data = text_to_binary(encrypted_message) + '1111111111111110'  # Add end delimiter

        # Step 3: Encode the binary data into the image
        image = Image.open(image_file.stream)
        encoded_image = encode_image(image, binary_data)

        # Prepare the image output as a downloadable file
        output = io.BytesIO()
        encoded_image.save(output, format="PNG")
        output.seek(0)

        return send_file(output, mimetype='image/png', as_attachment=True, download_name="encoded_image.png")

    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/decode', methods=['POST'])
def decode():
    try:
        # Step 1: Get image and the BB84-derived key from the request
        image_file = request.files['image']
        bb84_key = request.form['key']

        # Step 2: Decode binary data from the image
        encoded_image = Image.open(image_file.stream)
        binary_data = decode_image(encoded_image)
        encrypted_message = binary_to_text(binary_data)

        # Step 3: Decrypt the encrypted message using the BB84-simulated key
        hidden_message = decrypt_message(encrypted_message, bb84_key)

        return jsonify({"hidden_message": hidden_message})

    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
    # app.run(debug=True)
