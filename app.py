from flask import Flask, request, jsonify, send_file
from flask_cors import CORS  # Import CORS
from PIL import Image
import numpy as np
import io
import os

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes


def text_to_binary(text):
    """Convert text to binary string."""
    return ''.join(format(ord(char), '08b') for char in text)


def binary_to_text(binary_string):
    """Convert binary string to text."""
    chars = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    text = ''.join(chr(int(char, 2)) for char in chars)
    return text


def encode_image(image, text, key):
    """Encode text with a secret key into an image using basic LSB steganography."""
    binary_text = text_to_binary(text) + '1111111111111110'  # End delimiter
    pixels = np.array(image.convert('RGB'))
    pixels_flat = pixels.flatten()
    key_offset = sum(ord(char) for char in key) % 256
    text_index = 0

    for i in range(len(pixels_flat)):
        if text_index < len(binary_text):
            pixel = pixels_flat[i]
            new_pixel = pixel & ~1 | int(
                binary_text[text_index]) ^ (key_offset & 1)
            pixels_flat[i] = new_pixel
            text_index += 1
            key_offset >>= 1
        else:
            break

    encoded_pixels = pixels_flat.reshape(pixels.shape)
    encoded_image = Image.fromarray(encoded_pixels.astype('uint8'), 'RGB')
    return encoded_image


def decode_image(encoded_image, key):
    """Decode text from an image encoded with a secret key using basic LSB steganography."""
    pixels = np.array(encoded_image.convert('RGB'))
    pixels_flat = pixels.flatten()
    key_offset = sum(ord(char) for char in key) % 256
    binary_text = ''

    for pixel in pixels_flat:
        extracted_bit = (pixel & 1) ^ (key_offset & 1)
        binary_text += str(extracted_bit)
        key_offset >>= 1
        if binary_text.endswith('1111111111111110'):
            binary_text = binary_text[:-16]
            break

    return binary_to_text(binary_text)


@app.route('/encode', methods=['POST'])
def encode():
    try:
        image_file = request.files['image']
        text = request.form['text']
        key = request.form['key']

        image = Image.open(image_file.stream)
        encoded_image = encode_image(image, text, key)

        output = io.BytesIO()
        encoded_image.save(output, format="PNG")
        output.seek(0)

        return send_file(output, mimetype='image/png', as_attachment=True, download_name="encoded_image.png")
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/decode', methods=['POST'])
def decode():
    try:
        image_file = request.files['image']
        key = request.form['key']

        encoded_image = Image.open(image_file.stream)
        hidden_message = decode_image(encoded_image, key)

        return jsonify({"hidden_message": hidden_message})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
