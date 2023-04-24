from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import os


app = Flask(__name__)

def encrypt_aes(text, password):
    backend = default_backend()
    salt = os.urandom(16)  # Generate a random 16-byte salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(salt), backend=backend)
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return b64encode(salt + ciphertext).decode('utf-8')


def decrypt_aes(encrypted_text, password):
    backend = default_backend()
    decoded_data = b64decode(encrypted_text.encode())
    salt = decoded_data[:16]  # Extract the salt from the data
    ciphertext = decoded_data[16:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(salt), backend=backend)
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data.decode('utf-8')


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt_decrypt', methods=['POST'])
def encrypt_decrypt():
    action = request.form.get('action')
    text = request.form.get('text')
    password = request.form.get('password')

    if action == 'encrypt':
        result = encrypt_aes(text, password)
    elif action == 'decrypt':
        result = decrypt_aes(text, password)
    else:
        result = 'Invalid input'

    print("Result:", result)
    return jsonify({'result': result})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1312)

