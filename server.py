#!/usr/bin/env python3

import base64
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, jsonify, request

app = Flask(__name__)

PLAINTEXT = b"I'd just like to interject for a moment. What you're referring to as Linux, is in fact, GNU/Linux, or as I've recently taken to calling it, GNU plus Linux."  # noqa
KEY = b"STICKBUGSTICKBUG"


@app.route("/", methods=["GET"])
def index():
    return "Hello from the server!"


@app.route("/ciphertext", methods=["GET"])
def get_ciphertext():
    # Set up the encryptor
    iv = os.urandom(16)
    mode = modes.CBC(iv)
    algorithm = algorithms.AES(KEY)
    encryptor = Cipher(algorithm, mode).encryptor()

    # Pad the plaintext
    padder = padding.PKCS7(16 * 8).padder()
    padded_data = padder.update(PLAINTEXT)
    padded_data += padder.finalize()

    # Encrypt the plaintext
    ciphertext = encryptor.update(padded_data)

    # Base64 encode the ciphertext and IV and return them
    return jsonify(
        {
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "iv": base64.b64encode(iv).decode("utf-8"),
        }
    )


@app.route("/validate", methods=["GET"])
def validate_ciphertext():
    # Validate the request
    if "ciphertext" not in request.args or "iv" not in request.args:
        return "Invalid request", 400

    # Unpack the request
    ciphertext = base64.b64decode(request.args["ciphertext"])
    iv = base64.b64decode(request.args["iv"])

    # Set up the decryptor
    mode = modes.CBC(iv)
    algorithm = algorithms.AES(KEY)
    decryptor = Cipher(algorithm, mode).decryptor()

    # Decrypt the ciphertext
    padded_data = decryptor.update(ciphertext)

    # Unpad the plaintext
    padder = padding.PKCS7(16 * 8).unpadder()
    plaintext = padder.update(padded_data)
    try:
        plaintext += padder.update(padded_data)
    except ValueError:
        return "bad padding!", 500

    return "ok padding"


if __name__ == "__main__":
    app.run()
