#!/usr/bin/env python3

import base64
import multiprocessing

import requests


def chunks(data, size):
    for i in range(0, len(data), size):
        yield data[i : i + size]


def validate_padding(input_block, xor_block):
    # Encode the blocks to base64
    ciphertext = base64.b64encode(bytes(input_block))
    iv = base64.b64encode(bytes(xor_block))

    # Request validation from server
    resp = requests.get(
        "http://localhost:5000/validate",
        params={
            "ciphertext": ciphertext,
            "iv": iv,
        },
    )

    return resp.ok


def find_istate_value(input_block, xor_block, padding_val):
    # Re-derive the byte index
    byte_index = len(input_block) - padding_val

    # plaintext = istate ^ xor
    # istate = plaintext ^ xor
    # plaintext = padding_val
    for xor_val in range(0, 2 ** 8):
        xor_block[byte_index] = xor_val
        if validate_padding(input_block, xor_block):
            # We found the istate value!
            return padding_val ^ xor_val

    # We failed to find the istate value :(
    return None


def decrypt_block(block_data):
    input_block = block_data["input_block"]
    xor_block = block_data["xor_block"]

    # Copy the xor block so we can modify it
    working_xor = [x for x in xor_block]

    # Store the intermediate state as we discover it
    istate = [None] * len(input_block)

    # Iterate through the block backwords, one byte at a time
    for padding_val in range(1, len(input_block) + 1):
        # Set up the xor block so we can check the right kind of padding
        for i in range(1, padding_val):
            working_xor[-i] = padding_val ^ istate[-i]

        # Find the index of the byte within the input block we'll decrypt
        byte_index = len(input_block) - padding_val

        istate_value = find_istate_value(input_block, working_xor, padding_val)
        if istate_value is not None:
            istate[byte_index] = istate_value
        else:
            return

    # Determine plaintext
    plaintext = []
    for idx, val in enumerate(istate):
        plaintext.append(val ^ xor_block[idx])

    return bytes(plaintext)


def main():
    # Get the ciphertext and IV
    resp = requests.get("http://localhost:5000/ciphertext")
    ciphertext = base64.b64decode(resp.json()["ciphertext"])
    iv = base64.b64decode(resp.json()["iv"])

    # Split up ciphertext into blocks. For each block, we want to store the block that
    # is provided as an input to the block cipher (this is the "input block"), and we
    # also want to store the block that is XORed with the intermediate state (this is
    # the "xor block").
    blocks = []
    block_size = 16
    for i in range(0, len(ciphertext), block_size):
        block = {"input_block": ciphertext[i : i + block_size], "index": len(blocks)}

        # For the first block, the xor block is the overall IV. For all other blocks,
        # the xor block is the previous ciphertext block.
        if i == 0:
            block["xor_block"] = iv
        else:
            block["xor_block"] = ciphertext[i - block_size : i]

        blocks.append(block)

    with multiprocessing.Pool(processes=6) as pool:
        results = pool.map(decrypt_block, blocks)

    try:
        plaintext = b"".join(results)
        print(f"Decrypted the plaintext!\n{plaintext}")
    except TypeError:
        partial_plaintext = b"".join([x for x in results if x is not None])
        print(
            "Failed to decrypt the entire plaintext.\n"
            f"Partial plaintext is:\n{partial_plaintext}"
        )


if __name__ == "__main__":
    main()
