from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from io import BytesIO

import base64
import zlib

# generate a new RSA key pair, export the private and public keys, and save them to files
def generate():

    new_key = RSA.generate(2048)
    private_key = new_key.exportKey()
    public_key = new_key.publickey().exportKey()
    
    with open('key.pri', 'wb') as f:
        f.write(private_key)

    with open('key.pub', 'wb') as f:
        f.write(public_key)

# keytype: 'pri' or 'pub'
def get_rsa_cipher(keytype):
    with open(f'key.{keytype}') as f:
        key = f.read()
    rsakey = RSA.importKey(key)
    return (PKCS1_OAEP.new(rsakey), rsakey.size_in_bytes())

def encrypt(plaintext):
    # plaintext bytes compressed
    compressed_text = zlib.compress(plaintext)

    # generate session key used to encrypt compressed plaintext
    session_key = get_random_bytes(16)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(compressed_text)

    cipher_rsa, _ = get_rsa_cipher('pub')

    # encrypt session key with RSA public key
    encrypted_session_key = cipher_rsa.encrypt(session_key)

    # concatenate encrypted session key, AES nonce, tag, and ciphertext, then encode the result with base64 for transmission
    msg_payload = encrypted_session_key + cipher_aes.nonce + tag + ciphertext
    encrypted = base64.encodebytes(msg_payload)
    return encrypted

def decrypt(encrypted):
    # base64 decode the encrypted message
    encrypted_bytes = BytesIO(base64.decodebytes(encrypted))
    cipher_rsa, keysize_in_bytes = get_rsa_cipher('pri')

    # read the encrypted session key, nonce, tag, and ciphertext from the decoded message
    encrypted_session_key = encrypted_bytes.read(keysize_in_bytes)
    nonce = encrypted_bytes.read(16)
    tag = encrypted_bytes.read(16)
    ciphertext = encrypted_bytes.read()

    # decrypt session key with RSA private key
    session_key = cipher_rsa.decrypt(encrypted_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    
    #decrypt ciphertext with the decrypted session key
    decypted = cipher_aes.decrypt_and_verify(ciphertext, tag)

    # decompress to plaintext bytes
    plaintext = zlib.decompress(decypted)
    return plaintext

if __name__ == '__main__':
    # generate RSA key pair and save to files, only needs to be run once
    # generate()
    plaintext = b'Hello, world! This is a secret message.'
    print(decrypt(encrypt(plaintext)))


