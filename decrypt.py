#!/usr/bin/python
import sys, os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

def read_private_key(path):
    with open(path, 'rb') as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password = None
        )

    return private_key

def decrypt_file(private_key):
    algorithm = hashes.SHA256()
    padding_type = padding.MGF1(algorithm)

    with open(sys.argv[1], 'rb') as file:
        encrypted_data = file.read()

    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf = padding_type,
            algorithm = algorithm,
            label = None
        )
    )

    decrypted_file_name = sys.argv[1] + '.decrypted'
    file_name = decrypted_file_name.rsplit('/', 1)[-1]

    with open(decrypted_file_name, 'wb') as file:
        file.write(decrypted_data)
        print(f'Decrypted file stored as: {decrypted_file_name}')

def main():
    if (len(sys.argv)) != 2:
        print('File name for decryption not provided.')
        exit(-1)

    default_private_path = './private.pem'
    private_key_path = sys.argv[2] if len(sys.argv) == 3 else default_private_path 
    
    if len(sys.argv) != 3:
        print(f'No key path provided, using default path: {default_private_path}')

    with open(sys.argv[1], 'rb') as file:
        file_data = file.read()

    private_key = read_private_key(private_key_path)
    decrypt_file(private_key)

if __name__ == '__main__':
    main()
