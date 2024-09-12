#!/usr/bin/python
import sys, os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

def read_public_key(path = './'):
    with open(path, 'rb') as public_key_file:
        public_key = serialization.load_pem_public_key(public_key_file.read())

    return public_key

def encrypt_file(public_key):
    algorithm = hashes.SHA256()
    padding_type = padding.MGF1(algorithm)

    with open(sys.argv[1], 'rb') as file:
        file_data = file.read()

    encrypted_data = public_key.encrypt(
        file_data,
        padding.OAEP(
            mgf = padding_type,
            algorithm = algorithm,
            label = None
        )
    )

    encrypted_file_name = sys.argv[1] + '.encrypted'
    file_name = encrypted_file_name.rsplit('/', 1)[-1]

    with open(encrypted_file_name, 'wb') as file:
        file.write(encrypted_data)
        print(f'Encrypted file: {file_name}' )

def main():
    if (len(sys.argv)) != 2:
        print('File name for encryption not provided.')
        exit(-1)

    default_public_path = './public.pem'
    public_key_path = sys.argv[2] if len(sys.argv) == 3 else default_public_path 
    
    if len(sys.argv) != 3:
        print(f'No key path provided, using default path: {default_public_path}')

    with open(sys.argv[1], 'rb') as file:
        file_data = file.read()

    public_key = read_public_key(public_key_path)
    encrypt_file(public_key)

if __name__ == '__main__':
    main()
