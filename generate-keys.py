from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_private_key(path_to_save):
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 4096
    )

    private_pem = private_key.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm = serialization.NoEncryption()
    )

    filename = 'private.pem'
    path = path_to_save + filename

    with open(path, 'wb') as private_pem_file:
        private_pem_file.write(private_pem)
        print(f'Private key generated at {path}.')

    return private_key

def generate_public_key(private_key, path_to_save):
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    )

    filename = 'public.pem'
    path = path_to_save + filename

    with open(path, 'wb') as public_pem_file:
        public_pem_file.write(public_pem)
        print(f'Public key generated at {path}.')

    return public_pem

def generate_keys(private_path = './', public_path = './'):
    private_key = generate_private_key(private_path)
    public_key = generate_public_key(private_key, public_path)

generate_keys()
