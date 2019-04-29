import base64,os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.fernet import Fernet

class becrypted:
    def GenerateAssymetricKey(path: 'for storing generated files') -> '2 files: public_key.pem private_key.pem':
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        try:
            with open('{}/private_key.pem'.format(path), 'wb') as f:
                    f.write(pem)
        except:
            print ("ERROR WRITING PRIVATE KEY: path must be the path of directory you want to create public and private key there.(without '/' at the end)")
            return False
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        try:
            with open('{}/public_key.pem'.format(path), 'wb') as f:
                    f.write(pem)
        except:
            print ("ERROR WRITING PUBLIC KEY: path must be the path of directory you want to create public and private key there.(without '/' at the end)")
            return False
        print ("Successfully created public and private keys in path '{}'".format(path))

    def GenerateSymmetricKey(path_to_store: 'for storing generated file',password) -> '1 file: SymmetricKey.key':
        password_provided = password
        password = password_provided.encode()
        salt = '{}'.format(os.urandom(16))
        salt = salt.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        file = open('SymmetricKey.key', 'wb')
        file.write(key)
        file.close()
    def EncryptTextSymmetric(path_to_key,message: 'your desired message to encrypt') -> string :
        message = message.encode()
        with open(path_to_key,'rb') as f:
            key = f.read()
        f = Fernet(key)
        encrypted = f.encrypt(message)
        return encrypted.decode()

    def EncryptFileSymmetric(path_to_key,path_to_input,path_to_output) -> '1 file: encrypted file':
        with open(path_to_input,'rb') as f:
            message = f.read()
        with open(path_to_key,'rb') as f:
            key = f.read()
        f = Fernet(key)
        encrypted = f.encrypt(message)
        with open(path_to_output,'wb') as f:
            f.write(encrypted)
        return True

    def DecryptTextSymmetric(path_to_key,text: 'encrypted text') -> string:
        text = text.encode()
        with open(path_to_key,'rb') as f:
            key = f.read()
        f = Fernet(key)
        decrypted = f.decrypt(text)
        return decrypted.decode()

    def DecryptFileSymmetric(path_to_key,path_to_input,path_to_output) -> '1 file: decrypted file':
        with open(path_to_input,'rb') as f:
            text = f.read()
        with open(path_to_key,'rb') as f:
            key = f.read()
        f = Fernet(key)
        decrypted = f.decrypt(text)
        with open(path_to_output,'w') as f:
            f.write(decrypted.decode())

    def EncryptTextAsymmetric(message,path_to_public,path_to_output) -> '1 file: encrypted text in file':
        message = message.encode()
        with open(path_to_public, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        encrypted = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        with open(path_to_output,'wb') as f:
            f.write(encrypted)


    def EncryptFileAsymmetric(path_to_input,path_to_public,path_to_output) -> '1 file: encrypted file':
        with open(path_to_input,'rb') as f:
            message = f.read()
        with open(path_to_public, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        encrypted = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        with open(path_to_output,'wb') as f:
            f.write(encrypted)


    def DecryptTextAsymmetric(path_to_encrypted,path_to_private) -> 'decrypted text as string':
        with open(path_to_private, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        with open(path_to_encrypted,'rb') as f:
            encrypted = f.read()

        original_message = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return original_message.decode()


    def DecryptFileAsymmetric(path_to_encrypted,path_to_private,path_to_output) -> '1 file: decrypted file':
        with open(path_to_private, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        with open(path_to_encrypted,'rb') as f:
            encrypted = f.read()

        original_message = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        with open(path_to_output,'w') as f:
            f.write(original_message.decode())
