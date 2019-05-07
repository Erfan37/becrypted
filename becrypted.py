import base64,os,sys
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.fernet import Fernet

class becrypted:
    def __init__(self):
        pass
    def GenerateAsymmetricKey(self,path: 'for storing generated files') -> '2 files: public_key.pem private_key.pem':
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

    def GenerateSymmetricKey(self,path_to_store: 'for storing generated file',password) -> '1 file: SymmetricKey.key':
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
    def EncryptTextSymmetric(self,path_to_key,message: 'your desired message to encrypt') -> 'encrypted text as string' :
        message = message.encode()
        with open(path_to_key,'rb') as f:
            key = f.read()
        f = Fernet(key)
        encrypted = f.encrypt(message)
        return encrypted.decode()

    def EncryptFileSymmetric(self,path_to_key,path_to_input,path_to_output) -> '1 file: encrypted file':
        with open(path_to_input,'rb') as f:
            message = f.read()
        with open(path_to_key,'rb') as f:
            key = f.read()
        f = Fernet(key)
        encrypted = f.encrypt(message)
        with open(path_to_output,'wb') as f:
            f.write(encrypted)
        return True

    def DecryptTextSymmetric(self,path_to_key,text: 'encrypted text') -> 'encrypted text as string':
        text = text.encode()
        with open(path_to_key,'rb') as f:
            key = f.read()
        f = Fernet(key)
        decrypted = f.decrypt(text)
        return decrypted.decode()

    def DecryptFileSymmetric(self,path_to_key,path_to_input,path_to_output) -> '1 file: decrypted file':
        with open(path_to_input,'rb') as f:
            text = f.read()
        with open(path_to_key,'rb') as f:
            key = f.read()
        f = Fernet(key)
        decrypted = f.decrypt(text)
        try:
            with open(path_to_output,'w') as f:
                f.write(decrypted.decode())
        except:
            with open(path_to_output,'wb') as f:
                f.write(decrypted)

    def EncryptTextAsymmetric(self,message,path_to_public,path_to_output) -> '1 file: encrypted text in file':
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


    def EncryptFileAsymmetric(self,path_to_input,path_to_public,path_to_output) -> '1 file: encrypted file':

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


    def DecryptTextAsymmetric(self,path_to_encrypted,path_to_private) -> 'decrypted text as string':
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


    def DecryptFileAsymmetric(self,path_to_encrypted,path_to_private,path_to_output) -> '1 file: decrypted file':
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
        with open(path_to_output,'wb') as f:
            f.write(original_message)

    def EncryptHybrid(self,file_in: 'path to input',pub: 'path to public key',sym: 'path to symmetric key',file_out: 'path to output') -> '1 file: encrypted file':
        self.EncryptFileSymmetric(sym,file_in,'./.output.sym')
        y = 1
        with open("./.output.sym", "rb") as f:
            byte = f.read(50)
            while byte:
                if y == 1:
                    with open(file_out,'ab') as d:
                        self.EncryptTextAsymmetric(byte.decode(),pub,'./.tmp.bin')
                        with open('./.tmp.bin','rb') as g:
                            shode = g.read()
                        d.write(shode)
                        os.remove('./.tmp.bin')
                else:
                    with open(file_out,'ab') as d:
                        d.write(byte)
                byte = f.read(50)
                y += 1
        # os.system('sudo rm -rf ./.output.sym')
        os.remove('./.output.sym')

    def DecryptHybrid(self,file_in: 'path to input',priv: 'path to private key',sym: 'path to symmetric key',file_out: 'path to output') -> '1 file: decrypted file':
        y = 1
        with open(file_in, "rb") as f:
            byte = f.read(256)
            while byte:
                if y == 1:
                    with open('./.sec1.bin','ab') as d:
                        d.write(byte)
                else:
                    with open('./.sec2.sym','ab') as d:
                        d.write(byte)
                byte = f.read(256)
                y += 1
        self.DecryptFileAsymmetric('./.sec1.bin',priv,'./.final.sym')
        os.remove('./.sec1.bin')
        with open('./.final.sym','ab') as f:
            with open('./.sec2.sym','rb') as h:
                t = h.read()
            f.write(t)
        os.remove('./.sec2.sym')
        self.DecryptFileSymmetric(sym,'./.final.sym',file_out)
        os.remove('./.final.sym')
