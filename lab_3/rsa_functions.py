from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, asymmetric
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from typing import Tuple


def gen_rsa_keys() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Function generate public and private keys for RSA
    
    return:
        pair of pablic and private RSA keys
    """
    keys = rsa.generate_private_key( public_exponent=65537, key_size=2048)
    private_key = keys
    public_key = keys.public_key()
    return private_key, public_key


def serialize_public_key(public_key, public_key_path: str) -> None:
    """
    save key in the .pem format

    args:
        public_key: bublic rsa key
        public_key_path: path to save .pem public key
    """
    try:
        with open(public_key_path, 'wb') as public_out:
            public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
             format=serialization.PublicFormat.SubjectPublicKeyInfo))
    except AttributeError as e:
        print(f"Key object has no public_bytes method or is invalid: {e}")
        exit(2)
    except TypeError as e:
        print(f"Invalid parameters for public_bytes or wrong key type: {e}")
        exit(2)
    except PermissionError as e:
        print(f"Permission denied when writing to {public_key_path}: {e}")
        exit(2)
    except FileNotFoundError as e:
        print(f"Directory not found for {public_key_path}: {e}")
        exit(2)
    except IsADirectoryError as e:
        print(f"Path is a directory, not a file: {e}")
        exit(2)
    except OSError as e:
        print(f"OS error (disk full, invalid path, etc.): {e}")
        exit(2)
    except Exception as e:
        print(e)
        exit(2)


def serialize_private_key(private_key, private_key_path: str) -> None:
    """
    save key in the .pem format

    args:
        private_key: private rsa key
        private_key_path: path to save .pem private key
    """
    try:
        with open(private_key_path, 'wb') as private_out:
            private_out.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
              format=serialization.PrivateFormat.TraditionalOpenSSL,
              encryption_algorithm=serialization.NoEncryption()))
    except AttributeError as e:
        print(f"Key object has no public_bytes method or is invalid: {e}")
        exit(2)
    except TypeError as e:
        print(f"Invalid parameters for public_bytes or wrong key type: {e}")
        exit(2)
    except PermissionError as e:
        print(f"Permission denied when writing to {private_key_path}: {e}")
        exit(2)
    except FileNotFoundError as e:
        print(f"Directory not found for {private_key_path}: {e}")
        exit(2)
    except IsADirectoryError as e:
        print(f"Path is a directory, not a file: {e}")
        exit(2)
    except OSError as e:
        print(f"OS error (disk full, invalid path, etc.): {e}")
        exit(2)
    except Exception as e:
        print(e)
        exit(2)


def deserialize_public_key(public_key_path: str) -> rsa.RSAPublicKey:
    """
    read key in the .pem format

    args:
        public_key_path: path to get .pem public key

    return:
        public RSA key
    """
    try:
        with open(public_key_path, 'rb') as pem_in:
            public_bytes = pem_in.read()
            d_public_key = load_pem_public_key(public_bytes)
            return d_public_key
    except FileNotFoundError:
        print(f"File not found: {public_key_path}")
        exit(2)
    except PermissionError:
        print(f"Permission denied when reading {public_key_path}")
        exit(2)
    except IsADirectoryError:
        print(f"Path is a directory, not a file: {public_key_path}")
        exit(2)
    except OSError:
        print(f"OS error occurred while reading {public_key_path}")
        exit(2)
    except ValueError:
        print(f"Invalid PEM data or corrupted file: {public_key_path}")
        exit(2)
    except TypeError:
        print(f"Invalid data type in PEM file: {public_key_path}")
        exit(2)
    except Exception as e:
        print(e)
        exit(2)

def deserialize_private_key(private_key_path: str) -> rsa.RSAPrivateKey:
    """
    read key in the .pem format

    args:
        private_key_path: path to get .pem private key

    return:
        private RSA key
    """
    try:
        with open(private_key_path, 'rb') as pem_in:
            private_bytes = pem_in.read()
            d_private_key = load_pem_private_key(private_bytes,password=None,)
            return d_private_key
    except FileNotFoundError:
        print(f"File not found: {private_key_path}")
        exit(2)
    except PermissionError:
        print(f"Permission denied when reading {private_key_path}")
        exit(2)
    except IsADirectoryError:
        print(f"Path is a directory, not a file: {private_key_path}")
        exit(2)
    except OSError:
        print(f"OS error occurred while reading {private_key_path}")
        exit(2)
    except ValueError:
        print(f"Invalid PEM data or corrupted file: {private_key_path}")
        exit(2)
    except TypeError:
        print(f"Invalid data type in PEM file: {private_key_path}")
        exit(2)
    except AttributeError:
        print(f"load_pem_private_key function not available or wrong key type")
        exit(2)
    except Exception as e:
        print(e)
        exit(2)


def encrypt_data_rsa(text:str, public_key) -> bytes:
    """
    Encrypt data with rsa public key

    args:
        text: data for encrypt
        public_key: public rsa key
    
    return:
        encrypt data
    """
    c_text = public_key.encrypt(text, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),label=None))
    return c_text


def decrypt_data_rsa(text:str, private_key) ->bytes:
    """
    Decrypt data with rsa public key

    args:
        text: data for decrypt
        public_key: public rsa key
    
    return:
        encrypt data
    """
    dc_text = private_key.decrypt(text,padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),label=None))
    return dc_text

