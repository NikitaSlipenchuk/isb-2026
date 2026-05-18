import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms


def gen_chacha20_key():
    """
    create 256 bits symmetric key

    return:
        a random sequence of 32 bytes 
    """ 
    return os.urandom(16)


def gen_nonce():
    """
    create 128 bits one-time nonce number

    return:
        A random sequence of 16 bytes
    """
    return os.urandom(16)


def encrypt_chacha20(data:bytes, key:bytes, nonce:bytes) -> bytes:
    """
    encrypt data with chacha20 ciper

    args:
        data: source data to encrypt
        key: symmetric key 
        nonce: one-time nonce number

    return:
        ecrypt data
    """
    try:
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        encryptor = cipher.encryptor()
        return encryptor.update(data)
    except TypeError as e:
        raise RuntimeError(f"ChaCha20 encryption error - invalid parameter type: {e}")
    except ValueError as e:
        raise RuntimeError(f"ChaCha20 encryption error - invalid parameter value: {e}")
    except AttributeError as e:
        raise RuntimeError(f"ChaCha20 encryption error - missing attribute: {e}")
    except OverflowError as e:
        raise RuntimeError(f"ChaCha20 encryption error - numeric overflow: {e}")
    except MemoryError as e:
        raise RuntimeError(f"ChaCha20 encryption error - insufficient memory: {e}")
    except Exception as e:
        raise RuntimeError(f"ChaCha20 encryption error: {e}")
    

def decrypt_chacha20(data:bytes, key:bytes, nonce:bytes) -> bytes:
    """
    decrypt data with chacha20 ciper

    args:
        data: source data to decrypt
        key: symmetric key 
        nonce: one-time nonce number

    return:
        decrypt data
    """
    try:
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        decryptor = cipher.decryptor()
        return decryptor.update(data)
    except TypeError as e:
        raise RuntimeError(f"Wrong parameter type - key/nonce/data must be bytes: {e}")
    except ValueError as e:
        raise RuntimeError(f"Invalid key (32 bytes) or nonce (12/24 bytes) length: {e}")
    except AttributeError as e:
        raise RuntimeError(f"Missing cryptography module or class: {e}")
    except MemoryError as e:
        raise RuntimeError(f"Memory error during decryption: {e}")
    except OverflowError as e:
        raise RuntimeError(f"Internal counter overflow: {e}")
    except Exception as e:
        raise RuntimeError(f"Unexpected ChaCha20 decryption error: {e}")
