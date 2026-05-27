import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms


def gen_random_bytes(size: int) -> bytes:
    """
    Generate cryptographically secure random bytes.
    
    Args:
        size: Number of random bytes to generate
        
    Returns:
        Random bytes of specified size
    """
    return os.urandom(size)


def encrypt_chacha20(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Encrypt data with ChaCha20 cipher.
    
    Args:
        data: Source data to encrypt
        key: Symmetric key
        nonce: One-time nonce number
        
    Returns:
        Encrypted data
        
    Raises:
        RuntimeError: If encryption fails due to invalid parameters or other errors
    """
    try:
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        encryptor = cipher.encryptor()
        return encryptor.update(data)
    except TypeError as e:
        raise RuntimeError(f"ChaCha20 encryption error - invalid parameter type: {e}") from e
    except ValueError as e:
        raise RuntimeError(f"ChaCha20 encryption error - invalid parameter value: {e}") from e
    except AttributeError as e:
        raise RuntimeError(f"ChaCha20 encryption error - missing attribute: {e}") from e
    except OverflowError as e:
        raise RuntimeError(f"ChaCha20 encryption error - numeric overflow: {e}") from e
    except MemoryError as e:
        raise RuntimeError(f"ChaCha20 encryption error - insufficient memory: {e}") from e
    except Exception as e:
        raise RuntimeError(f"ChaCha20 encryption error: {e}") from e
    

def decrypt_chacha20(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Decrypt data with ChaCha20 cipher.
    
    Args:
        data: Source data to decrypt
        key: Symmetric key
        nonce: One-time nonce number
        
    Returns:
        Decrypted data
        
    Raises:
        RuntimeError: If decryption fails due to invalid parameters or other errors
    """
    try:
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        decryptor = cipher.decryptor()
        return decryptor.update(data)
    except TypeError as e:
        raise RuntimeError(f"Wrong parameter type - key/nonce/data must be bytes: {e}") from e
    except ValueError as e:
        raise RuntimeError(f"Invalid key or nonce length: {e}") from e
    except AttributeError as e:
        raise RuntimeError(f"Missing cryptography module or class: {e}") from e
    except MemoryError as e:
        raise RuntimeError(f"Memory error during decryption: {e}") from e
    except OverflowError as e:
        raise RuntimeError(f"Internal counter overflow: {e}") from e
    except Exception as e:
        raise RuntimeError(f"Unexpected ChaCha20 decryption error: {e}") from e