"""
decryptor.py
Decryption support for encrypted QR payloads.
Supports AES-GCM (PyCryptodome) and provides scaffold for XChaCha20-Poly1305.
"""

import base64

from Crypto.Cipher import AES, ChaCha20_Poly1305


def decrypt_aes_gcm(
    ciphertext_b64: str,
    key_b64: str,
    nonce_b64: str,
    tag_b64: str,
) -> dict:
    """
    Decrypt an AES-256-GCM encrypted payload.

    Args:
        ciphertext_b64: Base64-encoded ciphertext.
        key_b64:        Base64-encoded 32-byte AES key.
        nonce_b64:      Base64-encoded 12-byte nonce.
        tag_b64:        Base64-encoded 16-byte GCM authentication tag.

    Returns:
        Dict with: success (bool), plaintext (str|None), error (str|None).
    """
    try:
        ciphertext = base64.b64decode(ciphertext_b64)
        key        = base64.b64decode(key_b64)
        nonce      = base64.b64decode(nonce_b64)
        tag        = base64.b64decode(tag_b64)

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        return {
            'success':   True,
            'plaintext': plaintext.decode('utf-8'),
            'algorithm': 'AES-256-GCM',
            'error':     None,
        }
    except ValueError as e:
        return {
            'success':   False,
            'plaintext': None,
            'algorithm': 'AES-256-GCM',
            'error':     f'MAC check failed — ciphertext may be tampered: {str(e)}',
        }
    except Exception as e:
        return {
            'success':   False,
            'plaintext': None,
            'algorithm': 'AES-256-GCM',
            'error':     str(e),
        }


def decrypt_xchacha20_poly1305(
    ciphertext_b64: str,
    key_b64: str,
    nonce_b64: str,
) -> dict:
    """
    Decrypt an XChaCha20-Poly1305 encrypted payload.

    Args:
        ciphertext_b64: Base64-encoded ciphertext (includes tag appended at end).
        key_b64:        Base64-encoded 32-byte key.
        nonce_b64:      Base64-encoded 24-byte nonce.

    Returns:
        Dict with: success (bool), plaintext (str|None), error (str|None).
    """
    try:
        data  = base64.b64decode(ciphertext_b64)
        key   = base64.b64decode(key_b64)
        nonce = base64.b64decode(nonce_b64)

        # Tag is last 16 bytes
        ciphertext = data[:-16]
        tag        = data[-16:]

        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

        return {
            'success':   True,
            'plaintext': plaintext.decode('utf-8'),
            'algorithm': 'XChaCha20-Poly1305',
            'error':     None,
        }
    except ValueError as e:
        return {
            'success':   False,
            'plaintext': None,
            'algorithm': 'XChaCha20-Poly1305',
            'error':     f'Decryption/verification failed: {str(e)}',
        }
    except Exception as e:
        return {
            'success':   False,
            'plaintext': None,
            'algorithm': 'XChaCha20-Poly1305',
            'error':     str(e),
        }
