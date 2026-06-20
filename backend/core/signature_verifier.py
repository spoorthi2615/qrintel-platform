"""
signature_verifier.py
Cryptographic signature verification for QR payloads.
Supports RSA-PSS and Ed25519 algorithms via the cryptography library.
"""

import base64

from cryptography.hazmat.primitives.asymmetric import padding, ed25519
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature


def verify_signature(
    payload: str,
    signature_b64: str,
    public_key_pem: str,
    algorithm: str = 'rsa',
) -> dict:
    """
    Verify a digital signature for a QR payload.

    Args:
        payload:        The original plaintext payload.
        signature_b64:  Base64-encoded signature bytes.
        public_key_pem: PEM-encoded public key string.
        algorithm:      'rsa' or 'ed25519'.

    Returns:
        Dict with: verified (bool), algorithm (str), status (str), error (str|None).
    """
    try:
        payload_bytes = payload.encode('utf-8')
        signature_bytes = base64.b64decode(signature_b64)
        public_key = load_pem_public_key(public_key_pem.encode('utf-8'))

        algo = algorithm.lower()

        if algo == 'rsa':
            if not isinstance(public_key, RSAPublicKey):
                return {
                    'verified': False,
                    'algorithm': 'RSA',
                    'status': 'INVALID_KEY',
                    'error': 'Provided key is not an RSA public key',
                }
            public_key.verify(
                signature_bytes,
                payload_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return {
                'verified': True,
                'algorithm': 'RSA-PSS-SHA256',
                'status': 'VERIFIED',
                'error': None,
            }

        elif algo == 'ed25519':
            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                return {
                    'verified': False,
                    'algorithm': 'Ed25519',
                    'status': 'INVALID_KEY',
                    'error': 'Provided key is not an Ed25519 public key',
                }
            public_key.verify(signature_bytes, payload_bytes)
            return {
                'verified': True,
                'algorithm': 'Ed25519',
                'status': 'VERIFIED',
                'error': None,
            }

        else:
            return {
                'verified': False,
                'algorithm': algorithm,
                'status': 'UNSUPPORTED_ALGORITHM',
                'error': f'Unsupported algorithm: {algorithm}. Use "rsa" or "ed25519".',
            }

    except InvalidSignature:
        return {
            'verified': False,
            'algorithm': algorithm.upper(),
            'status': 'TAMPERED',
            'error': 'Signature verification failed — payload may have been tampered',
        }
    except Exception as e:
        return {
            'verified': False,
            'algorithm': algorithm.upper(),
            'status': 'ERROR',
            'error': str(e),
        }
