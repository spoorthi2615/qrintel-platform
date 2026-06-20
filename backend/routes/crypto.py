"""
crypto.py
Flask Blueprint for cryptographic operations.
POST /api/verify-signature — verify RSA or Ed25519 signature
POST /api/decrypt          — AES-GCM or XChaCha20-Poly1305 decryption
"""

from flask import Blueprint, request, jsonify

from core.signature_verifier import verify_signature
from core.decryptor import decrypt_aes_gcm, decrypt_xchacha20_poly1305

crypto_bp = Blueprint('crypto', __name__)


@crypto_bp.route('/verify-signature', methods=['POST'])
def api_verify_signature():
    """
    Verify a digital signature for a QR payload.

    Request body (JSON):
        payload:     str  — original plaintext payload
        signature:   str  — base64-encoded signature
        public_key:  str  — PEM-encoded public key
        algorithm:   str  — 'rsa' | 'ed25519' (default: 'rsa')
    """
    data = request.get_json(silent=True) or {}

    payload    = data.get('payload', '').strip()
    signature  = data.get('signature', '').strip()
    public_key = data.get('public_key', '').strip()
    algorithm  = data.get('algorithm', 'rsa').lower()

    if not payload or not signature or not public_key:
        return jsonify({'error': 'payload, signature, and public_key are required'}), 400

    result = verify_signature(payload, signature, public_key, algorithm)
    return jsonify(result)


@crypto_bp.route('/decrypt', methods=['POST'])
def api_decrypt():
    """
    Decrypt an encrypted QR payload.

    Request body (JSON):
        ciphertext: str  — base64-encoded ciphertext
        key:        str  — base64-encoded key
        nonce:      str  — base64-encoded nonce
        tag:        str  — base64-encoded tag (AES-GCM only)
        algorithm:  str  — 'aes-gcm' | 'xchacha20' (default: 'aes-gcm')
    """
    data = request.get_json(silent=True) or {}

    ciphertext = data.get('ciphertext', '').strip()
    key        = data.get('key', '').strip()
    nonce      = data.get('nonce', '').strip()
    tag        = data.get('tag', '').strip()
    algorithm  = data.get('algorithm', 'aes-gcm').lower()

    if not ciphertext or not key or not nonce:
        return jsonify({'error': 'ciphertext, key, and nonce are required'}), 400

    if algorithm == 'aes-gcm':
        if not tag:
            return jsonify({'error': 'tag is required for AES-GCM'}), 400
        result = decrypt_aes_gcm(ciphertext, key, nonce, tag)
    elif algorithm in ('xchacha20', 'xchacha20-poly1305'):
        result = decrypt_xchacha20_poly1305(ciphertext, key, nonce)
    else:
        return jsonify({'error': f'Unsupported algorithm: {algorithm}'}), 400

    return jsonify(result)
