import os, base64, hashlib
from django.conf import settings
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.fernet import Fernet

KEY_DIR = os.path.join(settings.BASE_DIR, "keys")
SERVER_PRIV = os.path.join(KEY_DIR, "server_rsa_private.pem")
SERVER_PUB  = os.path.join(KEY_DIR, "server_rsa_public.pem")


def _ensure_server_keys():
    os.makedirs(KEY_DIR, exist_ok=True)
    if os.path.exists(SERVER_PRIV) and os.path.exists(SERVER_PUB):
        return

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()

    with open(SERVER_PRIV, "wb") as f:
        f.write(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(SERVER_PUB, "wb") as f:
        f.write(pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))


def _load_server_pub():
    _ensure_server_keys()
    with open(SERVER_PUB, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def _load_server_priv():
    _ensure_server_keys()
    with open(SERVER_PRIV, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def ensure_user_keys(profile):
    """Crée une paire RSA utilisateur (pour signature) si absente.
    private key est stockée chiffrée via Fernet (ENCRYPTION_KEY)."""
    if profile.public_key_pem and profile.private_key_enc:
        return

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    f = Fernet(settings.ENCRYPTION_KEY.encode() if isinstance(settings.ENCRYPTION_KEY, str) else settings.ENCRYPTION_KEY)
    priv_enc = f.encrypt(priv_pem)

    profile.public_key_pem = pub_pem.decode("utf-8")
    profile.private_key_enc = priv_enc.decode("utf-8")
    profile.save(update_fields=["public_key_pem", "private_key_enc"])


def _load_user_private(profile):
    f = Fernet(settings.ENCRYPTION_KEY.encode() if isinstance(settings.ENCRYPTION_KEY, str) else settings.ENCRYPTION_KEY)
    priv_pem = f.decrypt(profile.private_key_enc.encode("utf-8"))
    return serialization.load_pem_private_key(priv_pem, password=None)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encrypt_bytes_hybrid(plaintext: bytes, signer_profile=None):
    """
    - AES-GCM avec clé aléatoire par fichier
    - clé AES chiffrée RSA (clé publique serveur)
    - signature (optionnelle) sur hash plaintext
    """
    aes_key = os.urandom(32)   # AES-256
    iv = os.urandom(12)        # recommandé pour GCM

    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)

    server_pub = _load_server_pub()
    wrapped_key = server_pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    p_hash = sha256_hex(plaintext)

    signature_b64 = None
    signer_pub_pem = None
    if signer_profile is not None:
        ensure_user_keys(signer_profile)
        user_priv = _load_user_private(signer_profile)
        sig = user_priv.sign(
            p_hash.encode("utf-8"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        signature_b64 = base64.b64encode(sig).decode("utf-8")
        signer_pub_pem = signer_profile.public_key_pem

    return ciphertext, {
        "iv_b64": base64.b64encode(iv).decode("utf-8"),
        "wrapped_key_b64": base64.b64encode(wrapped_key).decode("utf-8"),
        "plaintext_hash": p_hash,
        "signature_b64": signature_b64,
        "signer_pub_pem": signer_pub_pem,
    }


def decrypt_bytes_hybrid(ciphertext: bytes, iv_b64: str, wrapped_key_b64: str):
    iv = base64.b64decode(iv_b64)
    wrapped_key = base64.b64decode(wrapped_key_b64)

    server_priv = _load_server_priv()
    aes_key = server_priv.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return plaintext


def verify_signature(plaintext_hash: str, signature_b64: str, signer_pub_pem: str) -> bool:
    if not signature_b64 or not signer_pub_pem:
        return False
    pub = serialization.load_pem_public_key(signer_pub_pem.encode("utf-8"))
    sig = base64.b64decode(signature_b64)
    try:
        pub.verify(
            sig,
            plaintext_hash.encode("utf-8"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
