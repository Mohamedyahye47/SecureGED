# ton_app/upload_handlers.py
from cryptography.fernet import Fernet, InvalidToken
from django.core.files.uploadhandler import FileUploadHandler, StopUpload
from django.conf import settings
import os

# Clé Fernet (AES-128-CBC + HMAC-SHA256) – génère-la une fois et stocke-la SECUREMENT !
# Exemple : Fernet.generate_key() → mets-la dans .env ou Vault
FERNET_KEY = os.environ.get('FERNET_KEY')  # Doit être base64 32 bytes
if not FERNET_KEY:
    raise ValueError("FERNET_KEY manquante dans l'environnement !")

fernet = Fernet(FERNET_KEY.encode())


class EncryptedUploadHandler(FileUploadHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.encrypted_chunks = []
        self.file_size = 0

    def receive_data_chunk(self, raw_data, start):
        # Chiffre chaque chunk à la volée
        encrypted_chunk = fernet.encrypt(raw_data)
        self.encrypted_chunks.append(encrypted_chunk)
        self.file_size += len(encrypted_chunk)
        return encrypted_chunk  # Retourne le chunk chiffré

    def file_complete(self, file_size):
        if self.file_size == 0:
            raise StopUpload(True)  # Fichier vide → annuler

        # Optionnel : tu peux stocker le nonce/IV si tu utilises AES-GCM au lieu de Fernet
        return super().file_complete(self.file_size)