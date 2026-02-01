"""
Security utilities for file validation, encryption, and scanning
"""
import os
import hashlib
from pathlib import Path
from cryptography.fernet import Fernet
from django.conf import settings
from django.core.exceptions import ValidationError
import re



"""
Security utilities for file handling and encryption
"""
import os
import re
import hashlib
import shutil
import logging
from django.conf import settings
from django.db import transaction
from Crypto.Cipher import AES

# Configuration du logger
logger = logging.getLogger(__name__)

# Import du modèle Document
from documents.models import Document


class FileIngestionPipeline:
    """
    Complete security pipeline for file uploads
    """
    
    def process_upload(self, uploaded_file, user, metadata):
        """
        Process file through security pipeline
        """
        file_path = None
        
        try:
            # 1. Validate file type
            validation_result = self.validate_file_type(uploaded_file)
            if not validation_result['valid']:
                return {
                    'status': 'rejected',
                    'error': validation_result['error']
                }
            
            # 2. Sanitize filename
            safe_filename = self.sanitize_filename(uploaded_file.name)
            
            # 3. Create temporary file path
            temp_dir = os.path.join(settings.MEDIA_ROOT, 'temp')
            os.makedirs(temp_dir, exist_ok=True)
            file_path = os.path.join(temp_dir, safe_filename)
            
            # 4. Save uploaded file temporarily
            with open(file_path, 'wb+') as destination:
                for chunk in uploaded_file.chunks():
                    destination.write(chunk)
            
            # 5. Scan for malware
            scan_result = self.scan_file(file_path)
            if not scan_result['safe']:
                return {
                    'status': 'rejected',
                    'error': f"Menace détectée: {scan_result.get('threat', 'Unknown')}"
                }
            
            # 6. Calculate file hash
            file_hash = self.calculate_hash(file_path)
            
            # 7. Check for duplicates
            if Document.objects.filter(file_hash=file_hash).exists():
                return {
                    'status': 'rejected',
                    'error': 'Ce fichier existe déjà dans le système'
                }
            
            # 8. Encrypt file
            encrypted_path = self.encrypt_file(
                file_path, 
                metadata['classification_level']
            )
            
            # 9. Move to final storage location
            final_dir = os.path.join(
                settings.MEDIA_ROOT, 
                'documents', 
                str(metadata['classification_level'])
            )
            os.makedirs(final_dir, exist_ok=True)
            
            final_path = os.path.join(final_dir, f"{file_hash}_{safe_filename}.enc")
            shutil.move(encrypted_path, final_path)
            
            # 10. Get file info
            file_size = os.path.getsize(final_path)
            mime_type = validation_result.get('mime_type', 'application/octet-stream')
            
            return {
                'status': 'approved',
                'filename': safe_filename,
                'file_path': final_path,
                'file_size': file_size,
                'mime_type': mime_type,
                'file_hash': file_hash
            }
            
        except Exception as e:
            logger.error(f"Pipeline error: {str(e)}")
            return {
                'status': 'rejected',
                'error': f'Erreur inattendue: {str(e)}'
            }
        
        finally:
            # Nettoyer le fichier temporaire
            if file_path and os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except Exception as e:
                    logger.warning(f"Could not remove temp file: {e}")
    
    def validate_file_type(self, uploaded_file):
        """Validate file type using magic numbers"""
        try:
            # Read first bytes to check magic numbers
            uploaded_file.seek(0)
            header = uploaded_file.read(8)
            uploaded_file.seek(0)
            
            # Define magic numbers for allowed types
            ALLOWED_TYPES = {
                b'\x25\x50\x44\x46': 'application/pdf',  # PDF
                b'\x50\x4B\x03\x04': 'application/vnd.openxmlformats-officedocument',  # DOCX
                b'\xD0\xCF\x11\xE0': 'application/msword',  # DOC
                b'\xFF\xD8\xFF': 'image/jpeg',  # JPEG
                b'\x89\x50\x4E\x47': 'image/png',  # PNG
            }
            
            for magic, mime_type in ALLOWED_TYPES.items():
                if header.startswith(magic):
                    return {
                        'valid': True,
                        'mime_type': mime_type
                    }
            
            return {
                'valid': False,
                'error': 'Type de fichier non autorisé'
            }
            
        except Exception as e:
            return {
                'valid': False,
                'error': f'Erreur de validation: {str(e)}'
            }
    
    def sanitize_filename(self, filename):
        """Sanitize filename to prevent path traversal"""
        # Remove path components
        filename = os.path.basename(filename)
        
        # Remove dangerous characters
        filename = re.sub(r'[^\w\s\-\.]', '', filename)
        
        # Limit length
        name, ext = os.path.splitext(filename)
        if len(name) > 100:
            name = name[:100]
        
        return f"{name}{ext}"
    
    def scan_file(self, file_path):
        """Simple pattern-based malware detection"""
        try:
            # Read file content
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Check for suspicious patterns
            SUSPICIOUS_PATTERNS = [
                b'<script',
                b'javascript:',
                b'eval(',
                b'exec(',
                b'<?php',
                b'<iframe',
            ]
            
            for pattern in SUSPICIOUS_PATTERNS:
                if pattern in content.lower():
                    return {
                        'safe': False,
                        'threat': f'Suspicious pattern detected: {pattern.decode()}'
                    }
            
            return {'safe': True}
            
        except Exception as e:
            return {
                'safe': False,
                'threat': f'Scan error: {str(e)}'
            }
    
    def calculate_hash(self, file_path):
        """Calculate SHA-256 hash"""
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        return sha256_hash.hexdigest()
    
    def encrypt_file(self, file_path, classification_level):
        """Encrypt file with AES-256"""
        # Generate encryption key based on classification
        key = self.get_encryption_key(classification_level)
        
        # Read original file
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Encrypt with AES-256
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        # Save encrypted file
        encrypted_path = f"{file_path}.enc"
        with open(encrypted_path, 'wb') as f:
            f.write(cipher.nonce)
            f.write(tag)
            f.write(ciphertext)
        
        return encrypted_path
    
    def get_encryption_key(self, classification_level):
        """Get encryption key based on classification level"""
        # In production, use proper key management (e.g., AWS KMS, HashiCorp Vault)
        base_key = settings.SECRET_KEY.encode()
        
        # Derive key using PBKDF2
        key = hashlib.pbkdf2_hmac(
            'sha256',
            base_key,
            str(classification_level).encode(),
            100000,
            dklen=32
        )
        
        return key


class EncryptionManager:
    """
    Manage file encryption and decryption
    """
    
    @staticmethod
    def decrypt_file(encrypted_path, classification_level):
        """Decrypt a file"""
        try:
            # Generate the same key used for encryption
            key = FileIngestionPipeline().get_encryption_key(classification_level)
            
            # Read encrypted file
            with open(encrypted_path, 'rb') as f:
                nonce = f.read(16)
                tag = f.read(16)
                ciphertext = f.read()
            
            # Decrypt
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)
            
            return data
            
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            raise Exception(f"Échec du déchiffrement: {str(e)}")
    
    @staticmethod
    def encrypt_data(data, classification_level):
        """Encrypt raw data"""
        key = FileIngestionPipeline().get_encryption_key(classification_level)
        
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        return cipher.nonce + tag + ciphertext



class FileValidator:
    """Validate uploaded files for security"""
    
    # Magic numbers for file type validation
    MAGIC_NUMBERS = {
        'application/pdf': [b'%PDF'],
        'image/jpeg': [b'\xff\xd8\xff'],
        'image/png': [b'\x89PNG\r\n\x1a\n'],
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': [b'PK\x03\x04'],
    }
    
    @staticmethod
    def sanitize_filename(filename):
        """Clean filename to prevent path traversal attacks"""
        # Remove path components
        filename = os.path.basename(filename)
        
        # Remove dangerous characters
        filename = re.sub(r'[^\w\s.-]', '', filename)
        
        # Prevent multiple extensions
        name, ext = os.path.splitext(filename)
        name = name.replace('.', '_')
        
        # Limit length
        if len(name) > 200:
            name = name[:200]
        
        return f"{name}{ext}"
    
    @staticmethod
    def validate_file_type(file_content, declared_mime_type):
        """Validate file type using magic numbers"""
        if declared_mime_type not in settings.ALLOWED_FILE_TYPES:
            raise ValidationError(f"Type de fichier non autorisé: {declared_mime_type}")
        
        # Check magic numbers
        magic_nums = FileValidator.MAGIC_NUMBERS.get(declared_mime_type, [])
        
        if magic_nums:
            is_valid = any(file_content.startswith(magic) for magic in magic_nums)
            if not is_valid:
                raise ValidationError("Le contenu du fichier ne correspond pas au type déclaré")
        
        return True
    
    @staticmethod
    def validate_file_size(file_size):
        """Validate file size"""
        if file_size > settings.MAX_UPLOAD_SIZE:
            max_mb = settings.MAX_UPLOAD_SIZE / (1024 * 1024)
            raise ValidationError(f"Fichier trop volumineux. Maximum: {max_mb}MB")
        
        if file_size == 0:
            raise ValidationError("Le fichier est vide")
        
        return True
    
    @staticmethod
    def calculate_hash(file_content):
        """Calculate SHA-256 hash"""
        return hashlib.sha256(file_content).hexdigest()
    
    @staticmethod
    def check_duplicate(file_hash):
        """Check if file already exists"""
        from documents.models import Document
        return Document.objects.filter(file_hash=file_hash).exists()


class FileSanitizer:
    """Sanitize files to remove potential threats"""
    
    @staticmethod
    def sanitize_pdf(file_path):
        """Basic PDF sanitization (placeholder for advanced tools)"""
        # In production, use tools like:
        # - Dangerzone
        # - pdf-parser + pdf-redact-tools
        # - pikepdf for metadata removal
        return True
    
    @staticmethod
    def remove_metadata(file_path, mime_type):
        """Remove metadata from files"""
        # Placeholder - implement with exiftool or similar
        return True


class SimpleAVScanner:
    """Simple antivirus scanner (no ClamAV)"""
    
    @staticmethod
    def scan_file(file_content, mime_type):
        """Basic malware pattern detection"""
        content_lower = file_content.lower()
        
        # Patterns vraiment dangereux selon le type de fichier
        dangerous_patterns = {
            'application/pdf': [
                b'<script>', 
                b'/javascript', 
                b'/js',
                b'eval('
            ],
            'image/jpeg': [
                b'<script>', 
                b'<?php',
                b'<%@'
            ],
            'image/png': [
                b'<script>', 
                b'<?php',
                b'<%@'
            ],
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document': [
                b'<script>', 
                b'javascript:', 
                b'vbscript:',
                b'eval('
            ],
        }
        
        # Vérifier uniquement les patterns dangereux pour ce type
        patterns = dangerous_patterns.get(mime_type, [])
        
        for pattern in patterns:
            if pattern in content_lower:
                return {
                    'status': 'threat_detected',
                    'message': f'Code exécutable détecté dans le fichier'
                }
        
        # Validation de la signature du fichier
        if mime_type == 'application/pdf':
            if not file_content.startswith(b'%PDF'):
                return {
                    'status': 'threat_detected',
                    'message': 'Signature PDF invalide'
                }
            if len(file_content) < 100:
                return {
                    'status': 'suspicious',
                    'message': 'Fichier PDF anormalement petit'
                }
        
        elif mime_type == 'image/jpeg':
            if not file_content.startswith(b'\xff\xd8\xff'):
                return {
                    'status': 'threat_detected',
                    'message': 'Signature JPEG invalide'
                }
        
        elif mime_type == 'image/png':
            if not file_content.startswith(b'\x89PNG\r\n\x1a\n'):
                return {
                    'status': 'threat_detected',
                    'message': 'Signature PNG invalide'
                }
        
        return {
            'status': 'clean',
            'message': 'Aucune menace détectée'
        }


class EncryptionManager:
    """
    Handle file encryption/decryption with metadata encryption support.
    Implements Fernet (AES-128-CBC + HMAC-SHA256) for authenticated encryption.
    """
    
    def __init__(self, key=None):
        if key is None:
            key = settings.ENCRYPTION_KEY
        
        if key:
            self.cipher = Fernet(key.encode() if isinstance(key, str) else key)
        else:
            # Generate key for development only
            logger.warning("Encryption key not provided; generating ephemeral key (dev only)")
            self.cipher = Fernet(Fernet.generate_key())
    
    def encrypt_file(self, file_content):
        """Encrypt file content using authenticated encryption."""
        if isinstance(file_content, str):
            file_content = file_content.encode('utf-8')
        return self.cipher.encrypt(file_content)
    
    def decrypt_file(self, encrypted_content):
        """Decrypt file content with authentication verification."""
        try:
            return self.cipher.decrypt(encrypted_content)
        except Exception as e:
            logger.error(f"File decryption failed: {str(e)}")
            raise
    
    def encrypt_metadata(self, text):
        """
        Encrypt sensitive metadata fields (title, description, etc.).
        Returns encrypted string suitable for database storage.
        """
        if isinstance(text, str):
            text = text.encode('utf-8')
        
        encrypted = self.cipher.encrypt(text)
        # Return as URL-safe base64 string for DB storage
        return encrypted.decode('utf-8')
    
    def decrypt_metadata(self, encrypted_text):
        """Decrypt encrypted metadata fields."""
        try:
            if isinstance(encrypted_text, str):
                encrypted_text = encrypted_text.encode('utf-8')
            
            decrypted = self.cipher.decrypt(encrypted_text)
            return decrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"Metadata decryption failed: {str(e)}")
            raise
    
    @staticmethod
    def encrypt_sensitive_fields(document_dict, fields_to_encrypt):
        """
        Encrypt specified fields in a document dictionary.
        Used before saving to database.
        
        Args:
            document_dict: Dictionary with document data
            fields_to_encrypt: List of field names to encrypt
        """
        manager = EncryptionManager()
        result = document_dict.copy()
        
        for field in fields_to_encrypt:
            if field in result and result[field]:
                try:
                    result[f"{field}_encrypted"] = manager.encrypt_metadata(result[field])
                    result[field] = None  # Clear plaintext
                except Exception as e:
                    logger.error(f"Failed to encrypt field {field}: {str(e)}")
        
        return result
    
    @staticmethod
    def decrypt_sensitive_fields(document_dict, fields_to_decrypt):
        """
        Decrypt specified fields in a document dictionary.
        Used when retrieving from database.
        """
        manager = EncryptionManager()
        result = document_dict.copy()
        
        for field in fields_to_decrypt:
            encrypted_field = f"{field}_encrypted"
            if encrypted_field in result and result[encrypted_field]:
                try:
                    result[field] = manager.decrypt_metadata(result[encrypted_field])
                except Exception as e:
                    logger.error(f"Failed to decrypt field {field}: {str(e)}")
        
        return result


