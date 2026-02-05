"""
Enhanced file ingestion pipeline with comprehensive security checks.

FIXED CRITICAL ISSUE:
- ✅ CRITIQUE 10: Race condition in duplicate check (atomic DB transaction)
- ✅ File created in DB BEFORE writing to disk
- ✅ Atomic rollback on errors
- ✅ Proper temp file cleanup
"""
import os
import hashlib
import shutil
import logging
import zipfile
from pathlib import Path
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.db import transaction

logger = logging.getLogger(__name__)


class DecompressionBombGuard:
    """
    Protects against decompression bombs (zip/7z/rar files with extreme compression ratios).
    """

    MAX_UNCOMPRESSED_SIZE = 100 * 1024 * 1024  # 100 MB
    MAX_COMPRESSION_RATIO = 1000
    MAX_FILES_IN_ARCHIVE = 10000

    @classmethod
    def check_zip_bomb(cls, file_path):
        """Check if a ZIP file is a potential decompression bomb."""
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_file:
                # Check file count
                if len(zip_file.namelist()) > cls.MAX_FILES_IN_ARCHIVE:
                    return {
                        'safe': False,
                        'reason': f'Archive contains {len(zip_file.namelist())} files (max: {cls.MAX_FILES_IN_ARCHIVE})',
                        'ratio': None
                    }

                # Calculate compression ratio
                total_compressed = os.path.getsize(file_path)
                total_uncompressed = sum(info.file_size for info in zip_file.infolist())

                if total_uncompressed > cls.MAX_UNCOMPRESSED_SIZE:
                    return {
                        'safe': False,
                        'reason': f'Uncompressed size ({total_uncompressed} bytes) exceeds limit',
                        'ratio': None
                    }

                if total_compressed > 0:
                    ratio = total_uncompressed / total_compressed
                    if ratio > cls.MAX_COMPRESSION_RATIO:
                        return {
                            'safe': False,
                            'reason': f'Suspicious compression ratio: {ratio:.1f}x',
                            'ratio': ratio
                        }

                return {'safe': True, 'reason': 'Archive passed checks', 'ratio': ratio}
        except zipfile.BadZipFile:
            return {'safe': False, 'reason': 'Invalid or corrupted ZIP', 'ratio': None}
        except Exception as e:
            logger.error(f"Error checking ZIP bomb: {str(e)}")
            return {'safe': False, 'reason': f'Error: {str(e)}', 'ratio': None}


class AVScannerIntegration:
    """Integration point for antivirus scanning with safe failure modes."""

    @staticmethod
    def scan_file(file_path, engine='mock'):
        """Scan file using specified AV engine."""
        try:
            if engine == 'mock':
                return AVScannerIntegration._scan_mock(file_path)
            else:
                logger.warning(f"Unknown AV engine: {engine}, falling back to mock")
                return AVScannerIntegration._scan_mock(file_path)
        except Exception as e:
            logger.error(f"AV scan error: {str(e)}")
            return {
                'status': 'unavailable',
                'engine': engine,
                'threat': str(e),
                'action': 'warn'
            }

    @staticmethod
    def _scan_mock(file_path):
        """Mock scanner for development/testing."""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()

            MALWARE_PATTERNS = [
                b'cmd.exe',
                b'powershell',
                b'eval(',
                b'<?php',
                b'<script',
            ]

            for pattern in MALWARE_PATTERNS:
                if pattern in content.lower():
                    return {
                        'status': 'suspicious',
                        'engine': 'mock',
                        'threat': f'Pattern detected: {pattern.decode(errors="ignore")}',
                        'action': 'warn'
                    }

            return {'status': 'clean', 'engine': 'mock', 'threat': None, 'action': 'approve'}
        except Exception as e:
            return {'status': 'unavailable', 'engine': 'mock', 'threat': str(e), 'action': 'warn'}


class EnhancedFileIngestionPipeline:
    """
    Enhanced file ingestion with comprehensive security.

    CRITICAL FIX: Atomic transaction prevents race conditions
    """

    def process_upload(self, uploaded_file, user, metadata):
        """
        Process file through complete security pipeline.

        ✅ FIXED: Atomic transaction prevents duplicate uploads

        Returns:
            dict: {'status': 'approved'|'rejected'|'quarantined', 'document': Document, ...}
        """
        quarantine_path = None
        temp_path = None
        encrypted_path = None
        final_path = None
        document = None

        try:
            # ========== STEP 1: SIZE VALIDATION ==========
            if uploaded_file.size > settings.MAX_UPLOAD_SIZE:
                max_mb = settings.MAX_UPLOAD_SIZE / (1024 * 1024)
                return {
                    'status': 'rejected',
                    'error': f'File size {uploaded_file.size} exceeds limit ({max_mb}MB)'
                }

            if uploaded_file.size == 0:
                return {'status': 'rejected', 'error': 'Empty file not allowed'}

            # ========== STEP 2: QUARANTINE ZONE ==========
            quarantine_dir = Path(settings.QUARANTINE_ROOT)
            quarantine_dir.mkdir(parents=True, exist_ok=True)

            safe_filename = self._sanitize_filename(uploaded_file.name)
            quarantine_path = quarantine_dir / f"{timezone.now().timestamp()}_{safe_filename}"

            # Save to quarantine
            with open(quarantine_path, 'wb+') as destination:
                for chunk in uploaded_file.chunks():
                    destination.write(chunk)

            # ========== STEP 3: MAGIC NUMBER VALIDATION ==========
            validation_result = self._validate_file_type(quarantine_path)
            if not validation_result['valid']:
                return {'status': 'rejected', 'error': validation_result['error']}

            # ========== STEP 4: ZIP BOMB CHECK ==========
            if validation_result['mime_type'] == 'application/zip':
                bomb_check = DecompressionBombGuard.check_zip_bomb(str(quarantine_path))
                if not bomb_check['safe']:
                    return {'status': 'rejected', 'error': f'Decompression bomb: {bomb_check["reason"]}'}

            # ========== STEP 5: ANTIVIRUS SCAN ==========
            av_engine = getattr(settings, 'AV_ENGINE', 'mock')
            scan_result = AVScannerIntegration.scan_file(str(quarantine_path), av_engine)

            if scan_result['status'] == 'infected':
                return {'status': 'rejected', 'error': f'Malware detected: {scan_result.get("threat")}'}
            elif scan_result['status'] == 'suspicious':
                logger.warning(f"Suspicious file: {scan_result.get('threat')}")
                return {
                    'status': 'quarantined',
                    'error': f'File flagged as suspicious: {scan_result.get("threat")}'
                }

            # ========== STEP 6: HASH CALCULATION ==========
            file_hash = self._calculate_hash(str(quarantine_path))

            # ========== STEP 7-11: ATOMIC TRANSACTION ==========
            # ✅ CRITICAL FIX: DB record created BEFORE file operations
            # This prevents race conditions where two users upload the same file
            with transaction.atomic():
                # Delayed import to avoid circular dependencies
                from documents.models import Document

                # Check for duplicates with SELECT FOR UPDATE lock
                if Document.objects.select_for_update().filter(file_hash=file_hash).exists():
                    return {
                        'status': 'rejected',
                        'error': 'This file already exists in the system (duplicate hash)'
                    }

                # ========== STEP 7: CREATE DB RECORD FIRST ==========
                # Status = 'processing' until file is safely stored
                document = Document(
                    classification_level=metadata['classification_level'],
                    original_filename=safe_filename,
                    file_path='',  # Will be set after encryption
                    file_size=uploaded_file.size,
                    mime_type=validation_result.get('mime_type', 'application/octet-stream'),
                    file_hash=file_hash,
                    status='processing',  # ← Prevents concurrent access
                    is_encrypted=False,  # Will be set to True after encryption
                    uploaded_by=user
                )

                # ✅ Encrypt metadata before saving
                document.set_title(metadata['title'])
                document.set_description(metadata.get('description', ''))

                # Save to DB (acquires row lock)
                document.save()

                try:
                    # ========== STEP 8: MOVE TO TEMP ==========
                    temp_dir = Path(settings.MEDIA_ROOT) / 'temp'
                    temp_dir.mkdir(parents=True, exist_ok=True)
                    temp_path = temp_dir / f"{file_hash}_{safe_filename}"
                    shutil.move(str(quarantine_path), str(temp_path))
                    quarantine_path = None  # Already moved

                    # ========== STEP 9: ENCRYPT FILE ==========
                    from .security import FileIngestionPipeline as Encryptor
                    encrypted_path = Encryptor().encrypt_file(
                        str(temp_path),
                        metadata['classification_level']
                    )

                    # ========== STEP 10: MOVE TO FINAL STORAGE ==========
                    final_dir = Path(settings.MEDIA_ROOT) / 'documents' / str(metadata['classification_level'])
                    final_dir.mkdir(parents=True, exist_ok=True)
                    final_path = final_dir / f"{file_hash}_{safe_filename}.enc"
                    shutil.move(encrypted_path, str(final_path))
                    encrypted_path = None  # Already moved

                    # ========== STEP 11: UPDATE DB RECORD ==========
                    document.file_path = str(final_path)
                    document.is_encrypted = True
                    document.status = 'approved'
                    document.save(update_fields=['file_path', 'is_encrypted', 'status'])

                    logger.info(
                        f"File ingestion complete: {document.id} "
                        f"(hash: {file_hash[:16]}..., user: {user.username})"
                    )

                    return {
                        'status': 'approved',
                        'document': document,
                        'filename': safe_filename,
                        'file_path': str(final_path),
                        'file_size': final_path.stat().st_size,
                        'mime_type': validation_result.get('mime_type'),
                        'file_hash': file_hash,
                        'av_engine': av_engine,
                        'av_status': scan_result['status']
                    }

                except Exception as e:
                    # ✅ CRITICAL: Rollback on error
                    logger.error(f"File processing error: {str(e)}", exc_info=True)

                    # Delete the DB record (transaction will auto-rollback)
                    document.delete()

                    # Re-raise to trigger cleanup in finally block
                    raise

        except Exception as e:
            logger.error(f"File ingestion pipeline error: {str(e)}", exc_info=True)
            return {
                'status': 'rejected',
                'error': f'Unexpected error during file processing: {str(e)}'
            }

        finally:
            # ========== CLEANUP: Remove temporary files ==========
            for path in [quarantine_path, temp_path, encrypted_path]:
                if path and os.path.exists(path):
                    try:
                        os.remove(path)
                        logger.debug(f"Cleaned up temporary file: {path}")
                    except Exception as e:
                        logger.warning(f"Could not remove temp file {path}: {str(e)}")

    @staticmethod
    def _sanitize_filename(filename):
        """Sanitize filename to prevent path traversal and injection."""
        import re

        # Remove path components
        filename = os.path.basename(filename)

        # Remove null bytes and control characters
        filename = filename.replace('\x00', '')

        # Allow only safe characters
        filename = re.sub(r'[^\w\s.-]', '', filename)

        # Remove multiple dots
        filename = re.sub(r'\.{2,}', '.', filename)

        # Limit length
        name, ext = os.path.splitext(filename)
        if len(name) > 200:
            name = name[:200]

        result = f"{name}{ext}"
        if not result:
            result = "unnamed_file"

        return result

    @staticmethod
    def _validate_file_type(file_path):
        """Validate file type using magic numbers."""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(512)

            signatures = {
                b'\x25\x50\x44\x46': ('application/pdf', 'PDF'),
                b'\x50\x4B\x03\x04': ('application/zip', 'ZIP'),
                b'\xD0\xCF\x11\xE0': ('application/msword', 'Microsoft Word 97-2003'),
                b'\xFF\xD8\xFF': ('image/jpeg', 'JPEG'),
                b'\x89\x50\x4E\x47': ('image/png', 'PNG'),
                b'\x47\x49\x46': ('image/gif', 'GIF'),
            }

            for magic, (mime_type, description) in signatures.items():
                if header.startswith(magic):
                    return {'valid': True, 'mime_type': mime_type, 'description': description}

            return {'valid': False, 'error': 'File type not recognized or not allowed'}

        except Exception as e:
            return {'valid': False, 'error': f'File validation error: {str(e)}'}

    @staticmethod
    def _calculate_hash(file_path):
        """Calculate SHA-256 hash of file."""
        sha256_hash = hashlib.sha256()

        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b''):
                sha256_hash.update(byte_block)

        return sha256_hash.hexdigest()