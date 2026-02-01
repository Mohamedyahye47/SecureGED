"""
Enhanced file ingestion pipeline with comprehensive security checks.
Implements defense-in-depth validation, anti-zip-bomb protection, and AV integration hooks.
"""
import os
import hashlib
import shutil
import logging
import zipfile
from pathlib import Path
from django.conf import settings
from django.core.exceptions import ValidationError

logger = logging.getLogger(__name__)


class DecompressionBombGuard:
    """
    Protects against decompression bombs (zip/7z/rar files with extreme compression ratios).
    Implements size limits and uncompressed/compressed ratio checks.
    """
    
    # Maximum allowed uncompressed size (100 MB default)
    MAX_UNCOMPRESSED_SIZE = 100 * 1024 * 1024
    
    # Maximum allowed compression ratio (1000x = suspicious)
    MAX_COMPRESSION_RATIO = 1000
    
    # Maximum allowed file count in archive (to prevent slowdown)
    MAX_FILES_IN_ARCHIVE = 10000
    
    @classmethod
    def check_zip_bomb(cls, file_path):
        """
        Check if a ZIP file is a potential decompression bomb.
        Returns: {'safe': bool, 'reason': str, 'ratio': float}
        """
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
                        'reason': f'Uncompressed size ({total_uncompressed} bytes) exceeds limit ({cls.MAX_UNCOMPRESSED_SIZE})',
                        'ratio': None
                    }
                
                if total_compressed > 0:
                    ratio = total_uncompressed / total_compressed
                    if ratio > cls.MAX_COMPRESSION_RATIO:
                        return {
                            'safe': False,
                            'reason': f'Suspicious compression ratio: {ratio:.1f}x (max: {cls.MAX_COMPRESSION_RATIO}x)',
                            'ratio': ratio
                        }
                
                return {
                    'safe': True,
                    'reason': 'Archive passed checks',
                    'ratio': total_uncompressed / total_compressed if total_compressed > 0 else 0
                }
        except zipfile.BadZipFile:
            # Not a valid ZIP or corrupted
            return {
                'safe': False,
                'reason': 'Invalid or corrupted ZIP archive',
                'ratio': None
            }
        except Exception as e:
            logger.error(f"Error checking ZIP bomb: {str(e)}")
            return {
                'safe': False,
                'reason': f'Error during ZIP analysis: {str(e)}',
                'ratio': None
            }


class AVScannerIntegration:
    """
    Integration point for antivirus scanning.
    Supports external AV engines (ClamAV, VirusTotal, etc.) with safe failure modes.
    """
    
    # Supported engines
    ENGINES = {
        'clamav': 'ClamAV (local)',
        'virustotal': 'VirusTotal (cloud)',
        'mock': 'Mock/disabled (development only)'
    }
    
    @staticmethod
    def scan_file(file_path, engine='mock'):
        """
        Scan file using specified AV engine.
        Safe failure: if AV unavailable, returns {'status': 'unavailable', 'action': 'warn'}.
        
        Returns: {'status': 'clean'|'infected'|'suspicious'|'unavailable', 'engine': str, 'threat': str}
        """
        try:
            if engine == 'clamav':
                return AVScannerIntegration._scan_clamav(file_path)
            elif engine == 'virustotal':
                return AVScannerIntegration._scan_virustotal(file_path)
            elif engine == 'mock':
                return AVScannerIntegration._scan_mock(file_path)
            else:
                logger.warning(f"Unknown AV engine: {engine}")
                return {
                    'status': 'unavailable',
                    'engine': engine,
                    'threat': 'Unknown engine',
                    'action': 'warn'
                }
        except Exception as e:
            logger.error(f"AV scan error ({engine}): {str(e)}")
            return {
                'status': 'unavailable',
                'engine': engine,
                'threat': str(e),
                'action': 'warn'  # Warn but don't block if AV fails
            }
    
    @staticmethod
    def _scan_clamav(file_path):
        """
        Scan using ClamAV (requires pyclamd library).
        TODO: Implement when ClamAV infrastructure is available.
        """
        try:
            import pyclamd
            clam = pyclamd.ClamD()
            
            if not clam.ping():
                logger.warning("ClamAV daemon not available")
                return {
                    'status': 'unavailable',
                    'engine': 'clamav',
                    'threat': 'Daemon not responding',
                    'action': 'warn'
                }
            
            result = clam.scan_file(file_path)
            
            if result is None:
                return {
                    'status': 'clean',
                    'engine': 'clamav',
                    'threat': None,
                    'action': 'approve'
                }
            else:
                return {
                    'status': 'infected',
                    'engine': 'clamav',
                    'threat': str(result),
                    'action': 'reject'
                }
        except ImportError:
            logger.warning("pyclamd not installed; ClamAV scanning unavailable")
            return {
                'status': 'unavailable',
                'engine': 'clamav',
                'threat': 'pyclamd not installed',
                'action': 'warn'
            }
    
    @staticmethod
    def _scan_virustotal(file_path):
        """
        Scan using VirusTotal API.
        TODO: Implement when VirusTotal API key is available.
        """
        logger.warning("VirusTotal scanning not yet implemented")
        return {
            'status': 'unavailable',
            'engine': 'virustotal',
            'threat': 'API not configured',
            'action': 'warn'
        }
    
    @staticmethod
    def _scan_mock(file_path):
        """
        Mock scanner for development/testing.
        Performs basic pattern matching; use in development only.
        """
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Check for obvious malware signatures
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
            
            return {
                'status': 'clean',
                'engine': 'mock',
                'threat': None,
                'action': 'approve'
            }
        except Exception as e:
            logger.error(f"Mock scanner error: {str(e)}")
            return {
                'status': 'unavailable',
                'engine': 'mock',
                'threat': str(e),
                'action': 'warn'
            }


class EnhancedFileIngestionPipeline:
    """
    Enhanced file ingestion with comprehensive security:
    - Quarantine zone enforcement
    - File size validation
    - Magic number validation
    - Filename sanitization
    - Decompression bomb checks
    - Antivirus scanning with safe fallback
    - SHA-256 hashing
    - Encryption before final storage
    """
    
    def process_upload(self, uploaded_file, user, metadata):
        """
        Process file through complete security pipeline.
        Returns: {'status': 'approved'|'rejected'|'quarantined', 'error': str, ...metadata}
        """
        quarantine_path = None
        temp_path = None
        
        try:
            # STEP 1: Check file size immediately (fail fast)
            if uploaded_file.size > settings.MAX_UPLOAD_SIZE:
                max_mb = settings.MAX_UPLOAD_SIZE / (1024 * 1024)
                return {
                    'status': 'rejected',
                    'error': f'File size {uploaded_file.size} exceeds limit ({max_mb}MB)'
                }
            
            if uploaded_file.size == 0:
                return {
                    'status': 'rejected',
                    'error': 'Empty file not allowed'
                }
            
            # STEP 2: Place in quarantine zone (isolated memory/disk area)
            quarantine_dir = Path(settings.QUARANTINE_ROOT)
            quarantine_dir.mkdir(parents=True, exist_ok=True)
            
            safe_filename = self._sanitize_filename(uploaded_file.name)
            quarantine_path = quarantine_dir / safe_filename
            
            # Save to quarantine
            with open(quarantine_path, 'wb+') as destination:
                for chunk in uploaded_file.chunks():
                    destination.write(chunk)
            
            # STEP 3: Validate magic numbers (binary signature)
            validation_result = self._validate_file_type(quarantine_path)
            if not validation_result['valid']:
                return {
                    'status': 'rejected',
                    'error': validation_result['error']
                }
            
            # STEP 4: Check for decompression bombs
            if validation_result['mime_type'] == 'application/zip':
                bomb_check = DecompressionBombGuard.check_zip_bomb(str(quarantine_path))
                if not bomb_check['safe']:
                    return {
                        'status': 'rejected',
                        'error': f'Decompression bomb detected: {bomb_check["reason"]}'
                    }
            
            # STEP 5: Antivirus scanning with safe fallback
            av_engine = getattr(settings, 'AV_ENGINE', 'mock')
            scan_result = AVScannerIntegration.scan_file(str(quarantine_path), av_engine)
            
            if scan_result['status'] == 'infected':
                return {
                    'status': 'rejected',
                    'error': f'Malware detected: {scan_result.get("threat", "Unknown")}'
                }
            elif scan_result['status'] == 'suspicious':
                logger.warning(f"Suspicious file detected: {scan_result.get('threat', 'Unknown')}")
                # Log but don't reject; let user decide
                return {
                    'status': 'quarantined',
                    'error': f'File flagged as suspicious: {scan_result.get("threat", "Unknown")}. Pending manual review.'
                }
            elif scan_result['status'] == 'unavailable':
                # AV unavailable; log warning but proceed
                logger.warning(f"AV scan unavailable ({av_engine}): {scan_result.get('threat', 'Unknown')}")
            
            # STEP 6: Calculate SHA-256 hash
            file_hash = self._calculate_hash(str(quarantine_path))
            
            # STEP 7: Check for duplicates
            if Document.objects.filter(file_hash=file_hash).exists():
                return {
                    'status': 'rejected',
                    'error': 'This file already exists in the system (duplicate hash)'
                }
            
            # STEP 8: Move to temp directory before encryption
            temp_dir = Path(settings.MEDIA_ROOT) / 'temp'
            temp_dir.mkdir(parents=True, exist_ok=True)
            temp_path = temp_dir / f"{file_hash}_{safe_filename}"
            shutil.move(str(quarantine_path), str(temp_path))
            quarantine_path = None  # Already moved
            
            # STEP 9: Encrypt file with classification-level key
            from .security import FileIngestionPipeline as OriginalPipeline
            encrypted_path = OriginalPipeline().encrypt_file(str(temp_path), metadata['classification_level'])
            
            # STEP 10: Move to final storage location
            final_dir = Path(settings.MEDIA_ROOT) / 'documents' / str(metadata['classification_level'])
            final_dir.mkdir(parents=True, exist_ok=True)
            final_path = final_dir / f"{file_hash}_{safe_filename}.enc"
            shutil.move(encrypted_path, str(final_path))
            
            # STEP 11: Return success with metadata
            file_size = final_path.stat().st_size
            mime_type = validation_result.get('mime_type', 'application/octet-stream')
            
            return {
                'status': 'approved',
                'filename': safe_filename,
                'file_path': str(final_path),
                'file_size': file_size,
                'mime_type': mime_type,
                'file_hash': file_hash,
                'av_engine': av_engine,
                'av_status': scan_result['status']
            }
            
        except Exception as e:
            logger.error(f"File ingestion pipeline error: {str(e)}", exc_info=True)
            return {
                'status': 'rejected',
                'error': f'Unexpected error during file processing: {str(e)}'
            }
        
        finally:
            # Cleanup: ensure quarantine/temp files are removed
            for path in [quarantine_path, temp_path]:
                if path and os.path.exists(path):
                    try:
                        os.remove(path)
                        logger.debug(f"Cleaned up temporary file: {path}")
                    except Exception as e:
                        logger.warning(f"Could not remove temporary file {path}: {str(e)}")
    
    @staticmethod
    def _sanitize_filename(filename):
        """Sanitize filename to prevent path traversal and injection attacks."""
        import re
        
        # Remove path components
        filename = os.path.basename(filename)
        
        # Remove null bytes and control characters
        filename = filename.replace('\x00', '')
        
        # Allow only safe characters: alphanumeric, dash, underscore, dot
        filename = re.sub(r'[^\w\s.-]', '', filename)
        
        # Remove multiple dots (prevent double extensions)
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
        """Validate file type using magic numbers, not extensions."""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(512)
            
            # Magic number signatures
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
                    # Additional validation for specific types
                    if mime_type == 'application/pdf' and len(header) < 100:
                        return {
                            'valid': False,
                            'error': 'PDF file suspiciously small'
                        }
                    
                    return {
                        'valid': True,
                        'mime_type': mime_type,
                        'description': description
                    }
            
            return {
                'valid': False,
                'error': 'File type not recognized or not allowed'
            }
        
        except Exception as e:
            return {
                'valid': False,
                'error': f'File validation error: {str(e)}'
            }
    
    @staticmethod
    def _calculate_hash(file_path):
        """Calculate SHA-256 hash of file."""
        sha256_hash = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b''):
                sha256_hash.update(byte_block)
        
        return sha256_hash.hexdigest()
