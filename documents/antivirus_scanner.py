"""
documents/antivirus_scanner.py

✅ SCANNER ANTIVIRUS AUTOMATIQUE

Détecte :
- Malware connus (EICAR test)
- Scripts malveillants (cmd, powershell, bash)
- Code suspect (eval, exec, base64_decode)
- Extensions dangereuses
"""

import hashlib
import logging
import mimetypes
from pathlib import Path

logger = logging.getLogger(__name__)


class AntivirusScanner:
    """
    Scanner antivirus simple mais efficace

    Pour une version production, intégrez :
    - ClamAV (antivirus open-source)
    - VirusTotal API
    - Windows Defender API
    """

    # ✅ Signatures de malwares connus
    MALWARE_SIGNATURES = {
        # EICAR test file (standard de test antivirus)
        b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*': 'EICAR-Test-File',

        # Scripts système Windows
        b'cmd.exe': 'Windows-CMD',
        b'cmd /c': 'Windows-CMD',
        b'powershell.exe': 'PowerShell',
        b'PowerShell -': 'PowerShell',

        # Scripts Linux/Unix
        b'/bin/bash': 'Bash-Script',
        b'/bin/sh': 'Shell-Script',
        b'chmod +x': 'Chmod-Executable',
        b'curl -': 'Curl-Download',
        b'wget -': 'Wget-Download',

        # Code malveillant commun
        b'eval(': 'Eval-Injection',
        b'exec(': 'Exec-Injection',
        b'system(': 'System-Call',
        b'base64_decode': 'Base64-Decode',
        b'<?php system': 'PHP-System',
        b'<script>alert': 'XSS-Script',
        b'document.cookie': 'Cookie-Theft',
        b'<iframe src=': 'Iframe-Injection',
    }

    # ✅ Extensions dangereuses
    DANGEROUS_EXTENSIONS = {
        '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js',
        '.jar', '.msi', '.dll', '.sys', '.drv', '.cpl', '.ocx',
        '.app', '.deb', '.rpm', '.dmg', '.pkg',
        '.sh', '.bash', '.zsh', '.fish',
        '.ps1', '.psm1',  # PowerShell
    }

    # ✅ Types MIME suspects
    SUSPICIOUS_MIME_TYPES = {
        'application/x-msdownload',  # .exe
        'application/x-msdos-program',
        'application/x-executable',
        'application/x-sharedlib',
        'application/x-sh',
        'application/x-shellscript',
        'text/x-python',  # Scripts Python peuvent être dangereux
        'text/x-php',
        'application/javascript',
        'application/x-javascript',
    }

    def __init__(self):
        self.scan_count = 0
        self.threats_found = 0

    def scan_bytes(self, file_content, filename):
        """
        Scan le contenu d'un fichier

        Args:
            file_content (bytes): Contenu du fichier
            filename (str): Nom du fichier

        Returns:
            dict: {
                'status': 'clean'|'infected'|'suspicious'|'error',
                'threat_name': str ou None,
                'scanner': 'Pattern-Match',
                'details': str
            }
        """
        self.scan_count += 1

        try:
            # ========================================
            # ÉTAPE 1 : Vérifier l'extension
            # ========================================
            file_ext = Path(filename).suffix.lower()

            if file_ext in self.DANGEROUS_EXTENSIONS:
                logger.warning(f"Dangerous extension detected: {file_ext} in {filename}")
                self.threats_found += 1
                return {
                    'status': 'infected',
                    'threat_name': f'Dangerous-Extension-{file_ext}',
                    'scanner': 'Extension-Check',
                    'details': f'Extension {file_ext} is not allowed'
                }

            # ========================================
            # ÉTAPE 2 : Vérifier le type MIME
            # ========================================
            mime_type, _ = mimetypes.guess_type(filename)

            if mime_type in self.SUSPICIOUS_MIME_TYPES:
                logger.warning(f"Suspicious MIME type detected: {mime_type} in {filename}")
                self.threats_found += 1
                return {
                    'status': 'infected',
                    'threat_name': f'Suspicious-MIME-{mime_type}',
                    'scanner': 'MIME-Check',
                    'details': f'MIME type {mime_type} is not allowed'
                }

            # ========================================
            # ÉTAPE 3 : Scan des signatures
            # ========================================
            content_lower = file_content.lower()

            for signature, threat_name in self.MALWARE_SIGNATURES.items():
                if signature.lower() in content_lower:
                    logger.warning(
                        f"MALWARE DETECTED: {threat_name} in {filename} "
                        f"(signature: {signature[:30]})"
                    )
                    self.threats_found += 1
                    return {
                        'status': 'infected',
                        'threat_name': threat_name,
                        'scanner': 'Signature-Match',
                        'details': f'Malicious pattern detected: {threat_name}'
                    }

            # ========================================
            # ÉTAPE 4 : Heuristique (détection avancée)
            # ========================================
            suspicious_score = 0

            # Trop de code obfusqué
            if content_lower.count(b'eval') > 5:
                suspicious_score += 10

            # Base64 suspect
            if content_lower.count(b'base64') > 3:
                suspicious_score += 5

            # Appels système multiples
            if content_lower.count(b'exec') > 3:
                suspicious_score += 10

            if suspicious_score > 15:
                logger.warning(f"Heuristic detection: suspicious score {suspicious_score} for {filename}")
                self.threats_found += 1
                return {
                    'status': 'infected',
                    'threat_name': 'Heuristic-Suspicious',
                    'scanner': 'Heuristic-Analysis',
                    'details': f'Suspicious score: {suspicious_score}/100'
                }

            # ========================================
            # ÉTAPE 5 : Fichier propre
            # ========================================
            logger.info(f"✅ File CLEAN: {filename} ({len(file_content)} bytes)")

            return {
                'status': 'clean',
                'threat_name': None,
                'scanner': 'Full-Scan',
                'details': f'No threats detected in {len(file_content)} bytes',
                'file_hash': hashlib.sha256(file_content).hexdigest()
            }

        except Exception as e:
            logger.error(f"Scan error for {filename}: {e}", exc_info=True)
            return {
                'status': 'error',
                'threat_name': None,
                'scanner': 'Error',
                'details': str(e),
                'error': str(e)
            }

    def scan_file(self, file_path):
        """
        Scan un fichier sur le disque

        Args:
            file_path (str|Path): Chemin du fichier

        Returns:
            dict: Résultat du scan
        """
        file_path = Path(file_path)

        if not file_path.exists():
            return {
                'status': 'error',
                'threat_name': None,
                'scanner': 'File-Not-Found',
                'details': f'File not found: {file_path}',
                'error': 'File not found'
            }

        try:
            with open(file_path, 'rb') as f:
                content = f.read()

            return self.scan_bytes(content, file_path.name)

        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return {
                'status': 'error',
                'threat_name': None,
                'scanner': 'Read-Error',
                'details': str(e),
                'error': str(e)
            }

    def get_stats(self):
        """Retourne les statistiques du scanner"""
        return {
            'total_scans': self.scan_count,
            'threats_found': self.threats_found,
            'clean_files': self.scan_count - self.threats_found,
        }


# ============================================
# INTÉGRATION CLAMAV (OPTIONNEL - Production)
# ============================================

class ClamAVScanner:
    """
    ✅ POUR PRODUCTION : Intégration avec ClamAV

    Installation :
    ```bash
    # Ubuntu/Debian
    sudo apt-get install clamav clamav-daemon python3-pyclamd

    # macOS
    brew install clamav

    # Python
    pip install pyclamd
    ```
    """

    def __init__(self):
        try:
            import pyclamd
            self.cd = pyclamd.ClamdUnixSocket()
            # Test connection
            if not self.cd.ping():
                raise Exception("ClamAV daemon not responding")
            logger.info("✅ ClamAV scanner initialized")
        except ImportError:
            logger.warning("⚠️ pyclamd not installed, falling back to pattern scanner")
            self.cd = None
        except Exception as e:
            logger.warning(f"⚠️ ClamAV not available: {e}")
            self.cd = None

    def scan_bytes(self, file_content, filename):
        """Scan avec ClamAV"""
        if not self.cd:
            # Fallback to pattern scanner
            scanner = AntivirusScanner()
            return scanner.scan_bytes(file_content, filename)

        try:
            result = self.cd.scan_stream(file_content)

            if result is None:
                # Clean
                return {
                    'status': 'clean',
                    'threat_name': None,
                    'scanner': 'ClamAV',
                    'details': 'No virus detected'
                }
            else:
                # Infected
                threat = result.get('stream', ['UNKNOWN'])[1] if result else 'UNKNOWN'
                return {
                    'status': 'infected',
                    'threat_name': threat,
                    'scanner': 'ClamAV',
                    'details': f'Virus detected: {threat}'
                }

        except Exception as e:
            logger.error(f"ClamAV scan error: {e}")
            return {
                'status': 'error',
                'threat_name': None,
                'scanner': 'ClamAV-Error',
                'details': str(e),
                'error': str(e)
            }


# ============================================
# FACTORY : Choisir le bon scanner
# ============================================

def get_scanner():
    """
    Retourne le meilleur scanner disponible

    Ordre de priorité :
    1. ClamAV (si disponible)
    2. Pattern Scanner (fallback)
    """
    try:
        clamav = ClamAVScanner()
        if clamav.cd:
            logger.info("Using ClamAV scanner")
            return clamav
    except:
        pass

    logger.info("Using Pattern scanner")
    return AntivirusScanner()