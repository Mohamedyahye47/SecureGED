FILE_UPLOAD_HANDLERS = [
    'secure_ged.upload_handlers.EncryptedUploadHandler',  # Premier → chiffre avant les autres
    'django.core.files.uploadhandler.MemoryFileUploadHandler',
    'django.core.files.uploadhandler.TemporaryFileUploadHandler',
]