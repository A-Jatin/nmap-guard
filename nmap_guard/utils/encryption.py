"""
Encryption utilities for the application.
"""

from cryptography.fernet import Fernet
from ..core.config import settings
from ..utils.logging import get_logger

logger = get_logger(__name__)

def get_encryption_key() -> bytes:
    """Get encryption key from settings."""
    return settings.ENCRYPTION_KEY.encode()

def encrypt_data(data: str) -> str:
    """
    Encrypt data using Fernet symmetric encryption.
    
    Args:
        data: String data to encrypt
        
    Returns:
        Encrypted data as string
    """
    try:
        key = get_encryption_key()
        f = Fernet(key)
        encrypted_data = f.encrypt(data.encode())
        return encrypted_data.decode()
    except Exception as e:
        logger.error(f"Encryption failed: {str(e)}")
        raise

def decrypt_data(encrypted_data: str) -> str:
    """
    Decrypt data using Fernet symmetric encryption.
    
    Args:
        encrypted_data: Encrypted data as string
        
    Returns:
        Decrypted data as string
    """
    try:
        key = get_encryption_key()
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data.encode())
        return decrypted_data.decode()
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        raise 