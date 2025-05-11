"""
Custom exceptions for the application.
"""

class AuthenticationError(Exception):
    """Raised when authentication fails."""
    pass

class AuthorizationError(Exception):
    """Raised when authorization fails."""
    pass

class ScanError(Exception):
    """Raised when a scan operation fails."""
    pass

class ReportError(Exception):
    """Raised when report generation fails."""
    pass

class ConfigurationError(Exception):
    """Raised when there is a configuration error."""
    pass

class DatabaseError(Exception):
    """Raised when a database operation fails."""
    pass 

class ValidationError(Exception):
    """Raised when input validation fails."""
    pass

class CredentialError(Exception):
    """Raised when credential-related errors occur."""
    pass
