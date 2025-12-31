"""Custom exceptions for VulneraAI."""

class VulneraAIException(Exception):
    """Base exception for VulneraAI."""
    pass

class AnalysisException(VulneraAIException):
    """Raised during vulnerability analysis failures."""
    pass

class AIServiceException(VulneraAIException):
    """Raised when AI service calls fail."""
    pass

class ValidationException(VulneraAIException):
    """Raised for validation errors."""
    pass

class DatabaseException(VulneraAIException):
    """Raised for database operation failures."""
    pass

class ReportGenerationException(VulneraAIException):
    """Raised during report generation failures."""
    pass
