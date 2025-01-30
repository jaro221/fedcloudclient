"""
Define custom exceptions for fedcloudclient
"""
class PyJWTError(Exception):
    """
    Base class for all exceptions
    """

    pass

class InvalidTokenError(PyJWTError):
    pass


class FedcloudError(Exception):
    """
    Master class for all custom exception in fedcloudclient
    """
    ...


class TokenError(FedcloudError):
    """
    Authentication error, token not initialized and so on
    """
    ...


class ServiceError(FedcloudError):
    """
    Connection timeout, service not available and so on
    """
    ...


class ConfigError(FedcloudError):
    """
    Configuration error, files not exists and so on
    """
    ...
