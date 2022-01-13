from __future__ import annotations
from typing import Optional


class ProtonError(Exception):
    """Base class for Proton API specific exceptions"""
    def __init__(self, message, additional_context=None):
        self.message = message
        self.additional_context = additional_context
        super().__init__(self.message)

class ProtonCryptoError(ProtonError):
    """Exception thrown when something is wrong on the crypto side. 
    In general this has to be handled as being fatal, as something is super-wrong."""

class ProtonAPIError(ProtonError):
    """Exception that is raised whenever the API call didn't return a 1000/1001 code.
    Logic for handling these depend on the call (see API doc)
    """

    def __init__(self, http_code, http_headers, json_data):
        self._http_code = http_code
        self._http_headers = http_headers
        self._json_data = json_data

        super().__init__(f'[HTTP/{self.http_code}, {self.body_code}] {self.error}')

    @property
    def http_code(self) -> int:
        """:return: HTTP error code (401, 403, 422...)
        :rtype: int
        """
        return self._http_code

    @property
    def http_headers(self) -> dict:
        """:return: Dictionary of HTTP headers of the error reply
        :rtype: dict
        """
        return self._http_headers

    @property
    def json_data(self) -> dict:
        """:return: JSON data of the error reply
        :rtype: dict
        """
        return self._json_data

    @property
    def body_code(self) -> int:
        """:return: Body error code ("Code" in JSON)
        :rtype: int
        """
        return self._json_data['Code']
    
    @property
    def error(self) -> str:
        """:return: Body error message ("Error" in JSON)
        :rtype: str
        """
        return self._json_data['Error']

    @classmethod
    def from_proton_api_error(cls, e : "ProtonAPIError"):
        """Construct an instance of this class, based on a ProtonAPIError (this allows to downcast to a more specific exception)

        :param e: Initial API exception
        :type e: ProtonAPIError
        :return: An instance of the current class
        :rtype: Any
        """
        return cls(e._http_code, e._http_headers, e._json_data)

class ProtonAPINotReachable(ProtonError):
    """Exception thrown when the transport couldn't reach the API.
    
    One may try using a different transport, or later if the error is transient."""

class ProtonAPINotAvailable(ProtonError):
    """Exception thrown when the API is reachable (i.e. at the TLS level), but doesn't work. 
    
    This is definitive for that transport, it will not work by retrying in the same conditions."""

class ProtonAPIUnexpectedError(ProtonError):
    """Something went wrong, but we don't know how to handle it. Good luck :-)"""

class ProtonAPIAuthenticationNeeded(ProtonAPIError):
    """We tried to call a route that requires authentication, but we don't have it.
    
    This should be solved by calling session.authenticate() with valid credentials"""

class ProtonAPI2FANeeded(ProtonAPIError):
    """We need 2FA authentication, but it's not done yet.
    
    This should be solved by calling session.provide_2fa() with valid 2FA"""

class ProtonAPIMissingScopeError(ProtonAPIError):
    """We don't have a required scope.
    
    This might be because of user rights, but also might require a call to unlock."""

class ProtonAPIHumanVerificationNeeded(ProtonAPIError):
    """Human verification is needed for this API call to succeed."""

    @property
    def HumanVerificationToken(self) -> Optional[str]:
        """Get the Token for human verification"""
        return self.json_data.get('Details', {}).get('HumanVerificationToken', None)

    @property
    def HumanVerificationMethods(self) -> list[str]:
        """Return a list of allowed human verification methods.

        :return: human verification methods
        :rtype: list[str]
        """
        return self.json_data.get('Details', {}).get('Methods', [])
