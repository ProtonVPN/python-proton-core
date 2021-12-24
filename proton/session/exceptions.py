class ProtonError(Exception):
    def __init__(self, message, additional_context=None):
        self.message = message
        self.additional_context = additional_context
        super().__init__(self.message)

class ProtonCryptoError(ProtonError):
    """Exception thrown when something is wrong on the crypto side. 
    In general this has to be handled as being fatal, as something is super-wrong."""

class ProtonAPIError(ProtonError):
    """Exception that is raised whenever the API call didn't return a 1000/1001 code.
    Logic for handling these depend on the call (see API doc)"""
    def __init__(self, http_code, http_headers, json_data):
        self.http_code = http_code
        self.http_headers = http_headers
        self.json_data = json_data

        super().__init__(f'[HTTP/{self.http_code}, {self.body_code}] {self.error}')

    @property
    def body_code(self):
        return self.json_data['Code']
    
    @property
    def error(self):
        return self.json_data['Error']

    @classmethod
    def from_proton_api_error(cls, e):
        """This is a constructor allowing to downcast an exception"""
        return cls(e.http_code, e.http_headers, e.json_data)

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
    """Human verification is needed for this call to be able to happen."""
    def __init__(self, *a, **kw):
        print("ProtonAPIHumanVerificationNeeded", *a, **kw)
        super().__init__(*a,**kw)

    @property
    def HumanVerificationToken(self):
        return self.json_data.get('Details', {}).get('HumanVerificationToken', None)

    @property
    def Methods(self):
        return self.json_data.get('Details', {}).get('Methods', [])
