from typing import *

from proton import session
from .exceptions import ProtonCryptoError, ProtonAPIError, ProtonAPIAuthenticationNeeded, ProtonAPI2FANeeded, ProtonAPIMissingScopeError, ProtonAPIHumanVerificationNeeded
from .srp import User as PmsrpUser
from .environments import Environment

import asyncio
import base64
import random

SRP_MODULUS_KEY = """-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEXAHLgxYJKwYBBAHaRw8BAQdAFurWXXwjTemqjD7CXjXVyKf0of7n9Ctm
L8v9enkzggHNEnByb3RvbkBzcnAubW9kdWx1c8J3BBAWCgApBQJcAcuDBgsJ
BwgDAgkQNQWFxOlRjyYEFQgKAgMWAgECGQECGwMCHgEAAPGRAP9sauJsW12U
MnTQUZpsbJb53d0Wv55mZIIiJL2XulpWPQD/V6NglBd96lZKBmInSXX/kXat
Sv+y0io+LR8i2+jV+AbOOARcAcuDEgorBgEEAZdVAQUBAQdAeJHUz1c9+KfE
kSIgcBRE3WuXC4oj5a2/U3oASExGDW4DAQgHwmEEGBYIABMFAlwBy4MJEDUF
hcTpUY8mAhsMAAD/XQD8DxNI6E78meodQI+wLsrKLeHn32iLvUqJbVDhfWSU
WO4BAMcm1u02t4VKw++ttECPt+HUgPUq5pqQWe5Q2cW4TMsE
=Y4Mw
-----END PGP PUBLIC KEY BLOCK-----"""

SRP_MODULUS_KEY_FINGERPRINT = "248097092b458509c508dac0350585c4e9518f26"


def sync_wrapper(f):
    def wrapped_f(*a, **kw):
        try:
            loop = asyncio.get_running_loop()
            newloop = False
        except RuntimeError:
            newloop = True

        if not newloop:
            raise RuntimeError("It's forbidden to call sync_wrapped functions from an async one, please await directly the async one")
        
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(f(*a, **kw))
        finally:
            loop.close()
    wrapped_f.__doc__ = f"Synchronous wrapper for :meth:`{f.__name__}`"
    return wrapped_f

class Session:
    def __init__(self, appversion : str = "Other", user_agent:str="None"):
        """Get a session towards the Proton API.

        :param appversion: version for the new Session object, defaults to ``"Other"``
        :type appversion: str, optional
        :param user_agent: user agent to use, defaults to ``"None"``. It should be of the following syntax:

          * Linux based -> ``ClientName/client.version (Linux; Distro/distro_version)``
          * Non-linux based -> ``ClientName/client.version (OS)``

        :type user_agent: str, optional
        """
        self.__appversion = appversion
        self.__user_agent = user_agent

        self.__UID = None
        self.__AccessToken = None
        self.__RefreshToken = None
        self.__Scopes = None

        self.__AccountName = None

        # Temporary storage for 2FA object
        self.__2FA = None

        #Refresh revision (incremented each time a refresh is done)
        #This allows knowing if a refresh should be done or if it is already in progress
        self.__refresh_revision = 0

        #Lazy initialized by modulus decryption
        self.__gnupg_for_modulus = None

        #Lazy initialized by api request
        self.__transport = None
        self.__transport_factory = None

        self.transport_factory = None

        #Lazy initialized by request lock/unlock
        self.__can_run_requests = None

        #Lazy initialized by environment:
        self.__environment = None

        self.__persistence_observers = []

    def register_persistence_observer(self, observer: object):
        """Register an observer that will be notified of any persistent state change of the session

        :param observer: Observer to register. It has to provide the following interface (see :class:`proton.sso.ProtonSSO` for an actual implementation):

          * ``_acquire_session_lock(account_name : str, session_data : dict)``
          * ``_release_session_lock(account_name : str, new_session_data : dict)``

        :type observer: object
        """
        self.__persistence_observers.append(observer)

    def _clear_local_data(self) -> None:
        """Clear locally cache data for logout (or equivalently, when the session is "lost")."""
        self.__UID = None
        self.__AccessToken = None
        self.__RefreshToken = None
        self.__Scopes = None
        self.__2FA = None

    @property
    def transport_factory(self):
        return self.__transport_factory

    @transport_factory.setter
    def transport_factory(self, new_transport_factory):
        from .transports import TransportFactory
        from ..loader import Loader

        self.__transport = None
        # If we don't set a new transport factory, then let's create a default one
        if new_transport_factory is None:
            default_transport = Loader.get('transport')
            self.__transport_factory = TransportFactory(default_transport)
        elif isinstance(new_transport_factory, TransportFactory):
            self.__transport_factory = new_transport_factory
        else:
            self.__transport_factory = TransportFactory(new_transport_factory)

    @property
    def appversion(self) -> str:
        return self.__appversion

    @property
    def user_agent(self) -> str:
        return self.__user_agent

    @property
    def authenticated(self) -> bool:
        return self.__UID is not None
    
    @property
    def UID(self) -> str:
        return self.__UID

    @property
    def Scopes(self) -> list[str]:
        return self.__Scopes

    @property
    def AccountName(self):
        return self.__AccountName

    @property
    def needs_twofa(self):
        if self.Scopes is None:
            return False
        return 'twofactor' in self.Scopes

    @property
    def environment(self):
        if self.__environment is None:
            from proton.loader import Loader
            self.__environment = Loader.get('environment')()
        return self.__environment

    @environment.setter
    def environment(self, newvalue):
        # Do nothing if we set to None
        if newvalue is None:
            return
        if isinstance(newvalue, str):
            newvalue = Environment.get_environment(newvalue)
        if not isinstance(newvalue, Environment):
            raise TypeError("environment should be a subclass of Environment")

        #Same environment => nothing to do
        if self.__environment == newvalue:
            return
        
        if self.__environment is not None:
            raise ValueError("Cannot change environment of an established session (that would create security issues)!")
        self.__environment = newvalue

    def __setstate__(self, data):
        self.__UID = data.get('UID', None)
        self.__AccessToken = data.get('AccessToken', None)
        self.__RefreshToken = data.get('RefreshToken', None)
        self.__Scopes = data.get('Scopes', None)
        self.__AccountName = data.get('AccountName', None)
        #Reset transport (user agent etc might have changed)
        self.__transport = None
        #get environment as stored in the session
        self.__environment = Environment.get_environment(data.get('Environment', None))

    def __getstate__(self):
        # If we don't have an UID, then we're not logged in and we don't want to store a state
        if self.UID is None:
            return {}

        data = {
            #Session data
            'UID': self.UID,
            'AccessToken': self.__AccessToken,
            'RefreshToken': self.__RefreshToken,
            'Scopes': self.Scopes,
            'Environment': self.environment.name,
            'AccountName': self.__AccountName
        }

        return data

    def _requests_lock(self, no_condition_check=False):
        if no_condition_check:
            return
        
        if self.__can_run_requests is None:
            self.__can_run_requests = asyncio.Event()
        self.__can_run_requests.clear()

        # Lock observers (we're about to modify the session)
        account_name = self.AccountName
        session_data = self.__getstate__()
        for observer in self.__persistence_observers:
            observer._acquire_session_lock(account_name, session_data)

    def _requests_unlock(self, no_condition_check=False):
        if no_condition_check:
            return
        
        if self.__can_run_requests is None:
            self.__can_run_requests = asyncio.Event()
        self.__can_run_requests.set()

        # Unlock observers (we might have modified the session)
        # It's important to do it in reverse order, as otherwise there's a risk of deadlocks
        account_name = self.AccountName
        session_data = self.__getstate__()
        for observer in reversed(self.__persistence_observers):
            observer._release_session_lock(account_name, session_data)

    async def _requests_wait(self, no_condition_check=False):
        if no_condition_check or self.__can_run_requests is None:
            return
        
        await self.__can_run_requests.wait()

    async def async_api_request(self, endpoint,
        jsondata=None, additional_headers=None,
        method=None, params=None, no_condition_check=False):

        # We might need to loop
        attempts = 3
        while attempts > 0:
            attempts -= 1
            try:
                refresh_revision_at_start = self.__refresh_revision
                return await self.__async_api_request_internal(endpoint, jsondata, additional_headers, method, params, no_condition_check)
            except ProtonAPIError as e:
                # We have a missing scope.
                if e.http_code == 403:
                    # If we need a 2FA authentication, then ask for it by sending a specific exception.
                    if self.needs_twofa:
                        raise ProtonAPI2FANeeded.from_proton_api_error(e)
                    else:
                        # Otherwise, just throw the 403
                        raise ProtonAPIMissingScopeError.from_proton_api_error(e)
                #401: token expired
                elif e.http_code == 401:
                    #If we can refresh, than do it and retry
                    if await self.async_refresh(only_when_refresh_revision_is=refresh_revision_at_start, no_condition_check=no_condition_check):
                        continue
                    #Else, fail :-(
                    else:
                        raise ProtonAPIAuthenticationNeeded.from_proton_api_error(e)
                #422 + 9001: Human verification needed
                elif e.http_code == 422 and e.body_code == 9001:
                    raise ProtonAPIHumanVerificationNeeded.from_proton_api_error(e)
                #Invalid human verification token
                elif e.body_code == 12087:
                    raise ProtonAPIHumanVerificationNeeded.from_proton_api_error(e)
                #These are codes which require and immediate retry
                elif e.http_code in (408, 502):
                    continue
                #These not, let's retry more gracefully
                elif e.http_code in (429, 503):
                    await self.__sleep_for_exception(e)
                    continue
                #Something else, throw
                raise

    async def __sleep_for_exception(self, e):
        if e.http_headers.get('retry-after','-').isnumeric():
            await asyncio.sleep(int(e.http_headers.get('retry-after')))
        else:
            await asyncio.sleep(3+random.random()*5) # nosec (no crypto risk here of using an unsafe generator)

    async def __async_api_request_internal(
        self, endpoint,
        jsondata=None, additional_headers=None,
        method=None, params=None, no_condition_check=False
    ):
        """Make API request.

        Args:
            endpoint (string): API endpoint
            jsondata (json): json for the body to attach to the request
                (if files or data is not specified)
            additional_headers (dict): additional (dictionary of) headers to send
            method (string): get|post|put|delete|patch
            params: URL parameters to append to the URL. If a dictionary or
                list of tuples ``[(key, value)]`` is provided, form-encoding will
                take place.
            no_condition_check: do not check if we can run requests (handled by caller)

        Returns:
            Dictionary of obtained from the json data in the reply

        Raises:
            ProtonAPIError: if something went wrong with that call
        """
        # Should (and can we) create a transport
        if self.__transport is None and self.__transport_factory is not None:
            self.__transport = self.__transport_factory(self)
        if self.__transport is None:
            raise RuntimeError("Could not instanciate a transport, are required dependencies installed?")

        await self._requests_wait(no_condition_check)
        return await self.__transport.async_api_request(endpoint, jsondata, additional_headers, method, params)

    def _verify_modulus(self, armored_modulus) -> bytes:
        if self.__gnupg_for_modulus is None:
            import gnupg
            # Verify modulus
            self.__gnupg_for_modulus = gnupg.GPG()
            self.__gnupg_for_modulus.import_keys(SRP_MODULUS_KEY)

        # gpg.decrypt verifies the signature too, and returns the parsed data.
        # By using gpg.verify the data is not returned
        verified = self.__gnupg_for_modulus.decrypt(armored_modulus)

        if not (verified.valid and verified.fingerprint.lower() == SRP_MODULUS_KEY_FINGERPRINT):
            raise ProtonCryptoError('Invalid modulus')

        return base64.b64decode(verified.data.strip())

    async def async_authenticate(self, username: str, password: str, no_condition_check:bool=False) -> bool:
        """Authenticate against Proton API

        :param username: Proton account username
        :type username: str
        :param password: Proton account password
        :type password: str
        :param no_condition_check: Internal flag to disable locking, defaults to False
        :type no_condition_check: bool, optional
        :return: True if authentication succeeded, False otherwise.
        :rtype: bool
        """
        self._requests_lock(no_condition_check)

        await self.async_logout(no_condition_check=True)

        try:
            info_response = await self.__async_api_request_internal("/auth/info", {"Username": username}, no_condition_check=True)

            modulus = self._verify_modulus(info_response['Modulus'])
            server_challenge = base64.b64decode(info_response["ServerEphemeral"])
            salt = base64.b64decode(info_response["Salt"])
            version = info_response["Version"]

            usr = PmsrpUser(password, modulus)
            client_challenge = usr.get_challenge()
            client_proof = usr.process_challenge(salt, server_challenge, version)

            if client_proof is None:
                raise ProtonCryptoError('Invalid challenge')

            # Send response
            payload = {
                "Username": username,
                "ClientEphemeral": base64.b64encode(client_challenge).decode(
                    'utf8'
                ),
                "ClientProof": base64.b64encode(client_proof).decode('utf8'),
                "SRPSession": info_response["SRPSession"],
            }
            try:
                auth_response = await self.__async_api_request_internal("/auth", payload, no_condition_check=True)
            except ProtonAPIError as e:
                if e.body_code == 8002:
                    return False
                raise

            if "ServerProof" not in auth_response:
                return False

            usr.verify_session(base64.b64decode(auth_response["ServerProof"]))
            if not usr.authenticated():
                raise ProtonCryptoError('Invalid server proof')

            self.__UID = auth_response['UID']
            self.__AccessToken = auth_response['AccessToken']
            self.__RefreshToken = auth_response['RefreshToken']
            self.__Scopes = auth_response["Scopes"]
            self.__AccountName = username

            if '2FA' in auth_response:
                self.__2FA = auth_response['2FA']
            else:
                self.__2FA = None

            return True
        finally:
            self._requests_unlock(no_condition_check)

    

    async def async_provide_2fa(self, code, no_condition_check=False):
        """Provide Two Factor Authentication Code to the API.

        Args:
            code (string): string of ints

        Returns:
            True if successful, False otherwise

        The returning dict contains the Scopes of the account. This allows
        to identify if the account is locked, has unpaid invoices, etc.
        """
        self._requests_lock(no_condition_check)
        try:
            ret = await self.__async_api_request_internal('/auth/2fa', {
                "TwoFactorCode": code
            }, no_condition_check=True)
            self.__Scopes = ret['Scopes']
            if ret.get('Code') == 1000:
                self.__2FA = None
                return True
            
            return False
        except ProtonAPIError as e:
            if e.body_code == 8002:
                # 2FA jail, we need to start over (beware, we might hit login jails too)
                #Needs re-login
                self._clear_local_data()
                raise ProtonAPIAuthenticationNeeded.from_proton_api_error(e)
            if e.http_code == 401:
                return False
            raise
        finally:
            self._requests_unlock(no_condition_check)

    async def async_refresh(self, only_when_refresh_revision_is=None, no_condition_check=False):
        """Refresh tokens.

        Refresh AccessToken with a valid RefreshToken.
        If the RefreshToken is invalid then the user will have to
        re-authenticate.

        Returns:
            True if successful, False otherwise (doesn't throw an exception)
        """
        self._requests_lock(no_condition_check)

        #If we have the correct revision, and it doesn't match, then just exit
        if only_when_refresh_revision_is is not None and self.__refresh_revision != self.__refresh_revision:
            self._requests_unlock(no_condition_check)
            return True

        #Increment the refresh revision counter, so we don't refresh multiple times
        self.__refresh_revision += 1

        attempts = 3

        try:
            while attempts > 0:
                attempts -= 1
                try:
                    refresh_response = await self.__async_api_request_internal('/auth/refresh', {
                        "ResponseType": "token",
                        "GrantType": "refresh_token",
                        "RefreshToken": self.__RefreshToken,
                        "RedirectURI": "http://protonmail.ch"
                    }, no_condition_check=True)
                    self.__AccessToken = refresh_response["AccessToken"]
                    self.__RefreshToken = refresh_response["RefreshToken"]
                    self.__Scopes = refresh_response["Scopes"]
                    return True

                except ProtonAPIError as e:
                    #https://confluence.protontech.ch/display/API/Authentication%2C+sessions%2C+and+tokens#Authentication,sessions,andtokens-RefreshingSessions
                    if e.http_code == 409:
                        #409 Conflict - Indicates a race condition on the DB, and the request should be performed again
                        continue
                    #We're probably jailed, just retry later
                    elif e.http_code in (429, 503):
                        await self.__sleep_for_exception(e)
                        continue
                    elif e.http_code in (400, 422):
                        #Needs re-login
                        self._clear_local_data()
                        return False
                    return False
        finally:
            self._requests_unlock(no_condition_check)



    async def async_logout(self, no_condition_check=False):
        """Logout from API.
        
        Returns:
            True if logout was successful (or nothing was done)
        Raises:
            ProtonAPIError: in case something wrong happened (invalid token are ignored if the session is already invalid)
        """
        # No-op if not authenticated
        if not self.authenticated:
            return True

        self._requests_lock(no_condition_check)
        try:
            ret = await self.__async_api_request_internal('/auth', method='DELETE', no_condition_check=True)
             # Erase any information we have about the session
            self._clear_local_data()
            return True
        except ProtonAPIError as e:
            #If the token is already invalid, just ignore... otherwise raise
            if e.code != 401:
                raise
        finally:
            self._requests_unlock(no_condition_check)

    async def async_lock(self, no_condition_check=False):
        """ Lock the current user (remove PASSWORD and LOCKED scopes)"""

        self._requests_lock(no_condition_check)
        try:
            ret = await self.__async_api_request_internal('/users/lock', method='PUT', no_condition_check=True)
            ret = await self.__async_api_request_internal('/auth/scopes', no_condition_check=True)
            self.__Scopes = ret['Scopes']
            return True
        finally:
            self._requests_unlock(no_condition_check)

    #FIXME: implement unlock

    async def async_human_verif_request_code(self, address=None, phone=None):
        """Request a verification code. Either address (email address) or phone (phone number) should be specified."""
        assert address is not None ^ phone is not None # nosec (we use email validation by default if both are provided, but it's not super clean if the dev doesn't know about it)

        if address is not None:
            data = {'Type': 'email', 'Destination': {'Address': address}}
        elif phone is not None:
            data = {'Type': 'sms', 'Destination': {'Phone': phone}}
        
        return await self.async_api_request('/users/code', data).get('Code', 0) == 1000

    async def async_human_verif_provide_token(self, method, token):
        pass
    

    # Wrappers to provide non-asyncio API
    api_request = sync_wrapper(async_api_request)
    authenticate = sync_wrapper(async_authenticate)
    provide_2fa = sync_wrapper(async_provide_2fa)
    logout = sync_wrapper(async_logout)
    refresh = sync_wrapper(async_refresh)
    lock = sync_wrapper(async_lock)
    human_verif_request_code = sync_wrapper(async_human_verif_request_code)
    human_verif_provide_token = sync_wrapper(async_human_verif_provide_token)


