"""
Copyright (c) 2023 Proton AG

This file is part of Proton.

Proton is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Proton is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
"""
from __future__ import annotations

from pathlib import Path
from typing import *

from .exceptions import ProtonCryptoError, ProtonAPIError, ProtonAPIAuthenticationNeeded, ProtonAPI2FANeeded, ProtonAPIMissingScopeError, ProtonAPIHumanVerificationNeeded
from .srp import User as PmsrpUser
from .environments import Environment
from ..loader import Loader

import asyncio
import base64
import random

from ..utils import ExecutionEnvironment

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

        #Extra data that we want to persist (used if we load a session from a subclass)
        self.__extrastate = {}

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


    async def async_api_request(self, endpoint,
        jsondata=None, data=None, additional_headers=None,
        method=None, params=None, no_condition_check=False,
        return_raw=False):
        """Do an API request.

        This call can return any of the exceptions defined in :mod:`proton.session.exceptions`.

        :param endpoint: API endpoint
        :type endpoint: str
        :param jsondata: JSON serializable dict to send as request data
        :type jsondata: dict
        :param data: data to be sent as either `multipart/form-data` or
            `application/x-www-form-urlencoded`. `multipart/form-data` is used
            when required, for example if data includes fields with a file-like
            value (i.e. is an instance of io.IOBase).
        :type data: FormData
        :param additional_headers: additional headers to send
        :type additional_headers: dict
        :param method: HTTP method (get|post|put|delete|patch)
        :type method: str
        :param params: URL parameters to append to the URL. If a dictionary or
            list of tuples ``[(key, value)]`` is provided, form-encoding will
            take place.
        :type params: str, dict or iterable
        :param no_condition_check: Internal flag to disable locking, defaults to False
        :type no_condition_check: bool, optional
        :param return_raw: If set to true, the function will return a :class:`RawResponse` object
            instead of a dict, this class contains the header and status information along with the
            json response.
        :type return_raw: bool, optional

        :return: Deserialized JSON reply or a RawResponse object if return_raw is True
        :rtype: dict | RawResponse
        """

        # We might need to loop
        attempts = 3
        stored_exception = None  # in case of too many attempts, raise instead of returning None
        while attempts > 0:
            attempts -= 1
            try:
                refresh_revision_at_start = self.__refresh_revision
                return await self.__async_api_request_internal(endpoint, jsondata, data, additional_headers, method, params, no_condition_check,
                                                               return_raw=return_raw)
            except ProtonAPIError as e:
                stored_exception = e
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
        raise stored_exception  # if we have reached that point without returning any value, an exception should have been stored

    async def async_authenticate(self, username: str, password: str, client_secret: str = None, no_condition_check: bool = False, additional_headers=None) -> bool:
        """Authenticate against Proton API

        :param username: Proton account username
        :type username: str
        :param password: Proton account password
        :type password: str
        :param client_secret: Client Secret for SRP
        :type client_secret: str, optional
        :param no_condition_check: Internal flag to disable locking, defaults to False
        :type no_condition_check: bool, optional
        :param additional_headers: additional headers to send
        :type additional_headers: dict
        :return: True if authentication succeeded, False otherwise.
        :rtype: bool
        """
        self._requests_lock(no_condition_check)

        await self.async_logout(no_condition_check=True)

        try:
            req_data = {"Username": username}
            if client_secret is not None:
                req_data["ClientSecret"] = client_secret
            info_response = await self.__async_api_request_internal("/auth/info", req_data,
                                                                    no_condition_check=True,
                                                                    additional_headers=additional_headers)

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
            if client_secret is not None:
                payload["ClientSecret"] = client_secret
            try:
                auth_response = await self.__async_api_request_internal("/auth", payload, no_condition_check=True,
                                                                        additional_headers=additional_headers)
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

    

    async def async_provide_2fa(self, code : str, no_condition_check=False, additional_headers=None) -> bool:
        """Provide Two Factor Authentication Code to the API.
        
        :param code: 2FA code
        :type code: str
        :param no_condition_check: Internal flag to disable locking, defaults to False
        :type no_condition_check: bool, optional
        :return: True if 2FA succeeded, False otherwise.
        :rtype: bool
        :raises ProtonAPIAuthenticationNeeded: if 2FA failed, and the session was reset by the API backend (this is normally the case)
        """
        self._requests_lock(no_condition_check)
        try:
            ret = await self.__async_api_request_internal('/auth/2fa', {
                "TwoFactorCode": code
            }, no_condition_check=True, additional_headers=additional_headers)
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

    async def async_refresh(self, only_when_refresh_revision_is=None, no_condition_check=False, additional_headers=None):
        """Refresh tokens.

        Refresh AccessToken with a valid RefreshToken.
        If the RefreshToken is invalid then the user will have to
        re-authenticate.

        :return: True if refresh succeeded, False otherwise (doesn't throw an exception)
        :rtype: bool
        """

        #If we have the correct revision, and it doesn't match, then just exit
        if only_when_refresh_revision_is is not None and only_when_refresh_revision_is != self.__refresh_revision:
            # If we have the wrong revision, then this indicates that we have two refresh running in parallel.
            # Thanksfully, we can simply wait for the other to complete and return successfully.
            await self._requests_wait(no_condition_check)
            return True

        self._requests_lock(no_condition_check)

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
                    }, no_condition_check=True, additional_headers=additional_headers)
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



    async def async_logout(self, no_condition_check=False, additional_headers=None):
        """Logout from API.
        
        :return: True if logout was successful (or nothing was done)
        :rtype: bool
        """

        self._requests_lock(no_condition_check)
        previous_account_name = self.AccountName
        try:
            # No-op if not authenticated (but we do this inside the lock, so data is persisted nevertheless)
            if not self.authenticated:
                self._clear_local_data()
                return True

            ret = await self.__async_api_request_internal('/auth', method='DELETE', no_condition_check=True,
                                                          additional_headers=additional_headers)
            # Erase any information we have about the session
            self._clear_local_data()
            return True
        except ProtonAPIError as e:
            # If we get a 401, then we should erase data (session doesn't exist on the server), and we're fine
            if e.http_code == 401:
                self._clear_local_data()
                return True
            # We don't know what is going on, throw
            raise

        finally:
            self._requests_unlock(no_condition_check, previous_account_name)

    async def async_lock(self, no_condition_check=False, additional_headers=None):
        """ Lock the current user (remove PASSWORD and LOCKED scopes)"""

        self._requests_lock(no_condition_check)
        try:
            ret = await self.__async_api_request_internal('/users/lock', method='PUT', no_condition_check=True,
                                                          additional_headers=additional_headers)
            ret = await self.__async_api_request_internal('/auth/scopes', no_condition_check=True,
                                                          additional_headers=additional_headers)
            self.__Scopes = ret['Scopes']
            return True
        finally:
            self._requests_unlock(no_condition_check)
        #FIXME: clear user keys

    #FIXME: implement unlock

    async def async_human_verif_request_code(self, address=None, phone=None, additional_headers=None):
        """Request a verification code. Either address (email address) or phone (phone number) should be specified."""
        assert address is not None ^ phone is not None # nosec (we use email validation by default if both are provided, but it's not super clean if the dev doesn't know about it)

        if address is not None:
            data = {'Type': 'email', 'Destination': {'Address': address}}
        elif phone is not None:
            data = {'Type': 'sms', 'Destination': {'Phone': phone}}
        
        return await self.async_api_request('/users/code', data, additional_headers=additional_headers).get('Code', 0) == 1000

    async def async_human_verif_provide_token(self, method, token):
        pass


    async def async_fork(self, child_client_id: str, payload: str=None, independent: int=0, user_code: int=None, no_condition_check=False) -> str:
        """Try to fork the current session with parameters and return the fork selector if successful.

        :param child_client_id: The clientID that the client creating the child session will use.
        :type child_client_id: str
        :param payload: Will be downloaded by the child client, and can contain encrypted sensitive information.
        :type payload: str, optional
        :param independent: set to 1 if the newly forked session has to be independent, else 0.
        :type independent: int, optional
        :param user_code: If provided, the selector will not be randomly chosen, but rather the one already returned will be used.
        :type user_code: int, optional
        :param no_condition_check: Internal flag to disable locking, defaults to False
        :type no_condition_check: bool, optional

        :return selector: Fork selector to be used by method `async_import_fork()`
        :rtype: str
        """
        data = {'ChildClientID' : child_client_id, 'Independent': independent}
        if payload is not None:
            data['Payload'] = payload
        if user_code is not None:
            data['UserCode'] = user_code
        ret = await self.async_api_request('/auth/v4/sessions/forks', data, method='POST', no_condition_check=no_condition_check)
        return ret['Selector']


    async def async_import_fork(self, selector: str, no_condition_check=False) -> str:
        """Try to import the session fork specified by the selector.

        :param selector: Obtained via a successful call to `async_fork()`
        :type selector: str
        :param no_condition_check: Internal flag to disable locking, defaults to False
        :type no_condition_check: bool, optional

        :return payload: The payload sent by the parent session when initiating the fork.
        :rtype: str
        """
        self._requests_lock(no_condition_check)
        try:
            ret = await self.async_api_request(f"/auth/v4/sessions/forks/{selector}", method='GET', no_condition_check=True)
            self.__UID = ret['UID']
            self.__RefreshToken = ret['RefreshToken']
            self.__AccessToken = ret['AccessToken']
            self.__Scopes = ret['Scopes']
            return ret['Payload']
        finally:
            self._requests_unlock(no_condition_check)
        


    # Wrappers to provide non-asyncio API
    api_request = sync_wrapper(async_api_request)
    authenticate = sync_wrapper(async_authenticate)
    provide_2fa = sync_wrapper(async_provide_2fa)
    logout = sync_wrapper(async_logout)
    refresh = sync_wrapper(async_refresh)
    lock = sync_wrapper(async_lock)
    human_verif_request_code = sync_wrapper(async_human_verif_request_code)
    human_verif_provide_token = sync_wrapper(async_human_verif_provide_token)
    fork = sync_wrapper(async_fork)
    import_fork = sync_wrapper(async_import_fork)

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
        self.__extrastate = {}

    @property
    def transport_factory(self):
        """Set/read the factory used for transports (i.e. how to reach the API).

        If the property is set to a class, it will be wrapped in a factory.

        If the property is set to None, then the default ``transport`` will be obtained from :class:`.Loader`.
        """
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
        """:return: The appversion defined at construction (used for creating requests by transports)
        :rtype: str"""
        return self.__appversion

    @property
    def user_agent(self) -> str:
        """:return: The user_agent defined at construction (used for creating requests by transports)
        :rtype: str"""
        return self.__user_agent

    @property
    def authenticated(self) -> bool:
        """:return: True if session is authenticated, False otherwise.
        :rtype: bool
        """
        return self.__UID is not None
    
    @property
    def UID(self) -> Optional[str]:
        """:return: the session UID, None if not authenticated
        :rtype: str, optional
        """
        return self.__UID

    @property
    def Scopes(self) -> Optional[list[str]]:
        """:return: list of scopes of the current session, None if unknown or not defined.
        :rtype: list[str], optional
        """
        return self.__Scopes

    @property
    def AccountName(self) -> str:
        """:return: session account name (mostly used for SSO)
        :rtype: str
        """
        return self.__AccountName

    @property
    def AccessToken(self) -> str:
        """:return: return the access token for API calls (used by transports)
        :rtype: str
        """
        return self.__AccessToken

    @property
    def needs_twofa(self) -> bool:
        """:return: True if a 2FA authentication is needed, False otherwise.
        :rtype: bool
        """
        if self.Scopes is None:
            return False
        return 'twofactor' in self.Scopes

    @property
    def environment(self):
        """Get/set the environment in use for that session. It can be only set once at the beginning of the session's object lifetime,
        as changing the environment can lead to security hole.

        If the new value is:
        
        * None: do nothing
        * a string: will use :meth:`Loader.get("environment", newvalue)` to get the actual class.
        * an environment: use it
        """
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
            newvalue = Loader.get("environment", newvalue)()
        if not isinstance(newvalue, Environment):
            raise TypeError("environment should be a subclass of Environment")

        #Same environment => nothing to do
        if self.__environment == newvalue:
            return
        
        if self.__environment is not None:
            raise ValueError("Cannot change environment of an established session (that would create security issues)!")
        self.__environment = newvalue

    def __setstate__(self, data):
        # If we're running an unpickle, then the object constructor hasn't been called, so we need to populate __dict__
        for attr, default in (('gnupg_for_modulus', None), ('can_run_requests', None), ('transport', None), ('persistence_observers', [])):
            if '_Session__' + attr not in self.__dict__:
                self.__dict__['_Session__' + attr] = default

        # Restore data from LastUseData if we don't have it already (allow pickle load)
        for attr, default in (('2FA', None), ('appversion', 'Other'), ('user_agent', 'None'), ('refresh_revision', 0)):
            if '_Session__' + attr not in self.__dict__:
                self.__dict__['_Session__' + attr] = data.get('LastUseData', {}).get(attr, default)
        
        # We don't pickle the transport, so if not set just use the default
        if '_Session__transport_factory' not in self.__dict__:
            self.transport_factory = None

        self.__UID = data.get('UID', None)
        self.__AccessToken = data.get('AccessToken', None)
        self.__RefreshToken = data.get('RefreshToken', None)
        self.__Scopes = data.get('Scopes', None)
        self.__AccountName = data.get('AccountName', None)
        #Reset transport (user agent etc might have changed)
        self.__transport = None
        #get environment as stored in the session
        if data.get('Environment', None) is not None:
            self.__environment: Environment = Loader.get("environment", data.get('Environment', None))()
        else:
            self.__environment = None

        # Store everything we don't know about in extrastate
        self.__extrastate = dict([(k, v) for k, v in data.items() if k not in ('UID','AccessToken','RefreshToken','Scopes','AccountName','Environment', 'LastUseData')])

    def __getstate__(self):
        # If we don't have an UID, then we're not logged in and we don't want to store a specific state
        if self.UID is None:
            data = {}
        else:
            data = {
                #Session data
                'UID': self.UID,
                'AccessToken': self.__AccessToken,
                'RefreshToken': self.__RefreshToken,
                'Scopes': self.Scopes,
                'Environment': self.environment.name,
                'AccountName': self.__AccountName,
                'LastUseData': {
                    '2FA': self.__2FA,
                    'appversion': self.__appversion,
                    'user_agent': self.__user_agent,
                    'refresh_revision': self.__refresh_revision,
                }
            }
            # Add the additional extra state data that we might have
            data.update(self.__extrastate)

        return data

    def _requests_lock(self, no_condition_check=False):
        """Lock the session, this has to be done when doing requests that affect the session state (i.e. :meth:`authenticate` for 
        instance), to prevent race conditions.

        Internally, this is done using :class:`asyncio.Event`.

        :param no_condition_check: Internal flag to disable locking, defaults to False
        :type no_condition_check: bool, optional
        """
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

    def _requests_unlock(self, no_condition_check=False, account_name=None):
        """Unlock the session, this has to be done after doing requests that affect the session state (i.e. :meth:`authenticate` for 
        instance), to prevent race conditions.

        :param no_condition_check: Internal flag to disable locking, defaults to False
        :type no_condition_check: bool, optional
        :param account_name: Allow providing explicitly the account_name of the session, useful when it's for a logout when the session might not exist any more
        :type no_condition_check: str, optional
        """
        if no_condition_check:
            return
        
        if self.__can_run_requests is None:
            self.__can_run_requests = asyncio.Event()
        self.__can_run_requests.set()

        # Only store data if we have an actual account (session not logged in shouldn't store data)
        # If we have a known account, use it
        if self.AccountName is not None:
            account_name = self.AccountName
            session_data = self.__getstate__()
        else:
            session_data = None

        # Unlock observers (we might have modified the session)
        # It's important to do it in reverse order, as otherwise there's a risk of deadlocks
        for observer in reversed(self.__persistence_observers):
            observer._release_session_lock(account_name, session_data)

    async def _requests_wait(self, no_condition_check=False):
        """Wait for session unlock.

        :param no_condition_check: Internal flag to disable locking, defaults to False
        :type no_condition_check: bool, optional
        """
        if no_condition_check or self.__can_run_requests is None:
            return
        
        await self.__can_run_requests.wait()


    async def __sleep_for_exception(self, e):
        if e.http_headers.get('retry-after','-').isnumeric():
            await asyncio.sleep(int(e.http_headers.get('retry-after')))
        else:
            await asyncio.sleep(3+random.random()*5) # nosec (no crypto risk here of using an unsafe generator)

    async def __async_api_request_internal(
        self, endpoint,
        jsondata=None, data=None, additional_headers=None,
        method=None, params=None, no_condition_check=False,
        return_raw=False
    ):
        """Internal function to do an API request (without clever exception handling and retrying). 
        See :meth:`async_api_request` for the parameters specification."""
        # Should (and can we) create a transport
        if self.__transport is None and self.__transport_factory is not None:
            self.__transport = self.__transport_factory(self)
        if self.__transport is None:
            raise RuntimeError("Could not instanciate a transport, are required dependencies installed?")

        await self._requests_wait(no_condition_check)
        return await self.__transport.async_api_request(endpoint, jsondata, data, additional_headers, method, params,
                                                        return_raw=return_raw)

    def _verify_modulus(self, armored_modulus) -> bytes:
        if self.__gnupg_for_modulus is None:
            import gnupg
            # The modulus key is imported in a separate GPG keyring (rather than on the user's
            # default one) by modifying the gnupg home directory. The reason for doing this is
            # that we received crash reports due to users messing up with their default GPG
            # keyring permissions. In this case, python-gnupg fails silently when importing
            # Proton's modulus key, which then causes the signature verification errors.
            proton_gnupg_dir = Path(ExecutionEnvironment().path_cache) / "gnupg"
            proton_gnupg_dir.mkdir(exist_ok=True)
            self.__gnupg_for_modulus = gnupg.GPG(gnupghome=proton_gnupg_dir)
            self.__gnupg_for_modulus.import_keys(SRP_MODULUS_KEY)

        # gpg.decrypt verifies the signature too, and returns the parsed data.
        # By using gpg.verify the data is not returned
        verified = self.__gnupg_for_modulus.decrypt(armored_modulus)

        if not (verified.valid and verified.fingerprint.lower() == SRP_MODULUS_KEY_FINGERPRINT):
            raise ProtonCryptoError('Invalid modulus')

        return base64.b64decode(verified.data.strip())




