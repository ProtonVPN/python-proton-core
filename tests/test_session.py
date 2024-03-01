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
import asyncio
import unittest
import os
from unittest.mock import AsyncMock
import pyotp

from proton.session import Session
from proton.session.exceptions import ProtonAPIError
from proton.session.transports import TransportFactory


class TestSession(unittest.IsolatedAsyncioTestCase):
    async def test_ping(self):
        s = Session()
        assert await s.async_api_request('/tests/ping') == {'Code': 1000}

    async def test_session_refresh(self):
        session_state = {
            "UID": "7pqrddjjxmbqpmxcqzg3utlscjgw74xq",
            "AccessToken": "lvg7emrif23lwi3mgvpqlqfscbzzidni",
            "RefreshToken": "phormswshlqr7mzvgjfml26kcincqfv3",
            "Scopes": ["self", "parent", "user", "loggedin", "vpn", "verified"],
            "Environment": "prod",
            "AccountName": "vpnfree",
            "LastUseData": {
                "2FA": {
                    "Enabled": 0,
                    "FIDO2": {
                        "AuthenticationOptions": None,
                        "RegisteredKeys": []
                    },
                    "TOTP": 0
                },
                "appversion": "linux-vpn@4.0.0",
                "user_agent": "ProtonVPN/4.0.0 (Linux; debian/n/a)",
                "refresh_revision": 0
            }
        }
        refresh_reply = {
            'Code': 1000,
            'AccessToken': 'uu7eg2d6dudlgvcsyk2plkgktwmwjdbr',
            'ExpiresIn': 3600,
            'TokenType': 'Bearer',
            'Scope': 'self parent user loggedin vpn verified',
            'Scopes': ['self', 'parent', 'user', 'loggedin', 'vpn', 'verified'],
            'Uid': '7pqrddjjxmbqpmxcqzg3utlscjgw74xq',
            'UID': '7pqrddjjxmbqpmxcqzg3utlscjgw74xq',
            'RefreshToken': 'cuxdyjphk4snlgfjouffsj2behzsuvgs',
            'LocalID': 0
            }

        class MyMockCalls:
            callback_async_api_request = None

            async def async_api_request(self, endpoint, *args, **kwargs):
                return await self.callback_async_api_request(endpoint, *args, **kwargs)

        mock_calls = MyMockCalls()

        def _repr_session(session: "Session"):
            return f"{{UID={session.UID} , AccessToken={session.AccessToken}}}"

        class MyMockTransport:
            def __init__(self, session: "Session", *args, **kwargs) -> None:
                self._session = session
                self.mock_calls = mock_calls

            async def async_api_request(self, endpoint, *args, **kwargs):
                return await self.mock_calls.async_api_request(self._session, endpoint, *args, **kwargs)

        s = Session()
        s.transport_factory = TransportFactory(cls=MyMockTransport)

        async def mock_func_auth(session: "Session", endpoint, *args, **kwargs):
            if session.AccessToken == "lvg7emrif23lwi3mgvpqlqfscbzzidni":
                if endpoint == "/vpn/someroute":
                    raise ProtonAPIError(401, {}, {"Code": 401, "Error": ["...?..."]})
                elif endpoint == "/auth/refresh" and args[0]["RefreshToken"] == "phormswshlqr7mzvgjfml26kcincqfv3":
                    return refresh_reply
            elif session.AccessToken == "uu7eg2d6dudlgvcsyk2plkgktwmwjdbr":
                if endpoint == "/vpn/someroute":
                    return {"Code": 1000, "SomeRouteData": {"DataKey": "DataValue"}}

            raise ValueError(f"Unexpected request for {_repr_session(session)} and {endpoint=}")

        mock_calls.callback_async_api_request = AsyncMock(side_effect=mock_func_auth)
        s.__setstate__(session_state)
        assert s.AccountName == session_state["AccountName"]

        r = await s.async_api_request("/vpn/someroute")
        assert r == {"Code": 1000, "SomeRouteData": {"DataKey": "DataValue"}}

        mock_calls = mock_calls.callback_async_api_request.mock_calls
        assert len(mock_calls) == 3

        _, args, _ = mock_calls[0]
        assert args[1] == "/vpn/someroute"

        _, args, _ = mock_calls[1]
        assert args[1] == "/auth/refresh"

        _, args, _ = mock_calls[2]
        assert args[1] == "/vpn/someroute"


class TestSessionUsingApi(unittest.IsolatedAsyncioTestCase):
    """This class contain test that will use the atlas environment of Proton API to
    test session related features.
    Note that for session forking, we use the 'windows-vpn' app version because we need 
    the 'FULL' scope, and as time of writing it's not available for 'linux-vpn' app version."""

    _APP_VERSION = 'windows-vpn@4.1.0'
    _USER_AGENT = 'ProtonVPN/4.0.0 (windows; debian/n/a)'
    _CHILD_CLIENT_ID = 'windows-vpn'
    _parent_session = None
    _auth_mutex = asyncio.Lock()

    @classmethod
    def setUpClass(cls):
        cls._env_backup = os.environ.copy()
        atlas_scientist = os.environ.get('UNIT_TEST_ATLAS_SCIENTIST')
        if atlas_scientist:
            os.environ['PROTON_API_ENVIRONMENT'] = f"atlas:{atlas_scientist}"
        else:
            os.environ['PROTON_API_ENVIRONMENT'] = 'atlas'

    @classmethod
    def tearDownClass(cls):
        os.environ = cls._env_backup

    async def _init_parent_session(self):
        async with self._auth_mutex:
            if self._parent_session is not None:
                return
            parent_session = Session(appversion=self._APP_VERSION, user_agent=self._USER_AGENT)
            await parent_session.async_authenticate('twofa', 'a')
            otp = pyotp.TOTP("4R5YJICSS6N72KNN3YRTEGLJCEKIMSKJ").now()
            two_fa_succeeded = await parent_session.async_provide_2fa(otp)
            assert two_fa_succeeded
            self._parent_session = parent_session

    def _skip_if_no_internal_environments(self):
        try:
            from proton.session_internal.environments import AtlasEnvironment
        except (ImportError, ModuleNotFoundError):
            self.skipTest("Couldn't load proton-core-internal environments, they are probably not installed on this machine, so skip this test.")

    async def test_session_fork_ok(self):
        """Session forking expected to succeed"""
        self._skip_if_no_internal_environments()
        await self._init_parent_session()

        secret_payload = "MySuperSecretPayload"
        selector = await self._parent_session.async_fork(payload=secret_payload, child_client_id=self._CHILD_CLIENT_ID)
        child_session = Session(appversion=self._APP_VERSION, user_agent=self._USER_AGENT)
        clear_payload = await child_session.async_import_fork(selector)
        assert clear_payload == secret_payload
        r = await child_session.async_api_request("/auth/v4/sessions", method='GET')
        assert r['Code'] == 1000

    async def test_session_fork_not_ok(self):
        """
        1/ Make the fork failing in missing the required ChildClientID parameter.
        2/ Make the import fork failing in altering the selector.
        """
        self._skip_if_no_internal_environments()
        await self._init_parent_session()

        secret_payload = "MySuperSecretPayload"
        with self.assertRaises(ProtonAPIError) as cm:
            await self._parent_session.async_fork(child_client_id='')
        assert 'ChildClientID is required' in cm.exception.message

        selector = await self._parent_session.async_fork(payload=secret_payload, child_client_id=self._CHILD_CLIENT_ID)
        child_session = Session(appversion=self._APP_VERSION, user_agent=self._USER_AGENT)
        altered_selector = selector + '+crap'
        with self.assertRaises(ProtonAPIError) as cm:
            await child_session.async_import_fork(altered_selector)
        assert 'Invalid selector' in cm.exception.message
