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
import unittest
import os


class TestSession(unittest.IsolatedAsyncioTestCase):
    async def test_ping(self):
        from proton.session import Session
        s = Session()
        assert await s.async_api_request('/tests/ping') == {'Code': 1000}

    async def test_session_refresh(self):

        from proton.session.transports import TransportFactory
        from unittest.mock import AsyncMock

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

        from proton.session import Session
        from proton.session.exceptions import ProtonAPIError
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
