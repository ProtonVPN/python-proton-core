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
from unittest.mock import Mock, AsyncMock
import asyncio
import os
import time
import unittest

from proton.session import Session
from proton.session.transports.auto import AutoTransport
from proton.session.transports.requests import RequestsTransport


class TestAuto(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._env_backup = os.environ.copy()

    def tearDown(self):
        os.environ = self._env_backup

    async def test_auto_works_on_prod(self):
        os.environ['PROTON_API_ENVIRONMENT'] = 'prod'

        s = Session()
        s.transport_factory = AutoTransport
        assert await s.async_api_request('/tests/ping') == {'Code': 1000}

    async def test_auto_transport_is_not_available_when_all_transports_choices_time_out_pinging_rest_api(self):
        mock_transport_type = Mock()
        transport_timeout = 0.001
        auto_transport = AutoTransport(
            session=Session(),
            transport_choices=[(0, mock_transport_type)],
            transport_timeout=transport_timeout
        )

        mock_transport = Mock()
        mock_transport_type.return_value = mock_transport

        # Force a timeout from `/tests/ping` when checking if the transport is available.
        async def force_transport_timeout(url):
            await asyncio.sleep(transport_timeout + 1)
        mock_transport.async_api_request.side_effect = force_transport_timeout

        await auto_transport.find_available_transport()

        assert mock_transport.async_api_request.called_once_with('/tests/ping')
        assert not auto_transport.is_available

    async def test_auto_transport_is_not_available_when_all_transport_choices_receive_an_unexpected_ping_response(self):
        mock_transport_type = Mock()
        auto_transport = AutoTransport(
            session=Session(),
            transport_choices=[(0, mock_transport_type)]
        )

        mock_transport = Mock()
        mock_transport_type.return_value = mock_transport

        # Force an unexpected response from `/tests/ping` when checking if the transport is available.
        async def force_unexpected_ping_response(url):
            return "foobar"
        mock_transport.async_api_request.side_effect = force_unexpected_ping_response

        await auto_transport.find_available_transport()

        assert mock_transport.async_api_request.called_once_with('/tests/ping')
        assert not auto_transport.is_available
