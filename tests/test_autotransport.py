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
