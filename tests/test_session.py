import unittest
import os


class TestSession(unittest.IsolatedAsyncioTestCase):
    async def test_ping(self):
        from proton.session import Session
        s = Session()
        assert await s.async_api_request('/tests/ping') == {'Code': 1000}
