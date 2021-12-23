import unittest, os

class TestAuto(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._env_backup = os.environ.copy()

    def tearDown(self):
        os.environ = self._env_backup

    async def test_auto_works_on_prod(self):
        from proton.session import Session
        from proton.session.transports.auto import AutoTransport

        os.environ['PROTON_API_ENVIRONMENT'] = 'prod'

        s = Session()
        s.transport_factory = AutoTransport
        await s.async_api_request('/tests/ping') == {'Code': 1000}
