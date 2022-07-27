import unittest, os


class TestAlternativeRouting(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._env_backup = os.environ.copy()

    def tearDown(self):
        os.environ = self._env_backup

    async def test_alternative_routing_works_on_prod(self):
        from proton.session import Session
        from proton.session.transports.alternativerouting import AlternativeRoutingTransport

        os.environ['PROTON_API_ENVIRONMENT'] = 'prod'

        s = Session()
        s.transport_factory = AlternativeRoutingTransport
        assert await s.async_api_request('/tests/ping') == {'Code': 1000}
