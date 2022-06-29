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
        await s.async_api_request('/tests/ping') == {'Code': 1000}

    async def test_alternative_routing_fails_on_atlas(self):
        from proton.session import Session
        from proton.session.transports.alternativerouting import AlternativeRoutingTransport
        from proton.session.exceptions import ProtonAPINotAvailable
        try:
            from proton.session_internal.environments import AtlasEnvironment
        except (ImportError, ModuleNotFoundError):
            self.skipTest("Couldn't load proton-core-internal environments, they are probably not installed on this machine, so skip this test.")

        os.environ['PROTON_API_ENVIRONMENT'] = 'atlas'

        s = Session()
        s.transport_factory = AlternativeRoutingTransport
        with self.assertRaises(ProtonAPINotAvailable):
            await s.async_api_request('/tests/ping') == {'Code': 1000}

