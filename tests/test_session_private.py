import unittest, os, requests

class TestAtlasEnvironment(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._env_backup = os.environ.copy()

    def tearDown(self):
        os.environ = self._env_backup

    async def _skip_if_atlas_is_not_reachable(self):
        from proton.session import Session
        from proton.session.exceptions import ProtonAPINotReachable

        os.environ['PROTON_API_ENVIRONMENT'] = 'atlas'
        s = Session()
        try:
            if await s.async_api_request('/tests/ping') == {'Code': 1000}:
                return True
        except ProtonAPINotReachable:
            pass

        self.skipTest("atlas is not reachable, check that PROTON_ATLAS_SECRET is set if needed")


    async def test_atlas_global(self):
        await self._skip_if_atlas_is_not_reachable()

        from proton.session import Session
        s = Session()
        assert await s.async_api_request('/tests/ping') == {'Code': 1000}

        await s.async_authenticate('free','free')
        await s.async_logout()

    async def test_atlas_invalid_environment(self):
        from proton.session.exceptions import ProtonAPINotReachable
        await self._skip_if_atlas_is_not_reachable()
        
        os.environ['PROTON_API_ENVIRONMENT'] = 'atlas:nonexistentenvironment'

        from proton.session import Session
        s = Session()
        with self.assertRaises(ProtonAPINotReachable):
            await s.async_api_request('/tests/ping') == {'Code': 1000}

    async def test_atlas_secret_missing(self):
        from proton.session.exceptions import ProtonAPINotReachable
        if 'PROTON_ATLAS_SECRET' not in os.environ:
            self.skipTest("Cannot run test if secret is not provided")

        r = requests.get('https://proxy.proton.black/token/get')
        if r.status_code == 200:
            self.skipTest("Cannot run on whitelisted IPs")

        del os.environ['PROTON_ATLAS_SECRET']
        os.environ['PROTON_API_ENVIRONMENT'] = 'atlas'
        
        from proton.session import Session
        s = Session()
        with self.assertRaises(ProtonAPINotReachable):
            assert await s.async_api_request('/tests/ping') == {'Code': 1000}