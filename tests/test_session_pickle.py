import unittest, pickle, os

class TestSessionPickle(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._env_backup = os.environ.copy()

    def tearDown(self):
        os.environ = self._env_backup

    def _assert_session_survives_pickle(self, s):
        d1 = s.__dict__.copy() 
        d2 = pickle.loads(pickle.dumps(s)).__dict__.copy()

        for k in ('_Session__transport', '_Session__gnupg_for_modulus', '_Session__can_run_requests'):
            del d1[k]
            del d2[k]

        assert d1 == d2, "Session doesn't pickle correctly"

    async def test_pickle(self):
        from proton.session import Session
        from proton.session.exceptions import ProtonAPINotReachable

        os.environ['PROTON_API_ENVIRONMENT'] = 'atlas'
        s = Session()

        assert s.__dict__ == pickle.loads(pickle.dumps(s)).__dict__

        try:
            assert await s.async_api_request('/tests/ping') == {'Code': 1000}
        except ProtonAPINotReachable:
            self.skipTest("atlas is not reachable, check that PROTON_ATLAS_SECRET is set if needed")
            return

        assert await s.async_authenticate('pro','pro')
        self._assert_session_survives_pickle(s)

        assert await s.async_api_request('/tests/ping') == {'Code': 1000}
        s = pickle.loads(pickle.dumps(s))
        assert await s.async_api_request('/tests/ping') == {'Code': 1000}

        await s.async_refresh()
        self._assert_session_survives_pickle(s)

        await s.async_logout()


        