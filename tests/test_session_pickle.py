import unittest, pickle, os


class TestSessionPickle(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._env_backup = os.environ.copy()

    def tearDown(self):
        os.environ = self._env_backup

    async def test_pickle(self):
        from proton.session import Session

        os.environ['PROTON_API_ENVIRONMENT'] = 'prod'
        s = Session()

        pickled_session = pickle.loads(pickle.dumps(s))
        assert isinstance(pickled_session, Session)

        assert s.__dict__ == pickled_session.__dict__

        # we can't do much more testing as we don't log in in API in the tests...
