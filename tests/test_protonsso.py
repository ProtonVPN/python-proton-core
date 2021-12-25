import unittest
import os

class TestProtonSSO(unittest.IsolatedAsyncioTestCase):
    async def test_sessions(self):
        from proton.sso import ProtonSSO

        sso = ProtonSSO()

        fake_account_name = 'test-proton-sso-session'
        fake_account2_name = 'test-proton-sso-session2@pm.me'
        test_data_1 = {'test': 'data'}
        test_data_2 = {'test2': 'data2'}

        for i in range(2):
            sso._acquire_session_lock(fake_account_name, {})
            sso._release_session_lock(fake_account_name,test_data_1)

            assert fake_account_name in sso.sessions
            assert sso._get_session_data(fake_account_name) == test_data_1

            sso.set_default_account(fake_account_name)
            assert sso.sessions[0] == fake_account_name

            sso._acquire_session_lock(fake_account2_name, {})
            sso._release_session_lock(fake_account2_name,test_data_2)

            assert fake_account_name in sso.sessions
            assert fake_account2_name in sso.sessions
            assert sso._get_session_data(fake_account_name) == test_data_1
            assert sso._get_session_data(fake_account2_name) == test_data_2

            assert sso.sessions[0] == fake_account_name
            sso.set_default_account(fake_account2_name)
            assert sso.sessions[0] == fake_account2_name

            sso.set_default_account(fake_account_name)
            assert sso.sessions[0] == fake_account_name
            
            sso._acquire_session_lock(fake_account_name, test_data_1)
            sso._release_session_lock(fake_account_name,test_data_2)

            assert sso.sessions[0] == fake_account_name
            assert fake_account_name in sso.sessions
            assert fake_account2_name in sso.sessions
            assert sso._get_session_data(fake_account_name) == test_data_2
            assert sso._get_session_data(fake_account2_name) == test_data_2

            sso._acquire_session_lock(fake_account_name,test_data_2)
            sso._release_session_lock(fake_account_name, None)

            with self.assertRaises(KeyError):
                sso.set_default_account(fake_account_name)
            assert fake_account_name not in sso.sessions
            assert fake_account2_name in sso.sessions
            assert sso._get_session_data(fake_account_name) == {}
            assert sso._get_session_data(fake_account2_name) == test_data_2

            sso._acquire_session_lock(fake_account2_name, test_data_2)
            sso._release_session_lock(fake_account2_name, None)

            assert fake_account_name not in sso.sessions
            assert fake_account2_name not in sso.sessions
            assert sso._get_session_data(fake_account_name) == {}
            assert sso._get_session_data(fake_account2_name) == {}

    async def test_with_real_session(self):
        from proton.sso import ProtonSSO

        os.environ['PROTON_API_ENVIRONMENT'] = 'atlas'

        sso = ProtonSSO()

        if 'pro' in sso.sessions:
            await sso.get_session('pro').async_logout()

        s = sso.get_session('pro')
        assert await s.async_authenticate('pro','pro')
        assert await s.async_api_request('/tests/ping') == {'Code': 1000}
        assert await s.async_logout()
        