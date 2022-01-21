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
            sso._release_session_lock(fake_account_name,{'AccountName':fake_account_name,**test_data_1})

            assert fake_account_name in sso.sessions
            assert sso._get_session_data(fake_account_name) == {'AccountName':fake_account_name,**test_data_1}

            sso.set_default_account(fake_account_name)
            assert sso.sessions[0] == fake_account_name

            sso._acquire_session_lock(fake_account2_name, {})
            sso._release_session_lock(fake_account2_name,{'AccountName':fake_account2_name,**test_data_2})

            assert fake_account_name in sso.sessions
            assert fake_account2_name in sso.sessions
            assert sso._get_session_data(fake_account_name) == {'AccountName':fake_account_name,**test_data_1}
            assert sso._get_session_data(fake_account2_name) == {'AccountName':fake_account2_name,**test_data_2}

            assert sso.sessions[0] == fake_account_name
            sso.set_default_account(fake_account2_name)
            assert sso.sessions[0] == fake_account2_name

            sso.set_default_account(fake_account_name)
            assert sso.sessions[0] == fake_account_name
            
            sso._acquire_session_lock(fake_account_name, {'AccountName':fake_account_name,**test_data_1})
            sso._release_session_lock(fake_account_name, {'AccountName':fake_account_name,**test_data_2})

            assert sso.sessions[0] == fake_account_name
            assert fake_account_name in sso.sessions
            assert fake_account2_name in sso.sessions
            assert sso._get_session_data(fake_account_name) == {'AccountName':fake_account_name,**test_data_2}
            assert sso._get_session_data(fake_account2_name) == {'AccountName':fake_account2_name,**test_data_2}

            sso._acquire_session_lock(fake_account_name,{'AccountName':fake_account_name,**test_data_2})
            sso._release_session_lock(fake_account_name, None)

            with self.assertRaises(KeyError):
                sso.set_default_account(fake_account_name)
            assert fake_account_name not in sso.sessions
            assert fake_account2_name in sso.sessions
            assert sso._get_session_data(fake_account_name) == {}
            assert sso._get_session_data(fake_account2_name) == {'AccountName':fake_account2_name,**test_data_2}

            sso._acquire_session_lock(fake_account2_name, {'AccountName':fake_account2_name,**test_data_2})
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
            assert await sso.get_session('pro').async_logout()

        s = sso.get_session('pro')
        assert await s.async_authenticate('pro','pro')
        assert await s.async_api_request('/tests/ping') == {'Code': 1000}
        assert await s.async_logout()

    async def test_default_session(self):
        from proton.sso import ProtonSSO
        from proton.session.exceptions import ProtonAPIAuthenticationNeeded

        os.environ['PROTON_API_ENVIRONMENT'] = 'atlas'

        sso = ProtonSSO()
        while len(sso.sessions) > 0:
            assert await sso.get_default_session().async_logout()

        assert len(sso.sessions) == 0
        s = sso.get_default_session()
        assert (await s.async_api_request('/tests/ping'))['Code'] == 1000

        assert len(sso.sessions) == 0
        assert await s.async_authenticate('pro','pro')
        assert len(sso.sessions) == 1
        assert s.AccountName == 'pro'

        assert (await s.async_api_request('/users'))['Code'] == 1000

        sso2 = ProtonSSO()
        assert len(sso2.sessions) == 1

        s2 = sso2.get_default_session()
        assert s2.AccountName == 'pro'
        await s2.async_logout()

        assert len(sso2.sessions) == 0
        assert len(sso.sessions) == 0

        with self.assertRaises(ProtonAPIAuthenticationNeeded):
            assert (await s.async_api_request('/users'))['Code'] == 1000

    async def test_broken_index(self):
        from proton.loader import Loader
        from proton.sso import ProtonSSO

        sso = ProtonSSO()

        
        keyring = Loader.get('keyring')()
        keyring[sso._ProtonSSO__keyring_index_name()] = ['pro']
        keyring[sso._ProtonSSO__keyring_key_name('pro')] = {'additional_data': 'abc123'}

        assert 'pro' not in sso.sessions

    async def test_broken_data(self):
        from proton.sso import ProtonSSO

        sso = ProtonSSO()
        sso._acquire_session_lock('pro', None)
        with self.assertRaises(ValueError):
            sso._release_session_lock('pro', {'abc':'123'})

        sso._acquire_session_lock('pro', None)
        sso._release_session_lock('pro', {})

        sso._acquire_session_lock('pro', None)
        sso._release_session_lock('pro', None)




    async def test_additional_data(self):
        from proton.sso import ProtonSSO
        from proton.session import Session
        from proton.session.exceptions import ProtonAPIAuthenticationNeeded

        os.environ['PROTON_API_ENVIRONMENT'] = 'atlas'

        class SessionWithAdditionalData(Session):
            def __init__(self, *a, **kw):
                self.additional_data = None
                super().__init__(*a, **kw)

            def __setstate__(self, data):
                self.additional_data = data.get('additional_data', None)
                super().__setstate__(dict([(k, v) for k, v in data.items() if k not in ('additional_data',)]))

            def __getstate__(self):
                d = super().__getstate__()
                if self.additional_data is not None:
                    d['additional_data'] = self.additional_data
                return d

            async def set_additional_data(self, v):
                self._requests_lock()
                self.additional_data = v
                self._requests_unlock()

        sso = ProtonSSO()
        while len(sso.sessions) > 0:
            assert await sso.get_default_session().async_logout()

        s = sso.get_default_session(SessionWithAdditionalData)
        assert await s.async_authenticate('pro','pro')
        await s.set_additional_data('abc123')


        s = sso.get_default_session(SessionWithAdditionalData)
        assert s.additional_data == 'abc123'

        s = sso.get_default_session()
        with self.assertRaises(AttributeError):
            assert s.additional_data == 'abc123'

        # Call to force persistence save
        s._requests_lock()
        s._requests_unlock()

        # We should still have additional data
        s = sso.get_default_session(SessionWithAdditionalData)
        assert s.additional_data == 'abc123'