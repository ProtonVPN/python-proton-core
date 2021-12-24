import unittest
import os

class TestSession(unittest.IsolatedAsyncioTestCase):
    async def test_ping(self):
        from proton.session import Session
        s = Session()
        assert await s.async_api_request('/tests/ping') == {'Code': 1000}

    # This test have to run on atlas, because of the hard-coded credentials
    # (https://confluence.protontech.ch/display/API/Logins)
    async def test_login_state(self):
        from proton.session import Session
        from proton.session.exceptions import ProtonAPIAuthenticationNeeded, ProtonAPI2FANeeded, ProtonAPIMissingScopeError
        os.environ['PROTON_API_ENVIRONMENT'] = 'atlas'

        s = Session()
        # This should succeed (non-authenticated route)
        await s.async_api_request('/tests/ping') == {'Code': 1000}

        # We need a session for this to work
        with self.assertRaises(ProtonAPIAuthenticationNeeded):
            d = await s.async_api_request('/vpn/v1/certificate/sessions')

        assert await s.async_authenticate('pro', 'pro')

        # Now we can get sessions
        d = await s.async_api_request('/vpn/v1/certificate/sessions')

        # Logout and verify that we're indeed logged out
        await s.async_logout()
        with self.assertRaises(ProtonAPIAuthenticationNeeded):
            d = await s.async_api_request('/vpn/v1/certificate/sessions')

        # Try 2FA login
        assert await s.async_authenticate('twofa', 'a')

        # Now we need twofa
        with self.assertRaises(ProtonAPI2FANeeded):
            d = await s.async_api_request('/vpn/v1/certificate/sessions')

        assert s.needs_twofa

        import pyotp

        #Invalid 2fa
        try:
            assert not await s.async_provide_2fa(pyotp.TOTP('4R5YJICSS6N72KNN3YRTEGLJCEKIAAAA').now())
        except ProtonAPIAuthenticationNeeded:
            # If we end up jailed, then we might get a 8002, so we need to start over
            assert await s.async_authenticate('twofa', 'a')

        # We should still need a 2fa
        assert s.needs_twofa

        # Valid 2FA this time
        await s.async_provide_2fa(pyotp.TOTP('4R5YJICSS6N72KNN3YRTEGLJCEKIMSKJ').now())

        assert not s.needs_twofa

        d = await s.async_api_request('/vpn/v1/certificate/sessions')

        assert not s.needs_twofa

        d = await s.async_api_request('/keys/salts')

        assert await s.async_lock()

        # After a lock, we can't access salts
        with self.assertRaises(ProtonAPIMissingScopeError):
            d = await s.async_api_request('/keys/salts')

        #FIXME: we need to be able to unlock session
        #assert await s.async_unlock('twofa', 'a')
        #d = await s.async_api_request('/keys/salts')

        await s.async_logout()
        with self.assertRaises(ProtonAPIAuthenticationNeeded):
            d = await s.async_api_request('/keys/salts')
        

