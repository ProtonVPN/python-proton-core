"""
Copyright (c) 2023 Proton AG

This file is part of Proton.

Proton is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Proton is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
"""
import unittest

class TestTLSValidation(unittest.IsolatedAsyncioTestCase):
    async def test_successful(self):
        from proton.session import Session
        from proton.session.environments import ProdEnvironment

        s = Session()
        s.environment = ProdEnvironment()
        assert await s.async_api_request('/tests/ping') == {'Code': 1000}

    async def test_without_pinning(self):
        from proton.session import Session
        from proton.session.environments import ProdEnvironment


        class ProdWithoutPinningEnvironment(ProdEnvironment):
            @property
            def tls_pinning_hashes(self):
                return None

            @property
            def tls_pinning_hashes_ar(self):
                return None

        s = Session()
        s.environment = ProdWithoutPinningEnvironment()
        assert await s.async_api_request('/tests/ping') == {'Code': 1000}


    async def test_bad_pinning_url_changed(self):
        from proton.session import Session
        from proton.session.environments import ProdEnvironment
        from proton.session.exceptions import ProtonAPINotReachable
        from proton.session.transports.aiohttp import AiohttpTransport

        class BrokenProdEnvironment(ProdEnvironment):
            @property
            def http_base_url(self):
                # This is one of the URLs, but it uses different certificates than prod api, so pinning will fail
                return "https://www.protonvpn.com/api/"

        s = Session()
        s.environment = BrokenProdEnvironment()
        s.transport_factory = AiohttpTransport
        with self.assertRaises(ProtonAPINotReachable) as e:
            assert await s.async_api_request('/tests/ping') == {'Code': 1000}
        assert str(e.exception).startswith('TLS pinning verification failed')

    async def test_bad_pinning_fingerprint_changed(self):
        from proton.session import Session
        from proton.session.environments import ProdEnvironment
        from proton.session.exceptions import ProtonAPINotReachable
        from proton.session.transports.aiohttp import AiohttpTransport

        class BrokenProdEnvironment(ProdEnvironment):
            @property
            def tls_pinning_hashes(self):
                # This is an invalid hash
                return set([
                    "aaaaaaakFkM8qJClsuWgUzxgBkePfRCkRpqUesyDmeE=",
                ])

        s = Session()
        s.environment = BrokenProdEnvironment()
        s.transport_factory = AiohttpTransport
        with self.assertRaises(ProtonAPINotReachable) as e:
            assert await s.async_api_request('/tests/ping') == {'Code': 1000}
        assert str(e.exception).startswith('TLS pinning verification failed')

    async def test_pinning_disabled(self):
        from proton.session import Session
        from proton.session.environments import ProdEnvironment
        from proton.session.exceptions import ProtonAPINotReachable

        class PinningDisabledProdEnvironment(ProdEnvironment):
            @property
            def http_base_url(self):
                # This is one of the URLs, but it uses different certificates than prod api, so pinning would fail if it was used
                return "https://www.protonvpn.com/api/"
            @property
            def tls_pinning_hashes(self):
                return None

        s = Session()
        s.environment = PinningDisabledProdEnvironment()
        with self.assertRaises(ProtonAPINotReachable) as e:
            assert await s.async_api_request('/tests/ping') == {'Code': 1000}
        # Will probably return "API returned non-json results"
        assert not str(e.exception).startswith('TLS pinning verification failed')

    async def test_bad_ssl(self):
        from proton.session import Session
        from proton.session.environments import ProdEnvironment
        from proton.session.exceptions import ProtonAPINotReachable
        from proton.session.transports.aiohttp import AiohttpTransport

        class BrokenProdEnvironment(ProdEnvironment):
            @property
            def http_base_url(self):
                # This will break, as it's a self signed certificate
                return "https://self-signed.badssl.com/"
            @property
            def tls_pinning_hashes(self):
                return None

        s = Session()
        s.environment = BrokenProdEnvironment()
        s.transport_factory = AiohttpTransport
        with self.assertRaises(ProtonAPINotReachable) as e:
            assert await s.async_api_request('/tests/ping') == {'Code': 1000}

