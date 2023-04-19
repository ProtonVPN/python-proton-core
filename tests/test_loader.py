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
import os

from proton.session.environments import Environment


class DummyTest1Environment(Environment):
    @classmethod
    def _get_priority(cls):
        import os
        if os.environ.get('PROTON_API_ENVIRONMENT', '') == 'dummytest1':
            return 100
        else:
            return -100

    @property
    def http_base_url(self):
        return "https://dummy1.protonvpn.ch"

    @property
    def tls_pinning_hashes(self):
        return None

    @property
    def tls_pinning_hashes_ar(self):
        return None


class DummyTest2Environment(Environment):
    @classmethod
    def _get_priority(cls):
        import os
        if os.environ.get('PROTON_API_ENVIRONMENT', '') == 'dummytest2':
            return 100
        else:
            return -100

    @property
    def http_base_url(self):
        return "https://dummy2.protonvpn.ch"

    @property
    def tls_pinning_hashes(self):
        return None

    @property
    def tls_pinning_hashes_ar(self):
        return None


class DummyTest3Environment(Environment):
    @classmethod
    def _get_priority(cls):
        import os
        if os.environ.get('PROTON_API_ENVIRONMENT', '') == 'dummytest3':
            return 100
        else:
            return -100

    @property
    def http_base_url(self):
        return "https://dummy3.protonvpn.ch"

    @property
    def tls_pinning_hashes(self):
        return None

    @property
    def tls_pinning_hashes_ar(self):
        return None


class LoaderTest(unittest.TestCase):
    def setUp(self):
        from proton.loader import Loader
        self._loader = Loader
        self._loader.reset()

    def tearDown(self):
        self._loader.reset()
        self._loader = None

    def test_default(self):
        from proton.session.environments import ProdEnvironment

        assert self._loader.get('environment') == ProdEnvironment
        assert len(self._loader.get_all('environment')) >= 1  # by default, we have at least 1 environment : the default one

    def test_environments_explicit(self):
        from proton.session.environments import ProdEnvironment

        self._loader.set_all('environment', {'prod': ProdEnvironment, 'dummytest1': DummyTest1Environment, 'dummytest2': DummyTest2Environment})
        assert len(self._loader.get_all('environment')) == 3

        os.environ['PROTON_API_ENVIRONMENT'] = 'prod'
        assert self._loader.get('environment') == ProdEnvironment
        assert len(self._loader.get_all('environment')) == 3

        os.environ['PROTON_API_ENVIRONMENT'] = 'dummytest2'
        assert self._loader.get('environment') == DummyTest2Environment
        assert len(self._loader.get_all('environment')) == 3

        os.environ['PROTON_API_ENVIRONMENT'] = 'dummytest1'
        assert self._loader.get('environment') == DummyTest1Environment
        assert len(self._loader.get_all('environment')) == 3

        assert self._loader.get_name(ProdEnvironment) == ('environment','prod')
        assert self._loader.get_name(DummyTest1Environment) == ('environment','dummytest1')
        assert self._loader.get_name(DummyTest2Environment) == ('environment','dummytest2')
        # This ones are not loaded since we used set_all
        assert self._loader.get_name(DummyTest3Environment) is None

    def test_environments(self):
        from proton.session.environments import ProdEnvironment

        if len(self._loader.get_all('environment')) == 0:
            self.skipTest("No environments, probably because we have not entry points set up.")

        os.environ['PROTON_API_ENVIRONMENT'] = 'prod'
        assert self._loader.get('environment') == ProdEnvironment
        with self.assertRaises(RuntimeError):
            _ = self._loader.get('environment', 'unknown')

        os.environ['PROTON_API_ENVIRONMENT'] = 'unknown'
        assert self._loader.get('environment') == ProdEnvironment

        assert self._loader.get_name(ProdEnvironment) == ('environment','prod')
