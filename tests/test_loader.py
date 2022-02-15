import unittest
import os

class LoaderTest(unittest.TestCase):
    def setUp(self):
        from proton.loader import Loader
        self._loader = Loader
        self._loader.reset()

    def tearDown(self):
        self._loader.reset()
        self._loader = None

    def test_environments_explicit(self):
        from proton.session.environments import ProdEnvironment, AtlasEnvironment, CIEnvironment, URLEnvironment

        self._loader.set_all('environment', {'prod': ProdEnvironment, 'atlas': AtlasEnvironment})
        assert len(self._loader.get_all('environment')) == 2

        os.environ['PROTON_API_ENVIRONMENT'] = 'prod'
        assert self._loader.get('environment') == ProdEnvironment
        assert len(self._loader.get_all('environment')) == 2

        os.environ['PROTON_API_ENVIRONMENT'] = 'atlas'
        assert self._loader.get('environment') == AtlasEnvironment
        assert len(self._loader.get_all('environment')) == 2


        assert self._loader.get_name(ProdEnvironment) == ('environment','prod')
        assert self._loader.get_name(AtlasEnvironment) == ('environment','atlas')
        # This ones are not loaded since we used set_all
        assert self._loader.get_name(CIEnvironment) is None
        assert self._loader.get_name(URLEnvironment) is None

    def test_environments(self):
        from proton.session.environments import ProdEnvironment, AtlasEnvironment, CIEnvironment, URLEnvironment

        if len(self._loader.get_all('environment')) == 0:
            self.skipTest("No environments, probably because we have not entry points set up.")

        os.environ['PROTON_API_ENVIRONMENT'] = 'prod'
        assert self._loader.get('environment') == ProdEnvironment
        assert self._loader.get('environment', 'atlas') == AtlasEnvironment

        os.environ['PROTON_API_ENVIRONMENT'] = 'atlas'
        assert self._loader.get('environment') == AtlasEnvironment

        assert self._loader.get_name(ProdEnvironment) == ('environment','prod')
        assert self._loader.get_name(AtlasEnvironment) == ('environment','atlas')
        assert self._loader.get_name(CIEnvironment) == ('environment','ci')
        assert self._loader.get_name(URLEnvironment) == ('environment','url')
