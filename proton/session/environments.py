import abc
from typing import Union, Optional

class Environment(metaclass=abc.ABCMeta):
    @property
    def name(cls):
        cls_name = cls.__class__.__name__
        assert cls_name.endswith('Environment'), "Incorrectly named class" # nosec (dev should ensure that to avoid issues)
        return cls_name[:-11].lower()

    @property
    def http_extra_headers(self):
        #This can be overriden, but by default we don't add extra headers
        return {}

    @property
    @abc.abstractmethod
    def http_base_url(self):
        pass

    @property
    @abc.abstractmethod
    def tls_pinning_hashes(self):
        pass

    @property
    @abc.abstractmethod
    def tls_pinning_hashes_ar(self):
        pass

    def __eq__(self, other):
        if other is None:
            return False
        return self.name == other.name



class ProdEnvironment(Environment):
    @classmethod
    def _get_priority(cls):
        return 10

    @property
    def http_base_url(self):
        return "https://api.protonvpn.ch"

    @property
    def tls_pinning_hashes(self):
        return set([
            "drtmcR2kFkM8qJClsuWgUzxgBkePfRCkRpqUesyDmeE=",
            "YRGlaY0jyJ4Jw2/4M8FIftwbDIQfh8Sdro96CeEel54=",
            "AfMENBVvOS8MnISprtvyPsjKlPooqh8nMB/pvCrpJpw=",
        ])

    @property
    def tls_pinning_hashes_ar(self):
        return set([
            "EU6TS9MO0L/GsDHvVc9D5fChYLNy5JdGYpJw0ccgetM=",
            "iKPIHPnDNqdkvOnTClQ8zQAIKG0XavaPkcEo0LBAABA=",
            "MSlVrBCdL0hKyczvgYVSRNm88RicyY04Q2y5qrBt0xA=",
            "C2UxW0T1Ckl9s+8cXfjXxlEqwAfPM4HiW2y3UdtBeCw="
        ])

class AtlasEnvironment(Environment):
    @classmethod
    def _get_priority(cls):
        import os
        if os.environ.get('PROTON_API_ENVIRONMENT','').split(':')[0] == 'atlas':
            return 100
        else:
            return -100

    @property
    def _atlas_scientist(self):
        import os
        environment_split = os.getenv('PROTON_API_ENVIRONMENT', '').split(":", 1)
        if environment_split[0] != "atlas" or len(environment_split) <= 1:
            return None
            
        return environment_split[1]

    @property
    def http_base_url(self):
        scientist = self._atlas_scientist
        if scientist:
            return f"https://api.{scientist}.proton.black"
        else:
            return f"https://api.proton.black"

    @property
    def http_extra_headers(self):
        import os
        secret = os.getenv('PROTON_ATLAS_SECRET')
        if secret is not None:
            return {'x-atlas-secret': secret}
        else:
            return {}
            

    @property
    def tls_pinning_hashes(self):
        #No pinning for scientist environments
        return None

    @property
    def tls_pinning_hashes_ar(self):
        #No pinning for scientist environments
        return None

class CIEnvironment(Environment):
    @classmethod
    def _get_priority(cls):
        import os
        if os.environ.get('PROTON_API_ENVIRONMENT','') == 'ci':
            return 100
        else:
            return -100
    
    @property
    def http_base_url(self):
        return f"https://138.199.50.142"

    @property
    def tls_pinning_hashes(self):
        return {
            "e7gl+YVDm8yjCKj4WZna3FucEL4t84TSK7AKTLscxCc=",
        }

    @property
    def tls_pinning_hashes_ar(self):
        #No pinning for CI environment
        return None

class URLEnvironment(Environment):
    @classmethod
    def _get_priority(cls):
        import os
        if os.environ.get('PROTON_API_URL'):
            return 100
        else:
            return -100
    
    @property
    def http_base_url(self):
        import os
        return os.environ.get('PROTON_API_URL')

    @property
    def tls_pinning_hashes(self):
        return None

    @property
    def tls_pinning_hashes_ar(self):
        #No pinning for CI environment
        return None
