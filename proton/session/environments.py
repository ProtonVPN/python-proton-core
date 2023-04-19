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
