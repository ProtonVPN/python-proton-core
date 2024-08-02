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
from dataclasses import dataclass
from typing import Awaitable, List
import aiohttp
from ..exceptions import *
from .aiohttp import AiohttpTransport

import json, base64, struct, time, asyncio, random, itertools

from urllib.parse import urlparse

from ..api import sync_wrapper
from .utils.dns import DNSParser, DNSResponseError


@dataclass
class AlternativeRoutingDNSQueryAnswer:
    """Contains the result of a successful DNS query to retrieve the
    alternative routing server domain."""
    expiration_time: float
    domain: str


class AlternativeRoutingTransport(AiohttpTransport):
    DNS_PROVIDERS = [
        #dns.google
        (("8.8.4.4", "8.8.8.8"), ("2001:4860:4860::8844", "2001:4860:4860::8888"), '/dns-query'),
        #dns11.quad9.net
        (("149.112.112.11", "9.9.9.11"), ("2620:fe::fe:11", "2620:fe::11"), '/dns-query'),
    ]

    STRUCT_REPLY_COUNTS = struct.Struct('>HHHH')
    STRUCT_REC_FORMAT = struct.Struct('>HHIH')

    #Delay between DNS requests
    DELAY_DNS_REQUEST = 2
    TIMEOUT_DNS_REQUEST = 10

    @classmethod
    def _get_priority(cls):
        return 5


    def __init__(self, session):
        super().__init__(session)
        self._alternative_routes = []

    @classmethod
    def _compute_ar_domain(cls, host):
        return b'd' + base64.b32encode(host.encode('ascii')).strip(b'=') + b".protonpro.xyz"

    async def _async_dns_query(
            self, domain, dns_server_ip, dns_server_path, delay=0
    ) -> List[AlternativeRoutingDNSQueryAnswer]:
        import aiohttp

        if delay > 0:
            await asyncio.sleep(delay)

        ardomain = self._compute_ar_domain(domain)
        dns_request = DNSParser.build_query(ardomain, qtype=16, qclass=1)  # TXT IN
        dot_url = f'https://{dns_server_ip}{dns_server_path}'

        async with aiohttp.ClientSession() as session:
            async with session.post(dot_url, headers=[("Content-Type","application/dns-message")], data=dns_request) as r:
                reply_data = await r.content.read()

        try:
            dns_answers = DNSParser.parse(reply_data)
        except DNSResponseError as e:
            raise ProtonAPINotReachable(str(e))

        now = time.time()
        # Tuples (TTL, data)
        answers = []
        for rec_ttl, rec_val in dns_answers:
            answers.append(AlternativeRoutingDNSQueryAnswer(
                expiration_time=now + rec_ttl,
                domain=rec_val)
            )

        return answers

    @property
    def _http_domain(self):
        return urlparse(super().http_base_url).netloc

    async def _get_alternative_routes(self):
        # We generate a random list of dns servers, 
        # we query them following that order, simultaneoulsy on IPv4/IPv6
        choices_ipv4 = []
        choices_ipv6 = []
        for dns_server_ipv4s, dns_server_ipv6s, dns_server_path in self.DNS_PROVIDERS:
            for ip in dns_server_ipv4s:
                choices_ipv4.append((ip, dns_server_path))
            for ip in dns_server_ipv6s:
                choices_ipv6.append((ip, dns_server_path))

        random.shuffle(choices_ipv4)
        random.shuffle(choices_ipv6)

        pending = []
        i = 0
        for ipv4, ipv6 in itertools.zip_longest(choices_ipv4, choices_ipv6, fillvalue=None):
            if i * self.DELAY_DNS_REQUEST > self.TIMEOUT_DNS_REQUEST:
                break

            if ipv4 is not None:
                pending.append(asyncio.create_task(self._async_dns_query(self._http_domain, ipv4[0], ipv4[1], delay=i * self.DELAY_DNS_REQUEST)))
            if ipv6 is not None:
                pending.append(asyncio.create_task(self._async_dns_query(self._http_domain, f'[{ipv6[0]}]', ipv6[1], delay=i * self.DELAY_DNS_REQUEST)))
            
            i += 1

        results_ok = []
        results_fail = []
        proton_api_not_available_errors = []
        final_timestamp = time.time() + self.TIMEOUT_DNS_REQUEST
        while len(pending) > 0 and len(results_ok) == 0:
            done, pending = await asyncio.wait(pending, timeout=max(0.1, final_timestamp - time.time()), return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                try:
                    results_ok += task.result()
                except ProtonAPINotAvailable as e:
                    # That means that we were able to do a resolution, but it explicitly failed
                    proton_api_not_available_errors.append(e)
                except Exception as e:
                    results_fail.append(e)
        
        for task in pending:
            task.cancel()

        if proton_api_not_available_errors:
            raise proton_api_not_available_errors[0]

        if len(results_ok) == 0:
            if len(self._alternative_routes) > 0:
                # We have routes, but we were not able to resolve new ones. Just keep the old ones
                return
            else:
                # No routes, and failed to get new ones
                raise ProtonAPINotReachable("Couldn't resolve any alternative routing names")

        domains = [x.domain for x in results_ok]
        # Filter names that are in our results (we don't want duplicates)
        self._alternative_routes = [
            x for x in self._alternative_routes
            if x.domain not in domains and x.expiration_time >= time.time()
        ]
        # Add the results
        self._alternative_routes += results_ok
        # Sort them so we have the most recent on top
        self._alternative_routes.sort(key=lambda x: x.expiration_time, reverse=True)

    @property
    def http_base_url(self):
        if len(self._alternative_routes) == 0:
            raise ProtonAPINotReachable("AlternativeRouting transport doesn't have any route")

        path = urlparse(super().http_base_url).path
        
        return f'https://{self._alternative_routes[0].domain}{path}'

    @property
    def tls_pinning_hashes(self):
        return self._environment.tls_pinning_hashes_ar

    async def async_api_request(
        self, endpoint,
        jsondata=None, data=None, additional_headers=None,
        method=None, params=None
    ):
        if len(self._alternative_routes) == 0 or self._alternative_routes[0].expiration_time < time.time():
            await self._get_alternative_routes()

        return await super().async_api_request(endpoint, jsondata, data, additional_headers, method, params)
