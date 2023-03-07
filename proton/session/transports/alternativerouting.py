from dataclasses import dataclass
from typing import Awaitable, List
import aiohttp
from ..exceptions import *
from .aiohttp import AiohttpTransport

import json, base64, struct, time, asyncio, random, itertools

from urllib.parse import urlparse

from ..api import sync_wrapper


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

    def _get_ar_domain_for(self, host):
        host_part = b'd' + base64.b32encode(host.encode('ascii')).strip(b'=')

        return bytes([len(host_part)]) + host_part + b'\x09protonpro\x03xyz\x00'

    def _dns_parse_name(self, buffer, offset = 0):
        # Length that we've parsed (for that specific record)
        parsed_length = 0
        # Have we jumped to somewhere else?
        has_jumped = False
        # Parts we've seen until now
        parts = []
        # While we're in the buffer, and we are not on a null byte (terminator)
        while offset < len(buffer) and buffer[offset] != 0:
            # Read the length of the part, in one byte
            length = buffer[offset]
            # If the length starts with two one bytes, then it's a pointer
            if length & 0b1100_0000 == 0b1100_0000:
                offset = ((buffer[offset] & 0b0011_1111) << 8) + buffer[offset + 1]
                # Pointers have length 2
                if not has_jumped:
                    parsed_length += 2
                # We're not any more in the current record, stop counting
                has_jumped = True
            else:
                # Real entry
                # Add the part
                if offset + 1 + length > len(buffer):
                    raise ProtonAPINotReachable(f"DNS resolution failed (non-parsable value)")
                parts.append(buffer[offset + 1:offset + 1 + length])
                # Add length, and the length byte
                if not has_jumped:
                    parsed_length += length + 1
                offset += length + 1
        
        # This is for the 0-byte that terminates a name
        if not has_jumped:
            parsed_length += 1
        
        return parsed_length, parts

    async def _async_dns_query(
            self, domain, dns_server_ip, dns_server_path, delay=0
    ) -> List[AlternativeRoutingDNSQueryAnswer]:
        import aiohttp

        if delay > 0:
            await asyncio.sleep(delay)

        ardomain = self._get_ar_domain_for(domain)
        dns_request = b"\x00\x00\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" + ardomain + b"\x00\x10\x00\x01"
        dot_url = f'https://{dns_server_ip}{dns_server_path}'

        async with aiohttp.ClientSession() as session:
            async with session.post(dot_url, headers=[("Content-Type","application/dns-message")], data=dns_request) as r:
                reply_data = await r.content.read()

        if len(reply_data) < 12:
            raise ProtonAPINotReachable(f"DNS resolution failed using server {dot_url} (truncated reply)")
        
        #Match reply code (0x0 = OK)
        dns_rcode = reply_data[3] & 0xf
        if dns_rcode == 0x3:
            #NXDOMAIN, this is fatal
            raise ProtonAPINotAvailable("No alternative routing exists for this environment (NXDOMAIN)")
        elif dns_rcode != 0x0:
            raise ProtonAPINotReachable(f"DNS resolution failed using server {dot_url} (RCODE={dns_rcode:x})")

        # Get counts
        dns_qdcount, dns_ancount, dns_nscount, dns_arcount = self.STRUCT_REPLY_COUNTS.unpack(reply_data[4:12])

        offset = 12
        # Questions
        for dns_qd_idx in range(dns_qdcount):
            length, data = self._dns_parse_name(reply_data, offset)
            #We ignore QTYPE/QCLASS
            offset += length + 4

        # Tuples (TTL, data)
        answers = []

        # Answers
        for dns_an_idx in range(dns_ancount):
            length, data = self._dns_parse_name(reply_data, offset)
            
            offset += length
            rec_type, rec_class, rec_ttl, rec_dlen = self.STRUCT_REC_FORMAT.unpack_from(reply_data[offset:])
            offset += 10

            record = reply_data[offset:offset + rec_dlen]

            offset += rec_dlen

            if rec_type == 0x10 and rec_class == 0x01: #IN TXT
                if record[0] != rec_dlen - 1:
                    raise ProtonAPINotReachable(f"DNS resolution failed using server {dot_url} (length of TXT record doesn't match REC_DLEN)")
                if record[0] != len(record) - 1:
                    raise ProtonAPINotReachable(f"DNS resolution failed using server {dot_url} (length of TXT record doesn't actual record data)")    

            answers.append(AlternativeRoutingDNSQueryAnswer(
                expiration_time=time.time() + rec_ttl,
                domain=record[1:].decode('ascii'))
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
        final_timestamp = time.time() + self.TIMEOUT_DNS_REQUEST
        while len(pending) > 0 and len(results_ok) == 0:
            done, pending = await asyncio.wait(pending, timeout=max(0.1, final_timestamp - time.time()), return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                try:
                    results_ok += task.result()
                except ProtonAPINotAvailable as e:
                    # That means that we were able to do a resolution, but it explicitly failed
                    # Cancel tasks and raise exception
                    for task in pending:
                        task.cancel()
                    raise
                except Exception as e:
                    results_fail.append(e)
        
        for task in pending:
            task.cancel()

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
