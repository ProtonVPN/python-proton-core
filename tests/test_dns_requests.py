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
import base64
import dataclasses
import ipaddress
import typing
import pytest
from proton.session.transports.utils.dns import DNSParser, DNSResponseError

@dataclasses.dataclass
class _DnsParsingTestData:
    name: str
    domain: str
    #expected_ar_domain: bytes
    expected_dns_request: bytes
    dns_reply: bytes
    expected_parsed_reply: typing.List[dict]


ar_old_domain_data = _DnsParsingTestData(
    name = "legacy domain",
    domain = "api.protonvpn.ch",
    #expected_ar_domain = b'\x1bdMFYGSLTQOJXXI33OOZYG4LTDNA\tprotonpro\x03xyz\x00',
    expected_dns_request = b'\xfa\x83\x01 \x00\x01\x00\x00\x00\x00\x00\x00\x1bdMFYGSLTQOJXXI33OOZYG4LTDNA\tprotonpro\x03xyz\x00\x00\x10\x00\x01',
    dns_reply = b'\xfa\x83\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x1bdMFYGSLTQOJXXI33OOZYG4LTDNA\tprotonpro\x03xyz\x00\x00\x10\x00\x01\xc0\x0c\x00\x10\x00\x01\x00\x00\x00x\x0032ec2-3-127-37-78.eu-central-1.compute.amazonaws.com\xc0\x0c\x00\x10\x00\x01\x00\x00\x00x\x0054ec2-54-93-234-150.eu-central-1.compute.amazonaws.com',
    expected_parsed_reply = [(120, "ec2-3-127-37-78.eu-central-1.compute.amazonaws.com"),
                             (120, "ec2-54-93-234-150.eu-central-1.compute.amazonaws.com"),]
)

ar_current_domain_data1 = _DnsParsingTestData(
    name = "current domain",
    domain = "vpn-api.proton.me",
    #expected_ar_domain = b'\x1ddOZYG4LLBOBUS44DSN52G63RONVSQ\tprotonpro\x03xyz\x00',
    expected_dns_request = b'\xcc\x72\x01 \x00\x01\x00\x00\x00\x00\x00\x00\x1ddOZYG4LLBOBUS44DSN52G63RONVSQ\tprotonpro\x03xyz\x00\x00\x10\x00\x01',
    dns_reply = b'\xcc\x72\x81\x80\x00\x01\x00\x03\x00\x00\x00\x00\x1ddOZYG4LLBOBUS44DSN52G63RONVSQ\tprotonpro\x03xyz\x00\x00\x10\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x00x\x00\x06\x03vpn\xc0*\xc0I\x00\x10\x00\x01\x00\x00\x00x\x00\x0e\r18.185.75.113\xc0I\x00\x10\x00\x01\x00\x00\x00x\x00\x0e\r18.196.59.154',
    expected_parsed_reply = [(120, '18.185.75.113'),
                             (120, '18.196.59.154'),],
)

ar_current_domain_data2 = _DnsParsingTestData(
    name = "current domain",
    domain = "vpn-api.proton.me",
    #expected_ar_domain = b'\x1ddOZYG4LLBOBUS44DSN52G63RONVSQ\tprotonpro\x03xyz\x00',
    expected_dns_request = b'\x00\x00\x01 \x00\x01\x00\x00\x00\x00\x00\x00\x1ddOZYG4LLBOBUS44DSN52G63RONVSQ\tprotonpro\x03xyz\x00\x00\x10\x00\x01',
    dns_reply = b'\x00\x00\x81\x80\x00\x01\x00\x03\x00\x00\x00\x00\x1ddOZYG4LLBOBUS44DSN52G63RONVSQ\tprotonpro\x03xyz\x00\x00\x10\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x00x\x00\x06\x03vpn\xc0*\xc0I\x00\x10\x00\x01\x00\x00\x00x\x00\x0e\r35.158.124.21\xc0I\x00\x10\x00\x01\x00\x00\x00x\x00\x0b\n3.72.109.7',
    expected_parsed_reply = [(120, '35.158.124.21'),
                             (120, '3.72.109.7')],
)

standard_legacy_domain = _DnsParsingTestData(
    name = "legacy domain",
    domain = "api.protonvpn.ch",
    expected_dns_request = b'\xdf\r\x01 \x00\x01\x00\x00\x00\x00\x00\x00\x03api\tprotonvpn\x02ch\x00\x00\x01\x00\x01',
    dns_reply = b'\xdf\r\x81\x80\x00\x01\x00\x01\x00\x03\x00\x03\x03api\tprotonvpn\x02ch\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x04\xb0\x00\x04\xb9\x9f\x9f\xaa\xc0\x10\x00\x02\x00\x01\x00\x00\x04\xb0\x00\x06\x03ns2\xc0\x10\xc0\x10\x00\x02\x00\x01\x00\x00\x04\xb0\x00\x06\x03ns3\xc0\x10\xc0\x10\x00\x02\x00\x01\x00\x00\x04\xb0\x00\x06\x03ns1\xc0\x10\xc0b\x00\x01\x00\x01\x00\x00\x04\xb0\x00\x04\xb9F*\x96\xc0>\x00\x01\x00\x01\x00\x00\x04\xb0\x00\x04\xb0w\xc8\x96\xc0P\x00\x01\x00\x01\x00\x00\x04\xb0\x00\x04\xcd\x84/\x01',
    expected_parsed_reply = [(1200, ipaddress.ip_address('185.159.159.170')),],
)

standard_current_domain = _DnsParsingTestData(
    name = "current domain",
    domain = "vpn-api.proton.me",
    expected_dns_request = b'jW\x01 \x00\x01\x00\x00\x00\x00\x00\x00\x07vpn-api\x06proton\x02me\x00\x00\x01\x00\x01',
    dns_reply = b'jW\x81\x80\x00\x01\x00\x01\x00\x03\x00\x03\x07vpn-api\x06proton\x02me\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x04\xb0\x00\x04\xb9\x9f\x9f\x94\xc0\x14\x00\x02\x00\x01\x00\x00\x04\xb0\x00\x06\x03ns3\xc0\x14\xc0\x14\x00\x02\x00\x01\x00\x00\x04\xb0\x00\x06\x03ns1\xc0\x14\xc0\x14\x00\x02\x00\x01\x00\x00\x04\xb0\x00\x06\x03ns2\xc0\x14\xc0Q\x00\x01\x00\x01\x00\x00\x04\xb0\x00\x04\xb9F*\x96\xc0c\x00\x01\x00\x01\x00\x00\x04\xb0\x00\x04\xb0w\xc8\x96\xc0?\x00\x01\x00\x01\x00\x00\x04\xb0\x00\x04\xcd\x84/\x01',
    expected_parsed_reply = [(1200, ipaddress.ip_address('185.159.159.148')),],
)

other_reply_data = [
    _DnsParsingTestData(
        name="full DNS reply legacy domain",
        domain = "api.protonvpn.ch",
        expected_dns_request = None,
        dns_reply = \
            b"\x09\x8c\x81\x80\x00\x01\x00\x01\x00\x00\x00\x01\x07\x76\x70\x6e" \
            b"\x2d\x61\x70\x69\x06\x70\x72\x6f\x74\x6f\x6e\x02\x6d\x65\x00\x00" \
            b"\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x03\x8b\x00\x04\xb9" \
            b"\x9f\x9f\x94\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00",
        expected_parsed_reply = [(907, ipaddress.ip_address('185.159.159.148'))],
        ),
    _DnsParsingTestData(
        name="full DNS reply current domain",
        domain = "vpn-api.proton.me",
        expected_dns_request = None,
        dns_reply = \
            b"\xaa\xfc\x81\x80\x00\x01\x00\x01\x00\x03\x00\x04\x03\x61\x70\x69" \
            b"\x09\x70\x72\x6f\x74\x6f\x6e\x76\x70\x6e\x02\x63\x68\x00\x00\x01" \
            b"\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x04\xb0\x00\x04\xb9\x9f" \
            b"\x9f\xaa\xc0\x10\x00\x02\x00\x01\x00\x00\x04\xb0\x00\x06\x03\x6e" \
            b"\x73\x32\xc0\x10\xc0\x10\x00\x02\x00\x01\x00\x00\x04\xb0\x00\x06" \
            b"\x03\x6e\x73\x31\xc0\x10\xc0\x10\x00\x02\x00\x01\x00\x00\x04\xb0" \
            b"\x00\x06\x03\x6e\x73\x33\xc0\x10\xc0\x50\x00\x01\x00\x01\x00\x00" \
            b"\x04\xb0\x00\x04\xb9\x46\x2a\x96\xc0\x3e\x00\x01\x00\x01\x00\x00" \
            b"\x04\xb0\x00\x04\xb0\x77\xc8\x96\xc0\x62\x00\x01\x00\x01\x00\x00" \
            b"\x04\xb0\x00\x04\xcd\x84\x2f\x01\x00\x00\x29\x10\x00\x00\x00\x00" \
            b"\x00\x00\x00",
        expected_parsed_reply = [(1200, ipaddress.ip_address('185.159.159.170'))],
        ),
]


class TestDNSParser:
    def _test_ar_input_data(self, input_data: _DnsParsingTestData):
        ar_domain = b'd' + base64.b32encode(input_data.domain.encode('ascii')).strip(b'=') + b".protonpro.xyz"
        print(f"Testing Alternative Routing DNS for {input_data.name} : {input_data.domain} => AR domain = {ar_domain}")

        dns_query = DNSParser.build_query(ar_domain, qtype=16, qclass=1)  # TXT IN
        print(f"DNS query : {dns_query}")
        # the request 2 first bytes are randomly generated and may not match
        assert dns_query[2:] == input_data.expected_dns_request[2:]
        assert len(dns_query) == len(input_data.expected_dns_request)

        dns_answers = DNSParser.parse(input_data.dns_reply)
        print(f"DNS answers : {dns_answers}")
        assert set(dns_answers) == set(input_data.expected_parsed_reply)

    def test_ar_legacy_domain(self):
        self._test_ar_input_data(input_data=ar_old_domain_data)

    def test_ar_current_domain1(self):
        self._test_ar_input_data(input_data=ar_current_domain_data1)

    def test_ar_current_domain2(self):
        self._test_ar_input_data(input_data=ar_current_domain_data2)

    def _test_normal_input_data(self, input_data: _DnsParsingTestData):
        print(f"Testing standard DNS for {input_data.name} : {input_data.domain}")
        print(input_data.expected_dns_request)

        dns_query = DNSParser.build_query(input_data.domain, qtype=1, qclass=1)  # A IN
        print(f"DNS query : {dns_query}")
        # the request 2 first bytes are randomly generated and may not match
        assert dns_query[2:] == input_data.expected_dns_request[2:]
        assert len(dns_query) == len(input_data.expected_dns_request)

        dns_answers = DNSParser.parse(input_data.dns_reply)
        print(f"DNS answers : {dns_answers}")
        assert set(dns_answers) == set(input_data.expected_parsed_reply)

    def test_normal_query_legacy_domain(self):
        self._test_normal_input_data(standard_legacy_domain)

    def test_normal_query_current_domain(self):
        self._test_normal_input_data(standard_current_domain)

    def test_generic_parsing(self):

        for input_data in other_reply_data:
            print(f"Parsing other DNS reply : {input_data.name}")
            dns_answers = DNSParser.parse(input_data.dns_reply)
            print(f"DNS answers : {dns_answers}")
            assert set(dns_answers) == set(input_data.expected_parsed_reply)

    @pytest.mark.parametrize("description, invalid_input", [
        ("Empty reply", b''),
        ("Super small reply (1)", b'x'),
        ("Super small reply (7)", b'\xfa\x83\x81\x80\x00\x01\x00'),
        ("Unicode Decode error", b'\xfa\x83\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x1bdMFYGSLTQOJXXI33OOZYG4LTDNA\tprotonpro\x03xyz\x00\x00\x10\x00\x01\xc0\x0c\x00\x10\x00\x01\x00\x00\x00x\x0032ec2\xcc3-127-37-78.eu-central-1.compute.amazonaws.com\xc0\x0c\x00\x10\x00\x01\x00\x00\x00x\x0054ec2-54-93-234-150.eu-central-1.compute.amazonaws.com'),
        ("Wrong query reply", b'\xfa\x83\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x1bdMFYGSLTQOJXXI33OOZYG4LTDNA\nprotonpro\x03xyz'),
        ("Truncated query reply", b'\xfa\x83\x81\x80\x00\x01\x00\x02\x00\x00\x00\x00\x1bdMFYGSLTQOJXXI33OOZYG4LTDNA\tproto'),
        ("Truncated TXT record value", b'\x00\x00\x81\x80\x00\x01\x00\x03\x00\x00\x00\x00\x1ddOZYG4LLBOBUS44DSN52G63RONVSQ\tprotonpro\x03xyz\x00\x00\x10\x00\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x00x\x00\x06\x03vpn\xc0*\xc0I\x00\x10\x00\x01\x00\x00\x00x\x00\x0e\r35.15'),
        ("Truncated A record value", b'jW\x81\x80\x00\x01\x00\x01\x00\x03\x00\x03\x07vpn-api\x06proton\x02me\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x04\xb0\x00\x04\xb9\x9f\x9f'),
        ("Truncated A record headers", b'jW\x81\x80\x00\x01\x00\x01\x00\x03\x00\x03\x07vpn-api\x06proton\x02me\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00'),
    ])
    def test_incorrect_records(self, description: str, invalid_input: bytes):
        print(f"{description}")
        with pytest.raises(DNSResponseError):
            _ = DNSParser.parse(invalid_input)

    @pytest.mark.parametrize("hostname, valid", [
        ("ec2-3-127-37-78.eu-central-1.compute.amazonaws.com", True),
        ("hostnames.can.end.with.one.period.", True),
        ("a"*257, False),  # hostnames have a 256-char limit
        ("-hostname", False),  # hostnames cannot start with hyphen
        ("hostname-", False),  # hostnames cannot end with hyphen
        ("a"*64 + ".blah.com", False),  # hostname segments have a 63-char limit
        ("blah..com", False),  # hostname segments should have a lest 1 char
        ("special-chars!.com", False),  # hostname segments only allow alphanumeric chars and hyphens
        ("vpn-api.proton.me/malicious/", False)  # hostname with potentially malicious path
    ])
    def test_valid_hostname_in_A_record(self, hostname, valid):
        assert DNSParser._is_valid_hostname(hostname) is valid
    