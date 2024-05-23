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
import ipaddress
import logging
import re
import struct
import typing
import random


class DNSResponseError(Exception):
    pass


class DNSParsingException(DNSResponseError):
    pass


class DNSParser:
    """Parse response from any DNS resolvers"""

    STRUCT_REPLY_COUNTS = struct.Struct('>HHHH')
    STRUCT_REC_FORMAT = struct.Struct('>HHIH')

    _MINIMUM_RECORD_LENGTH = 12  # => Transaction ID/Flags/#Questions/#Answers/#AuthorRRs/#AdditRRs

    # Regular expression used in _is_valid_hostname.
    # Each hostname segment (the strings in between the period characters) is only valid if:
    #  - it has a minimum of 1 character and maximum of 63,
    #  - it only contains alphanumeric characters or the hyphen but
    #  - it does not start or end with a hyphen.
    _VALID_HOSTNAME_SEGMENT = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)

    # type definitions
    IPvxAddress = typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    ParsedData = typing.Union[str, IPvxAddress]

    @classmethod
    def parse(cls, reply_data) -> typing.Optional[typing.List[typing.Tuple[int, ParsedData]]]:
        """ parse DNS reply and returns list of : TTL, address(IP or CNAME)"""

        if len(reply_data) < cls._MINIMUM_RECORD_LENGTH:
            raise DNSParsingException(f"(truncated reply)")

        # Match reply code (0x0 = OK)
        dns_rcode = reply_data[3] & 0xf

        # ensure we have something to parse
        if dns_rcode == 0x3:
            #NXDOMAIN, this is fatal
            raise DNSResponseError("No alternative routing exists for this environment (NXDOMAIN)")
        elif dns_rcode != 0x0:
            raise DNSResponseError(f"DNS response error code: {dns_rcode}")

        # Get counts
        offset = 4
        dns_qdcount, dns_ancount, dns_nscount, dns_arcount = cls.STRUCT_REPLY_COUNTS.unpack_from(reply_data[offset:])
        offset += cls.STRUCT_REPLY_COUNTS.size
        # skip questions
        for dns_qd_idx in range(dns_qdcount):
            length, data = cls._get_name(reply_data, offset)
            # We ignore QTYPE/QCLASS
            offset += length + 4

        # tuples (TTL, data)
        answers = []
        # answers
        for dns_an_idx in range(dns_ancount):
            length, data = cls._get_name(reply_data, offset)

            offset += length
            try:
                rec_type, rec_class, rec_ttl, rec_dlen = cls.STRUCT_REC_FORMAT.unpack_from(reply_data[offset:])
            except struct.error:
                raise DNSParsingException(f"(truncated record headers)")
            offset += cls.STRUCT_REC_FORMAT.size

            record = reply_data[offset:offset + rec_dlen]
            if offset + rec_dlen > len(reply_data):
                raise DNSParsingException(f"(truncated reply while parsing record)")
            offset += rec_dlen

            if rec_type == 0x10 and rec_class == 0x01:  # IN TXT
                if record[0] != rec_dlen - 1:
                    raise DNSParsingException(f"(length of TXT record doesn't match REC_DLEN)")
                if record[0] != len(record) - 1:
                    raise DNSParsingException(f"(length of TXT record doesn't actual record data)")
                try:
                    hostname = record[1:].decode('ascii')

                    # Only hostnames with a valid format are accepted in TXT records.
                    # This is to avoid possible security exploits where the TXT record contains
                    # a full URL (hostname + path), which e.g. could trigger SSO redirects.
                    if not cls._is_valid_hostname(hostname):
                        raise DNSParsingException(f"Invalid hostname in TXT record: {hostname}")

                    answers.append((int(rec_ttl), hostname))
                except UnicodeDecodeError:
                    raise DNSParsingException(f"(UnicodeDecodeError in TXT record)")
            elif rec_type == 0x01 and rec_class == 0x01:  # IN A
                if len(record) != 4:
                    raise DNSParsingException(f"(length of A record doesn't match)")

                try:
                    ipv4_address = ipaddress.IPv4Address(record)
                except ValueError as exc:
                    raise DNSParsingException(f"Invalid IP address in A record: {record}") from exc

                answers.append((int(rec_ttl), ipv4_address))
            else:
                logging.warning(f"record type currently not supported: {rec_type}... skip")

        return answers

    @staticmethod
    def _get_name(buffer: bytes, offset=0):
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
                    raise DNSParsingException(f"DNS resolution failed (non-parsable value)")
                parts.append(buffer[offset + 1:offset + 1 + length])
                # Add length, and the length byte
                if not has_jumped:
                    parsed_length += length + 1
                offset += length + 1

        # This is for the 0-byte that terminates a name
        if not has_jumped:
            parsed_length += 1

        return parsed_length, parts

    @classmethod
    def _build_simple_query(cls, domain: bytes, qtype: int, qclass: int):
        """internal utility to build the simplest DNS request we need"""
        id: bytes = struct.pack('!H', random.randint(0, 65535))
        qtype: bytes = struct.pack('!H', qtype)
        qclass: bytes = struct.pack('!H', qclass)

        # it's a query with a single question, no AN, no RR, no AR
        return id + b"\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" + domain + qtype + qclass

    @classmethod
    def build_query(cls, fqdn: typing.Union[str, bytes], qtype, qclass):
        """Build a very simple dns request that is just a query with no AN, no RR, no AR, and a single question"""

        if type(fqdn) == str:
            domain = b''.join([bytes([len(el)]) + el.encode('ascii') for el in fqdn.split('.')]) + b'\x00'
        elif type(fqdn) == bytes:
            domain = b''.join([bytes([len(el)]) + el for el in fqdn.split(b'.')]) + b'\x00'
        else:
            raise TypeError("fqdn can only be str or bytes")

        query = cls._build_simple_query(domain, qtype, qclass)
        return query

    @classmethod
    def _is_valid_hostname(cls, hostname):
        if len(hostname) > 255:
            return False

        # Strip exactly one dot from the right, if present.
        if hostname[-1] == ".":
            hostname = hostname[:-1]

        # The hostname is valid if all its segments are valid.
        return all(cls._VALID_HOSTNAME_SEGMENT.match(segment) for segment in hostname.split("."))
