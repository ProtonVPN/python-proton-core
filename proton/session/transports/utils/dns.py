import ipaddress
import logging
import struct
import time
import typing
import random


class DNSParsingException(Exception):
    pass


class DNSResponseError(Exception):
    pass


class DNSParser:
    """Parse response from any DNS resolvers"""

    STRUCT_REPLY_COUNTS = struct.Struct('>HHHH')
    STRUCT_REC_FORMAT = struct.Struct('>HHIH')

    # type defintiions
    IPvxAddress = typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    ParsedData = typing.Union[str, IPvxAddress]

    def parse(self, reply_data) -> typing.Optional[typing.List[typing.Tuple[int, ParsedData]]]:
        if len(reply_data) < 12:
            raise DNSParsingException(f"(truncated reply)")

        # Match reply code (0x0 = OK)
        dns_rcode = reply_data[3] & 0xf

        # ensure we have something to parse
        if dns_rcode != 0x0:
            raise DNSResponseError(f"DNS response error code: {dns_rcode}")

        # Get counts
        dns_qdcount, dns_ancount, dns_nscount, dns_arcount = self.STRUCT_REPLY_COUNTS.unpack(reply_data[4:12])

        offset = 12
        # skip questions
        for dns_qd_idx in range(dns_qdcount):
            length, data = self._get_name(reply_data, offset)
            # We ignore QTYPE/QCLASS
            offset += length + 4

        # tuples (TTL, data)
        answers = []
        now = int(time.time())
        # answers
        for dns_an_idx in range(dns_ancount):
            length, data = self._get_name(reply_data, offset)

            offset += length
            rec_type, rec_class, rec_ttl, rec_dlen = self.STRUCT_REC_FORMAT.unpack_from(reply_data[offset:])
            offset += 10

            record = reply_data[offset:offset + rec_dlen]

            offset += rec_dlen

            if rec_type == 0x10 and rec_class == 0x01:  # IN TXT
                if record[0] != rec_dlen - 1:
                    raise DNSParsingException(f"(length of TXT record doesn't match REC_DLEN)")
                if record[0] != len(record) - 1:
                    raise DNSParsingException(f"(length of TXT record doesn't actual record data)")
                answers.append((now + int(rec_ttl), record[1:].decode('ascii')))
            elif rec_type == 0x01 and rec_class == 0x01:  # IN A
                answers.append((now + int(rec_ttl), ipaddress.ip_address(record)))
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


def build_dns_query(fqdn: typing.Union[str, bytes], qtype, qclass):
    """Build a very simple dns request that is just a query with no AN, no RR, no AR, and a single question"""
    def build_simple_dns_query(domain: bytes, qtype: int, qclass: int):
        id: bytes = struct.pack('!H', random.randint(0, 65535))
        qtype: bytes = struct.pack('!H', qtype)
        qclass: bytes = struct.pack('!H', qclass)

        # it's a query with a single question, no AN, no RR, no AR
        return id + b"\x01\x20\x00\x01\x00\x00\x00\x00\x00\x00" + domain + qtype + qclass

    if type(fqdn) == str:
        domain = b''.join([bytes([len(el)]) + el.encode('ascii') for el in fqdn.split('.')]) + b'\x00'
    elif type(fqdn) == bytes:
        domain = b''.join([bytes([len(el)]) + el for el in fqdn.split(b'.')]) + b'\x00'
    else:
        raise TypeError("fqdn can only be str or bytes")

    query = build_simple_dns_query(domain, qtype, qclass)
    return query
