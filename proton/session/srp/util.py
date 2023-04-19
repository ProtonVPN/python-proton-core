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
import bcrypt
import os

from proton.session.exceptions import ProtonUnsupportedAuthVersionError


PM_VERSION = 4

SRP_LEN_BYTES = 256
SALT_LEN_BYTES = 10


def bcrypt_b64_encode(s):  # The joy of bcrypt
    bcrypt_base64 = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" # noqa
    std_base64chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"  # noqa
    s = base64.b64encode(s)
    return s.translate(bytes.maketrans(std_base64chars, bcrypt_base64))


def hash_password_3(hash_class, password, salt, modulus):
    salt = (salt + b"proton")[:16]
    salt = bcrypt_b64_encode(salt)[:22]
    hashed = bcrypt.hashpw(password, b"$2y$10$" + salt)
    return hash_class(hashed + modulus).digest()


def hash_password(hash_class, password, salt, modulus, version):
    if version == 4 or version == 3:
        return hash_password_3(hash_class, password, salt, modulus)

    # If the auth_version is lower then the
    # supported value 3 (which were dropped in 2018). In such a case, the user
    # needs to first login via web so that the auth version can be properly updated.
    #
    # This usually happens on older accounts that haven't been used in a while or
    # account that rarely login via the web client.
    raise ProtonUnsupportedAuthVersionError(
        "Account auth_version is not supported. "
        "Login via webclient for it to  be updated."
    )


def bytes_to_long(s):
    return int.from_bytes(s, 'little')


def long_to_bytes(n, num_bytes):
    return n.to_bytes(num_bytes, 'little')


def get_random(nbytes):
    return bytes_to_long(os.urandom(nbytes))


def get_random_of_length(nbytes):
    offset = (nbytes * 8) - 1
    return get_random(nbytes) | (1 << offset)


def custom_hash(hash_class, *args, **kwargs):
    h = hash_class()
    for s in args:
        if s is not None:
            data = long_to_bytes(s, SRP_LEN_BYTES) if isinstance(s, int) else s
            h.update(data)

    return bytes_to_long(h.digest())
