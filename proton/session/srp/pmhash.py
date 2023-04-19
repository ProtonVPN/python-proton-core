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
# Custom expanded version of SHA512
import hashlib


class PMHash:
    digest_size = 256
    name = 'PMHash'

    def __init__(self, b=b""):
        self.b = b

    def update(self, b):
        self.b += b

    def digest(self):
        return hashlib.sha512(
                self.b + b'\0'
            ).digest() + hashlib.sha512(
                self.b + b'\1'
            ).digest() + hashlib.sha512(
                self.b + b'\2'
            ).digest() + hashlib.sha512(
                self.b + b'\3'
            ).digest()

    def hexdigest(self):
        return self.digest().hex()

    def copy(self):
        return PMHash(self.b)


def pmhash(b=b""):
    return PMHash(b)
