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
import re
from typing import Union
from proton.loader import Loader


class Keyring:
    """Base class for keyring implementations.

    Keyrings emulate a dictionary, with:

    * keys: lower case alphanumeric strings (dashes are allowed)
    * values: JSON-serializable list or dictionary.
    """
    def __init__(self):
        pass

    @classmethod
    def get_from_factory(cls, backend: str = None) -> "Keyring":
        """
            :param backend: Optional.
                Specific backend name.

        If backend is passed then it will attempt to get that specific
        backend, otherwise it will attempt to get the default backend.
        The definition of default is as follows:

         - The backend passes the `_validate()`
         - The backend with the highest `_get_priority()` value
        :raises RuntimeError: if there's no available backend
        """
        keyring_backend = Loader.get("keyring", class_name=backend)

        return keyring_backend()

    def __getitem__(self, key: str):
        """Get an item from the keyring

        :param key: Key (lowercaps alphanumeric, dashes are allowed)
        :type key: str
        :raises TypeError: if key is not of valid type
        :raises ValueError: if key doesn't satisfy constraints
        :raises KeyError: if key does not exist
        :raises KeyringLocked: if keyring is locked when it shouldn't be
        :raises KeyringError: if there's something broken with keyring
        """
        self._ensure_key_is_valid(key)
        return self._get_item(key)

    def __delitem__(self, key: str):
        """Remove an item from the keyring

        :param key: Key (lowercaps alphanumeric, dashes are allowed)
        :type key: str
        :raises TypeError: if key is not of valid type
        :raises ValueError: if key doesn't satisfy constraints
        :raises KeyError: if key does not exist
        :raises KeyringLocked: if keyring is locked when it shouldn't be
        :raises KeyringError: if there's something broken with keyring
        """
        self._ensure_key_is_valid(key)
        self._del_item(key)

    def __setitem__(self, key: str, value: Union[dict, list]):
        """Add or replace an item in the keyring

        :param key: Key (lowercaps alphanumeric, dashes are allowed)
        :type key: str
        :param value: Value to set. It has to be json-serializable.
        :type value: dict or list
        :raises TypeError: if key or value is not of valid type
        :raises ValueError: if key or value doesn't satisfy constraints
        :raises KeyringLocked: if keyring is locked when it shouldn't be
        :raises KeyringError: if there's something broken with keyring
        """
        self._ensure_key_is_valid(key)
        self._ensure_value_is_valid(value)
        self._set_item(key, value)

    def _get_item(self, key: str):
        raise NotImplementedError

    def _del_item(self, key: str):
        raise NotImplementedError

    def _set_item(self, key: str, value: Union[dict, list]):
        raise NotImplementedError

    def _ensure_key_is_valid(self, key):
        """Ensure key satisfies requirements"""
        if type(key) != str:
            raise TypeError(f"Invalid key for keyring: {key!r}")
        if not re.match(r'^[a-z0-9-]+$', key):
            raise ValueError("Keyring key should be alphanumeric")

    def _ensure_value_is_valid(self, value):
        """Ensure value satisfies requirements"""
        if not isinstance(value, dict) and not isinstance(value, list):
            raise TypeError(f"Provided value {value} is not a valid type (expect dict or list)")

    @classmethod
    def _get_priority(cls) -> int:
        return None

    @classmethod
    def _validate(cls):
        return False
