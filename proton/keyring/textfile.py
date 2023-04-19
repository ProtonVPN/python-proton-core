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
import json
import os

from ..utils import ExecutionEnvironment
from ._base import Keyring
from .exceptions import KeyringError


class KeyringBackendJsonFiles(Keyring):
    """Primitive data storage implementation, to be used when no better keyring is present.

    It stores each entry a json in the configuration path.
    """
    def __init__(self, path_config=None):
        super().__init__()
        self.__path_base = path_config or ExecutionEnvironment().path_config

    def _get_item(self, key):
        filepath = self.__get_filename_for_key(key)
        if not os.path.exists(filepath):
            raise KeyError(key)

        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            self._del_item(key)
            raise KeyError(key) from e

    def _del_item(self, key):
        filepath = self.__get_filename_for_key(key)
        if not os.path.exists(filepath):
            raise KeyError(key)

        os.unlink(filepath)

    def _set_item(self, key, value):
        try:
            with open(self.__get_filename_for_key(key), 'w') as f:
                json.dump(value, f)
        except TypeError as e:
            # The value we got is not serializable, thus a type error is thrown,
            # we re-raise it as a ValueError because the value that was provided was in
            # in un-expected format/type
            raise ValueError(value) from e
        except FileNotFoundError as e:
            # if the path was not previously created for some reason,
            # we get a FileNotFoundError
            raise KeyringError(key) from e

    def __get_filename_for_key(self, key):
        return os.path.join(self.__path_base, f'keyring-{key}.json')

    @classmethod
    def _get_priority(cls) -> int:
        return -1000

    @classmethod
    def _validate(cls):
        is_able_to_write_in_dir = True
        try:
            ExecutionEnvironment().path_config
        except: # noqa
            is_able_to_write_in_dir = False

        return is_able_to_write_in_dir
