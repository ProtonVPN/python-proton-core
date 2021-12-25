from abc import ABCMeta, abstractmethod
import re
from typing import Union, Optional

class KeyringException(Exception):
    pass

class KeyringNotWorking(KeyringException):
    """This exception is thrown when the keyring is broken in some sense.
    
    In that situation, probably the best option is to use another backend."""
    pass


class KeyringBackend(metaclass=ABCMeta):
    def __init__(self):
        pass

    @classmethod
    def _get_priority(cls) -> Optional[float]:
        """Return the priority of the specific class (see :class:`proton.loader.loader.Loader`)"""
        return None

    def _ensure_key_is_valid(self, key):
        if type(key) != str:
            raise TypeError(f"Invalid key for keyring: {key!r}")
        if not re.match(r'^[a-z0-9-]+$', key):
            raise ValueError("Keyring key should be alphanumeric")

    def _ensure_value_is_valid(self, value):
        if not isinstance(value, dict) and not isinstance(value, list):
            raise TypeError(f"Provided value {value} is not a valid type (expect dict or list)")

    @abstractmethod
    def __getitem__(self, key: str):
        """Get an item from the keyring

        :param key: Key (lowercaps alphanumeric, dashes are allowed)
        :type key: str
        """
        pass

    @abstractmethod
    def __delitem__(self, key: str):
        """Remove an item from the keyring

        :param key: Key (lowercaps alphanumeric, dashes are allowed)
        :type key: str"""
        pass

    @abstractmethod
    def __setitem__(self, key: str, value: Union[dict, list]):
        """Add or replace an item in the keyring

        :param key: Key (lowercaps alphanumeric, dashes are allowed)
        :type key: str
        :param value: Value to set. It has to be json-serializable.
        :type value: dict or list
        """
        pass
