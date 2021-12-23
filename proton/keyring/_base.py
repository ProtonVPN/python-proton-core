from abc import ABCMeta, abstractmethod

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
    def _get_priority(cls) -> int:
        """
        Return the priority of the specific class

        (loader will use the object with highest non-None priority)
        """
        return None

    def _ensure_key_is_valid(self, key):
        if type(key) != str:
            raise TypeError(f"Invalid key for keyring: {key!r}")
        if not key.isalnum():
            raise ValueError("Keyring key should be alphanumeric")

    def _ensure_value_is_valid(self, value):
        if not isinstance(value, dict):
            msg = "Provided value {} is not a valid type (expect {})".format(
                value, dict
            )

            raise TypeError(msg)

    @abstractmethod
    def __getitem__(self, key):
        """Get an item from the keyring"""
        pass

    @abstractmethod
    def __delitem__(self, key):
        """Remove an item from the keyring"""
        pass

    @abstractmethod
    def __setitem__(self, key, value):
        """Add or replace an item in the keyring"""
        pass
