import json
import os

from ..utils import ExecutionEnvironment
from ._base import Keyring
from .exceptions import KeyringNotWorking


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

        with open(filepath, 'r') as f:
            try:
                return json.load(f)
            except Exception as e:
                # logger.exception(e)
                # We just return that the key doesn't exist, as we can't load the key
                raise KeyringNotWorking(e) from e

    def _del_item(self, key):
        filepath = self.__get_filename_for_key(key)
        if not os.path.exists(filepath):
            raise KeyError(key)

        try:
            os.unlink(filepath)
        except Exception as e:
            raise KeyringNotWorking(e)

    def _set_item(self, key, value):
        try:
            with open(self.__get_filename_for_key(key), 'w') as f:
                json.dump(value, f)
        except Exception as e:
            raise KeyringNotWorking(e)

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
