import json
import os
from ._base import KeyringBackend

class KeyringBackendJsonFiles(KeyringBackend):
    def __init__(self):
        super().__init__()

        from ..utils import ExecutionEnvironment
        self.__path_base = ExecutionEnvironment().path_config

    @classmethod
    def _get_priority(cls) -> int:
        # Low priority, but it should always work
        return -1000

    def __get_filename_for_key(self, key):
        self._ensure_key_is_valid(key)

        return os.path.join(self.__path_base, f'keyring-{key}.json')

    def __getitem__(self, key):
        f = self.__get_filename_for_key(key)
        if not os.path.exists(f):
            raise KeyError(key)
        with open(self.__get_filename_for_key(key), 'r') as f:
            try:
                return json.load(f)
            except Exception:
                #logger.exception(e)

                # We just return that the key doesn't exist, as we can't load the key
                raise KeyError(key)

    def __delitem__(self, key):
        f = self.__get_filename_for_key(key)
        if not os.path.exists(f):
            raise KeyError(key)
        os.unlink(f)

    def __setitem__(self, key, value):
        self._ensure_key_is_valid(key)
        self._ensure_value_is_valid(value)

        with open(self.__get_filename_for_key(key), 'w') as f:
            json.dump(value, f)
