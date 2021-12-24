import os
import warnings

from ..utils import Singleton

class Loader(metaclass=Singleton):
    """This is the loader for pluggable components. These components are identified by a type name (string)
    and a class name (also a string).
    
    You can influence which component to use using the PROTON_LOADER_OVERRIDES environment variable. It's a comma separated list
    of type_name=class_name (to force class_name to be used) and type_name=-class_name (to exclude class_name from the options considered).

    To find the candidates, Loader will use entry points, that are to be defined in setup.py, as follows:
    ```
    setup(
        [...],
        entry_points={
            "proton_loader_keyring": [
                "json = proton.keyring.textfile:KeyringBackendJsonFiles"
            ]
        },
        [...]
    )
    ```

    The class pointed by these entrypoints should implement the following class methods:
    * _get_priority(): return a numeric value, larger ones have higher priority. If it's None, then this class won't be considered
    * _validate(): check if the object can indeed be used (might be expensive/annoying). If it returns False, then the backend won't be considered for the rest of the session.

    If _validate() is not defined, then it's assumed that it will always succeed.

    To display the list of valid values, you can use `python3 -m proton.loader`.
    """

    __loader_prefix = 'proton_loader_'

    def __init__(self):
        try:
            from importlib import metadata
        except ImportError:
            # Python < 3.8
            import importlib_metadata as metadata

        self.__metadata = metadata
        self.__known_types = {}

    @property
    def type_names(self): 
        return [x[len(self.__loader_prefix):] for x in self.__metadata.entry_points().keys() if x.startswith(self.__loader_prefix)]

    def _get_metadata_group_for_typename(self, type_name: str) -> str:
        return self.__loader_prefix + type_name

    def get_all(self, type_name: str):
        # If we don't have already loaded the entry points, just do so
        if type_name not in self.__known_types:
            entry_points = self.__metadata.entry_points().get(self._get_metadata_group_for_typename(type_name), ())
            self.__known_types[type_name] = {}
            for ep in entry_points:
                try:
                    self.__known_types[type_name][ep.name] = ep.load()
                except AttributeError:
                    warnings.warn(f"Loader: couldn't load {type_name}/{ep.name}, is it installed properly?", RuntimeWarning, stacklevel=2)

        
        
        # We do this at runtime, because we want to make sure we can change it after start.
        overrides = os.environ.get('PROTON_LOADER_OVERRIDES', '')
        overrides = [x.strip() for x in overrides.split()]
        overrides = [x[len(type_name)+1:] for x in overrides if x.startswith(f'{type_name}=')]

        force_class = set([x for x in overrides if not x.startswith('-')])
        if len(force_class) == 1:
            force_class = list(force_class)[0]
            if force_class in self.__known_types[type_name]:
                acceptable_entry_points = [force_class]
        elif len(force_class) > 1:
            raise RuntimeError(f"Loader: PROTON_LOADER_OVERRIDES contains multiple force for {type_name}")
        else:
            # Load all entry_points, except those that are excluded by PROTON_LOADER_OVERRIDES
            acceptable_entry_points = []
            for k in self.__known_types[type_name].keys():
                if '-' + k not in overrides:
                    acceptable_entry_points.append(k)

        acceptable_classes = [(v._get_priority(), k, v) for k, v in self.__known_types[type_name].items() if k in acceptable_entry_points]
        acceptable_classes += [(None, k, v) for k, v in self.__known_types[type_name].items() if k not in acceptable_entry_points]
        acceptable_classes_with_prio = [(priority, class_name, v) for priority, class_name, v in acceptable_classes if priority is not None]
        acceptable_classes_without_prio = [(priority, class_name, v) for priority, class_name, v in acceptable_classes if priority is None]
        acceptable_classes_with_prio.sort(reverse=True)
        
        return acceptable_classes_with_prio + acceptable_classes_without_prio

    def get(self, type_name: str) -> type:
        acceptable_classes = self.get_all(type_name)

        for prio, class_name, cls in acceptable_classes:
            # Invalid priority, just continue (this will fail anyway because we have ordered the list in get_all, but for what it costs I prefer to go through the list)
            if prio is None:
                continue
            # If we have a _validate class method, try to see if the object is indeed acceptable
            if hasattr(cls, '_validate'):
                if cls._validate():
                    return cls
                else:
                    # If not, remove that from the acceptable types definitely (it's broken)
                    self.__known_types[type_name] = dict([(k,v) for k, v in self.__known_types[type_name].items() if v != cls])
            else:
                return cls

        raise RuntimeError(f"Loader: couldn't find an acceptable implementation for {type_name}.")


