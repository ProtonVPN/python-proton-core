from .metaclasses import Singleton
import os

class ExecutionEnvironment(metaclass=Singleton):
    def __init__(self):
        # If we run as a system user, use system paths
        if os.getuid() == 0:
            self._path_config = '/etc/proton'
            self._path_cache = '/var/cache/proton'
            self._path_logs = '/var/log/proton'
            self._path_runtime = '/run/proton'
            self._path_systemd_unit = '/etc/systemd/system'

        # If we run as a normal user
        else:
            # Try to get the BaseDirectory module
            try:
                from xdg import BaseDirectory
            except ImportError:
                BaseDirectory = None

            # If we have it, then we can get quite a few info from there
            if BaseDirectory is not None:
                config_home = BaseDirectory.xdg_config_home
                cache_home = BaseDirectory.xdg_cache_home
                runtime_dir = BaseDirectory.get_runtime_dir()
            # Otherwise, we just use default constructed from $HOME environment variable
            else:
                home = os.environ.get('HOME', None)
                if home is None:
                    raise RuntimeError("Cannot figure out where to place files, is $HOME defined?")
                config_home = os.path.join(home, '.config')
                cache_home = os.path.join(home, '.cache')
                runtime_dir = f'/run/user/{os.getuid()}'

            self._path_config = os.path.join(config_home, 'proton')
            self._path_cache = os.path.join(cache_home, 'proton')
            self._path_logs = os.path.join(cache_home, 'proton', 'logs')
            self._path_runtime = os.path.join(runtime_dir, 'proton')
            self._path_systemd_unit = os.path.join(config_home, "systemd", "user")

    @property
    def path_config(self):
        os.makedirs(self._path_config, mode=0o700, exist_ok=True)
        return self._path_config

    @property
    def path_cache(self):
        os.makedirs(self._path_cache, mode=0o700, exist_ok=True)
        return self._path_cache

    @property
    def path_logs(self):
        os.makedirs(self._path_logs, mode=0o700, exist_ok=True)
        return self._path_logs

    @property
    def path_runtime(self):
        os.makedirs(self._path_runtime, mode=0o700, exist_ok=True)
        return self._path_runtime

    @property
    def systemd_unit(self):
        return self._path_systemd_unit
