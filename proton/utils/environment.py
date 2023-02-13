from .metaclasses import Singleton
import os
import shutil
# Try to get the BaseDirectory module
try:
    from xdg import BaseDirectory
except ImportError:
    BaseDirectory = None


class ExecutionEnvironment(metaclass=Singleton):
    PROTON_DIR_NAME = "Proton"

    def __init__(self):
        # If we run as a system user, use system paths
        if os.getuid() == 0:
            self._setup_as_system_user()
        else:
        # If we run as a normal user
            self._setup_as_regular_user()

    @property
    def path_config(self):
        self.generate_dirs(self._path_config)
        return self._path_config

    @property
    def path_cache(self):
        self.generate_dirs(self._path_cache)
        return self._path_cache

    @property
    def path_logs(self):
        self.generate_dirs(self._path_logs)
        return self._path_logs

    @property
    def path_runtime(self):
        self.generate_dirs(self._path_runtime)
        return self._path_runtime

    @property
    def systemd_unit(self):
        return self._path_systemd_unit

    def generate_dirs(self, path):
        if os.path.isdir(path):
            return

        os.makedirs(path, mode=0o700, exist_ok=True)

    def _setup_as_system_user(self):
        self._path_config = f'/etc/{self.PROTON_DIR_NAME}'
        self._path_cache = f'/var/cache/{self.PROTON_DIR_NAME}'
        self._path_logs = f'/var/log/{self.PROTON_DIR_NAME}'
        self._path_runtime = f'/run/{self.PROTON_DIR_NAME}'
        self._path_systemd_unit = '/etc/systemd/system'

    def _setup_as_regular_user(self):
        config_home, cache_home, runtime_dir = self._get_dir_paths()

        self._path_config = os.path.join(config_home, self.PROTON_DIR_NAME)
        self._path_cache = os.path.join(cache_home, self.PROTON_DIR_NAME)
        self._path_logs = os.path.join(cache_home, self.PROTON_DIR_NAME, 'logs')
        self._path_runtime = os.path.join(runtime_dir, self.PROTON_DIR_NAME)
        self._path_systemd_unit = os.path.join(config_home, "systemd", "user")

    def _get_dir_paths(self):
        # If BaseDirectory is found then we can extract valuable data from it
        if BaseDirectory:
            config_home = BaseDirectory.xdg_config_home
            cache_home = BaseDirectory.xdg_cache_home
            runtime_dir = BaseDirectory.get_runtime_dir()
        else:
        # Otherwise use default constructed from $HOME environment variable
            home = os.environ.get('HOME', None)
            if home is None:
                raise RuntimeError("Cannot figure out where to place files, is $HOME defined?")

            config_home = os.path.join(home, '.config')
            cache_home = os.path.join(home, '.cache')
            runtime_dir = f'/run/user/{os.getuid()}'

        return config_home, cache_home, runtime_dir

class ProductExecutionEnvironment(ExecutionEnvironment):
    """
    This class serves the purpose of helping in standardizing folder structure
    across products. Thus each product should derive from `ProductExecutionEnvironment`
    and setting the class property `PRODUCT` to match its correspondent product.

    This should help to more easily find files and improving cross-product
    collaboration. 
    """
    PRODUCT = None

    def __init__(self):
        super().__init__()
        if self.PRODUCT is None:
            raise RuntimeError("`PRODUCT` is not set")

    @property
    def path_config(self):
        path = os.path.join(super().path_config, self.PRODUCT)
        self.generate_dirs(path)
        return path

    @property
    def path_cache(self):
        path = os.path.join(super().path_cache, self.PRODUCT)
        self.generate_dirs(path)
        return path

    @property
    def path_logs(self):
        path = os.path.join(super().path_logs, self.PRODUCT)
        self.generate_dirs(path)
        return path

    @property
    def path_runtime(self):
        path = os.path.join(super().path_runtime, self.PRODUCT)
        self.generate_dirs(path)
        return path



class VPNExecutionEnvironment(ProductExecutionEnvironment):
    """Execution environment dedicated for the VPN product."""
    PRODUCT = "VPN"
