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
from proton.utils.environment import ProductExecutionEnvironment
import shutil
import pytest
from unittest.mock import Mock, patch
import os


@pytest.fixture
def config_mock(tmp_path):
    d = tmp_path / "etc"
    d.mkdir()
    yield d
    shutil.rmtree(str(d))

@pytest.fixture
def cache_mock(tmp_path):
    d = tmp_path / "var" / "cache"
    d.mkdir(parents=True)
    yield d
    shutil.rmtree(str(d))

@pytest.fixture
def runtime_mock(tmp_path):
    d = tmp_path / "run"
    d.mkdir(parents=True)
    yield d
    shutil.rmtree(str(d))


@patch("proton.utils.environment.BaseDirectory")
@patch("proton.utils.environment.os.getuid")
def test_successfully_create_product_dirs_when_creating_new_product_class(
   get_uid_mock, base_directory_mock, config_mock, cache_mock, runtime_mock
):
    get_uid_mock.return_value = 1
    base_directory_mock.xdg_config_home = config_mock
    base_directory_mock.xdg_cache_home = cache_mock
    base_directory_mock.get_runtime_dir.return_value = runtime_mock

    class MockEnv(ProductExecutionEnvironment):
        PRODUCT = "mock"

    assert MockEnv().path_config == str(config_mock / "Proton" / "mock")
    assert MockEnv().path_cache == str(cache_mock / "Proton" / "mock")
    assert MockEnv().path_logs == str(cache_mock / "Proton" / "logs" / "mock")
    assert MockEnv().path_runtime == str(runtime_mock / "Proton" / "mock")


def test_raises_exception_when_creating_new_product_class_and_not_setting_product_class_property():
    class MockEnv(ProductExecutionEnvironment):
        ...

    with pytest.raises(RuntimeError):
        MockEnv()
