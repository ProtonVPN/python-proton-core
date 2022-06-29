from proton.keyring.textfile import KeyringBackendJsonFiles
import tempfile
import pytest
import json
import os
from proton.keyring.exceptions import KeyringError


@pytest.fixture
def mock_path_config():
    with tempfile.TemporaryDirectory(prefix="test_textfile_keyring") as tmpdirname:
        yield tmpdirname


def test_get_item(mock_path_config):
    test_get_values = {"test-key": "test-value"}
    test_key_fp = os.path.join(mock_path_config, "keyring-test-get-keyring.json")
    with open(test_key_fp, "w") as f:
        json.dump(test_get_values, f)

    k = KeyringBackendJsonFiles(path_config=mock_path_config)
    assert k._get_item("test-get-keyring") == test_get_values


def test_del_item(mock_path_config):
    test_key_fp = os.path.join(mock_path_config, "keyring-test-del-keyring.json")
    with open(test_key_fp, "w") as f:
        json.dump({"test-del-key": "test-del-value"}, f)

    k = KeyringBackendJsonFiles(path_config=mock_path_config)
    k._del_item("test-del-keyring")
    assert not os.path.isfile(test_key_fp)


def test_set_item(mock_path_config):
    k = KeyringBackendJsonFiles(path_config=mock_path_config)
    k._set_item("test-set-keyring", {"set-test-key": "set-test-value"})
    assert os.path.isfile(os.path.join(mock_path_config, "keyring-test-set-keyring.json"))


def test_get_item_raises_exception_filepath_does_not_exist(mock_path_config):
    k = KeyringBackendJsonFiles(path_config=mock_path_config)
    with pytest.raises(KeyError):
        k._get_item("test-get-keyring")


def test_get_item_raises_exception_corrupted_json_data(mock_path_config):
    test_key_fp = os.path.join(mock_path_config, "keyring-test-get-keyring.json")
    with open(test_key_fp, "w") as f:
        f.write("{\"test:}")

    k = KeyringBackendJsonFiles(path_config=mock_path_config)
    with pytest.raises(KeyError):
        k._get_item("test-get-keyring")


def test_del_item_raises_exception_filepath_does_not_exist(mock_path_config):
    k = KeyringBackendJsonFiles(path_config=mock_path_config)
    with pytest.raises(KeyError):
        k._del_item("test-del-fail")


def test_set_item_raises_exception_unable_to_write_in_path():
    k = KeyringBackendJsonFiles(path_config="fake-dirpath")
    with pytest.raises(KeyringError):
        k._set_item("test", ["test"])


def test_set_item_serialize_invalid_json_object_raises_exception(mock_path_config):
    k = KeyringBackendJsonFiles(path_config=mock_path_config)
    with pytest.raises(ValueError):
        k._set_item("test", {1, 2, 3, 4, 5})
