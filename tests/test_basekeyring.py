from unittest.mock import patch

import pytest
from proton.keyring import Keyring


@patch("proton.keyring._base.Keyring._get_item")
def test_get_item_from_keyring(_get_item_mock):
    _get_item_mock.return_value = "first"
    k = Keyring()
    assert k["test-get"] == "first"
    _get_item_mock.assert_called_once_with("test-get")


@patch("proton.keyring._base.Keyring._set_item")
def test_set_item(_set_item_mock):
    k = Keyring()
    k["test-set"] = ["arg1"]
    _set_item_mock.assert_called_once_with("test-set", ["arg1"])


@patch("proton.keyring._base.Keyring._get_item")
@patch("proton.keyring._base.Keyring._del_item")
def test_del_item(_del_item_mock, _get_item_mock):
    _get_item_mock.return_value = "first"
    k = Keyring()
    del k["test-delete"]
    _del_item_mock.assert_called_once_with("test-delete")


def test_raise_exception_not_implemented_methods():
    keyring = Keyring()
    with pytest.raises(NotImplementedError):
        keyring["test"]

    with pytest.raises(NotImplementedError):
        keyring["test"] = ["test"]

    with pytest.raises(NotImplementedError):
        del keyring["test"]


@pytest.mark.parametrize("key", [1, [], {}, None, tuple()])
def test_get_item_raises_exception_invalid_key_type(key):
    with pytest.raises(TypeError):
        Keyring()[key]


@pytest.mark.parametrize("key", ["!", "A", "ç", "+", "*", "ã", "\\", "?", "="])
def test_get_item_raises_exception_invalid_key_value(key):
    with pytest.raises(ValueError):
        Keyring()[key]


@patch("proton.keyring._base.Keyring._get_item")
@pytest.mark.parametrize("key", [1, [], {}, None, tuple()])
def test_del_item_raises_exception_invalid_key_type(_get_item_mock, key):
    k = Keyring()
    _get_item_mock.return_value = None
    with pytest.raises(TypeError):
        del k[key]


@patch("proton.keyring._base.Keyring._get_item")
@pytest.mark.parametrize("key", ["!", "A", "ç", "+", "*", "ã", "\\", "?", "="])
def test_del_item_raises_exception_invalid_key_value(_get_item_mock, key):
    k = Keyring()
    _get_item_mock.return_value = None
    with pytest.raises(ValueError):
        del k[key]


@pytest.mark.parametrize("key", [1, [], {}, None, tuple()])
def test_set_item_raises_exception_invalid_key_type(key):
    with pytest.raises(TypeError):
        Keyring()[key] = "test"


@pytest.mark.parametrize("key", ["!", "A", "ç", "+", "*", "ã", "\\", "?", "="])
def test_set_item_raises_exception_invalid_key_value(key):
    with pytest.raises(ValueError):
        Keyring()[key] = "test"


@pytest.mark.parametrize("value", [1, "test", None, tuple()])
def test_set_item_raises_exception_invalid_value_type(value):
    with pytest.raises(TypeError):
        Keyring()["test-key"] = value


def test_get_from_factory_raises_exception_due_to_non_existent_backend():
    with pytest.raises(RuntimeError):
        Keyring.get_from_factory("non-existent-backend")
