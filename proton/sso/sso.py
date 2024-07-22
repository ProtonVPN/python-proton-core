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
from __future__ import annotations

import base64
import fcntl
import os
import re
from typing import TYPE_CHECKING, Optional

from proton.keyring import Keyring

if TYPE_CHECKING:
    from ..session import Session


# We don't necessarily need it to be a singleton, it doesn't harm in itself if multiple instances are created
class ProtonSSO:
    """Proton Single Sign On implementation. This allows session persistence for the current user.

    The general approach for this is to create a SSO instance, and then to get either a specific or the default session, and work from there:

    .. code-block::

        from proton.sso import ProtonSSO
        sso = ProtonSSO()
        session = sso.get_default_session()
        # or:
        session = sso.get_session('pro') # get session for account pro

    Note that it is advised not to try to "guess" the state of the session, but instead to just try to use it, and handle any exception that would arise.

    This object uses advisory locks (using ``flock``) to protect the session from multiple conflicting changes. This does not guarantee that
    Session objects are immune to what happens in another process (i.e. imagine if one process terminates the session.), but at least makes it consistent.
    In the future, it would be nice to use an IPC mechanism to make sure other processes are aware of the state change.
    """
    def __init__(self, appversion : str = "Other", user_agent: str ="None"):
        """Create a SSO instance

        :param appversion: Application version (see :class:`proton.session.Session`), defaults to "Other"
        :type appversion: str, optional
        :param user_agent: User agent version (see :class:`proton.session.Session`), defaults to "None"
        :type user_agent: str, optional
        """
        # Store appversion and user_agent for subsequent sessions
        self._appversion = appversion
        self._user_agent = user_agent

        from ..utils import ExecutionEnvironment
        self._adv_locks_path = ExecutionEnvironment().path_runtime
        self._adv_locks = {}

        self._session_data_cache = {}

        # This is a global lock, we use it when we modify the indexes
        self._global_adv_lock = open(os.path.join(self._adv_locks_path, f'proton-sso.lock'), 'w')
        self.__keyring_backend = None

    def __encode_name(self, account_name) -> str:
        """Helper function to convert an account_name into a safe alphanumeric string.

        :param account_name: normalized account_name
        :type account_name: str
        :return: base32 encoded string, without padding.
        :rtype: str
        """
        return base64.b32encode(account_name.encode('utf8')).decode('ascii').rstrip('=').lower()

    def __keyring_key_name(self, account_name : str) -> str:
        """Helper function to get the keyring key for account_name

        :param account_name: normalized account_name
        :type account_name: str
        :return: keyring key
        :rtype: str
        """
        return f'proton-sso-account-{self.__encode_name(account_name)}'

    def __keyring_index_name(self) -> str:
        """Helper function to get the keyring key to store the index (i.e. account names in order)

        :return: keyring key
        :rtype: str
        """
        return f'proton-sso-accounts'

    @property
    def _keyring(self) -> "Keyring":
        """Shortcut to get the default keyring backend

        :return: an instance of the default Keyring
        :rtype: Keyring
        """
        if self.__keyring_backend is None:
            self.__keyring_backend = Keyring.get_from_factory()
        elif not isinstance(self.__keyring_backend, type(Keyring.get_from_factory())):
            # If the current keyring does not match the keyring we were using previously,
            # then something must've changed in the env and we should raise an exception.
            raise RuntimeError("Keyring backends do not match")

        return self.__keyring_backend

    @property
    def sessions(self) -> list[str]:
        """Returns the account names for the current system user

        :return: list of normalized account_names
        :rtype: list[str]
        """

        # We might remove invalid session and clean the index, so create a full lock on the SSO object
        fcntl.flock(self._global_adv_lock, fcntl.LOCK_EX)
        try:
            keyring = self._keyring

            try:
                keyring_index = keyring[self.__keyring_index_name()]
            except KeyError:
                keyring_index = []

            cleaned_index = [account_name for account_name in keyring_index if len(self._get_session_data(account_name)) > 0]
            if cleaned_index != keyring_index:
                keyring[self.__keyring_index_name()] = cleaned_index

            # Try to remove any account from keyring that we've removed from SSO
            for removed_account in set(keyring_index).difference(cleaned_index):
                try:
                    del keyring[self.__keyring_key_name(removed_account)]
                except KeyError:
                    pass

            return cleaned_index
        finally:
            fcntl.flock(self._global_adv_lock, fcntl.LOCK_UN)

    def get_session(self, account_name : Optional[str], override_class : Optional[type] = None) -> "Session":
        """Get the session identified by account_name

        :param account_name: account name to use. If None will return an empty session (can be used as a factory)
        :type account_name: Optional[str]
        :param override_class: Class to use for the session to be returned, by default will use proton.session.Session
        :type override_class: Optional[type]
        :return: the Session object. It will be an empty session if there's no session for account_name
        :rtype: Session
        """
        from ..session import Session

        if override_class is None:
            override_class = Session

        session = override_class(self._appversion, self._user_agent)
        session.register_persistence_observer(self)

        # If we have an account, then let's fetch the data from it. Otherwise we just ignore and return a blank session
        if account_name is not None:
            try:
                session_data = self._get_session_data(account_name)
            except KeyError:
                session_data = None
        else:
            session_data = None

        if session_data is not None:
            session.__setstate__(session_data)

        return session

    def get_default_session(self, override_class : Optional[type] = None)  -> "Session":
        """Get the default session for the system user. It will always be one valid session if one exists.

        :param override_class: Class to use for the session to be returned, see :meth:`get_session`.
        :type override_class: Optional[type]
        :return: the Session object. It will be an empty session if there's no session at all
        :rtype: Session
        """
        sessions = self.sessions
        if len(sessions) == 0:
            account_name = None
        else:
            account_name = sessions[0]

        return self.get_session(account_name, override_class)

    def set_default_account(self, account_name : str):
        """Set the default account for user to be account_name

        :param account_name: the account_name to use as default
        :type account_name: str
        :raises KeyError: if the account name is unknown
        """
        # We might be reordering accounts, so let's lock the full sso so we can't have concurrent actions here
        fcntl.flock(self._global_adv_lock, fcntl.LOCK_EX)
        try:
            keyring = self._keyring

            try:
                keyring_index = keyring[self.__keyring_index_name()]
            except KeyError:
                keyring_index = []

            if account_name not in keyring_index:
                raise KeyError(account_name)

            new_keyring_index = [account_name] + [x for x in keyring_index if x != account_name]
            if new_keyring_index != keyring_index:
                keyring[self.__keyring_index_name()] = new_keyring_index
            
        finally:
            fcntl.flock(self._global_adv_lock, fcntl.LOCK_UN)

    def _get_session_data(self, account_name):
        try:
            data = self._keyring.get_keyring_data(account_name)
            
            # Check if data is a list
            if isinstance(data, list):
                # If it's a list, we assume the first item is the session data
                if data and isinstance(data[0], dict):
                    return data[0]
                else:
                    return {}  # Return an empty dict if the list is empty or first item is not a dict
            
            # If data is a dict, proceed as before
            elif isinstance(data, dict):
                if data.get('AccountName') != account_name:
                    return {}
                return data
            
            # If data is neither a list nor a dict, return an empty dict
            else:
                return {}
        
        except Exception as e:
            # Log the error (replace with your logging mechanism)
            print(f"Error in _get_session_data: {str(e)}")
            return {}


    def _acquire_session_lock(self, account_name : str, current_data : dict) -> None:
        """Observer pattern for :class:`proton.session.Session` (see :meth:`proton.session.Session.register_persistence_observer`). It is called when the Session object is getting locked, because it's expected to be changed
        and we want to avoid race conditions.

        :param account_name: account name of the session
        :type account_name: str
        :param current_data: current session data serialized as a dictionary
        :type current_data: dict
        """
        if not account_name:
            # Don't do anything, we don't know the account yet!
            return

        self._adv_locks[account_name] = open(os.path.join(self._adv_locks_path, f'proton-sso-{self.__encode_name(account_name)}.lock'), 'w')
        # This is a blocking call. 
        # FIXME: this is Linux specific
        fcntl.flock(self._adv_locks[account_name], fcntl.LOCK_EX)

        self._session_data_cache[account_name] = current_data


    def _release_session_lock(self, account_name : str, new_data : dict) -> None:
        """Observer pattern for :class:`proton.session.Session` (see :meth:`proton.session.Session.register_persistence_observer`). It is called when the Session object is getting unlocked.

        If the data between has changed since :meth:`_acquire_session_lock` was called, it will be persisted in the keyring.

        :param account_name: account name of the session
        :type account_name: str
        :param new_data: current session data serialized as a dictionary
        :type new_data: dict
        """
        if not account_name:
            # Don't do anything, we don't know the account yet!
            return

        if new_data is not None and len(new_data) > 0 and new_data.get('AccountName', None) != account_name:
            raise ValueError("Sessions need to store a valid AccountName in order to store data.")

        # Don't do anything if data hasn't changed
        if account_name in self._session_data_cache:
            if self._session_data_cache[account_name] == new_data:
                return
            del self._session_data_cache[account_name]

        # We might be reordering accounts, so let's lock the full sso so we can't have concurrent actions here
        fcntl.flock(self._global_adv_lock, fcntl.LOCK_EX)
        try:
            keyring = self._keyring

            # Get current data
            try:
                keyring_entry = keyring[self.__keyring_key_name(account_name)]
            except KeyError:
                keyring_entry = {}

            try:
                keyring_index = keyring[self.__keyring_index_name()]
            except KeyError:
                keyring_index = []

            # By default, we don't change anything
            new_keyring_index = keyring_index

            # No data, this is probably a logout
            if new_data is None or len(new_data) == 0:
                # Discard from the index
                new_keyring_index = [x for x in keyring_index if x != account_name]

                # Delete the entry if we had some data previously
                if len(keyring_entry) > 0:
                    del keyring[self.__keyring_key_name(account_name)]
            # We have new data
            else:
                # If this is a new entry, then append the index with the account (we leave the default as is)
                if account_name not in keyring_index:
                    if isinstance(keyring_index, dict):
                        new_keyring_index = {**keyring_index, account_name: len(keyring_index)}
                    elif isinstance(keyring_index, list):
                        new_keyring_index = keyring_index + [account_name]
                    else:
                        raise TypeError(f"Unexpected type for keyring_index: {type(keyring_index)}")
                # Store the new data
                keyring[self.__keyring_key_name(account_name)] = new_data

            # We only store the new index if it has changed (wouldn't harm to do it anyway)
            if new_keyring_index != keyring_index:
                keyring[self.__keyring_index_name()] = new_keyring_index

        finally:
            fcntl.flock(self._global_adv_lock, fcntl.LOCK_UN)

        if account_name in self._adv_locks:
            # FIXME: this is Linux specific
            fcntl.flock(self._adv_locks[account_name], fcntl.LOCK_UN)
