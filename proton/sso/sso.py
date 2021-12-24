import os, fcntl, re, base64

# We don't necessarily need it to be a singleton, it doesn't harm in itself if multiple instances are created
class ProtonSSO:
    def __init__(self, appversion : str = "Other", user_agent:str="None"):
        # Store appversion and user_agent for subsequent sessions
        self._appversion = appversion
        self._user_agent = user_agent

        from ..utils import ExecutionEnvironment
        self._adv_locks_path = ExecutionEnvironment().path_runtime
        self._adv_locks = {}

        self._session_data_cache = {}

        # This is a global lock, we use it when we modify the indexes
        self._global_adv_lock = open(os.path.join(self._adv_locks_path, f'proton-sso.lock'), 'w')

    def __normalize_account_name(self, account_name):
        account_name = account_name.lower()
        if not re.match(r'^[a-z][0-9a-z@\.-]*$', account_name):
            raise ValueError("Invalid account name")
        
        return account_name

    def __encode_name(self, account_name):
        return base64.b32encode(account_name.encode('utf8')).decode('ascii').rstrip('=').lower()

    def __keyring_key_name(self, account_name):
        return f'proton-sso-account-{self.__encode_name(account_name)}'

    def __keyring_index_name(self):
        return f'proton-sso-accounts'

    @property
    def _keyring(self):
        # Just to make our life simpler
        from proton.loader import Loader
        return Loader.get('keyring')()

    @property
    def sessions(self):
        """Return a list of account_names that we currently have"""
        
        # There is no point in locking, because anyway as soon as we exit this code, the data might not be relevant anymore
        try:
            return self._keyring[self.__keyring_index_name()]
        except KeyError:
            return []

    def set_default_account(self, account_name):
        account_name = self.__normalize_account_name(account_name)

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

    def get_session(self, account_name):
        from ..session import Session

        session = Session(self._appversion, self._user_agent)
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

    def get_default_session(self):
        sessions = self.sessions
        if len(sessions) == 0:
            account_name = None
        else:
            account_name = sessions[0]

        return self.get_session(account_name)
            


    def _get_session_data(self, account_name):
        "Get data of a session, returns an empty dict if no data is present"
        try:
            return self._keyring[self.__keyring_key_name(account_name)]
        except KeyError:
            return {}


    def _acquire_session_lock(self, account_name, current_data):
        if account_name is None:
            # Don't do anything, we don't know the account yet!
            return

        account_name = self.__normalize_account_name(account_name)
        self._adv_locks[account_name] = open(os.path.join(self._adv_locks_path, f'proton-sso-{self.__encode_name(account_name)}.lock'), 'w')
        # This is a blocking call. 
        # FIXME: this is Linux specific
        fcntl.flock(self._adv_locks[account_name], fcntl.LOCK_EX)

        self._session_data_cache[account_name] = current_data


    def _release_session_lock(self, account_name, new_data):
        if account_name is None:
            # Don't do anything, we don't know the account yet!
            return

        account_name = self.__normalize_account_name(account_name)

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
                    new_keyring_index = keyring_index + [account_name]

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