from os import environ
from proton import session
from proton.session import exceptions
from proton.session.api import Session

import sys

from proton.sso.sso import ProtonSSO

from ..views._base import BasicView

import enum
class ProtonSSOPresenterCredentialLogicState(enum.Enum):
    CALL_BASE_FUNCTION = 0
    NEEDS_AUTHENTICATE = 1
    NEEDS_TWOFA = 2


class ProtonSSOPresenter:
    def __init__(self, view : BasicView):
        from .sso import ProtonSSO

        self._view = view
        self._session = None
        self._provided_account_name = None
        self._sso = ProtonSSO()

    def set_session(self, account_name = None):
        self._provided_account_name = account_name
        if account_name is not None:
            self._session = self._sso.get_session(account_name)
        else:
            self._session = self._sso.get_default_session()

    def set_environment(self, environment):
        self._session.environment = environment

    def CredentialsLogic(base_function):
        import functools

        @functools.wraps(base_function)
        def wrapped_function(self : 'ProtonSSOPresenter', *a, **kw):
            
            from proton.session.exceptions import ProtonAPIAuthenticationNeeded, ProtonAPI2FANeeded, ProtonAPIMissingScopeError
            state = ProtonSSOPresenterCredentialLogicState.CALL_BASE_FUNCTION
            while True:
                try:
                    if state == ProtonSSOPresenterCredentialLogicState.CALL_BASE_FUNCTION:
                        return base_function(self, *a, **kw)
                    elif state == ProtonSSOPresenterCredentialLogicState.NEEDS_AUTHENTICATE:
                        account_name, password, twofa = self._view.ask_credentials(self._provided_account_name is None, True, False)
                        if account_name is None:
                            account_name = self._provided_account_name
                        if password is None:
                            break
                        ret = self._session.authenticate(account_name, password)
                        if ret:
                            state = ProtonSSOPresenterCredentialLogicState.CALL_BASE_FUNCTION
                        else:
                            self._view.display_error("Invalid credentials!")
                            # Remain in NEEDS_AUTHENTICATE state
                    elif state == ProtonSSOPresenterCredentialLogicState.NEEDS_TWOFA:
                        account_name, password, twofa = self._view.ask_credentials(False, False, True)
                        if twofa is None:
                            break
                        ret = self._session.provide_2fa(twofa)
                        if ret:
                            state = ProtonSSOPresenterCredentialLogicState.CALL_BASE_FUNCTION
                        else:
                            self._view.display_error("Invalid 2FA code!")

                except ProtonAPIAuthenticationNeeded:
                    state = ProtonSSOPresenterCredentialLogicState.NEEDS_AUTHENTICATE
 
                except ProtonAPI2FANeeded:
                    state = ProtonSSOPresenterCredentialLogicState.NEEDS_TWOFA


        
        return wrapped_function


    @CredentialsLogic
    def login(self):
        # This will force a login call if needed
        self._session.api_request('/users')

    def logout(self):
        self._session.logout()

    def unlock(self):
        self._session.fetch_user_key()

    def lock(self):
        self._session.lock()

    def set_default(self):
        account_name = self._session.AccountName
        if account_name is not None:
            self._sso.set_default_account(account_name)

    def list(self):
        sessions = [self._sso.get_session(s) for s in self._sso.sessions]
        sessions = [s for s in sessions if s.AccountName is not None]
        self._view.display_session_list(sessions)


def main():
    import argparse

    parser = argparse.ArgumentParser('proton-sso', description="Tool to manage user SSO sessions")
    subparsers = parser.add_subparsers(help='action', dest='action', required=True)

    parser_login = subparsers.add_parser('login', help='Sign into an account')
    parser_login.add_argument('--unlock', action='store_true', help="Unlock and store user keys")
    parser_login.add_argument('--set-default', action='store_true', help="Set this account as default")
    parser_login.add_argument('--env', type=str, help="Environment to use")
    parser_login.add_argument('account', type=str, help="Proton account")

    parser_logout = subparsers.add_parser('logout', help='Sign out of an account')
    parser_logout.add_argument('account', type=str, help="Proton account (default session if omitted)", nargs="?")

    parser_lock = subparsers.add_parser('lock', help='Lock a session and erased stored user keys')
    parser_lock.add_argument('account', type=str, help="Proton account (default session if omitted)", nargs="?")

    parser_unlock = subparsers.add_parser('unlock', help='Unlock a session and store user keys')
    parser_unlock.add_argument('account', type=str, help="Proton account (default session if omitted)", nargs="?")

    parser_unlock = subparsers.add_parser('set-default', help='Sets the account as default')
    parser_unlock.add_argument('account', type=str, help="Proton account")
    
    parser_list = subparsers.add_parser('list', help='List the currently logged-in account')
    args = parser.parse_args()

    from proton.loader import Loader

    view = Loader.get('basicview')()
    presenter = ProtonSSOPresenter(view)

    # All action except list require an active account
    if args.action != 'list':
        presenter.set_session(args.account)

    if args.action == 'login':
        if args.env is not None:
            presenter.set_environment(args.env)
        presenter.login()
        if args.unlock:
            presenter.unlock()
        else:
            presenter.lock()
        if args.set_default:
            presenter.set_default()

    elif args.action == 'logout':
        presenter.logout()

    elif args.action == 'lock':
        presenter.lock()

    elif args.action == 'unlock':
        presenter.unlock()
    elif args.action == 'list':
        presenter.list()
    elif args.action == 'set-default':
        presenter.set_default()
    else:
        raise NotImplementedError(f"Action {args.action} is not yet implemented")