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
    def __init__(self, view : BasicView, appversion=None, user_agent=None):
        from .sso import ProtonSSO

        self._view = view
        self._session = None
        self._provided_account_name = None
        self._client_secret: str = None

        kwargs_sso = {}
        if appversion is not None:
            kwargs_sso["appversion"] = appversion
        if user_agent is not None:
            kwargs_sso["user_agent"] = user_agent
        self._sso = ProtonSSO(**kwargs_sso)

    def set_session(self, account_name = None):
        self._provided_account_name = account_name
        if account_name is not None:
            self._session = self._sso.get_session(account_name)
        else:
            self._session = self._sso.get_default_session()

    def set_environment(self, environment):
        self._session.environment = environment

    def set_client_secret(self, client_secret):
        self._client_secret = client_secret

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
                        ret = self._session.authenticate(account_name, password, client_secret=self._client_secret),
                        if ret:
                            if self._session.needs_twofa:
                                state = ProtonSSOPresenterCredentialLogicState.NEEDS_TWOFA
                            else:
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
    parser.add_argument('--appversion', help="App version")
    parser.add_argument('--user-agent', help="User Agent")
    subparsers = parser.add_subparsers(help='action', dest='action', required=True)

    parser_login = subparsers.add_parser('login', help='Sign into an account')
    parser_login.add_argument('--unlock', action='store_true', help="Unlock and store user keys")
    parser_login.add_argument('--set-default', action='store_true', help="Set this account as default")
    parser_login.add_argument('--env', type=str, help="Environment to use")
    parser_login.add_argument('--client-secret', type=str, help="Some API require a client secret")
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
    presenter = ProtonSSOPresenter(view, appversion=args.appversion, user_agent=args.user_agent)

    # All action except list require an active account
    if args.action != 'list':
        presenter.set_session(args.account)

    if args.action == 'login':
        if args.env is not None:
            presenter.set_environment(args.env)
        if args.client_secret is not None:
            presenter.set_client_secret(args.client_secret)
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


if __name__ == '__main__':
    main()
