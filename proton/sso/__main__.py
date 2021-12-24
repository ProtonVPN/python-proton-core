def main():
    import argparse

    parser = argparse.ArgumentParser('proton-sso', description="Tool to manage user SSO sessions")
    subparsers = parser.add_subparsers(help='action', dest='action')

    parser_login = subparsers.add_parser('login', help='Sign into an account')
    parser_login.add_argument('--unlock', action='store_true', help="Unlock and store user keys")
    parser_login.add_argument('--set-default', action='store_true', help="Set this account as default")
    parser_login.add_argument('account', type=str, help="Proton account", nargs="?")

    parser_logout = subparsers.add_parser('logout', help='Sign out of an account')
    parser_logout.add_argument('account', type=str, help="Proton account", nargs="?")

    parser_lock = subparsers.add_parser('lock', help='Lock a session and erased stored user keys')
    parser_lock.add_argument('account', type=str, help="Proton account", nargs="?")

    parser_unlock = subparsers.add_parser('unlock', help='Unlock a session and store user keys')
    parser_unlock.add_argument('account', type=str, help="Proton account", nargs="?")

    parser_unlock = subparsers.add_parser('set-default', help='Sets the account as default')
    parser_unlock.add_argument('account', type=str, help="Proton account")
    
    args = parser.parse_args()
    print(args)