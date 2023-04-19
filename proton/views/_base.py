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
from abc import ABCMeta, abstractmethod

from typing import TYPE_CHECKING, Optional
if TYPE_CHECKING:
    from ..session import Session

class BasicView(metaclass = ABCMeta):
    @abstractmethod
    def display_error(self, message : str) -> None:
        """Display an error message. No action is expected from user.

        :param message: Message to display
        :type message: str
        """
        pass

    @abstractmethod
    def display_notice(self, message : str) -> None:
        """Display a message. No action is expected from user.

        :param message: Message to display
        :type message: str
        """
        pass

    @abstractmethod
    def display_session_list(self, sessions : list["Session"], ask_to_select_one : bool = False) -> Optional["Session"]:
        """Display a list of Sessions, and optionally ask the user to select one of them.

        :param sessions: List of sessions
        :type sessions: list[Session]
        :param ask_to_select_one: ask user to select a session, defaults to False
        :type ask_to_select_one: bool, optional
        :return: the session selected by user (if asked for it), None otherwise (or if user has cancelled)
        :rtype: Optional[Session]
        """
        pass

    @abstractmethod
    def ask_credentials(self, ask_login : bool = False, ask_password : bool = False, ask_2fa : bool = False) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """Ask user for credentials.

        :param ask_login: Ask for user name, defaults to False
        :type ask_login: bool, optional
        :param ask_password: Ask for the password, defaults to False
        :type ask_password: bool, optional
        :param ask_2fa: Ask for a 2FA code, defaults to False
        :type ask_2fa: bool, optional
        :return: A tuple (login, password, 2fa). Values are None if not asked from the user, or if user cancelled.
        :rtype: tuple[Optional[str], Optional[str], Optional[str]]
        """
        pass

