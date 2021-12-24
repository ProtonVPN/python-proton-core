from abc import ABCMeta, abstractmethod

from typing import TYPE_CHECKING, Optional
if TYPE_CHECKING:
    from ..session import Session

class BasicView(metaclass = ABCMeta):
    @abstractmethod
    def display_error(self, message : str) -> None:
        """Display an error message. No action is expected from user."""
        pass

    @abstractmethod
    def display_notice(self, message : str) -> None:
        """Display an message. No action is expected from user."""
        pass

    @abstractmethod
    def display_session_list(self, sessions : list["Session"], ask_to_select_one : bool = False) -> Optional["Session"]:
        """Display a list of session. If user needs to select one, returns the session selected, otherwise (or if user cancelled) None"""
        pass

    @abstractmethod
    def ask_credentials(self, ask_login : bool = False, ask_password : bool = False, ask_2fa : bool = False) -> tuple[Optional[str], Optional[str], Optional[str]]:
        pass

