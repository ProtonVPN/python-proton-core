class KeyringError(Exception):
    """Base class for Proton API specific exceptions"""
    def __init__(self, message, additional_context=None):
        self.message = message
        self.additional_context = additional_context
        super().__init__(self.message)


class KeyringLocked(KeyringError):
    """When keyring is locked but it shouldn't be, this exception is raised"""
