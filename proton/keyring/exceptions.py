class KeyringError(Exception):
    """Base class for Proton API specific exceptions"""
    def __init__(self, message, additional_context=None):
        self.message = message
        self.additional_context = additional_context
        super().__init__(self.message)


class KeyringNotWorking(KeyringError):
    """If for some reason the keyring is not accessible, then this exception should be raised"""