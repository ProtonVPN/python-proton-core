from typing import List, Any, Optional


class FormField:
    """FormData entry."""
    def __init__(
            self, name: str, value: Any, filename: Optional[str] = None,
            content_type: Optional[str] = None
    ):
        self.name = name
        self.value = value
        self.filename = filename
        self.content_type = content_type


class FormData:
    """Data to be sent as form-encoded data, like an HTML form would."""
    def __init__(self, fields: Optional[List[FormField]] = None):
        self.fields = fields or []

    def add(self, field: FormField):
        """Appends a new field in the form."""
        self.fields.append(field)
