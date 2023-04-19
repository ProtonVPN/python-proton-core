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
