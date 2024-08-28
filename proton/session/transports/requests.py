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
import io

import requests

from ..formdata import FormData
from ..exceptions import *
from .base import Transport, RawResponse

import json

NOT_MODIFIED = 304

class RequestsTransport(Transport):
    """ This is a simple transport based on the requests library, it's not advised to use in production """
    def __init__(self, session, requests_session: requests.Session = None):
        super().__init__(session)
        
        self._s = requests_session or requests.Session()

    @classmethod
    def _get_priority(cls):
        try:
            return 3
        except ImportError:
            return None

    def _parse_json(self, ret, allow_unmodified=False):
        if allow_unmodified and ret.status_code == NOT_MODIFIED:
            return None

        try:
            ret_json = ret.json()
        except json.decoder.JSONDecodeError:
            raise ProtonAPIError(ret.status_code, dict(ret.headers), {})

        if ret_json['Code'] not in [1000, 1001]:
            raise ProtonAPIError(ret.status_code, dict(ret.headers), ret_json)

        return ret_json

    async def async_api_request(
        self, endpoint,
        jsondata=None, data=None, additional_headers=None,
        method=None, params=None, return_raw=False
    ):
        self._s.headers['x-pm-appversion'] = self._session.appversion
        self._s.headers['User-Agent'] = self._session.user_agent

        if self._session.authenticated:
            self._s.headers['x-pm-uid'] = self._session.UID
            self._s.headers['Authorization'] = 'Bearer ' + self._session.AccessToken

        # If we don't have an explicit method, default to get if there's no data, post otherwise
        if method is None:
            if not jsondata and not data:
                fct = self._s.get
            else:
                fct = self._s.post
        else:
            fct = {
                'get': self._s.get,
                'post': self._s.post,
                'put': self._s.put,
                'delete': self._s.delete,
                'patch': self._s.patch
            }.get(method.lower())

            if fct is None:
                raise ValueError("Unknown method: {}".format(method))

        data_dict = self._get_requests_data(data) if data else None
        files_dict = self._get_requests_files(data) if data else None
        try:
            ret = fct(
                self._environment.http_base_url + endpoint,
                headers=additional_headers,
                json=jsondata,
                data=data_dict,
                files=files_dict,
                params=params
            )
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            raise ProtonAPINotReachable(e)
        except (Exception, requests.exceptions.BaseHTTPError) as e:
            raise ProtonAPIUnexpectedError(e)

        if return_raw:
            return RawResponse(ret.status_code, tuple(ret.headers.items()),
                               self._parse_json(ret, allow_unmodified=True))

        ret_json = self._parse_json(ret)

        return ret_json

    @staticmethod
    def _get_requests_data(form_data: FormData) -> dict:
        """
        Converts the FormData instance to a dict that can be passed
        as the data parameter in requests (e.g. `requests.post(url, data=data)`.

        File-like fields are ignored, use `_get_requests_files` for those.
        """
        return {
            field.name: field.value
            for field in form_data.fields if not isinstance(field.value, io.IOBase)
        }

    @staticmethod
    def _get_requests_files(form_data: FormData) -> dict:
        """
        Extracts the file-like fields to a dict that can be passed as the `files`
        parameter in requests (e.g. `requests.post(url, files=files`).
        """
        # From https://requests.readthedocs.io/en/latest/api/#requests.request:
        # files – (optional) Dictionary of 'name': file-like-objects
        # (or {'name': file-tuple}) for multipart encoding upload. file-tuple
        # can be a 2-tuple ('filename', fileobj), 3-tuple ('filename', fileobj, 'content_type')
        # or a 4-tuple ('filename', fileobj, 'content_type', custom_headers),
        # where 'content-type' is a string defining the content type of the
        # given file and custom_headers a dict-like object containing additional
        # headers to add for the file.
        return {
            field.name: (field.filename, field.value, field.content_type)
            for field in form_data.fields if isinstance(field.value, io.IOBase)
        }
