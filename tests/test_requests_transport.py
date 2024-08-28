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
import unittest
from io import StringIO
from unittest.mock import Mock

import requests

from proton.session import Session
from proton.session.formdata import FormData, FormField
from proton.session.transports.requests import RequestsTransport
from proton.session.transports.base import RawResponse

HTTP_STATUS_OK = 200
HTTP_STATUS_NOT_MODIFIED = 304
CODE_SUCCESS = 1000


class TestRequestsTransport(unittest.IsolatedAsyncioTestCase):

    async def test_async_api_request_posts_form_data_with_data_param(self):
        session = Session()

        # Mock requests post call.
        requests_session = Mock(spec=requests.Session)
        requests_session.headers = {}  # Allow setting headers.
        requests_session.post.return_value.json.return_value = {"Code": 1000}

        requests_transport = RequestsTransport(session, requests_session)

        # Build form data.
        form_data = FormData()
        # Add a simple field to the form.
        form_data.add(FormField(name="foo", value="bar"))
        # Add a file to the form.
        file = StringIO("File content.")
        form_data.add(FormField(
            name="file", value=file,
            filename="file.txt", content_type="text/plain"
        ))

        # SUT.
        await requests_transport.async_api_request("/endpoint", data=form_data)

        # Adding the data kwarg should have triggered a POST call.
        requests_session.post.assert_called_once()

        # The posted data/files should be the ones in our FormData instance.
        posted_data = requests_session.post.call_args.kwargs["data"]
        assert posted_data == {"foo": "bar"}
        posted_files = requests_session.post.call_args.kwargs["files"]
        assert posted_files == {
            "file": ("file.txt", file, "text/plain")
        }


class TestRequestsTransportRawResult(unittest.IsolatedAsyncioTestCase):

    def _setup(self, status, headers, json):
        # Mock requests get call.
        req_session = Mock(spec=requests.Session)
        req_session.headers = headers
        req_session.get.return_value.headers = headers
        req_session.get.return_value.json.return_value = json
        req_session.get.return_value.status_code = status

        session = Session()

        return session, RequestsTransport(session, req_session), req_session

    async def test_async_api_request_get_raw(self):
        session, requests_transport, req_session = self._setup(
            HTTP_STATUS_OK,
            {"content-type": "application/json"},
            {"Code": CODE_SUCCESS}
        )

        # SUT.
        response = await requests_transport.async_api_request("/endpoint", return_raw=True)

        # Checks
        assert isinstance(response, RawResponse), "The response should be a RawResponse object."
        assert response.status_code == HTTP_STATUS_OK
        assert response.find_first_header("content-type") == "application/json"
        assert response.json == {"Code": CODE_SUCCESS}
        req_session.get.assert_called_once()

    async def test_async_api_request_last_modified(self):
        # Setup
        session, requests_transport, req_session = self._setup(
            HTTP_STATUS_NOT_MODIFIED,
            {},
            None
        )

        # Test
        response = await requests_transport.async_api_request("/endpoint", return_raw=True)

        # Checks
        assert isinstance(response, RawResponse), "The response should be a RawResponse object."
        assert response.status_code == HTTP_STATUS_NOT_MODIFIED
        assert response.find_first_header("content-type", None) is None
        assert response.json is None
        req_session.get.assert_called_once()
