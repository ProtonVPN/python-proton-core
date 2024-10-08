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
from unittest.mock import patch, AsyncMock, Mock

from proton.session import Session
from proton.session.formdata import FormData, FormField
from proton.session.transports import AiohttpTransport
from proton.session.transports.aiohttp import FormDataTransformer
from proton.session.transports.base import RawResponse

HTTP_STATUS_OK = 200
HTTP_STATUS_NOT_MODIFIED = 304
CODE_SUCCESS = 1000


class TestAiohttpTransport(unittest.IsolatedAsyncioTestCase):

    @patch("proton.session.transports.aiohttp.aiohttp.ClientSession.post")
    async def test_async_api_request_posts_form_data_with_data_param(self, post_mock):
        session = Session()
        form_data_transformer_mock = Mock(spec=FormDataTransformer)
        aiohttp_transport = AiohttpTransport(session, form_data_transformer_mock)

        # Mock POST response.
        post_mock.return_value.__aenter__.return_value.status = HTTP_STATUS_OK
        post_mock.return_value.__aenter__.return_value.headers = {"content-type": "application/json"}
        post_mock.return_value.__aenter__.return_value.json = AsyncMock(
            return_value={"Code": CODE_SUCCESS}
        )

        # Form data to be posted.
        form_data = FormData()
        form_data.add(FormField(name="foo", value="bar"))

        # SUT.
        await aiohttp_transport.async_api_request("/endpoint", data=form_data)

        # Assert that the form data has been transformed to aiohttp.FormData.
        form_data_transformer_mock.to_aiohttp_form_data.assert_called_once_with(form_data)
        expected_payload_to_be_posted = form_data_transformer_mock.to_aiohttp_form_data.return_value

        # Assert that the POST call is done with the transformed form data.
        post_mock.assert_called_once()
        posted_payload = post_mock.call_args.kwargs["data"]
        assert posted_payload is expected_payload_to_be_posted


class TestFormDataTransformer(unittest.TestCase):

    @patch("proton.session.transports.aiohttp.aiohttp.FormData")
    def test_to_aiohttp_form_data(self, _aiohttp_form_data_mock):
        form_data_transformer = FormDataTransformer()

        # Form data to be transformed:
        form_data = FormData()
        # Add a simple field to the form.
        first_field_name, first_field_value = "foo", "bar"
        form_data.add(FormField(name=first_field_name, value=first_field_value))
        # Add a file to the form.
        second_field_name = "file"
        second_field_value = StringIO("File content.")
        second_field_filename = "file.txt"
        second_field_content_type = "text/plain"
        form_data.add(FormField(
            name=second_field_name, value=second_field_value,
            filename=second_field_filename, content_type=second_field_content_type
        ))

        # SUT.
        result = form_data_transformer.to_aiohttp_form_data(form_data)

        # Assert that aiohttp.FormData was created with the form data passed above.
        assert result.add_field.call_count == 2
        assert result.add_field.call_args_list[0].kwargs == {
            "name": first_field_name, "value": first_field_value,
            "content_type": None, "filename": None
        }
        assert result.add_field.call_args_list[1].kwargs == {
            "name": second_field_name, "value": second_field_value,
            "content_type": second_field_content_type, "filename": second_field_filename
        }


class TestAiohttpTransportRawResult(unittest.IsolatedAsyncioTestCase):

    def _setup(self, get_mock, status, headers, json):
        # Mock the GET response
        get_mock.return_value.__aenter__.return_value.status = status
        get_mock.return_value.__aenter__.return_value.headers = headers
        get_mock.return_value.__aenter__.return_value.json = AsyncMock(
            return_value=json
        )

        session = Session()
        aiohttp_transport = AiohttpTransport(session)

        return session, aiohttp_transport

    @patch("proton.session.transports.aiohttp.aiohttp.ClientSession.get")
    async def test_async_api_request_get_raw(self, get_mock):
        # Setup
        session, aiohttp_transport = self._setup(get_mock,
                                                 status=HTTP_STATUS_OK,
                                                 headers={"content-type": "application/json"},
                                                 json={"Code": CODE_SUCCESS})

        # Test
        response = await aiohttp_transport.async_api_request("/endpoint", return_raw=True)

        # Checks
        assert isinstance(response, RawResponse), "The response should be a RawResponse object."
        assert response.status_code == HTTP_STATUS_OK
        assert response.find_first_header("content-type") == "application/json"
        assert response.json == {"Code": CODE_SUCCESS}
        get_mock.assert_called_once()

    @patch("proton.session.transports.aiohttp.aiohttp.ClientSession.get")
    async def test_async_api_request_last_modified(self, get_mock):
        # Setup
        session, aiohttp_transport = self._setup(get_mock,
                                                 status=HTTP_STATUS_NOT_MODIFIED,
                                                 headers={},
                                                 json=None)

        # Test
        response = await aiohttp_transport.async_api_request("/endpoint", return_raw=True)

        # Checks
        assert isinstance(response, RawResponse), "The response should be a RawResponse object."
        assert response.status_code == HTTP_STATUS_NOT_MODIFIED
        assert response.find_first_header("content-type", None) is None
        assert response.json is None
        get_mock.assert_called_once()
