import unittest
from io import StringIO
from unittest.mock import Mock

import requests

from proton.session import Session
from proton.session.formdata import FormData, FormField
from proton.session.transports.requests import RequestsTransport


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
