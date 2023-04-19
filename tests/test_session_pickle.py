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
import unittest, pickle, os


class TestSessionPickle(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._env_backup = os.environ.copy()

    def tearDown(self):
        os.environ = self._env_backup

    async def test_pickle(self):
        from proton.session import Session

        os.environ['PROTON_API_ENVIRONMENT'] = 'prod'
        s = Session()

        pickled_session = pickle.loads(pickle.dumps(s))
        assert isinstance(pickled_session, Session)

        assert s.__dict__ == pickled_session.__dict__

        # we can't do much more testing as we don't log in in API in the tests...
