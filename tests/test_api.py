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

import base64
from testdata import srp_instances, modulus_instances
from testserver import TestServer
from proton.session.srp.util import PM_VERSION
from proton.session.api import Session
from proton.session.exceptions import ProtonUnsupportedAuthVersionError


class SRPTestCases:
    class SRPTestBase(unittest.TestCase):
        def test_invalid_version(self):
            modulus = bytes.fromhex(srp_instances[0]['Modulus'])
            salt = base64.b64decode(srp_instances[0]['Salt'])

            with self.assertRaises(ProtonUnsupportedAuthVersionError):
                usr = self.user('pass', modulus)
                salt, usr.compute_v(salt, 2)

            with self.assertRaises(ProtonUnsupportedAuthVersionError):
                usr = self.user('pass', modulus)
                salt, usr.compute_v(salt, 5)

        def test_compute_v(self):
            for instance in srp_instances:
                if instance["Exception"] is not None:
                    with self.assertRaises(instance['Exception']):
                        usr = self.user(
                            instance["Password"],
                            bytes.fromhex(instance["Modulus"])
                        )
                        usr.compute_v(
                            base64.b64decode(instance["Salt"]), PM_VERSION
                        )
                else:
                    usr = self.user(
                        instance["Password"],
                        bytes.fromhex(instance["Modulus"])
                    )
                    salt, v = usr.compute_v(
                        base64.b64decode(instance["Salt"]), PM_VERSION
                    )

                    self.assertEqual(
                        instance["Salt"],
                        base64.b64encode(salt).decode('utf8'),
                        "Wrong salt while generating v, "
                        + "instance: {}...".format(str(instance)[:30])
                    )

                    self.assertEqual(
                        instance["Verifier"],
                        base64.b64encode(v).decode('utf8'),
                        "Wrong verifier while generating v, "
                        + "instance: {}...".format(str(instance)[:30])
                    )

        def test_generate_v(self):
            for instance in srp_instances:
                if instance["Exception"] is not None:
                    continue

                usr = self.user(
                    instance["Password"],
                    bytes.fromhex(instance["Modulus"])
                )
                generated_salt, generated_v = usr.compute_v()

                computed_salt, computed_v = usr.compute_v(generated_salt)

                self.assertEqual(
                    generated_salt,
                    computed_salt,
                    "Wrong salt while generating v, "
                    + "instance: {}...".format(str(instance)[:30])
                )

                self.assertEqual(
                    generated_v,
                    computed_v,
                    "Wrong verifier while generating v, "
                    + "instance: {}...".format(str(instance)[:30])
                )

        def test_srp(self):
            for instance in srp_instances:
                if instance["Exception"]:
                    continue

                server = TestServer()

                server.setup(
                    instance["Username"],
                    bytes.fromhex(instance["Modulus"]),
                    base64.b64decode(instance["Verifier"])
                )

                server_challenge = server.get_challenge()
                usr = self.user(
                    instance["Password"], bytes.fromhex(instance["Modulus"])
                )

                client_challenge = usr.get_challenge()
                client_proof = usr.process_challenge(
                    base64.b64decode(instance["Salt"]),
                    server_challenge,
                    PM_VERSION
                )
                server_proof = server.process_challenge(
                    client_challenge, client_proof
                )
                usr.verify_session(server_proof)

                self.assertIsNotNone(
                    client_proof,
                    "SRP exchange failed, "
                    "client_proof is none for instance: {}...".format(
                        str(instance)[:30]
                    )
                )

                self.assertEqual(
                    server.get_session_key(),
                    usr.get_session_key(),
                    "Secrets do not match, instance: {}...".format(
                        str(instance)[:30]
                    )
                )

                self.assertTrue(
                    server.get_authenticated(),
                    "Server is not correctly authenticated, "
                    + "instance: {}...".format(
                        str(instance)[:30]
                    )
                )

                self.assertTrue(
                    usr.authenticated(),
                    "User is not correctly authenticated, "
                    + "instance: {}...".format(
                        str(instance)[:30]
                    )
                )


class TestCTSRPClass(SRPTestCases.SRPTestBase):
    def setUp(self):
        try:
            from proton.session.srp._ctsrp import User as CTUser
        except (ImportError, OSError):
            self.skipTest("Couldn't load C implementation of the SRP code, so skip this test.")
            
        self.user = CTUser


class TestPYSRPClass(SRPTestCases.SRPTestBase):
    def setUp(self):
        from proton.session.srp._pysrp import User as PYUser
        self.user = PYUser


class TestModulus(unittest.TestCase):
    def test_modulus_verification(self):
        session = Session('dummy')
        for instance in modulus_instances:
            if instance["Exception"] is not None:
                with self.assertRaises(instance['Exception']):
                    session._verify_modulus(instance["SignedModulus"])
            else:
                self.assertEqual(
                    base64.b64decode(instance["Decoded"]),
                    session._verify_modulus(instance["SignedModulus"]),
                    "Error verifying modulus in instance: " + str(instance)[:30] + "..."
                )


if __name__ == '__main__':
    unittest.main()
