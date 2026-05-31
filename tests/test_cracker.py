import hashlib
import os
import sys
import unittest


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

import cracker


class HashTests(unittest.TestCase):
    def test_common_hash_vectors(self):
        self.assertEqual(cracker.compute_hash("password", "md5"), hashlib.md5(b"password").hexdigest())
        self.assertEqual(cracker.compute_hash("password", "sha1"), hashlib.sha1(b"password").hexdigest())
        self.assertEqual(cracker.compute_hash("password", "sha256"), hashlib.sha256(b"password").hexdigest())
        self.assertEqual(cracker.compute_hash("password", "sha3_256"), hashlib.sha3_256(b"password").hexdigest())

    def test_ntlm_known_vector(self):
        self.assertEqual(cracker.compute_hash("password", "ntlm"), "8846f7eaee8fb117ad06bdd830b7586c")

    def test_crack_finds_candidate(self):
        result = cracker.crack(
            "5f4dcc3b5aa765d61d8327deb882cf99",
            ["md5"],
            ["hello", "password"],
        )
        self.assertEqual(result[0], "password")
        self.assertEqual(result[1], "md5")


if __name__ == "__main__":
    unittest.main()
