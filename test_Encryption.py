import unittest
import Encryption


class TestEnc(unittest.TestCase):
	def setUp(self) -> None:
		print("Setup.")
	
	def tearDown(self) -> None:
		print("Tearing down.\n")
	
	def test_genkeys(self):
		print("Generating key.")
		pk = Encryption.RSAGenKey()
		self.assertEqual(str(type(pk)), "<class 'cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey'>")
	
	def test_loadkeys(self):
		print("Loading key.")


if __name__ == "__main__":
	unittest.main()
