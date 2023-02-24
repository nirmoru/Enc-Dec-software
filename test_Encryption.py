import unittest
import Encryption
import os
import shutil
import cryptography as cryptography_test


class TestEnc(unittest.TestCase):
	@classmethod
	def setUpClass(cls) -> None:
		cls.test_key_folder = 'test_key'
		cls.cwd = os.getcwd()
		cls.cfg_file = "[_]\nkey = RXsTXcI5Yn9DvJSJWU/wUkhLHcRDmZkjesTYH5JV2QE=\niv = OGhyY0q4crlzG0eyPrA2Gg=="
		
	def setUp(self) -> None:
		print(self.id().split('.')[-1])
		print("Starting Setup for {}.".format(self.id().split('.')[-1]))
		match self.id().split('.')[-1]:
			case"test_LoadPrivKey":
				os.mkdir(self.test_key_folder)
				os.chdir(os.path.join(self.cwd, self.test_key_folder))
				priv_key = Encryption.AsymmetricEncryptionPrivateKey('PrivKey.pem')
				priv_key.GenRSAPrivKey()
				os.chdir(self.cwd)
			
			case 'test_LoadPubKey':
				os.chdir(self.cwd)
				os.mkdir(self.test_key_folder)
				os.chdir(os.path.join(self.cwd, self.test_key_folder))
				priv_key = Encryption.AsymmetricEncryptionPrivateKey('PrivKey.pem')
				priv_key.GenRSAPrivKey()
				key = Encryption.AsymmetricEncryptionPublicKey('PubKey.pub')
				key.GenPublicKey('PrivKey.pem')
			
			case "test_configFileKey":
				os.chdir(self.cwd)
				os.mkdir(self.test_key_folder)
				os.chdir(os.path.join(self.cwd, self.test_key_folder))
				with open('cfg.ini', 'w') as f:
					f.write(self.cfg_file)
				
			case "test_configFileIV":
				os.chdir(self.cwd)
				os.mkdir(self.test_key_folder)
				os.chdir(os.path.join(self.cwd, self.test_key_folder))
				with open('cfg.ini', 'w') as f:
					f.write(self.cfg_file)
		print("Setup Complete.")
		
	def tearDown(self) -> None:
		print("Starting Teardown.")
		os.chdir(self.cwd)
		shutil.rmtree(self.test_key_folder)
		print("Tearing complete for {}.".format(self.id().split('.')[-1]))
		print("-------------------------\n")
		
	def test_LoadPrivKey(self):
		os.chdir(os.path.join(self.cwd, self.test_key_folder))
		key = Encryption.AsymmetricEncryptionPrivateKey('PrivKey.pem')
		load_priv_key = key.LoadPrivKey()
		self.assertEqual(isinstance(load_priv_key, cryptography_test.hazmat.backends.openssl.rsa._RSAPrivateKey), True)

	def test_LoadPubKey(self):
		os.chdir(os.path.join(self.cwd, self.test_key_folder))
		key = Encryption.AsymmetricEncryptionPublicKey('PubKey.pub')
		key.GenPublicKey('PrivKey.pem')
		load_pub_key = key.LoadPubKey()
		self.assertEqual(isinstance(load_pub_key, cryptography_test.hazmat.backends.openssl.rsa._RSAPublicKey), True)
		
	def test_configFileKey(self):
		os.chdir(os.path.join(self.cwd, self.test_key_folder))
		key = Encryption.DisplayConfigFile()[0]
		self.assertEqual(isinstance(key, str), True)
		
	def test_configFileIV(self):
		os.chdir(os.path.join(self.cwd, self.test_key_folder))
		iv = Encryption.DisplayConfigFile()[1]
		self.assertEqual(isinstance(iv, str), True)
		
	
if __name__ == "__main__":
	test_order = ["test_LoadPrivKey", "test_LoadPubKey", "test_configFileKey", "test_configFileIV"]
	test_loader = unittest.TestLoader()
	test_loader.sortTestMethodsUsing = lambda x, y: test_order.index(x) - test_order.index(y)
	unittest.main(testLoader=test_loader)
	