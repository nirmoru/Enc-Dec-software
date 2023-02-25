import base64
import os
from configparser import ConfigParser

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


class AsymmetricEncryptionPrivateKey:
	def __init__(self, filename):
		self.filename = filename
	
	def GenRSAPrivKey(self):
		private_key = rsa.generate_private_key(
			public_exponent=65537,
			key_size=2048,
			backend=default_backend()
		)
		
		pem = private_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.TraditionalOpenSSL,
			encryption_algorithm=serialization.NoEncryption()
		)
		with open(self.filename, 'wb') as pem_out:
			pem_out.write(pem)
	
	def LoadPrivKey(self):
		with open(self.filename, 'rb') as pem_in:
			pemlines = pem_in.read()
		private_key = load_pem_private_key(pemlines, None, default_backend())
		return private_key


class AsymmetricEncryptionPublicKey:
	def __init__(self, filename):
		self.filename = filename
	
	def GenPublicKey(self, priv_key_filename):
		pk = AsymmetricEncryptionPrivateKey(priv_key_filename)
		private_key = pk.LoadPrivKey()
		public_key = private_key.public_key()
		public_key_pem = public_key.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		)
		with open(self.filename, 'wb') as f:
			f.write(public_key_pem)
	
	def LoadPubKey(self):
		with open(self.filename, 'rb') as pub_in:
			pub_key = load_pem_public_key(pub_in.read(), default_backend())
		
		return pub_key


class AsymmetricEncDecFile:
	def __init__(self, filename, output_folder):
		self.filename = filename
		self.output_folder = output_folder
	
	def AsymmetricEncFile(self, pub_key):
		pub = AsymmetricEncryptionPublicKey(pub_key)
		public_key = pub.LoadPubKey()
		
		with open(self.filename, 'rb') as f:
			f_read = f.read()
		
		encrypted = public_key.encrypt(
			f_read,
			asym_padding.OAEP(
				mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label=None
			)
		)
		
		out_filename = os.path.join(self.output_folder, '{0}_enc.{1}'.format(str(self.filename).split('/')[-1].split('.')[0],
																 str(self.filename).split('/')[-1].split('.')[1]))
		
		with open(out_filename, 'wb') as f:
			enc = base64.b64encode(encrypted)
			f.write(enc)
		
		return None
	
	def AsymmetricDecFile(self, priva_key):
		pk = AsymmetricEncryptionPrivateKey(priva_key)
		private_key = pk.LoadPrivKey()
		
		with open(self.filename, 'rb') as f:
			f_read = f.read()
			file_content = base64.b64decode(f_read)
		
		dec = private_key.decrypt(
			file_content,
			asym_padding.OAEP(
				mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label=None
			)
		)
		
		out_filename = os.path.join(self.output_folder, '{0}_dec.{1}'.format(str(self.filename).split('/')[-1].split('.')[0],
																 str(self.filename).split('/')[-1].split('.')[1]))
		
		with open(out_filename, 'wb') as f:
			f.write(dec)


# Symmetric Encryption From here
class SymmetricEncryption:
	def __init__(self, method, mode, auth=None):
		self.method = method
		self.mode = mode
		self.auth = auth
	
	def EncryptWithoutAuth(self, data):
		cipher = Cipher(self.method, self.mode)
		encryptor = cipher.encryptor()
		ct = encryptor.update(data) + encryptor.finalize()
		return ct
	
	def DecryptWithoutAuth(self, data):
		cipher = Cipher(self.method, self.mode)
		decrypted = cipher.decryptor()
		return decrypted.update(data) + decrypted.finalize()


class SymmetricEncryptionWithAuth:
	def __init__(self, method, mode, tag):
		self.method = method
		self.mode = mode
		self.tag = tag
	
	def EncryptWithAuth(self, data):
		if self.tag is None:
			print("You need to set auth key.\n")
			exit(-1)
		cipher = Cipher(self.method, self.mode)
		encryptor = cipher.encryptor()
		encryptor.authenticate_additional_data(self.tag)
		ct = encryptor.update(data) + encryptor.finalize()
		return [ct, encryptor.tag]
	
	def DecryptWithAuth(self, data):
		if self.tag is None:
			print("You need to set auth key.\n")
			exit(-1)
		cipher = Cipher(self.method, self.mode)
		decryptor = cipher.decryptor()
		decryptor.authenticate_additional_data(self.tag)
		pl = decryptor.update(data) + decryptor.finalize()
		return pl


class SymmetricPad:
	def __init__(self, data):
		self.data = data
		self.size = 128
	
	def pad(self):
		padder = sym_padding.PKCS7(self.size).padder()
		padded_data = padder.update(self.data)
		padded_data += padder.finalize()
		return padded_data
	
	def unpad(self):
		padder = sym_padding.PKCS7(self.size).unpadder()
		unpadded_data = padder.update(self.data)
		unpadded_data += padder.finalize()
		return unpadded_data


class SymmetricEncDecFileWithAuth:
	def __init__(self, filename, auth_tag, enc_algo, output=None, config_file='cfg.ini'):
		self.filename = filename
		self.auth_tag = auth_tag.encode()
		self.output = output
		
		self.key, self.iv = ReadConfigFile(config_file=config_file)
		self.enc_algo = enc_algo
		
		match self.enc_algo:
			case "AES GCM":
				self.method = algorithms.AES(self.key)
				self.mode = modes.GCM(self.iv)
		
	def SymmetricEncFile(self):
		# mode = modes.GCM(self.iv)
		with open(self.filename, 'rb') as f:
			f_read = f.read()
		
		enc = SymmetricEncryptionWithAuth(method=self.method, mode=self.mode, tag=self.auth_tag)
		enc_data, auth_tag_out = enc.EncryptWithAuth(f_read)
		
		out_filename = os.path.join(self.output, '{0}_AuthSymEnc.{1}'.format(str(self.filename).split('/')[-1].split('.')[0],
												   str(self.filename).split('/')[-1].split('.')[1]))
		
		encrypted = base64.b64encode(enc_data)
		enc_auth_tag = base64.b64encode(auth_tag_out)
		
		with open(out_filename, 'wb') as f:
			f.write(encrypted)
		
		with open(out_filename + '.key', 'wb') as f:
			f.write(enc_auth_tag)
	
	def SymmetricDecFile(self, key):
		with open(self.filename, 'rb') as f:
			undecoded_data = f.read()
		
		with open(key, 'rb') as f:
			undecoded_key = f.read()
		
		decoded_data = base64.b64decode(undecoded_data)
		decoded_key = base64.b64decode(undecoded_key)
		mode = modes.GCM(self.iv, decoded_key)
		
		dec = SymmetricEncryptionWithAuth(method=self.method, mode=mode, tag=self.auth_tag)
		plain_data = dec.DecryptWithAuth(data=decoded_data)
		
		out_filename = os.path.join(self.output,
									'{0}_AuthSymDec.{1}'.format(str(self.filename).split('/')[-1].split('.')[0],
															str(self.filename).split('/')[-1].split('.')[1]))
		
		with open(out_filename, 'wb') as f:
			f.write(plain_data)


class SymmetricEncDecFileWithoutAuth:
	def __init__(self, filename, enc_algo, output, config_file='cfg.ini'):
		self.filename = filename
		self.key, self.iv = ReadConfigFile(config_file=config_file)
		self.output = output
		
		self.enc_algo = enc_algo
		
		match self.enc_algo:
			case "AES ECB":
				self.method = algorithms.AES(self.key)
				self.mode = modes.ECB()
			case "AES CBC":
				self.method = algorithms.AES(self.key)
				self.mode = modes.CBC(self.iv)
			case "AES OFB":
				self.method = algorithms.AES(self.key)
				self.mode = modes.OFB(self.iv)
			case "AES CTR":
				self.method = algorithms.AES(self.key)
				self.mode = modes.CTR(self.iv)
			case "Blowfish ECB":
				self.method = algorithms.Blowfish(self.key)
				self.mode = modes.ECB()
			case "Blowfish CBC":
				self.method = algorithms.Blowfish(self.key)
				self.modes = modes.CBC(self.iv[:8])
			case "ChaCha20":
				self.method = algorithms.ChaCha20(self.key, self.iv)
			case "3DES CBC":
				self.method = algorithms.TripleDES(self.key[:16])
				self.mode = modes.ECB()
			case "Camellia ECB":
				self.method = algorithms.Camellia(self.key)
				self.mode = modes.CBC(self.iv[:8])
			case "Camellia CBC":
				self.method = algorithms.Camellia(self.key)
				self.mode = modes.CBC(self.iv)

	def SymmetricEncWithoutAuth(self):
		with open(self.filename, 'rb') as f:
			f_read = f.read()
		
		padded = SymmetricPad(f_read)
		padded_data = padded.pad()
	
		cipher = SymmetricEncryption(method=self.method, mode=self.mode)
		cipher_out = cipher.EncryptWithoutAuth(data=padded_data)
		
		if self.output is None:
			out_filename = '{0}_SymEnc.{1}'.format(str(self.filename).split('/')[-1].split('.')[0],
											   str(self.filename).split('/')[-1].split('.')[1])
		else:
			out_filename = os.path.join(self.output, '{0}_UnauthSymEnc.{1}'.format(str(self.filename).split('/')[-1].split('.')[0],
											   str(self.filename).split('/')[-1].split('.')[1]))
		
		with open(out_filename, 'wb') as f:
			encoded = base64.b64encode(cipher_out)
			f.write(encoded)
	
	def SymmetricDecWithoutAuth(self):
		with open(self.filename, 'rb') as fd:
			f_read = fd.read()
		
		fd = base64.b64decode(f_read)
		decipher = SymmetricEncryption(method=self.method, mode=self.mode)
		decipher_out = decipher.DecryptWithoutAuth(data=fd)
		
		if self.output is None:
			out_filename = '{0}_SymEnc.{1}'.format(str(self.filename).split('/')[-1].split('.')[0],
											   str(self.filename).split('/')[-1].split('.')[1])
		else:
			out_filename = os.path.join(self.output, '{0}_UnauthSymDec.{1}'.format(str(self.filename).split('/')[-1].split('.')[0],
											   str(self.filename).split('/')[-1].split('.')[1]))
		
		with open(out_filename, 'wb') as f:
			padded = SymmetricPad(decipher_out)
			padded_data = padded.unpad()
			f.write(padded_data)


def GenerateConfigFile(config_file='cfg.ini'):
	cfg = ConfigParser()
	
	try:
		with open(config_file, encoding='utf-8') as f:
			cfg.read_file(f)
	except (FileNotFoundError, KeyError):
		with open(config_file, 'w') as f:
			f.write('[_]\nkey = 0\niv = 0')
		GenerateConfigFile(config_file)
	
	cfg['_']['key'] = base64.b64encode(os.urandom(32)).decode()
	cfg['_']['iv'] = base64.b64encode(os.urandom(16)).decode()
	
	with open(config_file, 'w', encoding='utf-8') as f:
		cfg.write(f)


def ReadConfigFile(config_file='cfg.ini'):
	cfg = ConfigParser()
	
	try:
		with open(config_file, encoding='utf-8') as f:
			cfg.read_file(f)
	except (FileNotFoundError, KeyError):
		GenerateConfigFile(config_file)
	
	key = cfg['_']['key']
	iv = cfg['_']['iv']
	
	return [base64.b64decode(key.encode()), base64.b64decode(iv.encode())]


def DisplayConfigFile(config_file="cfg.ini"):
	cfg = ConfigParser()
	
	try:
		with open(config_file, encoding='utf-8') as f:
			cfg.read_file(f)
	except (FileNotFoundError, KeyError):
		GenerateConfigFile(config_file)
	
	key = cfg['_']['key']
	iv = cfg['_']['iv']
	return [key, iv]
