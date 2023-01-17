import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
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
	def __init__(self, filename, output=None):
		self.filename = filename
		self.output = output
	
	def AsymmetricEncFile(self, pub_key):
		pub = AsymmetricEncryptionPublicKey(pub_key)
		public_key = pub.LoadPubKey()
		
		with open(self.filename, 'rb') as f:
			f_read = f.read()
		
		encrypted = public_key.encrypt(
			f_read,
			padding.OAEP(
				mgf=padding.MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label=None
			)
		)
		
		if self.output is None:
			out_filename = '{0}_enc.{1}'.format(str(self.filename).split('/')[-1].split('.')[0],
												str(self.filename).split('/')[-1].split('.')[1])
		else:
			out_filename = self.output
		
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
			padding.OAEP(
				mgf=padding.MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label=None
			)
		)
		
		if self.output is None:
			out_filename = '{0}_dec.{1}'.format(str(self.filename).split('.')[0],
												 str(self.filename).split('.')[1])
		else:
			out_filename = self.output
		
		with open(out_filename, 'wb') as f:
			f.write(dec)
