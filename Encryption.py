from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
import base64


class AsymmetricEncryption:
	def __init__(self, filename):
		self.filename = filename
	
	@staticmethod
	def GenRSAPrivKey():
		private_key = rsa.generate_private_key(
			public_exponent=65537,
			key_size=2048,
			backend=default_backend()
		)
		return private_key
	
	def SaveKey(self, pk):
		pem = pk.private_bytes(
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
	
	@staticmethod
	def GenPublicKey(priv_filename, pub_filename):
		pk = AsymmetricEncryption(priv_filename)
		private_key = pk.LoadPrivKey()
		public_key = private_key.public_key()
		public_key_pem = public_key.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		)
		with open('./keys/' + pub_filename, 'wb') as f:
			f.write(public_key_pem)
	
	@staticmethod
	def LoadPubKey(pub_filename):
		with open(pub_filename, 'rb') as pub_in:
			pub_key = load_pem_public_key(pub_in.read(),
										  backend=default_backend()
										  )
		
		return pub_key


def AsymmEncFile(filename, pubkey) -> None:
	pub_key = AsymmetricEncryption.LoadPubKey(pubkey)
	
	with open(filename, 'rb') as f:
		f_read = f.read()
	
	encrypted = pub_key.encrypt(
		f_read,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)
	
	out_filename = str(filename).split('/')[-1].split('.')[0] + '_enc.' + str(filename).split('/')[-1].split('.')[1]
	
	with open(out_filename, 'wb') as f:
		enc = base64.b64encode(encrypted)
		f.write(enc)

	return None


def AsymmDecFile(filename, privkey, output=None):
	pk = AsymmetricEncryption(privkey)
	private_key = pk.LoadPrivKey()
	
	with open(filename, 'rb') as f:
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
	
	if output is None:
		output = str(filename).split('.')[0] + '_dec.' + str(filename).split('.')[1]
	
	with open(output, 'wb') as f:
		f.write(dec)


def main():
	pass


if __name__ == "__main__":
	main()
