from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import os


class AsymmetricEncryption:
	def __init__(self, filename):
		self.filename = filename

	@staticmethod
	def RSAGenKey():
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

	def LoadKey(self):
		with open(self.filename, 'rb') as pem_in:
			pemlines = pem_in.read()
		private_key = load_pem_private_key(pemlines, None, default_backend())
		return private_key

	@staticmethod
	def GenPublicKey(priv_filename):
		public_key = priv_filename.public_key()
		public_key_pem = public_key.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		)
		with open('./keys/asd_pubkey.pub', 'wb') as f:
			f.write(public_key_pem)


def main():
	pass


if __name__ == "__main__":
	main()
