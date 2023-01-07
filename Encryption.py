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


def GenRSA():
	pk = AsymmetricEncryption.RSAGenKey()
	dwd = os.getcwd()
	try:
		os.chdir('keys')
	except FileNotFoundError:
		os.mkdir('keys')
		os.chdir('keys')
	file = input('Enter the name of the file you want to create: ')
	filename = dwd + '/keys/' + file + '.pem'
	os.chdir(dwd)
	savekey = AsymmetricEncryption(filename)
	savekey.SaveKey(pk)


def main():
	GenRSA()


if __name__ == "__main__":
	main()
