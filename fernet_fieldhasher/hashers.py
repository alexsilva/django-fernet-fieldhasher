# coding=utf-8
import base64
from collections import OrderedDict

from django.conf import settings
from django.contrib.auth.hashers import BasePasswordHasher, mask_hash
from django.utils.encoding import force_bytes, force_text
from django.utils.translation import gettext_noop as _


class FernetPassword(str):
	"""Encrypted data string"""
	pass


class FernetPasswordHasher(BasePasswordHasher):
	"""
	Fernet guarantees that a message encrypted using it cannot be manipulated or read without the key.
	Fernet is an implementation of symmetric (also known as “secret key”) authenticated cryptography.
	"""
	algorithm = "cryptography_fernet"
	library = "cryptography.fernet"

	def __init__(self, key=None):
		self.key = self.generate_key(key or settings.SECRET_KEY)
		# Usually used in password decoding
		self._encoding = 'utf-8'

	@staticmethod
	def generate_key(key):
		key = force_bytes(key[0:32])
		return base64.urlsafe_b64encode(key)

	def encode(self, password, salt=None, **options):
		fernet = self._load_library()
		encoding = options.get('encoding', self._encoding)
		password = force_bytes(password, encoding=encoding)
		f = fernet.Fernet(self.key)
		token = f.encrypt(password)
		token = force_text(token, 'ascii')
		return "%s$%s" % (self.algorithm, token)

	def decode(self, token, salt=None, **options):
		fernet = self._load_library()
		algorithm, token = token.split("$", 1)
		token = force_bytes(token, encoding='ascii')
		f = fernet.Fernet(self.key)
		password = f.decrypt(token)
		encoding = options.get('encoding', self._encoding)
		return FernetPassword(password, encoding)

	def is_hash(self, encoded):
		"""Checks if the password was encoded with this algorithm"""
		try:
			summary = self.safe_summary(encoded)
		except (ValueError, AssertionError):
			return False
		return summary[_('algorithm')] == self.algorithm

	def verify(self, password, encoded):
		return password == self.decode(encoded)

	def safe_summary(self, encoded):
		algorithm, token = encoded.split("$", 1)
		assert algorithm == self.algorithm
		mask_show = 6
		mask_max = len(token[mask_show:])
		return OrderedDict([
			(_('algorithm'), algorithm),
			(_('hash'), mask_hash(token, show=mask_show)[:int(mask_max * 0.25)]),
		])
