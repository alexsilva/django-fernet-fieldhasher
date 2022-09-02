# coding=utf-8
from django.db import models
import django.forms as django_forms
from fernet_fieldhasher.hashers import FernetPasswordHasher
from fernet_fieldhasher.forms.fields import PasswordField


class EncryptedCharField(models.CharField):
	"""CharField with encrypted data"""

	def __init__(self, key=None, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.key = key
		self.fernet = FernetPasswordHasher(key)

	def from_db_value(self, value, expression, connection):
		"""Decrypt data from the database"""
		if value is None:
			return value
		if self.fernet.is_hash(value):
			value = self.fernet.decode(value)
		return value

	def to_python(self, value):
		"""Encrypt database data"""
		if value is None:
			return value
		if self.fernet.is_hash(value):
			return value
		value = self.fernet.encode(value)
		return value

	def deconstruct(self):
		name, path, args, kwargs = super().deconstruct()
		if self.key is not None:
			kwargs['key'] = self.key
		return name, path, args, kwargs


class EncryptedPasswordField(EncryptedCharField):
	"""A field that defines an encrypted password"""
	def formfield(self, **kwargs):
		defaults = {'form_class': PasswordField, 'strip': False}
		defaults.update(kwargs)
		return super().formfield(**defaults)
