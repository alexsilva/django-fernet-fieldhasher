# coding=utf-8
from django.db import models
from fernet_fieldhasher.forms.fields import PasswordField
from fernet_fieldhasher.hashers import FernetPasswordHasher


class FernetCharField(models.CharField):
	"""CharField with encrypted data"""

	def __init__(self, key=None, *args, **kwargs):
		self.encoding = kwargs.pop('encoding', None)
		super().__init__(*args, **kwargs)
		self.key = key
		self.fernet = FernetPasswordHasher(key)

	def from_db_value(self, value, expression, connection):
		"""Decrypt data from the database"""
		if value is None:
			return value
		if self.fernet.is_hash(value):
			options = {}
			if self.encoding is not None:
				options['encoding'] = self.encoding
			value = self.fernet.decode(value, **options)
		return value

	def to_python(self, value):
		"""Encrypt database data"""
		if value is None:
			return value
		if self.fernet.is_hash(value):
			return value
		options = {}
		if self.encoding is not None:
			options['encoding'] = self.encoding
		value = self.fernet.encode(value, **options)
		return value

	def deconstruct(self):
		name, path, args, kwargs = super().deconstruct()
		if self.key is not None:
			kwargs['key'] = self.key
		if self.encoding is not None:
			kwargs['encoding'] = self.encoding
		return name, path, args, kwargs


class FernetPasswordField(FernetCharField):
	"""A field that defines an encrypted password"""
	def formfield(self, **kwargs):
		defaults = {'form_class': PasswordField, 'strip': False}
		defaults.update(kwargs)
		return super().formfield(**defaults)
