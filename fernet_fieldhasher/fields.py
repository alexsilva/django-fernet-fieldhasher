# coding=utf-8
from django.core import validators as dj_validators
from django.core import checks as dj_checks

from django.db import models
from fernet_fieldhasher.forms.fields import PasswordField
from fernet_fieldhasher.hashers import FernetPasswordHasher


class FernetField(models.Field):
	def __init__(self, key=None, *args, **kwargs):
		max_length = kwargs.get('max_length', None)
		self.encoding = kwargs.pop('encoding', None)
		self.text_length = kwargs.pop('text_length', max_length)
		super().__init__(*args, **kwargs)
		self.validators.append(dj_validators.MaxLengthValidator(self.text_length))
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
		if self.text_length is not None:
			kwargs['text_length'] = self.text_length
		return name, path, args, kwargs

	def check(self, **kwargs):
		return [
			*super().check(**kwargs),
			*self._check_text_length_attribute(**kwargs),
		]

	def _check_text_length_attribute(self, **kwargs):
		if self.text_length is None:
			return [
				dj_checks.Error(
					"FernetField must define a 'text_length' attribute.",
					obj=self,
					id='fields.E120',
				)
			]
		elif (not isinstance(self.text_length, int) or isinstance(self.text_length, bool) or
		      self.text_length <= 0):
			return [
				dj_checks.Error(
					"'text_length' must be a positive integer.",
					obj=self,
					id='fields.E121',
				)
			]
		else:
			return []


class FernetTextField(FernetField, models.TextField):
	"""TextField with encrypted data"""
	...


class FernetCharField(FernetField, models.CharField):
	"""CharField with encrypted data"""
	...


class FernetPasswordField(FernetCharField):
	"""A field that defines an encrypted password"""

	def formfield(self, **kwargs):
		defaults = {
			'form_class': PasswordField,
			'max_length': self.text_length,
			'strip': False,
		}
		defaults.update(kwargs)
		return super().formfield(**defaults)


class FernetPasswordHashField(FernetTextField):
	"""A field that defines an encrypted password"""

	def formfield(self, **kwargs):
		defaults = {
			'form_class': PasswordField,
			'max_length': self.text_length,
			'strip': False,
		}
		defaults.update(kwargs)
		return super().formfield(**defaults)
