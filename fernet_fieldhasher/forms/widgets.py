# coding=utf-8
import django.contrib.auth.forms as auth_forms


class ReadOnlyPasswordHashWidget(auth_forms.ReadOnlyPasswordHashWidget):
	template_name = "fernet_fieldhasher/forms/read_only_password_hash.html"

	def get_context(self, name, value, attrs, **kwargs):
		"""Convert password from text to hash"""
		from fernet_fieldhasher.fields import FernetPasswordField
		field = FernetPasswordField()
		value = field.to_python(value)
		return super().get_context(name, value, attrs, **kwargs)
