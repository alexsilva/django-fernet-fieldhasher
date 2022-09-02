# coding=utf-8
import django.forms as django_forms
import django.contrib.auth.forms as auth_forms
from fernet_fieldhasher.forms.widgets import ReadOnlyPasswordHashWidget


class PasswordField(django_forms.CharField):
	"""Field CharField with characters masked in edit."""
	widget = django_forms.PasswordInput


class ReadOnlyPasswordHashField(auth_forms.ReadOnlyPasswordHashField):
	widget = ReadOnlyPasswordHashWidget
