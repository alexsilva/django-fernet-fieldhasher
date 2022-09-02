# coding=utf-8
import django.forms as django_forms


class PasswordField(django_forms.CharField):
	"""Field CharField with characters masked in edit."""
	widget = django_forms.PasswordInput
