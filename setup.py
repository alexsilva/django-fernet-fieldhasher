# coding=utf-8
from distutils.core import setup

setup(
	name='django-fernet-fieldhasher',
	version='1.0.0',
	packages=['fernet_fieldhasher', 'fernet_fieldhasher.forms'],
	url='https://github.com/alexsilva/django-fernet-fieldhasher',
	include_package_data=True,
	license='MIT',
	author='alex',
	author_email='',
	description='Creating encrypted database fields with the algorithm with cryptography.fernet'
)
