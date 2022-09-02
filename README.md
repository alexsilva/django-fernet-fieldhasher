# django-fernet-fieldhasher
Creating encrypted database fields with the algorithm with cryptography.fernet

# Usage

```
from django.db import models

class User(models.Model):
    name = models.CharField(verbose_name="name")
    
    # The password is stored encrypted but when retrieved through the instance it returns to its text form.
    password = EncryptedCharField(verbose_name=_("Password"), max_length=350)
```