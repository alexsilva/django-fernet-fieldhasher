# django-fernet-fieldhasher
Creating encrypted database fields with the algorithm cryptography.fernet

# Usage

```
from django.db import models

class User(models.Model):
    name = models.CharField(verbose_name="Name")
    
    # The password is stored encrypted but when retrieved through the instance it returns to its text form.
    password = FernetPasswordField(verbose_name=Password", max_length=350)
```