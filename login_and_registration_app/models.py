from django.db import models
import re
import bcrypt

# Create your models here.
class UserManager(models.Manager):
    
    # function for form validation
    def basic_validator(self, postData):
        errors = {}
        EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
        if len(postData["first_name"]) < 2:
            errors["first_name"] = "First name should be at least 2 characters."
        if len(postData["last_name"]) < 2:
            errors["last_name"] = "Last name should be at least 2 characters."
        if not EMAIL_REGEX.match(postData['email']):
            errors["email"] = "Invalid email address."
        if len(postData["password"]) < 8:
            errors["password"] = "Password must be at least 8 characters."
        if postData["password"] != postData["confirm_password"]:
            errors["password"] = "Passwords do not match."
            
        return errors



class User(models.Model):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.EmailField(max_length=255)
    password = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()