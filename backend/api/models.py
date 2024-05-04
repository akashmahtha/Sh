from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from datetime import datetime

class CustomUserManager(BaseUserManager):
    def create_user(self, email, name, username, password=None, category=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, name=name, category=category, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, username, password=None, category=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(email, name, username, password, category, **extra_fields)

class RegistrationUser(AbstractUser):
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=255)
    username = models.CharField(max_length=255, unique=True)
    category = models.CharField(max_length=100, blank=True, null=True)  
    is_approved = models.BooleanField(default=False)
    # New field for category

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name', 'username']

    objects = CustomUserManager()

    def __str__(self):
        return self.email



    
class SchoolOrCollege(models.Model):
    name = models.CharField(max_length=255)
    board = models.CharField(max_length=255)

    def __str__(self):
        return self.name
    
class Subject(models.Model):
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name
    
class ClassSemester(models.Model):
    name = models.IntegerField()
        
    def __str__(self):
        return str(self.name)
    
class Topic(models.Model):
    subject = models.ForeignKey(Subject, on_delete=models.CASCADE)
    topic = models.CharField(max_length=255)

    def __str__(self):
        return self.topic

    
class Term(models.Model):
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name
    
class Question(models.Model):
    subject = models.ForeignKey(Subject, on_delete=models.CASCADE, null=True, blank=True)
    class_semester = models.ForeignKey(ClassSemester, on_delete=models.CASCADE, null=True, blank=True)
    topic = models.ForeignKey(Topic, on_delete=models.CASCADE, null=True, blank=True)
    term = models.ForeignKey(Term, on_delete=models.CASCADE, null=True, blank=True)
    school = models.ForeignKey(SchoolOrCollege, on_delete=models.CASCADE, null=True, blank=True)
    file = models.FileField(upload_to='question_files/')
    remark = models.TextField()

    def __str__(self):
        return f"{self.subject.name}"


class Answer(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=255)
    pdf_file = models.FileField(upload_to='answer_files/')
    date_uploaded = models.DateTimeField(auto_now_add=True)
    status = models.BooleanField(default=False)  

    def __str__(self):
        return f"Answer for {self.question.subject.name} uploaded on {self.date_uploaded}"
    
class CreditPoint(models.Model):
    type = models.CharField(max_length=100)
    value = models.IntegerField()