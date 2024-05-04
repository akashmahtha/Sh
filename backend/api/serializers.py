from django.contrib.auth import authenticate
from rest_framework import serializers
from rest_framework.authtoken.models import Token
from .models import RegistrationUser, Question, SchoolOrCollege, Subject, ClassSemester, Topic, Term,Answer,CreditPoint


class RegistrationUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = RegistrationUser
        fields = ['id', 'email', 'name', 'username', 'password', 'category']

    def create(self, validated_data):
        user = RegistrationUser.objects.create_user(
            email=validated_data['email'],
            name=validated_data['name'],
            username=validated_data['username'],
            password=validated_data['password'],
            category=validated_data['category']
        )
        return user


class LoginSerializer(serializers.Serializer):
    email_or_username = serializers.CharField()
    password = serializers.CharField(write_only=True)
    category = serializers.CharField(write_only=True)  # Add category field

    def validate(self, data):
        email_or_username = data.get('email_or_username')
        password = data.get('password')
        category = data.get('category')  # Retrieve category

        if email_or_username and password:
            user = authenticate(request=self.context.get('request'),
                                username=email_or_username,
                                password=password)

            if user is None:
                try:
                    user = RegistrationUser.objects.get(email=email_or_username)
                    user = authenticate(request=self.context.get('request'),
                                        username=user.username,
                                        password=password)
                except RegistrationUser.DoesNotExist:
                    pass

            if user:
                # Validate user category
                if category and user.category != category:
                    raise serializers.ValidationError('Invalid category')
                
                data['user'] = user
            else:
                raise serializers.ValidationError('Invalid login credentials')
        else:
            raise serializers.ValidationError('Email/Username, password, and category must be provided')

        return data

    def create(self, validated_data):
        user = validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return {'token': token.key, 'user': user.id}



class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = RegistrationUser
        fields = ['id', 'email', 'name', 'username', 'category']
        read_only_fields = ['id', 'email', 'name', 'username', 'category']


class EditProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = RegistrationUser
        fields = ['email', 'name', 'username', 'category']


class SchoolOrCollegeSerializer(serializers.ModelSerializer):
    class Meta:
        model = SchoolOrCollege
        fields = ('id', 'name', 'board')


class SubjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subject
        fields = ['id', 'name']


class ClassSemesterSerializer(serializers.ModelSerializer):
    class Meta:
        model = ClassSemester
        fields = ['id', 'name']


class TopicSerializer(serializers.ModelSerializer):
    class Meta:
        model = Topic
        fields = ['id', 'subject', 'topic']
        extra_kwargs = {
            'subject': {'required': True}
        }

    def validate(self, data):
        if not data.get('subject'):
            raise serializers.ValidationError({'subject': 'This field is required.'})
        return data


class TermSerializer(serializers.ModelSerializer):
    class Meta:
        model = Term
        fields = ['id', 'name']


class QuestionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Question
        fields = ['id', 'subject', 'class_semester', 'topic', 'term', 'school', 'file', 'remark', ]
        extra_kwargs = {
            'class_semester': {'required': False},
            'file': {'write_only': True},
        }

    def validate(self, data):
        if not data.get('subject'):
            raise serializers.ValidationError({'subject': 'This field is required.'})
        if not data.get('term'):
            raise serializers.ValidationError({'term': 'This field is required.'})
        if not data.get('school'):
            raise serializers.ValidationError({'school': 'This field is required.'})
        return data


class QuestionUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Question
        fields = ['school', 'subject', 'class_semester', 'topic', 'term', 'file', 'remark']
        extra_kwargs = {
            'class_semester': {'required': False},
            'file': {'write_only': True},
        }

    def validate(self, data):
        if not data.get('subject'):
            raise serializers.ValidationError({'subject': 'This field is required.'})
        if not data.get('term'):
            raise serializers.ValidationError({'term': 'This field is required.'})
        if not data.get('topic'):
            raise serializers.ValidationError({'topic': 'This field is required.'})
        if not data.get('school'):
            raise serializers.ValidationError({'school': 'This field is required.'})
        return data    
    

class AnswerSerializer(serializers.ModelSerializer):
    date_uploaded = serializers.DateTimeField(format='%Y-%m-%d %H:%M:%S', read_only=True)

    class Meta:
        model = Answer
        fields = ['id', 'question', 'name', 'pdf_file', 'date_uploaded', 'status']


class CreditPointSerializer(serializers.ModelSerializer):
    class Meta:
        model = CreditPoint
        fields = ['id', 'type', 'value']