from rest_framework import serializers
from account.models import User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError, force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from account.utils import send_email

class UserRegisterationSerializer(serializers.ModelSerializer):
    """Adding the password2 field because we need a password
    confirmation field in our forms"""

    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    name = serializers.CharField()

    class Meta:
        model = User
        fields = ['name', 'email', 'password', 'password2', 'tc']
        extra_kwargs = {
            'password': {'write_only': True},
        }
    
    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password Don't Match!")
        return data
    
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = User
        fields = ['email', 'password']

class UserProfileSerializer(serializers.ModelSerializer):
    #A Serializer class for the users to view their profile

    class Meta:
        model = User
        fields = ['name', 'email', 'tc']
        extra_kwargs = {
            'name': {'read_only': True},
            'email': {'read_only': True},
            'tc': {'read_only': True}
        }

class UserChangePasswordSerializier(serializers.Serializer):
    #A serializer class for users to change their passwords

    password = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['password', 'password2']

    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        user = self.context.get('user')

        if password != password2:
            raise serializers.ValidationError('Password and Confirm Password Does NOT Match!')

        return data
    
    #Overiding the save() method to set the user's new password
    def save(self, **kwargs):
        user = self.context.get('user')
        password = self.validated_data.get('password')
        user.set_password(password)
        user.save()
        return user
        
class SendPasswordResetEmailSerializer(serializers.Serializer):
    #A serializer class to generate a link to send an email to users for resetting their passwords

    email = serializers.EmailField(max_length=255)

    def validate(self, data):
        email = data.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            #Encoding the user id to send it to the url
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print('User UID', uid)
            #Generating a short-lived token to validate the user and then reset their password
            token = PasswordResetTokenGenerator().make_token(user)
            print('User Token', token)
            #The link to hit the email on with the user uid and a token
            link = 'https://localhost:3000/api/user/reset-password/' + uid + '/' + token + '/'
            print('Reset Password Link:', link)

            #Send Email
            body = 'Click The Following Link to Reset Your Password: ' + link

            data = {
                'subject': 'Reset Your Password',
                'body': body,
                'to_email': user.email,
            }

            send_email(data)
            return data
        else:
            raise serializers.ValidationError('An Account With That Email DOES NOT Exist!')

class UserPasswordResetSerializer(serializers.Serializer):
    #A serializer class to reset passwords

    password = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['password', 'password2']

    def validate(self, data):
        try:
            password = data.get('password')
            password2 = data.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')

            if password != password2:
                raise serializers.ValidationError('Password and Confirm Password Does NOT Match!')
            
            #Decoding the encoded uid to find the user with the help of Django ORM 
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            
            #Validating if the user has the correct token for resetting password
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError('Wrong Token Or Token EXpired!')

            user.set_password(password)
            user.save()

            return data
        
        #An extra lair of protection for resetting a user's password
        except DjangoUnicodeDecodeError:
            raise serializers.ValidationError('Wrong Token Or Token EXpired!')
    
