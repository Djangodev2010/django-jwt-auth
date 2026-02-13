from rest_framework import serializers
from account.models import User

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

    class Meta:
        model = User
        fields = ['name', 'email', 'tc']
        extra_kwargs = {
            'name': {'read_only': True},
            'email': {'read_only': True},
            'tc': {'read_only': True}
        }
