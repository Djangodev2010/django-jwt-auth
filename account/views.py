from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from account.serializers import UserRegisterationSerializer, UserLoginSerializer, UserProfileSerializer, UserChangePasswordSerializier, SendPasswordResetEmailSerializer, UserPasswordResetSerializer
from account.models import User
from django.contrib.auth import authenticate
from account.renders import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

# Create your views here.

#Generating Tokens for Users manually
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class UserRegitserationView(APIView):
    #A view for the users to register

    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserRegisterationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            #Calling manual user token generation
            token = get_tokens_for_user(user)
            return Response({'token': token, 'message': 'Registeration Successful!'}, status=status.HTTP_201_CREATED)
        print(serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    #A view for the users to login

    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email=email, password=password)
            #Calling manual user token validation
            if user is not None:
                token = get_tokens_for_user(user)
                return Response({'token': token,'message': 'Login Successful!'}, status=status.HTTP_200_OK)
            return Response({'errors': {'non_field_error': ['Email Or Password Is INCORRECT!']}}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserProfileView(APIView):
    #A view for users to view their details

    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)

class UserChangePasswordView(APIView):
    #A view for users to change their passwords

    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        serializer = UserChangePasswordSerializier(data=request.data, context={'user': request.user})
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({'message': 'Password Changed Successful!'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
class SendPasswordResetEmailView(APIView):
    #A view to send a reset password email to the email that the user provides

    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({'message': 'Password Reset Email Sent! Please Check Your Emails.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserPasswordResetView(APIView):
     #A view to reset the password of the users with the help of a reset password email
     
     renderer_classes = [UserRenderer]

     def post(self, request, uid, token, format=None):
         serializer = UserPasswordResetSerializer(data=request.data, context={'uid': uid, 'token': token})
         if serializer.is_valid(raise_exception=True):
             return Response({'message': 'Password Reset Successful!'}, status=status.HTTP_200_OK)
         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
