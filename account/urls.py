from django.urls import path
from account.views import UserRegitserationView, UserLoginView, UserProfileView

urlpatterns = [
    path('register/', UserRegitserationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name='profile'),
]
