from django.urls import path
from account.views import UserRegitserationView, UserLoginView

urlpatterns = [
    path('register/', UserRegitserationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
]
