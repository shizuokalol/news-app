from typing import Any

from django.contrib.auth import login
from rest_framework import status, generics, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

from .models import User
from .serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    UserProfileSerializer,
    UserUpdateSerializer,
    ChangePasswordSerializer,
)


class RegisterView(generics.CreateAPIView):
    """
    View for user registration.

    This view allows unauthenticated users to register a new account.
    It uses UserRegistrationSerializer to validate and create the user,
    then generates JWT tokens for immediate authentication.
    """

    queryset = User.objects.all()
    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request: Any, *args: Any, **kwargs: Any) -> Response:
        """
        Handles the creation of a new user.

        Args:
            request (Any): The HTTP request object.
            *args (Any): Additional positional arguments.
            **kwargs (Any): Additional keyword arguments.

        Returns:
            Response: JSON response with user data, JWT tokens, and success message.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        refresh = RefreshToken.for_user(user)

        return Response(
            {
                "user": UserProfileSerializer(user).data,
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "message": "User registered successfully",
            },
            status=status.HTTP_201_CREATED,
        )


class LoginView(generics.CreateAPIView):
    """
    View for user login.

    This view allows unauthenticated users to log in with email and password.
    It uses UserLoginSerializer to validate credentials and generates JWT tokens.
    """
    serializer_class = UserLoginSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request: Any, *args: Any, **kwargs: Any) -> Response:
        """
        Handles user login.

        Args:
            request (Any): The HTTP request object.
            *args (Any): Additional positional arguments.
            **kwargs (Any): Additional keyword arguments.

        Returns:
            Response: JSON response with user data, JWT tokens, and success message.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]

        login(request, user)
        refresh = RefreshToken.for_user(user)

        return Response(
            {
                "user": UserProfileSerializer(user).data,
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "message": "User login successfully",
            },
            status=status.HTTP_200_OK,
        )


class ProfileView(generics.CreateAPIView):
    """
    View for user profile management.

    This view allows authenticated users to view and update their profile.
    It uses UserProfileSerializer for GET requests and UserUpdateSerializer for updates.
    """
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self) -> User:
        """
        Returns the current authenticated user.

        Returns:
            User: The user object.
        """
        return self.request.user

    def get_serializer_class(self) -> Any:
        """
        Returns the appropriate serializer class based on the request method.

        Returns:
            Any: The serializer class.
        """
        if self.request.method == "PUT" or self.request.method == "PATCH":
            return UserUpdateSerializer
        return UserProfileSerializer


class ChangePasswordView(generics.UpdateAPIView):
    """
    View for changing user password.

    This view allows authenticated users to change their password.
    It uses ChangePasswordSerializer to validate and update the password.
    """
    serializer_class = ChangePasswordSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self) -> User:
        """
        Returns the current authenticated user.

        Returns:
            User: The user object.
        """
        return self.request.user

    def update(self, request: Any, *args: Any, **kwargs: Any) -> Response:
        """
        Handles password update.

        Args:
            request (Any): The HTTP request object.
            *args (Any): Additional positional arguments.
            **kwargs (Any): Additional keyword arguments.

        Returns:
            Response: JSON response with success message.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            {"message": "Password changed successfully"}, status=status.HTTP_200_OK
        )


@api_view(["POST"])
@permission_classes([permissions.IsAuthenticated])
def logout_view(request: Any) -> Response:
    """
    View for user logout.

    This view allows authenticated users to log out by blacklisting the refresh token.

    Args:
        request (Any): The HTTP request object.

    Returns:
        Response: JSON response with success or error message.
    """
    try:
        refresh_token = request.data.get("refresh_token")
        if refresh_token:
            token = RefreshToken(refresh_token)
            token.blacklist()
        return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)
    except Exception:
        return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)
