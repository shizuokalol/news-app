from typing import Dict, Any

from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers

from .models import User


class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for registering new users.

    Handles creation of a new user by accepting fields: username, email, password,
    password_confirm, first_name, and last_name. Validates password confirmation and
    creates a user using the create_user method.

    Fields:
        - username: Unique username (required).
        - email: Unique email address used for login (required).
        - password: User password (write-only).
        - password_confirm: Password confirmation (write-only).
        - first_name: User's first name (optional).
        - last_name: User's last name (optional).

    Validation:
        - Ensures password and password_confirm match.
        - Applies Django's password validation rules.
    """

    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = (
            "username",
            "email",
            "password",
            "password_confirm",
            "first_name",
            "last_name",
        )

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validates that password and password_confirm match.

        Args:
            attrs (Dict[str, Any]): Input data for validation.

        Raises:
            serializers.ValidationError: If passwords do not match.

        Returns:
            Dict[str, Any]: Validated data.
        """
        if attrs["password"] != attrs["password_confirm"]:
            raise serializers.ValidationError(
                {"password": "Password fields did not match."}
            )
        return attrs

    def create(self, validated_data: Dict[str, Any]) -> User:
        """
        Creates a new user from validated data.

        Args:
            validated_data (Dict[str, Any]): Validated data for user creation.

        Returns:
            User: The created user object.
        """
        validated_data.pop("password_confirm")
        user = User.objects.create_user(**validated_data)
        return user


class UserLoginSerializer(serializers.Serializer):
    """
    Serializer for user authentication (login).

    Accepts email and password, validates them using Django's authenticate function,
    and returns the user object if credentials are valid and the account is active.

    Fields:
        - email: User's email address (required).
        - password: User's password (write-only).

    Validation:
        - Ensures email and password are provided.
        - Verifies user existence and account status.
    """

    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validates email and password for user authentication.

        Args:
            attrs (Dict[str, Any]): Input data for validation (email and password).

        Raises:
            serializers.ValidationError: If user is not found or account is inactive.

        Returns:
            Dict[str, Any]: Validated data with the user object.
        """
        email = attrs.get("email")
        password = attrs.get("password")

        if email and password:
            user = authenticate(
                request=self.context.get("request"), username=email, password=password
            )
            if not user:
                raise serializers.ValidationError("User not found.")
            if not user.is_active:
                raise serializers.ValidationError("User account in disabled.")
            attrs["user"] = user
            return attrs
        else:
            raise serializers.ValidationError("Must include email and password.")


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for displaying user profile information.

    Provides user details including full name, post count, and comment count.
    Used to retrieve user profile data via the API.

    Fields:
        - id: Unique identifier for the user (read-only).
        - username: User's username.
        - email: User's email address.
        - first_name: User's first name.
        - last_name: User's last name.
        - full_name: Computed full name (read-only).
        - avatar: User's profile picture (optional).
        - bio: User's biography (optional).
        - created_at: Account creation timestamp (read-only).
        - updated_at: Account last updated timestamp (read-only).
        - posts_count: Number of user's posts (computed).
        - comments_count: Number of user's comments (computed).
    """

    full_name = serializers.ReadOnlyField()
    posts_count = serializers.SerializerMethodField()
    comments_count = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = (
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
            "full_name",
            "avatar",
            "bio",
            "created_at",
            "updated_at",
            "posts_count",
            "comments_count",
        )
        read_only_fields = ("id", "created_at", "updated_at")

    @staticmethod
    def get_posts_count(obj: User) -> int:
        """
        Returns the number of posts by the user.

        Args:
            obj (User): The user object.

        Returns:
            int: The count of posts.
        """
        try:
            return obj.posts.count()
        except AttributeError:
            return 0

    @staticmethod
    def get_comments_count(obj: User) -> int:
        """
        Returns the number of comments by the user.

        Args:
            obj (User): The user object.

        Returns:
            int: The count of comments.
        """
        try:
            return obj.comments.count()
        except AttributeError:
            return 0


class UserUpdateSerializer(serializers.ModelSerializer):
    """
    Serializer for updating user profile information.

    Allows updating of first_name, last_name, avatar, and bio fields.

    Fields:
        - first_name: User's first name (optional).
        - last_name: User's last name (optional).
        - avatar: User's profile picture (optional).
        - bio: User's biography (optional).
    """

    class Meta:
        model = User
        fields = ("first_name", "last_name", "avatar", "bio")

    def update(self, instance: User, validated_data: Dict[str, Any]) -> User:
        """
        Updates user data with validated input.

        Args:
            instance (User): The user object to update.
            validated_data (Dict[str, Any]): Validated data for updating.

        Returns:
            User: The updated user object.
        """
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance


class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for changing a user's password.

    Accepts old password, new password, and new password confirmation. Validates
    the old password and ensures the new password matches its confirmation.

    Fields:
        - old_password: Current password (required).
        - new_password: New password (required).
        - new_password_confirm: Confirmation of new password (required).

    Validation:
        - Verifies the old password is correct.
        - Ensures new password and confirmation match.
        - Applies Django's password validation to the new password.
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, validators=[validate_password])
    new_password_confirm = serializers.CharField(required=True)

    def validate_old_password(self, value: str) -> str:
        """
        Validates that the old password is correct.

        Args:
            value (str): The old password.

        Raises:
            serializers.ValidationError: If the old password is incorrect.

        Returns:
            str: The validated old password.
        """
        user = self.context["request"].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is incorrect.")
        return value

    def validate(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validates that new password and confirmation match.

        Args:
            attrs (Dict[str, Any]): Input data for validation.

        Raises:
            serializers.ValidationError: If passwords do not match.

        Returns:
            Dict[str, Any]: Validated data.
        """
        if attrs["new_password"] != attrs["new_password_confirm"]:
            raise serializers.ValidationError(
                {"new_password": "Password fields did not match."}
            )
        return attrs

    def save(self) -> User:
        """
        Sets the new password for the user and saves the changes.

        Returns:
            User: The updated user object.
        """
        user = self.context["request"].user
        user.set_password(self.validated_data["new_password"])
        user.save()
        return user
