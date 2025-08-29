from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """
    Custom user model.

    Extends Django's AbstractUser to include additional fields like avatar and bio,
    and uses email as the primary identifier for authentication.
    """

    email = models.EmailField(unique=True, help_text="The user's email address.")
    first_name = models.CharField(
        max_length=30,
        blank=True,
        help_text="The user's first name (optional, max 30 characters).",
    )
    last_name = models.CharField(
        max_length=30,
        blank=True,
        help_text="The user's last name (optional, max 30 characters).",
    )
    avatar = models.ImageField(
        upload_to="avatars/",
        blank=True,
        help_text="An optional profile picture uploaded to the 'avatars/' directory.",
    )
    bio = models.TextField(
        max_length=500,
        blank=True,
        help_text="A short biography of the user (optional, max 500 characters).",
    )
    created_at = models.DateTimeField(
        auto_now_add=True, help_text="Timestamp when the user account was created."
    )
    updated_at = models.DateTimeField(
        auto_now=True, help_text="Timestamp when the user account was last updated."
    )
    is_active = models.BooleanField(
        default=True, help_text="Indicates whether the user account is active."
    )

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]

    class Meta:
        """
        Metadata for the User model.
        """

        db_table = "users"
        verbose_name = "User"
        verbose_name_plural = "Users"

    def __str__(self) -> str:
        """
        Returns the string representation of the user.

        Returns:
            str: The user's email address.
        """
        return self.email

    @property
    def full_name(self) -> str:
        """
        Computes the full name by combining first_name and last_name

        Returns:
            str: The concatenated first and last name, stripped of extra whitespace.
        """
        return f"{self.first_name} {self.last_name}".strip()
