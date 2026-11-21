"""Use real profile/password endpoints with the isolated suite's navigation."""
from django.urls import include, path

from authentication.password_views import UpdatePassword
from dashboard.test_urls import urlpatterns as navigation_urls
from user_management.views import Profile, Users

urlpatterns = [
    path("users/", include("user_management.urls")),
    path("api/v1/users/profile/", Profile.as_view()),
    path("api/v1/users/user/<str:uu_id>/", Users.as_view()),
    path("api/v1/auth/update-pass/", UpdatePassword.as_view()),
    path("auth/update-pass/", UpdatePassword.as_view()),
] + [route for route in navigation_urls if getattr(route, "namespace", None) != "users"]
