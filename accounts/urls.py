from django.urls import path

from . import views

urlpatterns = [
    path("kdf-defaults/", views.KdfDefaultsView.as_view(), name="kdf-defaults"),
    path("prelogin/", views.PreloginView.as_view(), name="prelogin"),
    path("register/", views.RegisterView.as_view(), name="register"),
    path("login/", views.LoginView.as_view(), name="login"),
    path("refresh/", views.RefreshView.as_view(), name="token-refresh"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path("me/", views.MeView.as_view(), name="me"),
    path("change-master-password/", views.ChangeMasterPasswordView.as_view(), name="change-master-password"),
    path("users/<str:username>/public-keys/", views.PublicKeysView.as_view(), name="public-keys"),
    path("admin/users/", views.AdminUserListView.as_view(), name="admin-users"),
    path("admin/users/<int:pk>/", views.AdminUserDetailView.as_view(), name="admin-user-detail"),
]
