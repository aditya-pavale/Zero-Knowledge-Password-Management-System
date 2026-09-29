from rest_framework.permissions import BasePermission


class IsAdminRole(BasePermission):
    message = "Admin role required."

    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and user.is_admin_role)


class IsAuditorOrAdmin(BasePermission):
    message = "Auditor or admin role required."

    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and user.is_auditor_role)
