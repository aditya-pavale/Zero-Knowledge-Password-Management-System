from django.core.management.base import BaseCommand, CommandError

from accounts.models import User
from audit.models import AuditLog
from audit.service import log_event


class Command(BaseCommand):
    help = "Set a user's role (user, auditor, admin). Use this to bootstrap the first admin."

    def add_arguments(self, parser):
        parser.add_argument("username")
        parser.add_argument("role", choices=[choice for choice, _ in User.Role.choices])

    def handle(self, *args, username, role, **options):
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist as exc:
            raise CommandError(f"No user named {username!r}") from exc
        old = user.role
        user.role = role
        user.save(update_fields=["role"])
        log_event(
            None, AuditLog.Event.ROLE_CHANGE, username="manage.py", target=user,
            metadata={"username": user.username, "from": old, "to": role, "via": "cli"},
        )
        self.stdout.write(self.style.SUCCESS(f"{username}: {old} -> {role}"))
