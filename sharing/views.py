from django.db.models import Q
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView

from audit.models import AuditLog
from audit.service import log_event
from vault_project.cryptoutils import share_signing_message, verify_pss_signature

from .models import SharedItem
from .serializers import CreateShareSerializer, OutboxShareSerializer, SharedItemSerializer


class CreateShareView(APIView):
    def post(self, request):
        serializer = CreateShareSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        sender, recipient = request.user, data["recipient"]

        # Defence in depth: the recipient verifies the signature in the browser, but the
        # server also refuses anything not signed by the authenticated sender's key.
        message = share_signing_message(
            sender=sender.username, recipient=recipient.username,
            iv=data["iv"], ciphertext=data["ciphertext"], wrapped_key=data["wrapped_key"],
        )
        if not verify_pss_signature(sender.signing_public_key, data["signature"], message):
            log_event(request, AuditLog.Event.SHARE_REJECTED_SIGNATURE, success=False,
                      metadata={"recipient": recipient.username})
            return Response({"detail": "Invalid signature."}, status=status.HTTP_400_BAD_REQUEST)

        share = SharedItem.objects.create(
            sender=sender, recipient=recipient,
            iv=data["iv"], ciphertext=data["ciphertext"], wrapped_key=data["wrapped_key"],
            signature=data["signature"], sender_signing_public_key=sender.signing_public_key,
        )
        log_event(request, AuditLog.Event.SHARE_CREATE, target=share, metadata={"recipient": recipient.username})
        return Response(OutboxShareSerializer(share).data, status=status.HTTP_201_CREATED)


class InboxView(generics.ListAPIView):
    serializer_class = SharedItemSerializer

    def get_queryset(self):
        return SharedItem.objects.filter(recipient=self.request.user).select_related("sender", "recipient")


class OutboxView(generics.ListAPIView):
    serializer_class = OutboxShareSerializer

    def get_queryset(self):
        return SharedItem.objects.filter(sender=self.request.user).select_related("recipient")


class AcceptShareView(APIView):
    def post(self, request, pk):
        share = get_object_or_404(SharedItem, pk=pk, recipient=request.user)
        if share.status != SharedItem.Status.ACCEPTED:
            share.status = SharedItem.Status.ACCEPTED
            share.accepted_at = timezone.now()
            share.save(update_fields=["status", "accepted_at"])
            log_event(request, AuditLog.Event.SHARE_ACCEPT, target=share, metadata={"sender": share.sender.username})
        return Response(SharedItemSerializer(share).data)


class DeleteShareView(APIView):
    """Sender revokes, or recipient dismisses, a share."""

    def delete(self, request, pk):
        share = get_object_or_404(SharedItem, Q(sender=request.user) | Q(recipient=request.user), pk=pk)
        log_event(request, AuditLog.Event.SHARE_DELETE, target=share,
                  metadata={"by": "sender" if share.sender_id == request.user.pk else "recipient"})
        share.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
