from django.urls import path

from . import views

urlpatterns = [
    path("", views.CreateShareView.as_view(), name="share-create"),
    path("inbox/", views.InboxView.as_view(), name="share-inbox"),
    path("outbox/", views.OutboxView.as_view(), name="share-outbox"),
    path("<int:pk>/accept/", views.AcceptShareView.as_view(), name="share-accept"),
    path("<int:pk>/", views.DeleteShareView.as_view(), name="share-delete"),
]
