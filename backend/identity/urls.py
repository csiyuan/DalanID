"""URL map for the identity app."""

from django.urls import path

from . import views

urlpatterns = [
    path(
        "profile/<slug:public_id>",
        views.ContextualProfileView.as_view(),
        name="contextual-profile",
    ),
    path(
        "profile/<slug:public_id>/full",
        views.full_record,
        name="full-record",
    ),
    path("contexts", views.list_contexts, name="context-list"),
    path("contexts/create", views.ContextCreateView.as_view(),
         name="context-create"),
    path("contexts/<slug:slug>/grants", views.GrantCreateView.as_view(),
         name="grant-create"),
    path("keys/issue", views.issue_key, name="key-issue"),
    path("audit/verify", views.verify_audit_chain, name="audit-verify"),
    path("citizens/<slug:public_id>/disclosures", views.my_disclosures,
         name="my-disclosures"),
    path("subject/token", views.issue_subject_token, name="subject-token"),
    path("auth/login", views.auth_login, name="auth-login"),
    path("auth/verify", views.auth_verify, name="auth-verify"),
]
