"""
Clean URL routing for Core Identity REST API.
Delegates to modular controllers in core_identity.api.views.
"""

from django.urls import path, re_path
from backend_django.urls import schema_view
from core_identity.api.views import (
    SystemInfoView,
    InitializeIssuerView,
    IssueCredentialView,
    ListCredentialsView,
    RevokeCredentialView,
    GenerateSelectiveDisclosureProofView,
    VerifySelectiveDisclosureProofView,
    RunBenchmarkSuiteView,
)


urlpatterns = [
    path('system/info/', SystemInfoView.as_view(), name='system-info'),
    path('issuers/initialize/', InitializeIssuerView.as_view(), name='initialize-issuer'),
    path('credentials/issue/', IssueCredentialView.as_view(), name='issue-credential'),
    path('credentials/list/', ListCredentialsView.as_view(), name='list-credentials'),
    path('credentials/revoke/', RevokeCredentialView.as_view(), name='revoke-credential'),
    path('proofs/generate/', GenerateSelectiveDisclosureProofView.as_view(), name='generate-proof'),
    path('proofs/verify/', VerifySelectiveDisclosureProofView.as_view(), name='verify-proof'),
    path('benchmarks/run/', RunBenchmarkSuiteView.as_view(), name='run-benchmarks'),
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='api-schema-json'),
    path('schema.json', schema_view.without_ui(cache_timeout=0), name='api-schema-json-direct'),
]


