"""
URL configuration for backend_django project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include, re_path
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(
        title="Xenoverify Post-Quantum Identity API",
        default_version="v1",
        description="Comprehensive REST API for NIST FIPS 204 ML-DSA-65 Digital Identity Verification & Merkle-Tree Selective Disclosure Prototype (MSc Dissertation DSRM Implementation).",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="research@xenoverify.ac.ng"),
        license=openapi.License(name="MIT License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

from django.shortcuts import render

def cdn_swagger_view(request):
    return render(request, "swagger_cdn.html")

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("core_identity.urls")),

    # Swagger Documentation URLs
    path("swagger/", cdn_swagger_view, name="swagger-ui-cdn"),
    path("swagger.json", schema_view.without_ui(cache_timeout=0), name="schema-swagger-json"),
    path("swagger-drf/", schema_view.with_ui("swagger", cache_timeout=0), name="schema-swagger-ui"),
    path("redoc/", schema_view.with_ui("redoc", cache_timeout=0), name="schema-redoc"),
    re_path(r"^swagger(?P<format>\.json|\.yaml)$", schema_view.without_ui(cache_timeout=0), name="schema-json"),

]



