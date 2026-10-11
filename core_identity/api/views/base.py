"""
Base API View providing consistent response structure, logging, and error handling.
"""

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import logging

logger = logging.getLogger(__name__)


class BaseAPIView(APIView):
    """
    Abstract Base View ensuring unified response formatting across all endpoints.
    """

    def success_response(self, data: dict, status_code: int = status.HTTP_200_OK) -> Response:
        return Response(data, status=status_code)

    def error_response(self, message: str, status_code: int = status.HTTP_400_BAD_REQUEST, extra: dict = None) -> Response:
        payload = {"error": message, "success": False}
        if extra:
            payload.update(extra)
        return Response(payload, status=status_code)
