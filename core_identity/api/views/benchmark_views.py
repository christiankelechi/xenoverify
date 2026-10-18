"""
Empirical Evaluation & Benchmarking API Views (MRe Chapter 4).
"""

from rest_framework import status
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from core_identity.api.views.base import BaseAPIView
from core_identity.services import BenchmarkService


class RunBenchmarkSuiteView(BaseAPIView):
    """
    Automated Chapter 4 Experimental Suite:
    Executes N iterations across ML-DSA-65 vs Classical ECDSA,
    calculates Mean, Median, and p95 tail latencies, signature bytes, and storage overhead.
    """

    @swagger_auto_schema(
        operation_description="Run automated comparative benchmark suite between ML-DSA-65 and ECDSA baseline across N trials.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "iterations": openapi.Schema(type=openapi.TYPE_INTEGER, default=20, description="Trial count (5 to 100)")
            }
        ),
        responses={200: "Benchmark distribution dataset"}
    )
    def post(self, request):
        iterations = int(request.data.get("iterations", 20))
        results = BenchmarkService.run_comparative_benchmark(iterations=iterations)
        return self.success_response(results)
