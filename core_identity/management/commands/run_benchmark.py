from django.core.management.base import BaseCommand
from scripts.run_comparative_benchmark import run_comparative_benchmark

class Command(BaseCommand):
    help = "Execute the Comparative Cryptographic Benchmark Protocol (ML-DSA-65 vs ECDSA)"

    def add_arguments(self, parser):
        parser.add_argument("--iterations", type=int, default=50, help="Number of benchmark iterations (default: 50)")
        parser.add_argument("--warmup", type=int, default=5, help="Number of discarded warm-up rounds (default: 5)")

    def handle(self, *args, **options):
        iterations = options.get("iterations", 50)
        warmup = options.get("warmup", 5)
        self.stdout.write(self.style.NOTICE(f"Launching Comparative Benchmark Protocol ({iterations} iterations, {warmup} warmup rounds)..."))
        results = run_comparative_benchmark(iterations=iterations, warmup=warmup)
        self.stdout.write(self.style.SUCCESS("Comparative benchmark protocol completed successfully."))
