from django.core.management.base import BaseCommand
from scripts.run_feasibility_100 import run_feasibility_protocol

class Command(BaseCommand):
    help = "Execute the 100-trial Xenoverify Post-Quantum Feasibility Evaluation Protocol"

    def add_arguments(self, parser):
        parser.add_argument("--trials", type=int, default=100, help="Number of consecutive trials (default: 100)")
        parser.add_argument("--output", type=str, default=None, help="Custom output CSV file path")

    def handle(self, *args, **options):
        trials = options.get("trials", 100)
        output_csv = options.get("output", None)
        self.stdout.write(self.style.NOTICE(f"Launching Feasibility Protocol with {trials} trials..."))
        results = run_feasibility_protocol(num_trials=trials, output_csv=output_csv)
        self.stdout.write(self.style.SUCCESS(f"Feasibility protocol completed successfully. Results written."))
