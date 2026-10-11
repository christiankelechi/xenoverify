import os
import django
from django.core.management import call_command

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "backend_django.settings")
django.setup()

# Auto-migrate /tmp/db.sqlite3 on serverless cold start
try:
    call_command("migrate", interactive=False)
except Exception as e:
    print("Migration warning on cold start:", e)

from backend_django.wsgi import app
