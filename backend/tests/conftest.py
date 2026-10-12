"""Test isolation: every run uses a fresh local SQLite database and a temporary model folder.

Environment variables take precedence over any .env file, so tests can never reach the
configured production database (e.g. Supabase) or a real LLM provider.
"""
import os
import tempfile
from pathlib import Path

_tmp = Path(tempfile.mkdtemp(prefix="fixit-tests-"))
os.environ["DATABASE_URL"] = f"sqlite:///{(_tmp / 'test.db').as_posix()}"
os.environ["JWT_SECRET_KEY"] = "test-secret-key-for-pytest-only-0123456789"
os.environ["FIXIT_ADMIN_PASSWORD"] = "FixIT!2026"
os.environ["ML_MODEL_DIR"] = str(_tmp / "ml_models")
os.environ["UPLOAD_DIR"] = str(_tmp / "uploads")
os.environ["LLM_PROVIDER"] = ""
os.environ["LLM_API_KEY"] = ""
os.environ["ANTHROPIC_API_KEY"] = ""
