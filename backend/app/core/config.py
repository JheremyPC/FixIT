from pathlib import Path
from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    database_url: str
    jwt_secret_key: str
    jwt_access_minutes: int = 30
    jwt_refresh_days: int = 7
    upload_dir: str = "uploads"
    max_upload_bytes: int = 5_242_880

    # DEMO_ACCESS_TEMPORARY: one-click demo accounts on the login screen. Off unless DEMO_ACCESS_ENABLED=true;
    # turning it off also invalidates every open demo session.
    demo_access_enabled: bool = False

    # Machine Learning: trained artifacts live outside Git (see .gitignore).
    ml_model_dir: str = str(BACKEND_DIR / "ml_models")

    # LLM provider. Empty provider means "not configured": the assistant reports it
    # instead of pretending to answer. Keys are SecretStr so they never appear in reprs/logs.
    llm_provider: str = ""            # anthropic | openai_compatible
    llm_api_key: SecretStr | None = None
    anthropic_api_key: SecretStr | None = None
    llm_model: str = ""
    llm_base_url: str = ""            # required for openai_compatible (e.g. http://localhost:11434/v1 or Gemini's .../v1beta/openai)
    llm_fallback_model: str = "gemini-3.5-flash-lite"  # Gemini only: used if LLM_MODEL keeps answering HTTP 429/503; empty disables
    llm_max_tokens: int = 2048
    llm_timeout_seconds: float = 60.0
    llm_effort: str = "low"           # anthropic output_config.effort; Gemini reasoning_effort (minimal|low|medium|high)
    llm_anthropic_fallbacks: str = "default"  # "default" enables server-side refusal fallbacks; "off" disables

    # Running from backend/ also finds the project-level .env (README workflow).
    model_config = SettingsConfigDict(env_file=(str(BACKEND_DIR.parent / ".env"), ".env"), extra="ignore")

    @property
    def upload_path(self) -> Path:
        path = Path(self.upload_dir)
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def ml_path(self) -> Path:
        path = Path(self.ml_model_dir)
        path.mkdir(parents=True, exist_ok=True)
        return path


settings = Settings()
