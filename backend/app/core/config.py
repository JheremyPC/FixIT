from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
import os

class Settings(BaseSettings):
    database_url: str 
    jwt_secret_key: str
    jwt_access_minutes: int = 30
    jwt_refresh_days: int = 7
    upload_dir: str = "uploads"
    max_upload_bytes: int = 5_242_880
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def upload_path(self) -> Path:
        path = Path(self.upload_dir)
        path.mkdir(parents=True, exist_ok=True)
        return path


settings = Settings()

