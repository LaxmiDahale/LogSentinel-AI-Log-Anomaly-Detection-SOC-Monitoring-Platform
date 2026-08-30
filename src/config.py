import os
import yaml
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"

class Config:
    ENV = os.getenv("APP_ENV", "development")
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./logsentinel.db")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "20"))
    
    @staticmethod
    def load_yaml(filename: str) -> dict:
        filepath = CONFIG_DIR / filename
        if filepath.exists():
            with open(filepath, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        return {}

    @classmethod
    def get_detection_rules(cls) -> dict:
        return cls.load_yaml("detection_rules.yaml")

    @classmethod
    def get_settings(cls) -> dict:
        return cls.load_yaml("settings.yaml")

settings = Config()
